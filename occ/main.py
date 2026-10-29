# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The application factory: settings, pool, logging, the error envelope, the routes.

Run under uvicorn bound to 127.0.0.1 only (a web server in front handles the outside):
    OCC_ENV_FILE=/etc/occ/occ.env uvicorn occ.main:app --host 127.0.0.1 --port 8710 --workers 2
"""
import os
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__, db, errors, logs, ratelimit, settings as settings_mod, timefmt
from .auth import apikeys, sessions
from .db import migrate

API_ENDPOINTS = ("apikeys, batch, compounds, config, event, events, experiments, experiments_templates, exports, "
                 "extra_fields_keys, favtags, idps, idps_sources, import, info, instance, items, items_types, occ, "
                 "reports, storage_units, team_tags, teams, todolist, unfinished_steps, users")
LOCAL = {"127.0.0.1", "::1", "localhost", "testclient"}


def create_app(cfg=None):
    cfg = cfg or settings_mod.load()
    timefmt.set_zone(cfg.timezone)
    log = logs.setup(cfg.log_level)
    app = FastAPI(title="LabLynx.One OCC", version=__version__, root_path=cfg.root_path or "",
                  openapi_url="/api/v2/openapi.json", docs_url=None, redoc_url=None,
                  description="LabLynx.One Open Core CMS (AGPL-3.0-only). Mirrors eLabFTW API v2 and adds to it "
                              "under /api/v2/occ/.")
    app.state.settings = cfg
    app.state.pool = db.Pool(cfg.db_params(), size=cfg.pool_size)
    _pepper_cache = {}

    def pepper():
        if "v" not in _pepper_cache:
            _pepper_cache["v"] = apikeys.read_pepper(cfg.api_key_pepper_file)
        return _pepper_cache["v"]
    app.state.pepper = pepper
    app.state.metrics = {"requests": 0, "errors_5xx": 0}
    app.state.limiter = ratelimit.Limiter(cfg.rate_burst, cfg.rate_sustained, cfg.rate_downloads)

    @app.middleware("http")
    async def request_log(request: Request, call_next):
        rid = request.headers.get("x-request-id") or ""
        try:
            rid = str(uuid.UUID(rid))
        except ValueError:
            rid = str(uuid.uuid4())
        request.state.request_id = rid
        request.state.user_id = None
        request.state.team = None
        t0 = time.monotonic()
        status = 500
        try:
            try:
                wait = None
                if not request.url.path.endswith(ratelimit.EXEMPT_PATHS):
                    wait = app.state.limiter.check(ratelimit.caller_id(request, sessions.COOKIE),
                                                   download=ratelimit.is_download(request))
                if wait is not None:
                    response = JSONResponse({"code": 429, "message": "Too many requests: slow down and retry.",
                                             "description": "retry after %d s" % wait}, status_code=429,
                                            headers={"Retry-After": str(wait)})
                else:
                    response = await call_next(request)
            except Exception as exc:  # noqa: BLE001 - answered here, so the connection stays usable
                log.error("unhandled", exc_info=exc, extra={"occ": {"request_id": rid, "event": "unhandled error"}})
                response = JSONResponse({"code": 500, "message": "Something went wrong on the server.",
                                         "description": "request id %s" % rid}, status_code=500)
            status = response.status_code
        finally:
            route = request.scope.get("route")
            app.state.metrics["requests"] += 1
            if status >= 500:
                app.state.metrics["errors_5xx"] += 1
            logs.request_line(request_id=rid, method=request.method,
                              route=getattr(route, "path", None) or "(no route)", status=status,
                              duration_ms=int((time.monotonic() - t0) * 1000),
                              user_id=request.state.user_id, team=request.state.team)
        response.headers["X-Request-Id"] = rid
        return response

    @app.exception_handler(errors.OCCError)
    async def occ_error(request: Request, exc: errors.OCCError):
        return JSONResponse(exc.body(), status_code=exc.status, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        where = ""
        for e in exc.errors():
            loc = [str(x) for x in e.get("loc", ()) if x not in ("body", "path", "query")]
            if loc:
                where = loc[-1]
                break
        msg = ("Incorrect value for %s" % where) if where else "The request is not valid"
        return JSONResponse({"code": 400, "message": msg, "description": ""}, status_code=400)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        if exc.status_code == 404 and "/api/v2" in request.url.path:
            # As eLabFTW does: an unknown endpoint answers 400 listing the endpoints.
            return JSONResponse({"code": 400, "message": "Invalid endpoint: available endpoints: " + API_ENDPOINTS,
                                 "description": ""}, status_code=400)
        return JSONResponse({"code": exc.status_code, "message": str(exc.detail), "description": ""},
                            status_code=exc.status_code)

    @app.exception_handler(Exception)
    async def unexpected(request: Request, exc: Exception):
        log.error("unhandled", exc_info=exc, extra={"occ": {"request_id": getattr(request.state, "request_id", None),
                                                             "event": "unhandled error"}})
        return JSONResponse({"code": 500, "message": "Something went wrong on the server.",
                             "description": "request id %s" % getattr(request.state, "request_id", "")},
                            status_code=500)

    # -- health: answered only from localhost, never from outside ---------------------------
    def _local(request):
        host = request.client.host if request.client else ""
        if host not in LOCAL:
            raise errors.OCCError(404, "Not found")

    @app.get("/healthz", include_in_schema=False)
    def healthz(request: Request):
        _local(request)
        return {"ok": True}

    @app.get("/readyz", include_in_schema=False)
    def readyz(request: Request):
        _local(request)
        checks = {}
        try:
            with app.state.pool.tx(readonly=True) as tx:
                tx.val("SELECT 1")
            checks["database"] = "ok"
        except Exception as e:  # noqa: BLE001 - reported, not raised
            checks["database"] = "unreachable (%s)" % type(e).__name__
        try:
            st = migrate.status(cfg.db_params())
            checks["migrations"] = "ok (at %04d)" % st["current"] if st["at_head"] else \
                ("behind: at %04d, newest file %04d%s" % (st["current"], st["head"],
                                                          ("; " + st["problem"]) if st["problem"] else ""))
        except Exception as e:  # noqa: BLE001
            checks["migrations"] = "cannot read (%s)" % type(e).__name__
        try:
            os.makedirs(cfg.files_root, exist_ok=True)
            probe = os.path.join(cfg.files_root, ".readyz")
            with open(probe, "w") as fh:
                fh.write("ok")
            os.remove(probe)
            checks["file_store"] = "ok"
        except OSError as e:
            checks["file_store"] = "not writable (%s)" % type(e).__name__
        try:
            pepper()
            checks["api_key_pepper"] = "ok"
        except apikeys.PepperMissing:
            checks["api_key_pepper"] = "missing"
        ok = all(str(v).startswith("ok") for v in checks.values())
        return JSONResponse({"ok": ok, "checks": checks}, status_code=200 if ok else 503)

    @app.get("/metrics", include_in_schema=False)
    def metrics(request: Request):
        _local(request)
        m = app.state.metrics
        text = ("# TYPE occ_requests_total counter\nocc_requests_total %d\n"
                "# TYPE occ_errors_5xx_total counter\nocc_errors_5xx_total %d\n"
                "# TYPE occ_rate_limited_total counter\nocc_rate_limited_total %d\n"
                % (m["requests"], m["errors_5xx"], app.state.limiter.refused))
        try:
            # The worker: jobs by state (a dead job is one that failed five times), the last blob check's
            # mismatches and whether the last audit checkpoint verified.
            from .worker import jobs as jobs_mod
            with app.state.pool.tx(readonly=True) as tx:
                states = jobs_mod.counts(tx)
                bad_blobs = tx.val("SELECT COALESCE((payload->'result'->>'mismatches')::int, 0) FROM occ.jobs "
                                   "WHERE kind = 'blob-verify' AND state = 'done' ORDER BY finished_at DESC LIMIT 1")
                chain_ok = tx.val("SELECT verified_ok FROM occ.audit_checkpoints ORDER BY id DESC LIMIT 1")
            text += "# TYPE occ_jobs gauge\n" + "".join(
                'occ_jobs{state="%s"} %d\n' % (s, n) for s, n in sorted(states.items()))
            text += "# TYPE occ_jobs_dead gauge\nocc_jobs_dead %d\n" % states.get("dead", 0)
            text += "# TYPE occ_blob_mismatches gauge\nocc_blob_mismatches %d\n" % int(bad_blobs or 0)
            if chain_ok is not None:
                text += "# TYPE occ_audit_chain_ok gauge\nocc_audit_chain_ok %d\n" % (1 if chain_ok else 0)
            from .sync import status as sync_status          # how far the sync lags behind 2.x
            with app.state.pool.tx(readonly=True) as tx:
                text += sync_status.metrics_text(tx)
        except Exception as e:  # noqa: BLE001 - the counters above still answer
            text += "# occ_jobs unavailable: %s\n" % type(e).__name__
        return PlainTextResponse(text)

    from .api.occ import additions, ops
    from .api.v2 import events, files, people, records, site_admin, teams
    app.include_router(additions.router)
    app.include_router(ops.router)
    app.include_router(teams.router)
    app.include_router(people.router)
    app.include_router(events.router)
    app.include_router(site_admin.router)
    app.include_router(files.router)
    app.include_router(records.router)

    return app


def _lazy():
    """`occ.main:app` for uvicorn: built on first import with the settings from the environment."""
    return create_app()


app = None
if os.environ.get("OCC_NO_AUTOAPP") != "1":
    try:
        app = _lazy()
    except Exception:  # noqa: BLE001 - importing for tests or tooling without a configured server
        app = None
