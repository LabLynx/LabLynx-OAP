# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Site and team administration not yet served elsewhere: site configuration, the usage report,
storage-unit and compound writes, batch actions, identity-provider writes, team counts, the purge of a
team's records and the site assets."""
from typing import Any

from fastapi import APIRouter, Body, Depends, Request, Response
from fastapi.responses import PlainTextResponse, StreamingResponse

from ... import errors
from ...files import store as store_mod
from ...people import config as CFG
from ...people import siteops as OPS
from ...records import batch as B
from ..deps import Ctx, ctx, query_dict

router = APIRouter(tags=["site_admin"])


def _store(c: Ctx):
    return store_mod.for_settings(c.settings)


# ---------------------------------------------------------------------------- site configuration
@router.get("/api/v2/config", summary="Site configuration (secret values are never answered)")
def read_config(c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return CFG.read_config(tx, c.principal)


@router.patch("/api/v2/config", summary="Change site configuration")
def patch_config(c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        return CFG.patch_config(tx, c.principal, c.actor, c.settings, body)


# ---------------------------------------------------------------------------------- usage report
@router.get("/api/v2/reports", summary="Usage report")
def reports(request: Request, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        out = OPS.report(tx, c.principal, query_dict(request))
    if isinstance(out, str):
        return PlainTextResponse("﻿" + out, media_type="text/csv; charset=UTF-8",
                                 headers={"Content-Disposition": 'attachment; filename="report.csv"',
                                          "X-Content-Type-Options": "nosniff"})
    return out


# --------------------------------------------------------------------------------- storage units
@router.post("/api/v2/storage_units", status_code=201, summary="Add a location")
def create_unit(c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        uid = OPS.create_unit(tx, c.principal, c.actor, body)
    return Response(status_code=201, headers={"Location": c.location("storage_units/%d" % uid)})


@router.patch("/api/v2/storage_units/{unit_id}", summary="Rename or move a location")
def patch_unit(unit_id: int, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        return OPS.patch_unit(tx, c.principal, c.actor, unit_id, body)


@router.delete("/api/v2/storage_units/{unit_id}", status_code=204, summary="Delete an empty location")
def delete_unit(unit_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx() as tx:
        OPS.delete_unit(tx, c.principal, c.actor, unit_id)
    return Response(status_code=204)


# ------------------------------------------------------------------------------------- compounds
@router.post("/api/v2/compounds", status_code=201, summary="Add a compound")
def create_compound(c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        cid = OPS.create_compound(tx, c.principal, c.actor, body)
    return Response(status_code=201, headers={"Location": c.location("compounds/%d" % cid)})


@router.patch("/api/v2/compounds/{compound_id}", summary="Change a compound")
def patch_compound(compound_id: int, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        return OPS.patch_compound(tx, c.principal, c.actor, compound_id, body)


@router.delete("/api/v2/compounds/{compound_id}", status_code=204, summary="Delete a compound (state 3)")
def delete_compound(compound_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx() as tx:
        OPS.delete_compound(tx, c.principal, c.actor, compound_id)
    return Response(status_code=204)


# ----------------------------------------------------------------------------------------- batch
@router.post("/api/v2/batch", status_code=201, summary="Apply one action to many records")
def batch(c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        n = B.run(tx, c.principal, c.actor, body)
    return Response(status_code=201, headers={"Location": c.location("batch/%d" % n)})


# ------------------------------------------------------------------------------- identity providers
@router.post("/api/v2/idps", status_code=201, summary="Add an identity provider")
def create_idp(c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        iid = CFG.create_idp(tx, c.principal, c.actor, body)
    return Response(status_code=201, headers={"Location": c.location("idps/%d" % iid)})


@router.patch("/api/v2/idps/{idp_id}", summary="Change an identity provider")
def patch_idp(idp_id: int, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        return CFG.patch_idp(tx, c.principal, c.actor, idp_id, body)


@router.delete("/api/v2/idps/{idp_id}", status_code=204, summary="Remove an identity provider")
def delete_idp(idp_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx() as tx:
        CFG.delete_idp(tx, c.principal, c.actor, idp_id)
    return Response(status_code=204)


@router.post("/api/v2/idps_sources", status_code=201, summary="Add a metadata source")
def create_idp_source(c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        sid = CFG.create_idp_source(tx, c.principal, c.actor, body)
    return Response(status_code=201, headers={"Location": c.location("idps_sources/%d" % sid)})


@router.patch("/api/v2/idps_sources/{source_id}", summary="Change a source, or refresh its metadata")
def patch_idp_source(source_id: int, c: Ctx = Depends(ctx), body: Any = Body(None)):
    if isinstance(body, dict) and body.get("action") == "refresh":
        from ...people import idp_refresh
        CFG.may_refresh(c.principal)
        src, _counts = idp_refresh.refresh(c.pool, c.actor, source_id)
        return src
    with c.pool.tx() as tx:
        return CFG.patch_idp_source(tx, c.principal, c.actor, source_id, body)


@router.delete("/api/v2/idps_sources/{source_id}", status_code=204, summary="Remove a source")
def delete_idp_source(source_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx() as tx:
        CFG.delete_idp_source(tx, c.principal, c.actor, source_id)
    return Response(status_code=204)


# ---------------------------------------------------------------------- team counts and purge
@router.get("/api/v2/occ/teams/{team_id}/stats", summary="Counts for one team")
def team_stats(team_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return B.team_stats(tx, c.principal, team_id)


@router.post("/api/v2/occ/teams/{team_id}/purge", summary="Permanently remove a team's records (demo reset)")
def purge(team_id: int, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        return B.purge(tx, c.principal, c.actor, team_id, body, CFG.flag(tx, "allow_purge"))


# -------------------------------------------------------------------------------- site assets
@router.get("/api/v2/occ/site/assets/{name}", summary="Read a site asset (public)")
def read_asset(name: str, request: Request):
    store = store_mod.for_settings(request.app.state.settings)
    with request.app.state.pool.tx(readonly=True) as tx:
        mime, fh = OPS.read_asset(tx, store, name)
    return StreamingResponse(store_mod.iter_file(fh), media_type=mime,
                             headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "public, max-age=300"})


@router.put("/api/v2/occ/site/assets/{name}", summary="Replace a site asset (sysadmin)")
async def put_asset(name: str, request: Request, c: Ctx = Depends(ctx)):
    OPS.asset_name(name)
    form = await request.form(max_files=1, max_fields=5)
    f = form.get("file")
    if f is None or not hasattr(f, "read"):
        raise errors.bad("Send the image as multipart field 'file'")
    data = await f.read(OPS.ASSET_MAX + 1)
    store = _store(c)

    def _put():
        with c.pool.tx() as tx:
            return OPS.put_asset(tx, c.principal, c.actor, store, name, data, f.content_type)
    from starlette.concurrency import run_in_threadpool
    return await run_in_threadpool(_put)
