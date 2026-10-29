# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The job queue: rows in occ.jobs, claimed with FOR UPDATE SKIP LOCKED.

The contract other code uses:

    from occ.worker import jobs

    @jobs.register("export")
    def run_export(ctx, job):          # ctx: .pool, .settings, .store, .log; job: the occ.jobs row as a dict
        ...                            # do the work in the handler's own transactions
        return {"rows": 12}            # optional result, kept on the job (payload.result)

    jobs.enqueue(tx, "export", {"export_id": 7}, dedupe_key="export:7")

A job that raises is retried with a growing delay (30 s, 60 s, 120 s ... at most an hour); after
max_attempts (5) it is marked dead, stays in the table and is counted in /metrics. A dedupe_key
keeps a second copy of the same work out while one is queued or running. A job left 'running' by
a worker that died is put back after STALE_MINUTES.
"""
import datetime as dt
import traceback

from ..db import jsonb

HANDLERS = {}
STALE_MINUTES = 30
BACKOFF_BASE_S = 30
BACKOFF_MAX_S = 3600


def register(kind):
    def deco(fn):
        HANDLERS[kind] = fn
        return fn
    return deco


def enqueue(tx, kind, payload=None, *, dedupe_key=None, run_at=None, priority=5):
    """Queue a job; returns its id. With a dedupe_key already queued or running, returns that
    job's id and queues nothing."""
    jid = tx.val("INSERT INTO occ.jobs (kind, payload, dedupe_key, run_at, priority) "
                 "VALUES (:k, CAST(:p AS jsonb), :d, COALESCE(CAST(:r AS timestamptz), now()), :pr) "
                 "ON CONFLICT (dedupe_key) WHERE dedupe_key IS NOT NULL AND state IN ('queued','running') "
                 "DO NOTHING RETURNING id",
                 k=kind, p=jsonb(payload or {}), d=dedupe_key, r=run_at, pr=int(priority))
    if jid is None and dedupe_key is not None:
        jid = tx.val("SELECT id FROM occ.jobs WHERE dedupe_key = :d AND state IN ('queued','running')",
                     d=dedupe_key)
    return jid


def reap(tx):
    """Put back jobs a dead worker left 'running' (their attempt still counts)."""
    return tx.run("UPDATE occ.jobs SET state = 'queued', locked_by = NULL, locked_at = NULL, "
                  "last_error = 'the worker stopped while running it' "
                  "WHERE state = 'running' AND locked_at < now() - make_interval(mins => :m)", m=STALE_MINUTES)


def claim(tx, worker_id, kinds=None):
    """Take the next due job (of `kinds` only, when given), or None. Another worker's claimed row
    is skipped, never waited on."""
    return tx.one("UPDATE occ.jobs SET state = 'running', locked_by = :w, locked_at = now(), attempts = attempts + 1 "
                  "WHERE id = (SELECT id FROM occ.jobs WHERE state = 'queued' AND run_at <= now() "
                  "AND (CAST(:k AS text[]) IS NULL OR kind = ANY(CAST(:k AS text[]))) "
                  "ORDER BY priority, run_at, id FOR UPDATE SKIP LOCKED LIMIT 1) "
                  "RETURNING id, kind, payload, attempts, max_attempts, dedupe_key, created_at",
                  w=worker_id, k=list(kinds) if kinds else None)


def finish(tx, job_id, result=None):
    tx.run("UPDATE occ.jobs SET state = 'done', finished_at = now(), locked_by = NULL, last_error = NULL, "
           "payload = CASE WHEN CAST(:r AS jsonb) IS NULL THEN payload "
           "ELSE payload || jsonb_build_object('result', CAST(:r AS jsonb)) END WHERE id = :id",
           id=job_id, r=jsonb(result) if result is not None else None)


def error_text(exc):
    """What is kept of a failure: the exception type, where it was raised, and its message cut
    short. Handlers never put a secret in an exception message."""
    tb = traceback.extract_tb(exc.__traceback__)
    where = ("%s:%d" % (tb[-1].filename.rsplit("/", 1)[-1], tb[-1].lineno)) if tb else ""
    return ("%s at %s: %s" % (type(exc).__name__, where, str(exc)))[:500]


def fail(tx, job, text):
    """A failed attempt: queued again after a delay, or dead after max_attempts."""
    attempts = int(job["attempts"])
    if attempts >= int(job["max_attempts"]):
        tx.run("UPDATE occ.jobs SET state = 'dead', finished_at = now(), locked_by = NULL, last_error = :e "
               "WHERE id = :id", id=job["id"], e=text)
        return "dead"
    delay = min(BACKOFF_MAX_S, BACKOFF_BASE_S * (2 ** (attempts - 1)))
    tx.run("UPDATE occ.jobs SET state = 'queued', locked_by = NULL, locked_at = NULL, last_error = :e, "
           "run_at = now() + make_interval(secs => :s) WHERE id = :id", id=job["id"], e=text, s=float(delay))
    return "queued"


def run_one(ctx, worker_id, kinds=None):
    """Claim one job and run it. Returns (job id, outcome) or None when nothing is due."""
    with ctx.pool.tx() as tx:
        reap(tx)
        job = claim(tx, worker_id, kinds)
    if job is None:
        return None
    handler = HANDLERS.get(job["kind"])
    try:
        if handler is None:
            raise LookupError("no handler for job kind %r in this worker" % job["kind"])
        result = handler(ctx, job)
    except Exception as exc:  # noqa: BLE001 - recorded on the job, retried or dead
        text = error_text(exc)
        with ctx.pool.tx() as tx:
            outcome = fail(tx, job, text)
        ctx.log.error("job failed", extra={"occ": {"event": "job failed", "detail": {
            "job_id": job["id"], "kind": job["kind"], "outcome": outcome, "error": type(exc).__name__}}})
        return job["id"], outcome
    with ctx.pool.tx() as tx:
        finish(tx, job["id"], result)
    return job["id"], "done"


def counts(tx):
    """{state: n} over every job, for /metrics."""
    rows = tx.all("SELECT state, count(*) AS n FROM occ.jobs GROUP BY state")
    out = {s: 0 for s in ("queued", "running", "done", "failed", "dead")}
    out.update({r["state"]: int(r["n"]) for r in rows})
    return out


def utcnow():
    return dt.datetime.now(dt.timezone.utc)
