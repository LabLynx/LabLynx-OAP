# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The worker's 'export' job: renders one queued export into the file store.

The requester is rebuilt from the database, so permissions are those of the person now, not when
the export was queued. A failure that is the request's own fault (a record no longer readable, a
format not built) marks the export state 4 with the message and finishes the job; anything else
raises, so the worker retries it.
"""
from .. import errors
from ..auth import principal as principal_mod
from ..files import store as fstore
from ..records import kinds as K
from ..worker.jobs import register
from . import render


@register("export")
def run_export(ctx, job):
    eid = int((job.get("payload") or {}).get("export_id") or 0)
    with ctx.pool.tx() as tx:
        row = tx.one("SELECT * FROM occ.exports WHERE id = :id FOR UPDATE", id=eid)
        if row is None or row["state"] in (3, 4):
            return {"export_id": eid, "skipped": True}
        tx.run("UPDATE occ.exports SET state = 2, modified_at = now() WHERE id = :id", id=eid)
    try:
        with ctx.pool.tx() as tx:
            p = principal_mod.load(tx, row["requester_id"], row["team_id"])
            if p is None:
                raise errors.forbidden("The person who asked for this export can no longer sign in.")
            recs = []
            params = row["params"] or {}
            for code, ids in (params.get("ids") or {}).items():
                kind = K.get(code)
                recs.extend(render.records(tx, p, kind, ids, ctx.settings.base_url + ctx.settings.root_path,
                                           changelog=params.get("changelog", True)))
            data, name = render.render(tx, ctx.settings, p, None, [], row["format"], "", single=len(recs) == 1,
                                       recs=recs)
        sha, size = ctx.store.put_bytes(data)
        with ctx.pool.tx() as tx:
            fstore.register(tx, ctx.store, sha, size)
            tx.run("UPDATE occ.exports SET state = 3, sha256 = :s, filesize = :n, real_name = :rn, error = NULL, "
                   "modified_at = now() WHERE id = :id", s=sha, n=size, rn=name, id=eid)
        return {"export_id": eid, "bytes": size}
    except errors.OCCError as e:
        with ctx.pool.tx() as tx:
            tx.run("UPDATE occ.exports SET state = 4, error = :e, modified_at = now() WHERE id = :id",
                   e=e.message[:500], id=eid)
        return {"export_id": eid, "error": e.message}
