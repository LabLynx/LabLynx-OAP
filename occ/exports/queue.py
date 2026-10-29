# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The export queue: a request is a row in occ.exports and an 'export' job;
the worker renders it into the file store (occ/exports/jobs.py).

Body of a queue request: format, and the records as lists of ids per kind (experiments, items,
experiments_templates, items_types; a list or a comma-separated text), changelog (0/1).
Every listed record must be readable by the requester when the export is queued, and again when
it is rendered (a record that stopped being readable fails the export with a message).
"""
from .. import errors, timefmt
from ..audit import writer as audit
from ..files import store as fstore
from ..perms import engine
from ..records import kinds as K
from ..records import service as S
from . import render

KIND_KEYS = ("experiments", "items", "experiments_templates", "items_types")
STATES = {1: "pending", 2: "processing", 3: "success", 4: "error"}
MAX_RECORDS = 100000


def _ids(v, name):
    if v in (None, "", []):
        return []
    if isinstance(v, str):
        v = [x for x in v.split(",") if x.strip()]
    if not isinstance(v, list):
        raise errors.bad("Incorrect value for %s: a list of ids" % name)
    try:
        return [int(x) for x in v]
    except (TypeError, ValueError):
        raise errors.bad("Incorrect value for %s: a list of ids" % name)


def parse(body):
    if not isinstance(body, dict):
        raise errors.bad("The request body must be a JSON object")
    fmt = str(body.get("format") or "")
    render.check_format(fmt)
    sel = {k: _ids(body.get(k), k) for k in KIND_KEYS}
    total = sum(len(v) for v in sel.values())
    if total == 0:
        raise errors.bad("Nothing to export: name records in experiments, items, experiments_templates or items_types")
    if total > MAX_RECORDS:
        raise errors.bad("Too many records in one export (at most %d)." % MAX_RECORDS)
    return fmt, {"ids": sel, "changelog": body.get("changelog") not in (0, "0", False, "false")}


def check_readable(tx, p, params):
    for code, ids in params["ids"].items():
        kind = K.get(code)
        for i in ids:
            row = S.fetch(tx, p, kind, i, full=False)
            engine.readable_or_raise(p, row, errors)


def create(tx, p, actor, body):
    fmt, params = parse(body)
    if p.team_id not in p.member_teams:
        raise errors.forbidden()
    check_readable(tx, p, params)
    eid = tx.val("INSERT INTO occ.exports (requester_id, team_id, format, params) VALUES (:u, :t, :f, CAST(:p AS jsonb)) "
                 "RETURNING id", u=p.user_id, t=p.team_id, f=fmt, p=S.jsonb(params))
    from ..worker import jobs
    jobs.enqueue(tx, "export", {"export_id": eid}, dedupe_key="export:%d" % eid, priority=3)
    audit.write(tx, actor, "export.create", target="export", new=fmt,
                detail={"export_id": eid, "records": sum(len(v) for v in params["ids"].values())})
    return eid


def get(tx, p, export_id):
    row = tx.one("SELECT * FROM occ.exports WHERE id = :id", id=export_id)
    if row is None:
        raise errors.not_found()
    if row["requester_id"] != p.user_id and not p.is_sysadmin:
        raise errors.forbidden()
    return row


def shape(row):
    return {"id": row["id"], "requester_userid": row["requester_id"], "team": row["team_id"],
            "state": row["state"], "state_human": STATES.get(row["state"]), "format": row["format"],
            "real_name": row["real_name"], "filesize": row["filesize"],
            "hash": bytes(row["sha256"]).hex() if row["sha256"] is not None else None, "hash_algorithm": "sha256",
            "error": row["error"], "created_at": timefmt.out(row["created_at"]),
            "modified_at": timefmt.out(row["modified_at"])}


def delete(tx, cfg, p, actor, export_id):
    row = get(tx, p, export_id)
    tx.run("DELETE FROM occ.exports WHERE id = :id", id=row["id"])
    if row["sha256"] is not None:
        fstore.delete_if_unreferenced(tx, fstore.for_settings(cfg), bytes(row["sha256"]))
    audit.write(tx, actor, "export.delete", target="export", old=row["format"], detail={"export_id": row["id"]})
