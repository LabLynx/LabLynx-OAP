# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The change feed (GET /api/v2/occ/changes): records and sub-resources changed since a cursor.

The feed is read from the audit log, which every accepted write already passes through in the same
transaction, so nothing is missed and nothing extra is written. The cursor is the last audit
row id seen, as opaque text; without one the answer is empty with the cursor of 'now'. Only records
the caller can read appear (the permission engine's list filter); a site-scope key may name a
team. One row per record per page, at its latest change in that page.
"""
from .. import errors, timefmt
from ..perms import engine
from . import kinds as K

MAX_LIMIT = 1000


def _op(category):
    return {"record.create": "create", "record.delete": "delete"}.get(category, "update")


def feed(tx, p, q):
    try:
        limit = min(max(int(q.get("limit") or 100), 1), MAX_LIMIT)
        cursor = int(q["cursor"]) if q.get("cursor") not in (None, "") else None
    except ValueError:
        raise errors.bad("Incorrect value for cursor or limit")
    top = tx.val("SELECT coalesce(max(id), 0) FROM occ.audit_events")
    if cursor is None:
        return {"changes": [], "next_cursor": str(top)}
    kind_ids = [K.get(k).id for k in str(q.get("kinds") or "").split(",") if k.strip()] or \
        [k.id for k in K.KINDS.values()]
    team = None
    if q.get("team") not in (None, ""):
        if not p.site_scope:
            raise errors.forbidden("Only a site-scope key may name a team.")
        try:
            team = int(q["team"])
        except ValueError:
            raise errors.bad("Incorrect value for team")
    cond, params = engine.list_filter(p, engine.READ, "r")
    rows = tx.all("SELECT a.id AS aid, a.at, a.category, r.kind_id, r.id, r.team_id "
                  "FROM occ.audit_events a JOIN occ.records r ON r.rid = a.rid "
                  "WHERE a.id > :cur AND a.id <= :top AND r.kind_id = ANY(CAST(:kinds AS int[])) "
                  "AND (CAST(:team AS int) IS NULL OR r.team_id = CAST(:team AS int)) AND " + cond +
                  " ORDER BY a.id LIMIT :lim",
                  cur=cursor, top=top, kinds=kind_ids, team=team, lim=limit + 1, **params)
    more = len(rows) > limit
    rows = rows[:limit]
    latest = {}
    for r in rows:
        key = (r["kind_id"], r["id"])
        op = _op(r["category"])
        prev = latest.get(key)
        if prev and prev["op"] == "create" and op == "update":
            op = "create"
        latest[key] = {"kind": K.BY_ID[r["kind_id"]].code, "id": r["id"], "team": r["team_id"], "op": op,
                       "at": timefmt.out(r["at"]), "_aid": r["aid"]}
    changes = sorted(latest.values(), key=lambda x: x["_aid"])
    for c in changes:
        c.pop("_aid")
    nxt = rows[-1]["aid"] if (rows and more) else top
    return {"changes": changes, "next_cursor": str(nxt)}
