# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Reading the audit log and verifying its hash chain.

Who sees what: a sysadmin or a site-scope key sees every event; a team admin sees
the events of the teams they administer; everybody else sees the events of records they can read
(the permission engine's list filter) and their own events. Pages are newest first, at most 1000,
with an opaque cursor (the last id returned).
"""
from .. import errors, timefmt
from ..perms import engine
from ..records import kinds as K
from . import verify as V


def _int(v, name):
    try:
        return int(v)
    except (TypeError, ValueError):
        raise errors.bad("Incorrect value for %s" % name)


def list_events(tx, p, q):
    q = q or {}
    limit = _int(q.get("limit") or 100, "limit")
    if limit < 1 or limit > 1000:
        raise errors.bad("Incorrect value for limit: 1 to 1000")
    where, params = [], {"lim": limit}
    if p.is_sysadmin or p.site_scope:
        pass
    else:
        cond, fp = engine.list_filter(p, engine.READ, alias="r")
        params.update(fp)
        where.append("(a.team_id = ANY(CAST(:adm AS int[])) OR a.actor_user_id = :me OR EXISTS "
                     "(SELECT 1 FROM occ.records r WHERE r.rid = a.rid AND " + cond + "))")
        params["adm"] = sorted(p.admin_teams)
        params["me"] = p.user_id
    if q.get("cursor"):
        where.append("a.id < :cur")
        params["cur"] = _int(q["cursor"], "cursor")
    if q.get("since"):
        where.append("a.at >= :since")
        params["since"] = _when(q["since"], "since")
    if q.get("until"):
        where.append("a.at <= :until")
        params["until"] = _when(q["until"], "until")
    if q.get("category"):
        c = str(q["category"])
        if c.endswith(".*") or "." not in c:
            where.append("a.category LIKE :cat")
            params["cat"] = c.rstrip("*").rstrip(".") + ".%"
        else:
            where.append("a.category = :cat")
            params["cat"] = c
    if q.get("actor"):
        where.append("a.actor_user_id = :actor")
        params["actor"] = _int(q["actor"], "actor")
    if q.get("team"):
        where.append("a.team_id = :team")
        params["team"] = _int(q["team"], "team")
    if q.get("kind"):
        where.append("a.kind_id = :kind")
        params["kind"] = K.get(str(q["kind"])).id
    if q.get("record_id"):
        where.append("a.record_id = :rec")
        params["rec"] = _int(q["record_id"], "record_id")
    sql = ("SELECT a.id, a.at, a.actor_kind, a.actor_user_id, u.firstname, u.lastname, a.team_id, a.category, "
           "a.kind_id, a.record_id, a.target, a.old_value, a.new_value, a.detail, a.origin, a.orig_at "
           "FROM occ.audit_events a LEFT JOIN occ.users u ON u.id = a.actor_user_id")
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY a.id DESC LIMIT :lim"
    rows = tx.all(sql, **params)
    events = [{"id": r["id"], "at": timefmt.out(r["at"]), "actor_kind": r["actor_kind"],
               "actor_user_id": r["actor_user_id"],
               "fullname": ("%s %s" % (r["firstname"] or "", r["lastname"] or "")).strip() or None,
               "team_id": r["team_id"], "category": r["category"],
               "kind": K.BY_ID[r["kind_id"]].code if r["kind_id"] in K.BY_ID else None,
               "record_id": r["record_id"], "target": r["target"], "old_value": r["old_value"],
               "new_value": r["new_value"], "detail": r["detail"], "origin": r["origin"],
               "orig_at": timefmt.out(r["orig_at"])} for r in rows]
    return {"events": events, "next": str(events[-1]["id"]) if len(events) == limit else None}


def _when(v, name):
    try:
        return timefmt.parse_datetime(v)
    except ValueError:
        try:
            d = timefmt.parse_date(v)
        except ValueError:
            raise errors.bad("Incorrect value for %s" % name)
        return timefmt.parse_datetime(d.isoformat() + " 00:00:00")


def verify(tx, p, q):
    if not p.is_sysadmin:
        raise errors.forbidden("Only a sysadmin can verify the audit log.")
    q = q or {}
    res = V.verify(tx, from_id=_int(q["from"], "from") if q.get("from") else None,
                   to_id=_int(q["to"], "to") if q.get("to") else None)
    return {"ok": res["ok"], "checked": res["checked"], "first_bad_id": res["first_bad_id"],
            "reason": res["reason"], "last_id": res["last_id"], "last_checkpoint": V.last_checkpoint(tx)}
