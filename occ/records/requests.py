# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Request actions: asking someone to act on a record, and the open requests across records.

A request names a target person and an action number (10, 20, 30, 40 or 50, as the API numbers
them; 40 is sign). The requester needs read access; the target must be able to read the record
too. The target gets a notification. A request is open (state 1), done (2) or cancelled or
withdrawn (3); only open ones are listed on the record.
"""
from .. import errors, timefmt
from ..audit import writer as audit
from ..auth import principal as principal_mod
from ..db import jsonb
from ..perms import engine
from . import kinds as K
from . import service as S

ACTIONS = frozenset((10, 20, 30, 40, 50))
NOTIF_REQUEST = 20            # notification category for a new request
PAGES = {"experiments": "experiments.php", "items": "database.php", "experiments_templates": "templates.php",
         "items_types": "resources-templates.php"}

_SQL = """
SELECT ra.id, ra.rid, ra.requester_id, ra.target_user_id, ra.action, ra.state, ra.created_at, ra.done_at,
       r.id AS entity_id, r.kind_id, r.title AS entity_title, r.team_id,
       ru.firstname AS requester_firstname, ru.lastname AS requester_lastname,
       tu.firstname AS target_firstname, tu.lastname AS target_lastname
  FROM occ.request_actions ra
  JOIN occ.records r ON r.rid = ra.rid
  JOIN occ.users ru ON ru.id = ra.requester_id
  JOIN occ.users tu ON tu.id = ra.target_user_id
"""


def shape(r):
    kind = K.BY_ID[r["kind_id"]].code
    return {"id": r["id"], "created_at": timefmt.out(r["created_at"]), "requester_userid": r["requester_id"],
            "target_userid": r["target_user_id"], "entity_id": r["entity_id"], "action": r["action"],
            "state": r["state"], "entity_page": PAGES[kind], "kind": kind, "entity_title": r["entity_title"],
            "done_at": timefmt.out(r["done_at"]),
            "requester_firstname": r["requester_firstname"], "requester_lastname": r["requester_lastname"],
            "requester_fullname": ("%s %s" % (r["requester_firstname"], r["requester_lastname"])).strip(),
            "target_firstname": r["target_firstname"], "target_lastname": r["target_lastname"],
            "target_fullname": ("%s %s" % (r["target_firstname"], r["target_lastname"])).strip()}


def _record(tx, p, kind, rec_id):
    row = S.fetch(tx, p, kind, rec_id, full=False)
    engine.readable_or_raise(p, row, errors)
    return row


def list_on_record(tx, p, kind, rec_id):
    row = _record(tx, p, kind, rec_id)
    return [shape(r) for r in tx.all(_SQL + " WHERE ra.rid = :rid AND ra.state = 1 ORDER BY ra.id", rid=row["rid"])]


def create(tx, p, actor, kind, rec_id, body):
    S._check_can_write_key(p)
    body = body or {}
    row = _record(tx, p, kind, rec_id)
    try:
        target = int(body.get("target_userid"))
        action = int(body.get("target_action", body.get("action")))
    except (TypeError, ValueError):
        raise errors.bad("Send target_userid and target_action")
    if action not in ACTIONS:
        raise errors.bad("Incorrect value for target_action: 10, 20, 30, 40 or 50")
    tp = principal_mod.load(tx, target, row["team_id"])
    if tp is None:
        raise errors.bad("Incorrect value for target_userid: no such active user")
    if not engine.check(tp, row, engine.READ):
        raise errors.bad("That person cannot read this entry, so they cannot be asked to act on it.")
    if tx.val("SELECT 1 FROM occ.request_actions WHERE rid = :rid AND target_user_id = :t AND action = :a "
              "AND state = 1", rid=row["rid"], t=target, a=action):
        raise errors.bad("This request exists already.")
    ra_id = tx.val("INSERT INTO occ.request_actions (rid, requester_id, target_user_id, action) "
                   "VALUES (:rid, :u, :t, :a) RETURNING id", rid=row["rid"], u=p.user_id, t=target, a=action)
    tx.run("INSERT INTO occ.notifications (user_id, category, body, send_email) VALUES (:u, :c, CAST(:b AS jsonb), true)",
           u=target, c=NOTIF_REQUEST,
           b=jsonb({"request_action_id": ra_id, "action": action, "kind": kind.code, "entity_id": row["id"],
                    "entity_page": PAGES[kind.code], "requester_userid": p.user_id, "requester": p.fullname}))
    audit.write(tx, actor, "request.create", kind_id=kind.id, record_id=row["id"], rid=row["rid"],
                team_id=row["team_id"], target="request_action", new=action,
                detail={"request_action_id": ra_id, "target_userid": target})
    return ra_id


def _request(tx, p, kind, rec_id, ra_id, for_update=True):
    row = _record(tx, p, kind, rec_id)
    if for_update:
        tx.run("SELECT 1 FROM occ.request_actions WHERE id = :id FOR UPDATE", id=ra_id)
    ra = tx.one(_SQL + " WHERE ra.id = :id AND ra.rid = :rid", id=ra_id, rid=row["rid"])
    if ra is None:
        raise errors.not_found()
    return row, ra


def patch(tx, p, actor, kind, rec_id, ra_id, body):
    S._check_can_write_key(p)
    row, ra = _request(tx, p, kind, rec_id, ra_id)
    if p.user_id not in (ra["requester_id"], ra["target_user_id"]):
        raise errors.forbidden("Only the person who asked or the person asked can change this request.")
    what = str((body or {}).get("action") or "")
    if what not in ("done", "cancel"):
        raise errors.bad("Incorrect value for action: done or cancel")
    new = 2 if what == "done" else 3
    if ra["state"] != new:
        tx.run("UPDATE occ.request_actions SET state = :s, done_at = now() WHERE id = :id", s=new, id=ra_id)
        audit.write(tx, actor, "request.update", kind_id=kind.id, record_id=row["id"], rid=row["rid"],
                    team_id=row["team_id"], target="state", old=ra["state"], new=new,
                    detail={"request_action_id": ra_id})
    return shape(tx.one(_SQL + " WHERE ra.id = :id", id=ra_id))


def delete(tx, p, actor, kind, rec_id, ra_id):
    S._check_can_write_key(p)
    row, ra = _request(tx, p, kind, rec_id, ra_id)
    if p.user_id != ra["requester_id"]:
        raise errors.forbidden("Only the person who asked can withdraw this request.")
    if ra["state"] != 3:
        tx.run("UPDATE occ.request_actions SET state = 3, done_at = now() WHERE id = :id", id=ra_id)
        audit.write(tx, actor, "request.delete", kind_id=kind.id, record_id=row["id"], rid=row["rid"],
                    team_id=row["team_id"], target="state", old=ra["state"], new=3,
                    detail={"request_action_id": ra_id})


def _user(v, p, name):
    if v in (None, ""):
        return None
    if str(v) == "me":
        return p.user_id
    try:
        return int(v)
    except ValueError:
        raise errors.bad("Incorrect value for %s" % name)


def search(tx, p, q):
    """Requests across records. Your own (as target or requester) always; a team admin also
    sees those on records of the teams they administer; a sysadmin or site-scope key sees all."""
    sql = _SQL + " WHERE TRUE"
    params = {}
    target = _user(q.get("target_userid"), p, "target_userid")
    requester = _user(q.get("requester_userid"), p, "requester_userid")
    if target is not None:
        sql += " AND ra.target_user_id = :t"
        params["t"] = target
    if requester is not None:
        sql += " AND ra.requester_id = :q"
        params["q"] = requester
    if target is None and requester is None:
        sql += " AND (ra.target_user_id = :me OR ra.requester_id = :me)"
        params["me"] = p.user_id
    state = q.get("state", "1")
    if state not in (None, "", "all"):
        try:
            params["s"] = int(state)
        except ValueError:
            raise errors.bad("Incorrect value for state")
        sql += " AND ra.state = :s"
    if q.get("kind"):
        params["k"] = K.get(q["kind"]).id
        sql += " AND r.kind_id = :k"
    if not (p.is_sysadmin or p.site_scope):
        others = [x for x in (target, requester) if x is not None and x != p.user_id]
        if others:
            if not p.admin_teams:
                raise errors.forbidden("You can only see your own requests.")
            sql += " AND r.team_id = ANY(CAST(:adm AS int[]))"
            params["adm"] = sorted(p.admin_teams)
    rows = tx.all(sql + " ORDER BY ra.id DESC LIMIT 1000", **params)
    return [shape(r) for r in rows]
