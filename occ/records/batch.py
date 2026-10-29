# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Many records at once: batch actions (POST /batch), a team's counts and the demo purge.

Batch actions (team admin of the current team): the records chosen are the experiments and resources of
the caller's current team, not deleted, that match ANY of the lists sent (the lists combine with OR):
experiments_categories[] and experiments_status[] select experiments by category or status;
items_types[] and items_status[] select resources by category (the 2.x name for a resource's
category) or status; tags[] selects records of either kind carrying one of those tag ids; users[]
selects records of either kind those people own. The action is applied to each, each change is
audited on its own, and the whole batch is one transaction: one refusal undoes all of it. The
answer is 201 with the number of records changed in the id position of Location (reproduced).
"""
from .. import errors
from ..audit import writer as audit
from . import kinds as K
from . import service as S
from . import subs

BATCH_ACTIONS = frozenset(("forcelock", "forceunlock", "lock", "unlock", "archive", "unarchive", "updatecategory",
                           "updatestatus", "updatecanread", "updatecanwrite", "addtag", "delete"))
_FIELD_OF = {"updatecategory": "category", "updatestatus": "status", "updatecanread": "canread",
             "updatecanwrite": "canwrite"}


def _ids(body, name):
    v = body.get(name, body.get(name + "[]"))
    if v in (None, ""):
        return []
    if not isinstance(v, list):
        v = [v]
    try:
        return sorted({int(x) for x in v})
    except (TypeError, ValueError):
        raise errors.bad("Incorrect value for %s: a list of ids" % name)


def _select(tx, team_id, body):
    """[(kind_id, public id)] of the records the lists choose, in a stable order."""
    exp_cat, exp_st = _ids(body, "experiments_categories"), _ids(body, "experiments_status")
    it_cat, it_st = _ids(body, "items_types"), _ids(body, "items_status")
    tags, users = _ids(body, "tags"), _ids(body, "users")
    if not any((exp_cat, exp_st, it_cat, it_st, tags, users)):
        raise errors.bad("Choose the records: experiments_categories, experiments_status, items_types, "
                         "items_status, tags or users")
    rows = tx.all("""
        SELECT r.kind_id, r.id FROM occ.records r
         WHERE r.team_id = :t AND r.state IN (1, 2) AND r.kind_id IN (1, 2)
           AND ((r.kind_id = 1 AND r.category_id = ANY(CAST(:ec AS int[])))
             OR (r.kind_id = 1 AND r.status_id = ANY(CAST(:es AS int[])))
             OR (r.kind_id = 2 AND r.category_id = ANY(CAST(:ic AS int[])))
             OR (r.kind_id = 2 AND r.status_id = ANY(CAST(:ist AS int[])))
             OR r.owner_id = ANY(CAST(:us AS int[]))
             OR EXISTS (SELECT 1 FROM occ.record_tags rt WHERE rt.rid = r.rid AND rt.tag_id = ANY(CAST(:tg AS int[]))))
         ORDER BY r.kind_id, r.id FOR UPDATE""", t=team_id, ec=exp_cat, es=exp_st, ic=it_cat, ist=it_st, us=users,
                  tg=tags)
    return [(r["kind_id"], r["id"]) for r in rows]


def _set_lock(tx, p, actor, kind, row, locked):
    if bool(row["locked"]) == locked:
        return False
    if locked:
        tx.run("UPDATE occ.records SET locked = true, locked_by = :u, locked_at = now() WHERE rid = :rid",
               u=p.user_id, rid=row["rid"])
    else:
        tx.run("UPDATE occ.records SET locked = false, locked_by = NULL, locked_at = NULL WHERE rid = :rid",
               rid=row["rid"])
    audit.write(tx, actor, "record.lock", kind_id=kind.id, record_id=row["id"], rid=row["rid"],
                team_id=row["team_id"], target="locked", old="1" if row["locked"] else "0",
                new="1" if locked else "0", detail={"batch": True})
    return True


def _set_state(tx, actor, kind, row, state, category="record.update"):
    if row["state"] == state:
        return False
    tx.run("UPDATE occ.records SET state = :s WHERE rid = :rid", s=state, rid=row["rid"])
    audit.write(tx, actor, category, kind_id=kind.id, record_id=row["id"], rid=row["rid"], team_id=row["team_id"],
                target="state", old=row["state"], new=state, detail={"batch": True})
    return True


def run(tx, p, actor, body):
    if not p.can_write:
        raise errors.forbidden("This API key is read-only.")
    body = body or {}
    if p.team_id not in p.admin_teams:
        raise errors.forbidden("Sorry, you are not allowed to perform that action.")
    action = body.get("action")
    if action not in BATCH_ACTIONS:
        raise errors.bad("Incorrect value for action: %s" % ", ".join(sorted(BATCH_ACTIONS)))
    target = body.get("target")
    if action in _FIELD_OF or action == "addtag":
        if target in (None, ""):
            raise errors.bad("This action needs a target")
    changed = 0
    for kind_id, rec_id in _select(tx, p.team_id, body):
        kind = K.BY_ID[kind_id]
        row = S.fetch(tx, p, kind, rec_id, full=True)
        did = False
        if action in ("forcelock", "lock"):
            did = _set_lock(tx, p, actor, kind, row, True)
        elif action in ("forceunlock", "unlock"):
            did = _set_lock(tx, p, actor, kind, row, False)
        elif action == "archive":
            did = _set_state(tx, actor, kind, row, 2)
        elif action == "unarchive":
            did = _set_state(tx, actor, kind, row, 1)
        elif action == "delete":
            did = _set_state(tx, actor, kind, row, 3, "record.delete")
        elif action == "addtag":
            before = tx.val("SELECT count(*) FROM occ.record_tags WHERE rid = :rid", rid=row["rid"])
            subs.attach_tag(tx, p, actor, kind, row, str(target))
            did = tx.val("SELECT count(*) FROM occ.record_tags WHERE rid = :rid", rid=row["rid"]) != before
        else:
            fields = S.validate_fields(tx, p, kind, row, {_FIELD_OF[action]: target})
            did = bool(S.apply_fields(tx, p, actor, kind, row, fields))
        if did:
            changed += 1
            S.touch(tx, p, row["rid"])
    return changed


# ----------------------------------------------------------------------------- a team's counts
def team_stats(tx, p, team_id):
    if not (p.is_sysadmin or p.site_scope or team_id in p.admin_teams):
        raise errors.forbidden("Only an admin of that team can read its counts.")
    if not tx.val("SELECT 1 FROM occ.teams WHERE id = :t", t=team_id):
        raise errors.not_found()
    counts = {r["kind_id"]: r["n"] for r in tx.all(
        "SELECT kind_id, count(*) AS n FROM occ.records WHERE team_id = :t AND state <> 3 GROUP BY kind_id",
        t=team_id)}
    mem = tx.one("SELECT count(*) FILTER (WHERE NOT is_archived) AS members, "
                 "count(*) FILTER (WHERE is_admin AND NOT is_archived) AS admins FROM occ.memberships "
                 "WHERE team_id = :t", t=team_id)
    size = tx.val("SELECT coalesce(sum(u.size), 0) FROM occ.uploads u JOIN occ.records r ON r.rid = u.rid "
                  "WHERE r.team_id = :t AND u.state <> 3", t=team_id)
    by_cat, by_st = {}, {}
    for r in tx.all("""SELECT r.kind_id, c.title AS cat, s.title AS st, count(*) AS n FROM occ.records r
                        LEFT JOIN occ.categories c ON c.lookup_group = r.lookup_group AND c.id = r.category_id
                        LEFT JOIN occ.statuses s ON s.lookup_group = r.lookup_group AND s.id = r.status_id
                       WHERE r.team_id = :t AND r.state <> 3 AND r.kind_id IN (1, 2)
                       GROUP BY r.kind_id, c.title, s.title""", t=team_id):
        k = K.BY_ID[r["kind_id"]].code
        by_cat.setdefault(k, {})
        by_st.setdefault(k, {})
        ck, sk = r["cat"] or "(none)", r["st"] or "(none)"
        by_cat[k][ck] = by_cat[k].get(ck, 0) + r["n"]
        by_st[k][sk] = by_st[k].get(sk, 0) + r["n"]
    return {"team": team_id, "experiments": counts.get(1, 0), "items": counts.get(2, 0),
            "templates": counts.get(3, 0), "resource_templates": counts.get(4, 0),
            "members": mem["members"], "admins": mem["admins"], "uploads_bytes": int(size),
            "by_category": by_cat, "by_status": by_st}


# ------------------------------------------------------------------- purging a team's records
PURGE_KINDS = frozenset(K.KINDS)


def purge(tx, p, actor, team_id, body, allowed):
    """Permanently removes a team's records of the kinds named (demo reset). Sysadmin only, only
    while site setting allow_purge is 1, the team's name typed as confirm; refuses when any chosen
    record is signed or timestamped. Every purge is audited (the audit log keeps the records'
    history; its rows are never removed)."""
    if not p.is_sysadmin:
        raise errors.forbidden("Only a sysadmin can do that.")
    if not p.can_write:
        raise errors.forbidden("This API key is read-only.")
    if not allowed:
        raise errors.forbidden("Purging is switched off on this site (allow_purge).")
    body = body or {}
    name = tx.val("SELECT name FROM occ.teams WHERE id = :t FOR UPDATE", t=team_id)
    if name is None:
        raise errors.not_found()
    if str(body.get("confirm") or "") != name:
        raise errors.bad("Type the team's name in confirm to purge it.")
    kinds = body.get("kinds") or []
    if not isinstance(kinds, list) or not kinds or any(k not in PURGE_KINDS for k in kinds):
        raise errors.bad("Incorrect value for kinds: a list of %s" % ", ".join(sorted(PURGE_KINDS)))
    kind_ids = sorted(K.KINDS[k].id for k in kinds)
    held = tx.val("SELECT count(*) FROM occ.records WHERE team_id = :t AND kind_id = ANY(CAST(:k AS smallint[])) "
                  "AND (signature_count > 0 OR timestamped)", t=team_id, k=kind_ids)
    if held:
        raise errors.bad("%d of these records are signed or timestamped: they are never purged." % held)
    removed = {}
    for k in sorted(kinds):
        kid = K.KINDS[k].id
        rids = [r["rid"] for r in tx.all("SELECT rid FROM occ.records WHERE team_id = :t AND kind_id = :k",
                                         t=team_id, k=kid)]
        if rids:
            # Sub-resources, links, bookings and uploads go by ON DELETE CASCADE (or SET NULL);
            # signatures and timestamps restrict, and were refused above.
            tx.run("DELETE FROM occ.records WHERE rid = ANY(CAST(:r AS bigint[]))", r=rids)
        removed[k] = len(rids)
    audit.write(tx, actor, "purge", team_id=team_id, target="team", detail={"removed": removed, "team_name": name})
    return {"removed": removed}
