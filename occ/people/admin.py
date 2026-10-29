# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Administering teams, team groups, a team's tags and users: changing and deleting teams, team
groups, renaming and deleting a team's tags, changing and deleting users.

Who may do what (catalog): a team admin changes their team's settings, groups, tags and the
membership of their team; a sysadmin does everything, and alone renames a team, hides it, deletes
it and deletes users. A person changes their own name, ORCID and preferences. Every change is
validated first and applied in one transaction, one audit row per field, so the audit log says exactly what changed.
"""
import json

from .. import errors, timefmt
from ..audit import writer as audit
from ..db import ident, jsonb
from ..records import service as S
from . import service as P

# Team fields and who may write them: a team admin changes settings; only a sysadmin changes name,
# visible and orgid.
TEAM_BOOL = frozenset(("visible", "user_create_tag", "force_exp_tpl", "force_res_tpl", "users_canwrite_experiments",
                       "users_canwrite_experiments_categories", "users_canwrite_experiments_status",
                       "users_canwrite_experiments_templates", "users_canwrite_resources",
                       "users_canwrite_resources_categories", "users_canwrite_resources_status",
                       "users_canwrite_resources_templates", "onboarding_email_active", "newcomer_banner_active"))
TEAM_TEXT = frozenset(("name", "orgid", "announcement", "onboarding_email_subject", "onboarding_email_body",
                       "newcomer_banner"))
TEAM_INT = frozenset(("newcomer_threshold",))
TEAM_SYSADMIN_ONLY = frozenset(("name", "visible", "orgid"))
TEAM_COLUMNS = TEAM_BOOL | TEAM_TEXT | TEAM_INT
DEFAULT_PERM_COLUMNS = frozenset(("default_read", "default_write", "default_read_base", "default_write_base"))

USER_SELF = frozenset(("firstname", "lastname", "orcid"))
USER_SYSADMIN = frozenset(("email", "orgid", "valid_until", "is_sysadmin", "can_manage_users2teams",
                           "can_manage_compounds", "can_manage_inventory_locations", "write_exempt", "validated"))
USER_BOOL = frozenset(("is_sysadmin", "can_manage_users2teams", "can_manage_compounds",
                       "can_manage_inventory_locations", "write_exempt", "validated"))
USER_COLUMNS = USER_SELF | USER_SYSADMIN
MEMBERSHIP_TARGETS = frozenset(("is_admin", "is_owner", "is_archived"))
# Personal preferences kept whole in users.prefs (limit_nb, orderby, sort, lang, scope_*, sc_*,
# notif_*, pdf_* ...). A name is accepted when it is one of these or of their
# family, or when the person's stored preferences already hold it (carried from 2.x by the
# migration); anything else answers 400, so a typo is not stored silently. The other names are those the 2.x answer
# to GET /users/me carries (observed at the API, 2026-10-28).
PREF_NAMES = frozenset(("limit_nb", "orderby", "sort", "lang", "always_show_owned", "append_pdfs", "cjk_fonts",
                        "disable_shortcuts", "display_mode", "entrypoint", "inc_files_pdf", "scheduler_layout",
                        "show_weekends", "theme_variant", "uploads_layout", "use_isodate", "use_markdown"))
PREF_PREFIXES = ("scope_", "sc_", "notif_", "pdf_")
PREF_INT = frozenset(("limit_nb",))


def _int(v, name):
    try:
        return int(v)
    except (TypeError, ValueError):
        raise errors.bad("Incorrect value for %s" % name)


def _flag(v, name):
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off"):
        return False
    raise errors.bad("Incorrect value for %s" % name)


def _writer(p):
    if not p.can_write:
        raise errors.forbidden("This API key is read-only.")


def _team_id(p, team):
    return p.team_id if str(team) == "current" else _int(team, "team")


# ----------------------------------------------------------------------------------------- teams
def patch_team(tx, p, actor, team, body):
    _writer(p)
    team_id = _team_id(p, team)
    row = tx.one("SELECT * FROM occ.teams WHERE id = :t FOR UPDATE", t=team_id)
    if row is None:
        raise errors.not_found()
    if not p.is_sysadmin and team_id not in p.admin_teams:
        raise errors.forbidden("Only an admin of that team can change its settings.")
    body = body or {}
    changes = []
    for k, v in body.items():
        if k == "id":
            continue
        if k not in TEAM_COLUMNS:
            raise errors.bad("Incorrect value for %s: not a team setting" % k)
        if k in TEAM_SYSADMIN_ONLY and not p.is_sysadmin:
            raise errors.forbidden("Only a sysadmin can change a team's %s." % k)
        if k in TEAM_BOOL:
            nv = _flag(v, k)
        elif k in TEAM_INT:
            nv = _int(v, k)
            if nv < 0:
                raise errors.bad("Incorrect value for %s" % k)
        else:
            nv = None if v is None else str(v)
            if k == "name":
                nv = (nv or "").strip()
                if not nv:
                    raise errors.bad("Incorrect value for name: it is empty")
                if tx.val("SELECT 1 FROM occ.teams WHERE lower(name) = lower(:n) AND id <> :t", n=nv, t=team_id):
                    raise errors.bad("A team with that name exists already.")
        if nv != row[k]:
            changes.append((k, row[k], nv))
    for col, old, new in changes:
        tx.run("UPDATE occ.teams SET %s = :v WHERE id = :t" % ident(col, TEAM_COLUMNS), v=new, t=team_id)
        audit.write(tx, actor, "team.update", team_id=team_id, target=col, old=old, new=new)
    return P._team_shape(tx.one("SELECT * FROM occ.teams WHERE id = :t", t=team_id))


def delete_team(tx, p, actor, team):
    """Delete a team. As in 2.x: refused with 400 while the team has members or records."""
    _writer(p)
    if not p.is_sysadmin:
        raise errors.forbidden("Only a sysadmin can delete a team.")
    team_id = _int(team, "team")
    row = tx.one("SELECT id, name FROM occ.teams WHERE id = :t FOR UPDATE", t=team_id)
    if row is None:
        raise errors.not_found()
    busy = tx.val("SELECT EXISTS (SELECT 1 FROM occ.memberships WHERE team_id = :t) "
                  "OR EXISTS (SELECT 1 FROM occ.records WHERE team_id = :t)", t=team_id)
    if busy:
        raise errors.bad("The team is not empty! Aborting deletion!")
    # Keys and sessions bound to the team go with it (ON DELETE CASCADE); history keeps the id.
    tx.run("DELETE FROM occ.teams WHERE id = :t", t=team_id)
    audit.write(tx, actor, "team.delete", team_id=team_id, target="team", old=row["name"])


# ---------------------------------------------------------------------------------- team groups
def _group_shape(tx, g):
    users = tx.all("SELECT u.id, u.firstname, u.lastname FROM occ.team_group_members gm JOIN occ.users u "
                   "ON u.id = gm.user_id WHERE gm.group_id = :g ORDER BY u.lastname, u.firstname, u.id", g=g["id"])
    return {"id": g["id"], "name": g["name"], "team": g["team_id"],
            "users": [{"userid": u["id"], "fullname": ("%s %s" % (u["firstname"], u["lastname"])).strip()}
                      for u in users]}


def list_groups(tx, p, team):
    team_id = _team_id(p, team)
    if team_id not in p.member_teams and not p.is_sysadmin and not p.site_scope:
        raise errors.forbidden("You are not a member of that team.")
    groups = [_group_shape(tx, g) for g in tx.all("SELECT * FROM occ.team_groups WHERE team_id = :t "
                                                  "ORDER BY name, id", t=team_id)]
    # Reproduced from 2.x: it answers an object keyed by group id, and [] when there is none.
    return {str(g["id"]): g for g in groups} if groups else []


def _admin_of(p, team_id):
    if team_id not in p.admin_teams and not p.is_sysadmin:
        raise errors.forbidden("Only an admin of that team can change its groups.")


def create_group(tx, p, actor, team, body):
    _writer(p)
    team_id = _team_id(p, team)
    if not tx.val("SELECT 1 FROM occ.teams WHERE id = :t", t=team_id):
        raise errors.not_found()
    _admin_of(p, team_id)
    name = str((body or {}).get("name") or "").strip()
    if not name:
        raise errors.bad("Incorrect value for name: it is empty")
    gid = tx.val("INSERT INTO occ.team_groups (team_id, name) VALUES (:t, :n) RETURNING id", t=team_id, n=name)
    audit.write(tx, actor, "group.create", team_id=team_id, target="name", new=name, detail={"group_id": gid})
    return gid


def _group(tx, p, team, group_id):
    team_id = _team_id(p, team)
    g = tx.one("SELECT * FROM occ.team_groups WHERE id = :g AND team_id = :t FOR UPDATE", g=group_id, t=team_id)
    if g is None:
        raise errors.not_found()
    _admin_of(p, team_id)
    return g


def patch_group(tx, p, actor, team, group_id, body):
    """Change a group. As in 2.x: {name} renames; {userid, how: add|rm} changes membership; 'action' is ignored."""
    _writer(p)
    g = _group(tx, p, team, group_id)
    body = body or {}
    did = False
    if "name" in body:
        name = str(body.get("name") or "").strip()
        if not name:
            raise errors.bad("Incorrect value for name: it is empty")
        if name != g["name"]:
            tx.run("UPDATE occ.team_groups SET name = :n WHERE id = :g", n=name, g=group_id)
            audit.write(tx, actor, "group.update", team_id=g["team_id"], target="name", old=g["name"], new=name,
                        detail={"group_id": group_id})
        did = True
    if "userid" in body or "how" in body:
        uid = _int(body.get("userid"), "userid")
        how = str(body.get("how") or "")
        if how not in ("add", "rm"):
            raise errors.bad("Incorrect value for how: add or rm")
        if how == "add":
            if not tx.val("SELECT 1 FROM occ.memberships WHERE user_id = :u AND team_id = :t", u=uid, t=g["team_id"]):
                raise errors.bad("Incorrect value for userid: not a member of the group's team")
            n = tx.run("INSERT INTO occ.team_group_members (group_id, user_id) VALUES (:g, :u) ON CONFLICT DO NOTHING",
                       g=group_id, u=uid)
        else:
            n = tx.run("DELETE FROM occ.team_group_members WHERE group_id = :g AND user_id = :u", g=group_id, u=uid)
        if n:
            audit.write(tx, actor, "group.member_" + how, team_id=g["team_id"], target="userid", new=uid,
                        detail={"group_id": group_id})
        did = True
    if not did:
        raise errors.bad("Nothing to change: send name, or userid with how")
    return _group_shape(tx, tx.one("SELECT * FROM occ.team_groups WHERE id = :g", g=group_id))


def delete_group(tx, p, actor, team, group_id):
    _writer(p)
    g = _group(tx, p, team, group_id)
    tx.run("DELETE FROM occ.record_access WHERE principal = 'g' AND principal_id = :g", g=group_id)
    tx.run("DELETE FROM occ.team_groups WHERE id = :g", g=group_id)
    audit.write(tx, actor, "group.delete", team_id=g["team_id"], target="name", old=g["name"],
                detail={"group_id": group_id})


# ---------------------------------------------------------------------------------- team tags
def _team_tag(tx, p, team, tag_id):
    team_id = _team_id(p, team)
    t = tx.one("SELECT * FROM occ.tags WHERE id = :id AND team_id = :t FOR UPDATE", id=tag_id, t=team_id)
    if t is None:
        raise errors.not_found()
    if team_id not in p.admin_teams and not p.is_sysadmin:
        raise errors.forbidden("Only an admin of that team can change its tags.")
    return t


def patch_team_tag(tx, p, actor, team, tag_id, body):
    """Rename a team tag ({tag}). Renaming onto an existing tag merges the two (the records keep one)."""
    _writer(p)
    t = _team_tag(tx, p, team, tag_id)
    new = str((body or {}).get("tag") or "").strip()
    if not new:
        raise errors.bad("Incorrect value for tag: it is empty")
    if new == t["tag"]:
        return {"id": tag_id, "tag": new, "team": t["team_id"]}
    rids = [r["rid"] for r in tx.all("SELECT rid FROM occ.record_tags WHERE tag_id = :id", id=tag_id)]
    other = tx.val("SELECT id FROM occ.tags WHERE team_id = :t AND tag = :g", t=t["team_id"], g=new)
    if other is None:
        tx.run("UPDATE occ.tags SET tag = :g WHERE id = :id", g=new, id=tag_id)
        out_id = tag_id
    else:
        tx.run("INSERT INTO occ.record_tags (rid, tag_id) SELECT rid, :o FROM occ.record_tags WHERE tag_id = :id "
               "ON CONFLICT DO NOTHING", o=other, id=tag_id)
        tx.run("INSERT INTO occ.favorite_tags (user_id, tag_id) SELECT user_id, :o FROM occ.favorite_tags "
               "WHERE tag_id = :id ON CONFLICT DO NOTHING", o=other, id=tag_id)
        tx.run("DELETE FROM occ.tags WHERE id = :id", id=tag_id)
        out_id = other
    audit.write(tx, actor, "tag.update", team_id=t["team_id"], target="tag", old=t["tag"], new=new,
                detail={"tag_id": tag_id, "merged_into": out_id if out_id != tag_id else None, "records": len(rids)})
    for rid in rids:
        S.refresh_search(tx, rid)
    return {"id": out_id, "tag": new, "team": t["team_id"]}


def delete_team_tag(tx, p, actor, team, tag_id):
    _writer(p)
    t = _team_tag(tx, p, team, tag_id)
    rids = [r["rid"] for r in tx.all("SELECT rid FROM occ.record_tags WHERE tag_id = :id", id=tag_id)]
    tx.run("DELETE FROM occ.tags WHERE id = :id", id=tag_id)
    audit.write(tx, actor, "tag.delete", team_id=t["team_id"], target="tag", old=t["tag"],
                detail={"tag_id": tag_id, "records": len(rids)})
    for rid in rids:
        S.refresh_search(tx, rid)


# ----------------------------------------------------------------------------------------- users
def _user(tx, uid, lock=False):
    r = tx.one("SELECT * FROM occ.users WHERE id = :u AND deleted_at IS NULL" + (" FOR UPDATE" if lock else ""), u=uid)
    if r is None:
        raise errors.not_found()
    return r


def _shared_admin_team(tx, p, uid):
    return tx.val("SELECT team_id FROM occ.memberships WHERE user_id = :u AND team_id = ANY(CAST(:t AS int[])) "
                  "ORDER BY team_id LIMIT 1", u=uid, t=sorted(p.admin_teams))


def _membership_team(tx, p, body, uid):
    team = body.get("team")
    if team in (None, ""):
        raise errors.bad("Incorrect value for team")
    team_id = _team_id(p, team)
    if not tx.val("SELECT 1 FROM occ.teams WHERE id = :t", t=team_id):
        raise errors.bad("Incorrect value for team: no such team")
    if not p.is_sysadmin and team_id not in p.admin_teams:
        raise errors.forbidden("Only an admin of that team can change its members.")
    return team_id


def patch_user(tx, p, actor, user, body):
    """Change a user: fields, or one membership action (add, unreference, patchuser2team, validate,
    archive, unarchive). Answers the user as GET /users/{id} shows it to the caller."""
    _writer(p)
    uid = p.user_id if str(user) == "me" else _int(user, "user")
    row = _user(tx, uid, lock=True)
    body = dict(body or {})
    action = body.pop("action", None)
    is_self = uid == p.user_id
    admin_team = None if (p.is_sysadmin or is_self) else _shared_admin_team(tx, p, uid)
    if not (p.is_sysadmin or is_self or admin_team):
        raise errors.forbidden()

    if action not in (None, ""):
        _user_action(tx, p, actor, uid, row, str(action), body)
        return _answer(tx, p, uid, is_self)

    cols, prefs, reads = [], {}, {}
    for k, v in body.items():
        if k in ("userid", "id"):
            continue
        if k in USER_SELF:
            if not (is_self or p.is_sysadmin):
                raise errors.forbidden("Only the person or a sysadmin can change %s." % k)
            nv = None if v in (None, "") and k == "orcid" else ("" if v is None else str(v).strip())
            if k == "orcid" and nv is not None and not _orcid_ok(nv):
                raise errors.bad("Incorrect value for orcid")
            cols.append((k, nv))
        elif k in USER_SYSADMIN:
            if not p.is_sysadmin:
                raise errors.forbidden("Only a sysadmin can change %s." % k)
            if k in USER_BOOL:
                nv = _flag(v, k)
                if k == "is_sysadmin" and is_self and not nv:
                    raise errors.bad("A sysadmin cannot remove their own sysadmin right.")
            elif k == "valid_until":
                try:
                    nv = None if v in (None, "") else timefmt.parse_date(v)
                except ValueError:
                    raise errors.bad("Incorrect value for valid_until")
            elif k == "email":
                nv = str(v or "").strip()
                if "@" not in nv[1:]:
                    raise errors.bad("Incorrect value for email")
                if tx.val("SELECT 1 FROM occ.users WHERE email = :e AND id <> :u", e=nv, u=uid):
                    raise errors.bad("A user with that email exists already.")
            else:
                nv = None if v in (None, "") else str(v)
            cols.append((k, nv))
        elif k in ("default_read", "default_write"):
            if not is_self:
                raise errors.forbidden("Only the person can change their default permissions.")
            reads[k] = _default_perm(k, v)
        elif k in PREF_NAMES or k.startswith(PREF_PREFIXES) or k in (row["prefs"] or {}):
            if not is_self:
                raise errors.forbidden("Only the person can change their preferences.")
            if k in PREF_INT:
                n = _int(v, k)
                if n < 1 or n > 10000:
                    raise errors.bad("Incorrect value for %s: 1 to 10000" % k)
                prefs[k] = n
            else:
                prefs[k] = v
        else:
            raise errors.bad("Incorrect value for %s: not a user field" % k)

    team_for_audit = p.team_id if is_self else (admin_team or None)
    for col, nv in cols:
        old = row[col]
        if hasattr(old, "isoformat") and nv is not None and not isinstance(nv, str):
            same = old == nv
        else:
            same = (old == nv) or (str(old) if old is not None else None) == (str(nv) if nv is not None else None)
        if same:
            continue
        tx.run("UPDATE occ.users SET %s = :v WHERE id = :u" % ident(col, USER_COLUMNS), v=nv, u=uid)
        audit.write(tx, actor, "user.update", team_id=team_for_audit, target=col, old=old, new=nv,
                    detail={"userid": uid})
    if prefs:
        cur = dict(row["prefs"] or {})
        for k, v in prefs.items():
            if cur.get(k) != v:
                audit.write(tx, actor, "user.update", team_id=team_for_audit, target="prefs." + k, old=cur.get(k),
                            new=v, detail={"userid": uid})
                cur[k] = v
        tx.run("UPDATE occ.users SET prefs = CAST(:p AS jsonb) WHERE id = :u", p=jsonb(cur), u=uid)
    for k, (base, lists) in reads.items():
        old = json.dumps(dict(row[k] or {}, base=row[k + "_base"]), sort_keys=True)
        new = json.dumps(dict(lists, base=base), sort_keys=True)
        if old != new:
            tx.run("UPDATE occ.users SET %s = :b, %s = CAST(:l AS jsonb) WHERE id = :u"
                   % (ident(k + "_base", DEFAULT_PERM_COLUMNS), ident(k, DEFAULT_PERM_COLUMNS)),
                   b=base, l=jsonb(lists), u=uid)
            audit.write(tx, actor, "user.update", team_id=team_for_audit, target=k, old=old, new=new,
                        detail={"userid": uid})
    return _answer(tx, p, uid, is_self)


def _answer(tx, p, uid, is_self):
    """The user after the change. Not through get_user: a team admin who has just removed the
    person from their team would no longer be allowed to read them."""
    if is_self:
        return P.get_user(tx, p, "me")
    return P._user_shape(tx, _user(tx, uid))


def _orcid_ok(v):
    import re
    return bool(re.fullmatch(r"\d{4}-\d{4}-\d{4}-\d{3}[\dX]", v))


def _default_perm(name, v):
    if isinstance(v, str):
        try:
            v = json.loads(v)
        except ValueError:
            raise errors.bad("Incorrect value for %s: JSON text" % name)
    if not isinstance(v, dict):
        raise errors.bad("Incorrect value for %s" % name)
    base = _int(v.get("base", 30), name + ".base")
    if base not in (10, 20, 30, 40, 50):
        raise errors.bad("Incorrect value for %s.base" % name)
    lists = {}
    for k in ("teams", "users", "teamgroups"):
        vals = v.get(k) or []
        if not isinstance(vals, list):
            raise errors.bad("Incorrect value for %s.%s" % (name, k))
        lists[k] = [_int(x, "%s.%s" % (name, k)) for x in vals]
    return base, lists


def _user_action(tx, p, actor, uid, row, action, body):
    if action == "add":
        team_id = _membership_team(tx, p, body, uid)
        if tx.run("INSERT INTO occ.memberships (user_id, team_id) VALUES (:u, :t) ON CONFLICT DO NOTHING",
                  u=uid, t=team_id):
            audit.write(tx, actor, "membership.add", team_id=team_id, target="team", new=team_id,
                        detail={"userid": uid})
    elif action == "unreference":
        team_id = _membership_team(tx, p, body, uid)
        if tx.val("SELECT count(*) FROM occ.memberships WHERE user_id = :u", u=uid) <= 1 and \
                tx.val("SELECT 1 FROM occ.memberships WHERE user_id = :u AND team_id = :t", u=uid, t=team_id):
            raise errors.bad("A user must stay in at least one team.")
        if tx.run("DELETE FROM occ.memberships WHERE user_id = :u AND team_id = :t", u=uid, t=team_id):
            tx.run("DELETE FROM occ.team_group_members gm USING occ.team_groups g WHERE g.id = gm.group_id "
                   "AND g.team_id = :t AND gm.user_id = :u", t=team_id, u=uid)
            audit.write(tx, actor, "membership.remove", team_id=team_id, target="team", old=team_id,
                        detail={"userid": uid})
        else:
            raise errors.bad("Incorrect value for team: the user is not a member")
    elif action == "patchuser2team":
        team_id = _membership_team(tx, p, body, uid)
        target = str(body.get("target") or "")
        if target not in MEMBERSHIP_TARGETS:
            raise errors.bad("Incorrect value for target: is_admin, is_owner or is_archived")
        content = _flag(body.get("content"), "content")
        m = tx.one("SELECT * FROM occ.memberships WHERE user_id = :u AND team_id = :t FOR UPDATE", u=uid, t=team_id)
        if m is None:
            raise errors.bad("Incorrect value for team: the user is not a member")
        if m[target] != content:
            tx.run("UPDATE occ.memberships SET %s = :c WHERE user_id = :u AND team_id = :t"
                   % ident(target, MEMBERSHIP_TARGETS),
                   c=content, u=uid, t=team_id)
            audit.write(tx, actor, "membership.update", team_id=team_id, target=target, old=m[target], new=content,
                        detail={"userid": uid})
            if target == "is_archived":
                _sync_archived(tx, uid)
    elif action == "validate":
        if not p.is_sysadmin and not _shared_admin_team(tx, p, uid):
            raise errors.forbidden()
        if not row["validated"]:
            tx.run("UPDATE occ.users SET validated = true WHERE id = :u", u=uid)
            audit.write(tx, actor, "user.update", target="validated", old=False, new=True, detail={"userid": uid})
    elif action in ("archive", "unarchive"):
        # Archiving is per membership; without team, every team the caller
        # administers (all of the user's teams for a sysadmin). users.archived_at follows.
        want = action == "archive"
        if uid == p.user_id and want:
            raise errors.bad("You cannot archive yourself.")
        if body.get("team") not in (None, ""):
            teams = [_membership_team(tx, p, body, uid)]
        else:
            teams = [r["team_id"] for r in tx.all("SELECT team_id FROM occ.memberships WHERE user_id = :u", u=uid)
                     if p.is_sysadmin or r["team_id"] in p.admin_teams]
        if not teams:
            raise errors.forbidden()
        for t in teams:
            if tx.run("UPDATE occ.memberships SET is_archived = :a WHERE user_id = :u AND team_id = :t "
                      "AND is_archived <> :a", a=want, u=uid, t=t):
                audit.write(tx, actor, "membership.update", team_id=t, target="is_archived", old=not want, new=want,
                            detail={"userid": uid})
        _sync_archived(tx, uid)
    else:
        raise errors.bad("Incorrect value for action")


def _sync_archived(tx, uid):
    """users.archived_at is set while every membership is archived, and cleared otherwise."""
    tx.run("UPDATE occ.users SET archived_at = CASE WHEN NOT EXISTS (SELECT 1 FROM occ.memberships m "
           "WHERE m.user_id = :u AND NOT m.is_archived) THEN coalesce(archived_at, now()) ELSE NULL END "
           "WHERE id = :u", u=uid)


def delete_user(tx, p, actor, user):
    """Delete a user (sysadmin). Soft: the account is marked deleted, its keys revoked, its
    sessions ended and its memberships removed, so history keeps naming who did what. Refused
    while the user owns records (400)."""
    _writer(p)
    if not p.is_sysadmin:
        raise errors.forbidden("Only a sysadmin can delete a user.")
    uid = _int(user, "user")
    if uid == p.user_id:
        raise errors.bad("You cannot delete yourself.")
    row = _user(tx, uid, lock=True)
    if tx.val("SELECT 1 FROM occ.records WHERE owner_id = :u AND state <> 3 LIMIT 1", u=uid):
        raise errors.bad("This user owns records: move or delete them first.")
    tx.run("UPDATE occ.api_keys SET revoked_at = now() WHERE user_id = :u AND revoked_at IS NULL", u=uid)
    tx.run("UPDATE occ.sessions SET revoked_at = now() WHERE user_id = :u AND revoked_at IS NULL", u=uid)
    tx.run("DELETE FROM occ.team_group_members WHERE user_id = :u", u=uid)
    tx.run("DELETE FROM occ.memberships WHERE user_id = :u", u=uid)
    tx.run("UPDATE occ.users SET deleted_at = now() WHERE id = :u", u=uid)
    audit.write(tx, actor, "user.delete", target="email", old=row["email"], detail={"userid": uid})
