# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Teams, users, the team's tags, extra-field names and instance information: listing, reading and
the first writes."""
import json

from .. import API_REVISION, MIRRORED_API_VERSION, MIRRORED_API_VERSION_INT, __version__, errors, timefmt
from ..audit import writer as audit
from ..perms import engine

_TEAM_FIELDS = ("id", "name", "orgid", "visible", "user_create_tag", "force_exp_tpl", "force_res_tpl",
                "users_canwrite_experiments", "users_canwrite_experiments_categories",
                "users_canwrite_experiments_status", "users_canwrite_experiments_templates",
                "users_canwrite_resources", "users_canwrite_resources_categories", "users_canwrite_resources_status",
                "users_canwrite_resources_templates", "announcement", "onboarding_email_active",
                "onboarding_email_subject", "onboarding_email_body", "newcomer_threshold", "newcomer_banner",
                "newcomer_banner_active", "created_at")


def _team_shape(r):
    out = {}
    for k in _TEAM_FIELDS:
        v = r.get(k)
        out[k] = (1 if v else 0) if isinstance(v, bool) else (timefmt.out(v) if k == "created_at" else v)
    return out


def list_teams(tx, p):
    rows = tx.all("SELECT * FROM occ.teams ORDER BY id")
    if p.is_sysadmin or p.site_scope:
        return [_team_shape(r) for r in rows]
    return [{"id": r["id"], "name": r["name"], "visible": 1 if r["visible"] else 0} for r in rows
            if r["visible"] or r["id"] in p.member_teams]


def get_team(tx, p, team):
    team_id = p.team_id if str(team) == "current" else _int(team, "team")
    if team_id not in p.member_teams and not p.is_sysadmin and not p.site_scope:
        raise errors.forbidden("You are not a member of that team.")
    r = tx.one("SELECT * FROM occ.teams WHERE id = :t", t=team_id)
    if r is None:
        raise errors.not_found()
    return _team_shape(r)


def create_team(tx, p, actor, body):
    if not p.is_sysadmin:
        raise errors.forbidden("Only a sysadmin can create a team.")
    if not p.can_write:
        raise errors.forbidden("This API key is read-only.")
    name = str((body or {}).get("name") or "").strip()
    if not name:
        raise errors.bad("Incorrect value for name: it is empty")
    if tx.val("SELECT 1 FROM occ.teams WHERE lower(name) = lower(:n)", n=name):
        raise errors.bad("A team with that name exists already.")
    tid = tx.val("INSERT INTO occ.teams (name, orgid, visible) VALUES (:n, :o, :v) RETURNING id", n=name,
                 o=(body or {}).get("orgid"), v=str((body or {}).get("visible", 1)).lower() not in ("0", "false"))
    audit.write(tx, actor, "team.create", team_id=tid, target="name", new=name)
    return tid


def _int(v, name):
    try:
        return int(v)
    except (TypeError, ValueError):
        raise errors.bad("Incorrect value for %s" % name)


def _user_shape(tx, r, full=False):
    teams = tx.all("SELECT m.team_id AS id, t.name, m.is_admin, m.is_owner, m.is_archived FROM occ.memberships m "
                   "JOIN occ.teams t ON t.id = m.team_id WHERE m.user_id = :u ORDER BY m.team_id", u=r["id"])
    out = {"userid": r["id"], "firstname": r["firstname"], "lastname": r["lastname"],
           "fullname": ("%s %s" % (r["firstname"], r["lastname"])).strip(),
           "initials": ((r["firstname"] or " ")[0] + (r["lastname"] or " ")[0]).strip().upper(),
           "email": r["email"], "orcid": r["orcid"], "orgid": r["orgid"], "created_at": timefmt.out(r["created_at"]),
           "validated": 1 if r["validated"] else 0, "last_login": timefmt.out(r["last_login_at"]),
           "valid_until": timefmt.out(r["valid_until"]), "is_sysadmin": 1 if r["is_sysadmin"] else 0,
           "can_manage_users2teams": 1 if r["can_manage_users2teams"] else 0,
           "can_manage_compounds": 1 if r["can_manage_compounds"] else 0,
           "can_manage_inventory_locations": 1 if r["can_manage_inventory_locations"] else 0,
           "auth_service": r["auth_service"], "has_mfa_enabled": 0, "sig_pubkey": None,
           "archived": 1 if r["archived_at"] else 0,
           "teams": [{"id": t["id"], "name": t["name"], "is_admin": 1 if t["is_admin"] else 0,
                      "is_owner": 1 if t["is_owner"] else 0, "is_archived": 1 if t["is_archived"] else 0}
                     for t in teams]}
    if full:
        prefs = r["prefs"] or {}
        out.update(prefs)
        out["default_read"] = json.dumps(dict(r["default_read"] or {}, base=r["default_read_base"]))
        out["default_write"] = json.dumps(dict(r["default_write"] or {}, base=r["default_write_base"]))
    return out


def get_user(tx, p, user):
    uid = p.user_id if str(user) == "me" else _int(user, "user")
    r = tx.one("SELECT * FROM occ.users WHERE id = :u AND deleted_at IS NULL", u=uid)
    if r is None:
        raise errors.not_found()
    if uid != p.user_id and not p.is_sysadmin and not p.site_scope:
        shared = tx.val("SELECT 1 FROM occ.memberships WHERE user_id = :u AND team_id = ANY(CAST(:t AS int[]))",
                        u=uid, t=sorted(p.admin_teams))
        if not shared:
            raise errors.forbidden()
    out = _user_shape(tx, r, full=(uid == p.user_id))
    if uid == p.user_id:
        out["team"] = p.team_id
        out["is_admin"] = 1 if p.team_id in p.admin_teams else 0
    return out


def list_users(tx, p, q=None, limit=None, offset=None, team=None):
    """Members of the caller's teams; everybody for a sysadmin. limit/offset honored (2.x ignores them)."""
    where = ["u.deleted_at IS NULL"]
    params = {}
    if not (p.is_sysadmin or p.site_scope):
        where.append("EXISTS (SELECT 1 FROM occ.memberships m WHERE m.user_id = u.id AND "
                     "m.team_id = ANY(CAST(:mt AS int[])))")
        params["mt"] = sorted(p.member_teams)
    if team not in (None, ""):
        where.append("EXISTS (SELECT 1 FROM occ.memberships m2 WHERE m2.user_id = u.id AND m2.team_id = :tt)")
        params["tt"] = _int(team, "team")
    if q:
        where.append("(u.firstname || ' ' || u.lastname || ' ' || u.email) ILIKE :q")
        params["q"] = "%" + str(q).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    sql = "SELECT u.* FROM occ.users u WHERE " + " AND ".join(where) + " ORDER BY u.lastname, u.firstname, u.id"
    if limit not in (None, ""):
        sql += " LIMIT :lim"
        params["lim"] = _int(limit, "limit")
    if offset not in (None, ""):
        sql += " OFFSET :off"
        params["off"] = _int(offset, "offset")
    return [_user_shape(tx, r) for r in tx.all(sql, **params)]


def create_user(tx, p, actor, body):
    """Make a user (sysadmin): email, firstname, lastname, usergroup (2 admin, 4 user), team."""
    if not p.is_sysadmin:
        raise errors.forbidden("Only a sysadmin can create a user.")
    if not p.can_write:
        raise errors.forbidden("This API key is read-only.")
    body = body or {}
    email = str(body.get("email") or "").strip()
    if "@" not in email[1:]:
        raise errors.bad("Incorrect value for email")
    team = _int(body.get("team") or p.team_id, "team")
    if not tx.val("SELECT 1 FROM occ.teams WHERE id = :t", t=team):
        raise errors.bad("Incorrect value for team: no such team")
    if tx.val("SELECT 1 FROM occ.users WHERE email = :e", e=email):
        raise errors.bad("A user with that email exists already.")
    group = _int(body.get("usergroup") or 4, "usergroup")
    if group not in (2, 4):
        raise errors.bad("Incorrect value for usergroup: 2 (admin) or 4 (user)")
    uid = tx.val("INSERT INTO occ.users (email, firstname, lastname, validated, valid_until) "
                 "VALUES (:e, :f, :l, true, :vu) RETURNING id", e=email, f=str(body.get("firstname") or ""),
                 l=str(body.get("lastname") or ""),
                 vu=timefmt.parse_date(body["valid_until"]) if body.get("valid_until") else None)
    tx.run("INSERT INTO occ.memberships (user_id, team_id, is_admin) VALUES (:u, :t, :a)", u=uid, t=team, a=group == 2)
    audit.write(tx, actor, "user.create", team_id=team, target="email", new=email, detail={"userid": uid})
    return uid


def team_tags(tx, p, team, q=None):
    team_id = p.team_id if str(team) == "current" else _int(team, "team")
    if team_id not in p.member_teams and not p.is_sysadmin and not p.site_scope:
        raise errors.forbidden("You are not a member of that team.")
    params = {"t": team_id, "u": p.user_id}
    where = "tg.team_id = :t"
    if q:
        where += " AND tg.tag ILIKE :q"
        params["q"] = "%" + str(q).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    rows = tx.all("SELECT tg.id, tg.tag, tg.team_id, (SELECT count(*) FROM occ.record_tags rt JOIN occ.records r "
                  "ON r.rid = rt.rid WHERE rt.tag_id = tg.id AND r.state <> 3) AS item_count, "
                  "EXISTS (SELECT 1 FROM occ.favorite_tags f WHERE f.tag_id = tg.id AND f.user_id = :u) AS fav "
                  "FROM occ.tags tg WHERE " + where + " ORDER BY tg.tag", **params)
    return [{"id": r["id"], "tag": r["tag"], "item_count": r["item_count"], "is_favorite": 1 if r["fav"] else 0,
             "team": r["team_id"]} for r in rows]


def extra_fields_keys(tx, p, q=None, limit=None):
    """Extra-field names used in records the caller can read in the current team, by frequency."""
    cond, params = engine.list_filter(p, engine.READ)
    params["t"] = p.team_id
    extra = ""
    if q:
        extra = " AND e.key ILIKE :q"
        params["q"] = "%" + str(q).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    params["lim"] = _int(limit, "limit") if limit not in (None, "") else 1000
    rows = tx.all("SELECT e.key AS k, count(*) AS n FROM occ.records r, "
                  "jsonb_each(CASE WHEN jsonb_typeof(r.metadata->'extra_fields') = 'object' "
                  "THEN r.metadata->'extra_fields' ELSE '{}'::jsonb END) e "
                  "WHERE r.team_id = :t AND r.state <> 3 AND " + cond + extra +
                  " GROUP BY e.key ORDER BY count(*) DESC, e.key LIMIT :lim", **params)
    return [{"extra_fields_key": r["k"], "frequency": r["n"]} for r in rows]


def info(tx, p, read_only, caller_can_write):
    c = tx.one("""SELECT
        (SELECT count(*) FROM occ.users WHERE deleted_at IS NULL) AS all_users,
        (SELECT count(*) FROM occ.users WHERE deleted_at IS NULL AND archived_at IS NULL AND validated) AS active_users,
        (SELECT count(*) FROM occ.records WHERE kind_id = 2 AND state <> 3) AS items,
        (SELECT count(*) FROM occ.teams) AS teams,
        (SELECT count(*) FROM occ.compounds WHERE state <> 3) AS compounds,
        (SELECT count(*) FROM occ.records WHERE kind_id = 1 AND state <> 3) AS experiments,
        (SELECT count(*) FROM occ.records WHERE kind_id = 1 AND timestamped) AS exp_ts,
        (SELECT count(*) FROM occ.records WHERE timestamped AND timestamped_at > now() - interval '30 days') AS ts30,
        (SELECT coalesce(sum(size), 0) FROM occ.uploads WHERE state <> 3) AS upbytes""")
    return {
        "elabftw_version": MIRRORED_API_VERSION, "elabftw_version_int": MIRRORED_API_VERSION_INT,
        "ts_balance": 0, "ts_limit": 0,
        "uploads_filesize_sum": int(c["upbytes"]), "uploads_filesize_sum_formatted": _human(int(c["upbytes"])),
        "all_users_count": c["all_users"], "active_users_count": c["active_users"], "items_count": c["items"],
        "teams_count": c["teams"], "compounds_count": c["compounds"], "experiments_count": c["experiments"],
        "experiments_timestamped_count": c["exp_ts"], "entities_timestamped_count_last_30_days": c["ts30"],
        "occ_version": __version__, "occ_api_revision": API_REVISION, "occ_source_url": None,
        "server_time": timefmt.out(tx.val("SELECT now()")), "timezone": timefmt.zone().key,
        "read_only": 1 if read_only else 0, "caller_can_write": 1 if caller_can_write else 0,
    }


def _human(n):
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.2f %s" % (n, unit))
        n /= 1024.0
