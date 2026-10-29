# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Statuses and categories, and reordering them in one call (PUT .../{lookup}/order).

They are keyed (lookup_group, id): experiments and resources number them separately. A team's
list also carries the other teams' entries that are not private, flagged is_current_team 0, as
the 2.x answer does. Writing needs team admin, or membership when the team's users_canwrite_*
setting allows it. Delete is soft (state 3); records keep their value.
"""
import re

from .. import errors
from ..db import ident, sql_fragment
from ..audit import writer as audit
from . import kinds as K

_HEX = re.compile(r"^#?([0-9A-Fa-f]{6})$")


TEAM_SETTINGS = frozenset(v[2] for v in K.LOOKUPS.values())
LOOKUP_COLUMNS = frozenset(("title", "color", "ordering", "is_default", "is_private", "state"))


@sql_fragment
def _which(lookup):
    if lookup not in K.LOOKUPS:
        raise errors.bad("Invalid endpoint: %s" % lookup)
    return K.LOOKUPS[lookup]


def resolve_team(p, team):
    if str(team) == "current":
        return p.team_id
    try:
        return int(team)
    except (TypeError, ValueError):
        raise errors.bad("Incorrect value for team")


def _member(p, team_id):
    if team_id not in p.member_teams and not p.is_sysadmin and not p.site_scope:
        raise errors.forbidden("You are not a member of that team.")


def _may_write(tx, p, team_id, setting):
    if not p.can_write:
        raise errors.forbidden("This API key is read-only.")
    if team_id in p.admin_teams:
        return
    if team_id in p.member_teams and tx.val("SELECT %s FROM occ.teams WHERE id = :t" % ident(setting, TEAM_SETTINGS), t=team_id):
        return
    raise errors.forbidden("Only team admins can change this list.")


def _shape(r, team_id):
    return {"id": r["id"], "title": r["title"], "color": r["color"], "ordering": r["ordering"], "state": r["state"],
            "team": r["team_id"], "is_private": 1 if r["is_private"] else 0, "is_default": 1 if r["is_default"] else 0,
            "team_name": r["team_name"], "is_current_team": 1 if r["team_id"] == team_id else 0}


def _rows(tx, table_sql, group, where_sql, **params):
    return tx.all("SELECT l.id, l.title, l.color, l.ordering, l.state, l.team_id, l.is_private, l.is_default, "
                  "t.name AS team_name FROM occ.%s l JOIN occ.teams t ON t.id = l.team_id "
                  "WHERE l.lookup_group = :g AND %s" % (table_sql, where_sql), g=group, **params)


def list_lookup(tx, p, team, lookup):
    table, group, _ = _which(lookup)
    team_id = resolve_team(p, team)
    _member(p, team_id)
    rows = _rows(tx, table, group, "l.state = 1 AND (l.team_id = :t OR NOT l.is_private) "
                 "ORDER BY (l.team_id <> :t), l.team_id, l.ordering NULLS LAST, l.id", t=team_id)
    return [_shape(r, team_id) for r in rows]


def _one(tx, table_sql, group, lookup_id):
    rows = _rows(tx, table_sql, group, "l.id = :id", id=lookup_id)
    if not rows:
        raise errors.not_found()
    return rows[0]


def get_lookup(tx, p, team, lookup, lookup_id):
    table, group, _ = _which(lookup)
    team_id = resolve_team(p, team)
    _member(p, team_id)
    r = _one(tx, table, group, lookup_id)
    if r["team_id"] != team_id and r["is_private"]:
        raise errors.not_found()
    return _shape(r, team_id)


def _color(v):
    m = _HEX.match(str(v or ""))
    if not m:
        raise errors.bad("Incorrect value for color: six hexadecimal digits")
    return m.group(1).upper()


def create_lookup(tx, p, actor, team, lookup, body):
    table, group, setting = _which(lookup)
    team_id = resolve_team(p, team)
    _member(p, team_id)
    _may_write(tx, p, team_id, setting)
    body = body or {}
    title = str(body.get("name") or body.get("title") or "").strip()      # 2.x takes only 'name'; the OCC takes name or title
    if not title:
        raise errors.bad("Incorrect value for name: it is empty")
    color = _color(body["color"]) if body.get("color") not in (None, "") else "29AEB9"
    is_default = _bool(body.get("is_default", False))
    is_private = _bool(body.get("is_private", False))
    if is_default:
        tx.run("UPDATE occ.%s SET is_default = false WHERE team_id = :t AND lookup_group = :g" % table, t=team_id, g=group)
    new_id = tx.val("INSERT INTO occ.%s (lookup_group, team_id, title, color, is_default, is_private) "
                    "VALUES (:g, :t, :title, :c, :d, :pv) RETURNING id" % table,
                    g=group, t=team_id, title=title, c=color, d=is_default, pv=is_private)
    audit.write(tx, actor, "team.%s.create" % lookup, team_id=team_id, target=lookup, new=title,
                detail={"id": new_id})
    return new_id


def _bool(v):
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "on", "yes")


def patch_lookup(tx, p, actor, team, lookup, lookup_id, body):
    table, group, setting = _which(lookup)
    team_id = resolve_team(p, team)
    _member(p, team_id)
    r = _one(tx, table, group, lookup_id)
    if r["team_id"] != team_id or r["state"] == 3:
        raise errors.not_found()
    _may_write(tx, p, team_id, setting)
    body = body or {}
    changes = []
    for name, v in body.items():
        if name in ("title", "name"):                                          # name accepted too
            t = str(v or "").strip()
            if not t:
                raise errors.bad("Incorrect value for title: it is empty")
            changes.append(("title", r["title"], t))
        elif name == "color":
            changes.append(("color", r["color"], _color(v)))
        elif name == "ordering":                                               # 2.x refuses ordering here; the OCC writes it
            try:
                changes.append(("ordering", r["ordering"], None if v in (None, "") else int(v)))
            except (TypeError, ValueError):
                raise errors.bad("Incorrect value for ordering")
        elif name in ("is_default", "is_private"):
            changes.append((name, r[name], _bool(v)))
        elif name == "state":
            try:
                st = int(v)
            except (TypeError, ValueError):
                raise errors.bad("Incorrect value for state")
            if st not in (1, 2):
                raise errors.bad("Incorrect value for state")
            changes.append(("state", r["state"], st))
        else:
            raise errors.bad("Invalid update target: %s" % name)
    for col, old, new in changes:
        if old == new:
            continue
        if col == "is_default" and new:
            tx.run("UPDATE occ.%s SET is_default = false WHERE team_id = :t AND lookup_group = :g" % table,
                   t=team_id, g=group)
        tx.run("UPDATE occ.%s SET %s = :v, modified_at = now() WHERE lookup_group = :g AND id = :id"
               % (table, ident(col, LOOKUP_COLUMNS)),
               v=new, g=group, id=lookup_id)
        audit.write(tx, actor, "team.%s.update" % lookup, team_id=team_id, target="%s.%s" % (lookup, col),
                    old=old, new=new, detail={"id": lookup_id})
    return get_lookup(tx, p, team, lookup, lookup_id)


def delete_lookup(tx, p, actor, team, lookup, lookup_id):
    table, group, setting = _which(lookup)
    team_id = resolve_team(p, team)
    _member(p, team_id)
    r = _one(tx, table, group, lookup_id)
    if r["team_id"] != team_id:
        raise errors.not_found()
    _may_write(tx, p, team_id, setting)
    if r["state"] != 3:
        tx.run("UPDATE occ.%s SET state = 3, is_default = false, modified_at = now() "
               "WHERE lookup_group = :g AND id = :id" % table, g=group, id=lookup_id)
        audit.write(tx, actor, "team.%s.delete" % lookup, team_id=team_id, target=lookup, old=r["title"],
                    detail={"id": lookup_id})


def reorder(tx, p, actor, team, lookup, body):
    """Reorder: {ids: [...]} names every live entry of the team's list exactly once, in the new order."""
    table, group, setting = _which(lookup)
    team_id = resolve_team(p, team)
    _member(p, team_id)
    _may_write(tx, p, team_id, setting)
    ids = (body or {}).get("ids")
    if not isinstance(ids, list):
        raise errors.bad("Incorrect value for ids: a list in the new order")
    try:
        ids = [int(x) for x in ids]
    except (TypeError, ValueError):
        raise errors.bad("Incorrect value for ids")
    live = [r["id"] for r in _rows(tx, table, group, "l.team_id = :t AND l.state <> 3", t=team_id)]
    if sorted(ids) != sorted(live) or len(set(ids)) != len(ids):
        raise errors.bad("ids must name every entry of the list exactly once")
    for pos, lid in enumerate(ids, 1):
        tx.run("UPDATE occ.%s SET ordering = :o, modified_at = now() WHERE lookup_group = :g AND id = :id "
               "AND ordering IS DISTINCT FROM :o" % table, o=pos, g=group, id=lid)
    audit.write(tx, actor, "team.%s.reorder" % lookup, team_id=team_id, target=lookup, new=",".join(map(str, ids)))
    rows = _rows(tx, table, group, "l.team_id = :t AND l.state = 1 ORDER BY l.ordering NULLS LAST, l.id", t=team_id)
    return [_shape(r, team_id) for r in rows]
