# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The one permission engine: every permission decision is made here and nowhere else.

Every read and write decision and every list filter comes from the RULES table below. Each rule
has two renderings of the same condition: `py` decides one record already in memory, `sql` is a
WHERE fragment for lists. check() ORs the py forms, list_filter() ORs the sql forms, so a rule is
added or changed in one place; tests/unit/test_permissions.py proves the two agree on generated
record/person pairs.

    allowed(right) = owner
                  OR base >= 40                                   (40 every signed-in person, 50 link)
                  OR (base >= 30 AND record.team IN member_teams)
                  OR (base >= 20 AND record.team IN admin_teams)
                  OR the person, one of their teams or one of their groups is on the record's list

Writing additionally needs the record not deleted; locks are decided by write_block(). A
site-scope key (sysadmins only) reads every record; a sysadmin has no implicit record access.
"""
from dataclasses import dataclass

from ..db import ident, sql_fragment

READ, WRITE, BOOK = "r", "w", "b"
_BASE_COL = {READ: "canread_base", WRITE: "canwrite_base", BOOK: "canbook_base"}
BASES = (10, 20, 30, 40, 50)
BASE_HUMAN = {10: "Only the owner", 20: "Only owner and admins", 30: "Only members of the team",
              40: "Every connected user", 50: "Anyone with the link"}


@dataclass(frozen=True)
class Rule:
    name: str
    py: object      # (principal, record, right) -> bool
    sql: object     # (alias, right) -> SQL text using the :p_* parameters from params()


def _base(rec, right):
    v = rec.get(_BASE_COL[right])
    return v if v is not None else 0


RULES = (
    Rule("owner",
         lambda p, r, right: r["owner_id"] == p.user_id,
         lambda a, right: "%s.owner_id = :p_uid" % a),
    Rule("organization",
         lambda p, r, right: _base(r, right) >= 40,
         lambda a, right: "%s.%s >= 40" % (a, _BASE_COL[right])),
    Rule("team",
         lambda p, r, right: _base(r, right) >= 30 and r["team_id"] in p.member_teams,
         lambda a, right: "(%s.%s >= 30 AND %s.team_id = ANY(CAST(:p_members AS int[])))" % (a, _BASE_COL[right], a)),
    Rule("team admins",
         lambda p, r, right: _base(r, right) >= 20 and r["team_id"] in p.admin_teams,
         lambda a, right: "(%s.%s >= 20 AND %s.team_id = ANY(CAST(:p_admins AS int[])))" % (a, _BASE_COL[right], a)),
    Rule("named",
         lambda p, r, right: any(
             (kind == "t" and pid in p.member_teams) or (kind == "g" and pid in p.group_ids)
             or (kind == "u" and pid == p.user_id)
             for (rt, kind, pid) in (r.get("access") or ()) if rt == right),
         lambda a, right: ("EXISTS (SELECT 1 FROM occ.record_access ra WHERE ra.rid = %s.rid AND ra.access_right = '%s' "
                           "AND ((ra.principal = 't' AND ra.principal_id = ANY(CAST(:p_members AS int[]))) "
                           "OR (ra.principal = 'g' AND ra.principal_id = ANY(CAST(:p_groups AS int[]))) "
                           "OR (ra.principal = 'u' AND ra.principal_id = :p_uid)))") % (a, right)),
)


def params(p):
    """The parameters every sql rendering uses."""
    return {"p_uid": p.user_id, "p_members": sorted(p.member_teams), "p_admins": sorted(p.admin_teams),
            "p_groups": sorted(p.group_ids)}


def check(p, rec, right=READ):
    """May principal p use `right` on this record? rec needs owner_id, team_id, the base columns,
    state, and access: a collection of (right, principal kind, principal id)."""
    if right == READ and p.site_scope:
        return True
    if right != READ and rec.get("state") == 3:
        return False
    return any(rule.py(p, rec, right) for rule in RULES)


ALIASES = frozenset(("r", "t", "o"))
RIGHTS = frozenset((READ, WRITE, BOOK))


@sql_fragment
def list_filter(p, right=READ, alias="r"):
    """(SQL condition, params) selecting exactly the records check() allows."""
    alias, right = ident(alias, ALIASES), ident(right, RIGHTS)
    if right == READ and p.site_scope:
        return "TRUE", {}
    cond = "(" + " OR ".join(rule.sql(alias, right) for rule in RULES) + ")"
    if right != READ:
        cond = "(%s.state <> 3 AND %s)" % (alias, cond)
    return cond, params(p)


def write_block(p, rec, unlocking=False):
    """Why a permitted writer still may not write now: None, or (status, message).

    A locked record refuses writes (423), except unlocking by the person who locked it, its owner
    or an admin of its team.
    """
    if rec.get("locked"):
        if unlocking and (rec.get("locked_by") == p.user_id or rec["owner_id"] == p.user_id
                          or rec["team_id"] in p.admin_teams):
            return None
        return (423, "This entry is locked.")
    return None


def readable_or_raise(p, rec, errors):
    """403 when the record exists in one of the caller's teams, 404 otherwise, so a
    record outside the caller's teams is not even confirmed to exist."""
    if rec is None:
        raise errors.not_found()
    if not check(p, rec, READ):
        if rec["team_id"] in p.member_teams:
            raise errors.forbidden()
        raise errors.not_found()
