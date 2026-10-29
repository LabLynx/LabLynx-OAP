# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Who is calling: built once per request from an API key or a session."""
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Principal:
    user_id: int
    team_id: int                       # the current team: where the caller creates
    is_sysadmin: bool = False
    write_exempt: bool = False
    member_teams: frozenset = field(default_factory=frozenset)   # active (not archived) memberships
    admin_teams: frozenset = field(default_factory=frozenset)
    group_ids: frozenset = field(default_factory=frozenset)
    api_key_id: int = None
    can_write: bool = True             # an API key may be read-only
    site_scope: bool = False           # sysadmin service keys only: may act across teams
    via: str = "apikey"                # apikey | session
    firstname: str = ""
    lastname: str = ""

    @property
    def fullname(self):
        return ("%s %s" % (self.firstname, self.lastname)).strip()

    def is_admin_of(self, team_id):
        return team_id in self.admin_teams

    def is_member_of(self, team_id):
        return team_id in self.member_teams


def load(tx, user_id, team_id, **extra):
    """A Principal for user_id acting in team_id, read from the database."""
    u = tx.one("SELECT id, firstname, lastname, is_sysadmin, write_exempt, validated, archived_at, deleted_at "
               "FROM occ.users WHERE id = :id", id=user_id)
    if u is None or u["deleted_at"] is not None or u["archived_at"] is not None:
        return None
    mem = tx.all("SELECT team_id, is_admin FROM occ.memberships WHERE user_id = :id AND NOT is_archived", id=user_id)
    groups = tx.all("SELECT gm.group_id FROM occ.team_group_members gm JOIN occ.team_groups g ON g.id = gm.group_id "
                    "JOIN occ.memberships m ON m.team_id = g.team_id AND m.user_id = gm.user_id AND NOT m.is_archived "
                    "WHERE gm.user_id = :id", id=user_id)
    return Principal(user_id=u["id"], team_id=team_id, is_sysadmin=bool(u["is_sysadmin"]),
                     write_exempt=bool(u["write_exempt"]),
                     member_teams=frozenset(m["team_id"] for m in mem),
                     admin_teams=frozenset(m["team_id"] for m in mem if m["is_admin"]),
                     group_ids=frozenset(g["group_id"] for g in groups),
                     firstname=u["firstname"], lastname=u["lastname"], **extra)
