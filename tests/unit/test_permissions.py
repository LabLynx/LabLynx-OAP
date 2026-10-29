# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The permission engine.

1. The matrix: every base, and the named lists, against owner, team admin, member, group member,
   other-team member, outsider and a site-scope key, through the HTTP API (read and write).
2. Agreement: for 600 generated record/person pairs the single-record check and the list filter
   give the same answer, read and write.
"""
import random

import pytest

from occ.auth.principal import Principal
from occ.perms import engine

WHO = ("alice", "admin", "bob", "bea", "out")


def _make(client, world, base_r, base_w=10, **lists):
    h = world.h("alice")
    r = client.post("/api/v2/experiments", json={"title": "perm %s" % base_r}, headers=h)
    eid = int(r.headers["location"].rsplit("/", 1)[-1])
    canread = {"base": base_r, "teams": lists.get("teams", []), "users": lists.get("users", []),
               "teamgroups": lists.get("groups", [])}
    r = client.patch("/api/v2/experiments/%d" % eid, json={"canread": canread,
                                                           "canwrite": {"base": base_w}}, headers=h)
    assert r.status_code == 200, r.text
    return eid


# alice owns every record; admin is team A's admin; bob is a member of A and of group Readers;
# bea is in team B; out is in team C. 200 = may read; 403 = exists in caller's team; 404 = not shown.
MATRIX = {
    10: {"alice": 200, "admin": 403, "bob": 403, "bea": 404, "out": 404},
    20: {"alice": 200, "admin": 200, "bob": 403, "bea": 404, "out": 404},
    30: {"alice": 200, "admin": 200, "bob": 200, "bea": 404, "out": 404},
    40: {"alice": 200, "admin": 200, "bob": 200, "bea": 200, "out": 200},
    50: {"alice": 200, "admin": 200, "bob": 200, "bea": 200, "out": 200},
}


@pytest.mark.parametrize("base", sorted(MATRIX))
def test_read_matrix_by_base(client, world, base):
    eid = _make(client, world, base)
    for who in WHO:
        got = client.get("/api/v2/experiments/%d" % eid, headers=world.h(who)).status_code
        assert got == MATRIX[base][who], (base, who, got)
        listed = any(x["id"] == eid for x in client.get("/api/v2/experiments", params={"limit": 10000},
                                                        headers=world.h(who)).json())
        assert listed == (MATRIX[base][who] == 200), (base, who, "list")
    assert client.get("/api/v2/experiments/%d" % eid, headers=world.h("sys_site")).status_code == 200


def test_named_lists_grant_read(client, world):
    eid = _make(client, world, 10, users=[world.users["bea"]])
    assert client.get("/api/v2/experiments/%d" % eid, headers=world.h("bea")).status_code == 200
    assert client.get("/api/v2/experiments/%d" % eid, headers=world.h("out")).status_code == 404
    eid = _make(client, world, 10, groups=[world.group])
    assert client.get("/api/v2/experiments/%d" % eid, headers=world.h("bob")).status_code == 200
    assert client.get("/api/v2/experiments/%d" % eid, headers=world.h("admin")).status_code == 403
    eid = _make(client, world, 10, teams=[world.teams["B"]])
    assert client.get("/api/v2/experiments/%d" % eid, headers=world.h("bea")).status_code == 200


def test_write_matrix(client, world):
    for base_w, ok in ((10, {"alice"}), (20, {"alice", "admin"}), (30, {"alice", "admin", "bob"})):
        eid = _make(client, world, 30, base_w)
        for who in ("alice", "admin", "bob"):
            r = client.patch("/api/v2/experiments/%d" % eid, json={"rating": 2}, headers=world.h(who))
            assert (r.status_code == 200) == (who in ok), (base_w, who, r.status_code)


def test_read_only_key_and_sysadmin_have_no_implicit_access(client, world):
    eid = _make(client, world, 30)
    r = client.patch("/api/v2/experiments/%d" % eid, json={"rating": 1}, headers=world.h("alice_ro"))
    assert r.status_code == 403
    assert client.get("/api/v2/experiments/%d" % eid, headers=world.h("sys")).status_code == 404


def test_immutable_permissions_need_a_team_admin(client, world, pool):
    eid = _make(client, world, 30, 20)
    with pool.tx() as tx:
        tx.run("UPDATE occ.records SET canread_is_immutable = true WHERE kind_id = 1 AND id = :id", id=eid)
    r = client.patch("/api/v2/experiments/%d" % eid, json={"canread": {"base": 40}}, headers=world.h("alice"))
    assert r.status_code == 403
    r = client.patch("/api/v2/experiments/%d" % eid, json={"canread": {"base": 40}, "canwrite": {"base": 20}},
                     headers=world.h("admin"))
    assert r.status_code == 200


def test_single_check_and_list_filter_agree(world, pool):
    """600 generated pairs, read and write, each decided both ways."""
    rnd = random.Random(103)
    users = list(world.users.values())
    teams = list(world.teams.values())
    groups = [world.group]
    recs = []
    with pool.tx() as tx:
        for i in range(120):
            owner = rnd.choice(users)
            rid = tx.val("INSERT INTO occ.records (kind_id, id, elabid, team_id, owner_id, created_by, canread_base, "
                         "canwrite_base, state, title) VALUES (1, :id, :e, :t, :o, :o, :rb, :wb, :st, 'gen') "
                         "RETURNING rid", id=900000 + i, e="gen-%d" % i, t=rnd.choice(teams), o=owner,
                         rb=rnd.choice(engine.BASES), wb=rnd.choice(engine.BASES), st=rnd.choice((1, 1, 2, 3)))
            for right in "rw":
                for _ in range(rnd.randint(0, 2)):
                    kind = rnd.choice("tgu")
                    pid = {"t": rnd.choice(teams), "g": rnd.choice(groups), "u": rnd.choice(users)}[kind]
                    tx.run("INSERT INTO occ.record_access VALUES (:r, :rt, :k, :p) ON CONFLICT DO NOTHING",
                           r=rid, rt=right, k=kind, p=pid)
            recs.append(rid)
        rows = tx.all("SELECT r.rid, r.owner_id, r.team_id, r.canread_base, r.canwrite_base, r.state, "
                      "(SELECT coalesce(jsonb_agg(jsonb_build_array(ra.access_right, ra.principal, ra.principal_id)), "
                      "'[]'::jsonb) FROM occ.record_access ra WHERE ra.rid = r.rid) AS access "
                      "FROM occ.records r WHERE r.rid = ANY(CAST(:ids AS bigint[]))", ids=recs)
        for r in rows:
            r["access"] = [tuple(a) for a in r["access"]]
        people = []
        for i in range(5):
            mem = frozenset(rnd.sample(teams, rnd.randint(0, len(teams))))
            adm = frozenset(t for t in mem if rnd.random() < 0.4)
            people.append(Principal(user_id=rnd.choice(users), team_id=next(iter(mem), teams[0]), member_teams=mem,
                                    admin_teams=adm, group_ids=frozenset(groups) if rnd.random() < 0.5 else frozenset()))
        pairs = disagreements = 0
        for p in people:
            for right in (engine.READ, engine.WRITE):
                cond, params = engine.list_filter(p, right)
                allowed = {x["rid"] for x in tx.all("SELECT r.rid FROM occ.records r WHERE r.rid = ANY(CAST(:ids AS bigint[])) "
                                                    "AND " + cond, ids=recs, **params)}
                for r in rows:
                    pairs += 1
                    if engine.check(p, r, right) != (r["rid"] in allowed):
                        disagreements += 1
        tx.run("DELETE FROM occ.records WHERE rid = ANY(CAST(:ids AS bigint[]))", ids=recs)
    assert pairs >= 500
    assert disagreements == 0
