# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The record API end to end through HTTP, against a scratch database."""
import json


def _new(client, world, who="alice", kind="experiments", **body):
    r = client.post("/api/v2/%s" % kind, json=body or {"title": "t"}, headers=world.h(who))
    assert r.status_code == 201, r.text
    assert r.content == b""                                          # empty body, as 2.x answers a create
    return int(r.headers["location"].rsplit("/", 1)[-1])


def test_create_read_list(client, world):
    eid = _new(client, world, title="First")
    r = client.get("/api/v2/experiments/%d" % eid, headers=world.h("alice"))
    assert r.status_code == 200
    d = r.json()
    assert d["title"] == "First" and d["type"] == "experiments"
    assert isinstance(d["canread"], str) and json.loads(d["canread"]) == {"base": 30, "teams": [], "users": [], "teamgroups": []}
    assert d["changelog"][0]["target"] == "created"
    assert d["locked"] == 0 and d["state"] == 1
    rows = client.get("/api/v2/experiments", params={"limit": 50}, headers=world.h("alice")).json()
    assert any(x["id"] == eid for x in rows)


def test_errors_use_the_envelope(client, world):
    r = client.get("/api/v2/experiments/999999", headers=world.h("alice"))
    assert r.status_code == 404 and set(r.json()) == {"code", "message", "description"}
    r = client.get("/api/v2/nonsense", headers=world.h("alice"))
    assert r.status_code == 400 and r.json()["message"].startswith("Invalid endpoint")       # unknown endpoint: 400, as 2.x
    r = client.get("/api/v2/experiments")
    assert r.status_code == 401


def test_patch_is_atomic(client, world, pool):
    """One valid and one invalid field -> 400, neither changed, no audit row added."""
    eid = _new(client, world, title="Atomic")
    before = client.get("/api/v2/experiments/%d" % eid, headers=world.h("alice")).json()
    with pool.tx() as tx:
        n0 = tx.val("SELECT count(*) FROM occ.audit_events")
        top = tx.val("SELECT coalesce(max(id), 0) FROM occ.audit_events")
    r = client.patch("/api/v2/experiments/%d" % eid, json={"title": "Changed", "rating": 9}, headers=world.h("alice"))
    assert r.status_code == 400 and "rating" in r.json()["message"]
    after = client.get("/api/v2/experiments/%d" % eid, headers=world.h("alice")).json()
    assert after["title"] == before["title"] == "Atomic"
    with pool.tx() as tx:
        assert tx.val("SELECT count(*) FROM occ.audit_events") == n0
    r = client.patch("/api/v2/experiments/%d" % eid, json={"title": "Two", "rating": 4}, headers=world.h("alice"))
    assert r.status_code == 200 and r.json()["title"] == "Two" and r.json()["rating"] == 4
    with pool.tx() as tx:
        rows = tx.all("SELECT target, old_value, new_value FROM occ.audit_events WHERE id > :top ORDER BY id", top=top)
    assert {(r["target"], r["old_value"], r["new_value"]) for r in rows} == {("title", "Atomic", "Two"),
                                                                             ("rating", "0", "4")}


def test_divergences_d01_d08_d10_d11_d12_d13(client, world):
    eid = _new(client, world, title="Div")
    h = world.h("alice")
    assert client.patch("/api/v2/experiments/%d" % eid, json={"date": ""}, headers=h).json()["date"] is None   # a date can be cleared (2.x answers 500)
    assert client.patch("/api/v2/experiments/%d" % eid, json={"metadata": ""}, headers=h).status_code == 200   # metadata '' clears it (2.x answers 500)
    assert client.patch("/api/v2/experiments/%d" % eid, json={"metadata": {"a": 1}}, headers=h).status_code == 200  # metadata as an object (2.x answers 500)
    assert client.patch("/api/v2/experiments/%d" % eid, json={"date": "not-a-date"}, headers=h).status_code == 400  # a bad date: 400, not 500
    assert client.patch("/api/v2/experiments/%d" % eid, json={"rating": "abc"}, headers=h).status_code == 400  # a bad rating: 400 (2.x silently stores 0)
    assert client.patch("/api/v2/experiments/%d" % eid, json={"title": ""}, headers=h).json()["title"] == "Untitled"  # title '' renames it, as 2.x does


def test_delete_soft_and_idempotent(client, world):
    eid = _new(client, world, title="Gone")
    h = world.h("alice")
    assert client.delete("/api/v2/experiments/%d" % eid, headers=h).status_code == 204
    assert client.get("/api/v2/experiments/%d" % eid, headers=h).json()["state"] == 3              # delete is soft: still readable by id
    rows = client.get("/api/v2/experiments", params={"limit": 500}, headers=h).json()
    assert not any(x["id"] == eid for x in rows)
    assert client.delete("/api/v2/experiments/%d" % eid, headers=h).status_code == 204              # deleting again: 204 (2.x answers 400)


def test_lock_toggles_and_blocks(client, world):
    eid = _new(client, world, title="Lock")
    h = world.h("alice")
    assert client.patch("/api/v2/experiments/%d" % eid, json={"action": "lock"}, headers=h).json()["locked"] == 1
    assert client.patch("/api/v2/experiments/%d" % eid, json={"title": "x"}, headers=h).status_code == 423
    assert client.patch("/api/v2/experiments/%d" % eid, json={"action": "lock"}, headers=h).json()["locked"] == 0  # lock toggles, as 2.x does


def test_subresources(client, world):
    eid = _new(client, world, title="Subs")
    h = world.h("alice")
    assert client.post("/api/v2/experiments/%d/tags" % eid, json={"tag": "zz"}, headers=h).status_code == 201
    tags = client.get("/api/v2/experiments/%d/tags" % eid, headers=h).json()
    assert [t["tag"] for t in tags] == ["zz"]
    assert client.delete("/api/v2/experiments/%d/tags/%d" % (eid, tags[0]["tag_id"]), headers=h).status_code == 204
    r = client.post("/api/v2/experiments/%d/steps" % eid, json={"body": "s1"}, headers=h)
    sid = int(r.headers["location"].rsplit("/", 1)[-1])
    assert client.patch("/api/v2/experiments/%d/steps/%d" % (eid, sid), json={"action": "finish"},
                        headers=h).json()["finished"] == 1
    r = client.post("/api/v2/experiments/%d/comments" % eid, json={"comment": "c1"}, headers=h)
    cid = int(r.headers["location"].rsplit("/", 1)[-1])
    assert client.patch("/api/v2/experiments/%d/comments/%d" % (eid, cid), json={"comment": "c2"},
                        headers=h).json()["comment"] == "c2"
    other = _new(client, world, title="Target")
    assert client.post("/api/v2/experiments/%d/experiments_links/%d" % (eid, other), headers=h).status_code == 201
    d = client.get("/api/v2/experiments/%d" % eid, headers=h).json()
    assert [l["entityid"] for l in d["experiments_links"]] == [other]
    assert d["comments"][0]["comment"] == "c2" and d["steps"][0]["body"] == "s1"


def test_lookups_and_search(client, world):
    h = world.h("admin")
    r = client.post("/api/v2/teams/current/experiments_status", json={"name": "Running", "color": "29AEB9"}, headers=h)
    assert r.status_code == 201
    sid = int(r.headers["location"].rsplit("/", 1)[-1])
    eid = _new(client, world, who="admin", title="Searchable water sample")
    client.patch("/api/v2/experiments/%d" % eid, json={"status": sid}, headers=h)
    hits = client.get("/api/v2/experiments", params={"q": "WATER"}, headers=h).json()
    assert [x["id"] for x in hits] == [eid]
    hits = client.get("/api/v2/experiments", params={"extended": 'status:"running"'}, headers=h).json()
    assert eid in [x["id"] for x in hits]


def test_read_only_mode(client, world, pool):
    with pool.tx() as tx:
        tx.run("UPDATE occ.site_config SET value = '1' WHERE name = 'read_only'")
    try:
        r = client.post("/api/v2/experiments", json={"title": "no"}, headers=world.h("alice"))
        assert r.status_code == 403 and r.json()["message"] == "This is a read-only preview of LabLynx.One 3.x."
        assert client.get("/api/v2/occ/write-policy", headers=world.h("alice")).json()["caller_can_write"] == 0
    finally:
        with pool.tx() as tx:
            tx.run("UPDATE occ.site_config SET value = '0' WHERE name = 'read_only'")


def test_an_internal_error_is_a_500_envelope_without_detail(client, world, monkeypatch):
    from occ.people import service as P

    def boom(*a, **k):
        raise RuntimeError("internal detail that must not leak")
    monkeypatch.setattr(P, "info", boom)
    r = client.get("/api/v2/info", headers=world.h("alice"))
    assert r.status_code == 500 and set(r.json()) == {"code", "message", "description"}
    assert "internal detail" not in r.text
    assert client.get("/api/v2/experiments", params={"limit": 1}, headers=world.h("alice")).status_code == 200
