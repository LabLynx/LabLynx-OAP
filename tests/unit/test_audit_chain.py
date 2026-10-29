# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The audit chain: the stored row is hashed in a canonical,
time-zone-independent form; the Python verifier recomputes every hash from the stored columns;
one altered row (triggers disabled, scratch copy only) makes the verifier and the verify endpoint name that row."""
import os
import threading

from fastapi.testclient import TestClient

from occ import db, settings as settings_mod
from occ.audit import verify as V
from occ.auth import apikeys
from occ.db import scratch
from occ.main import create_app

NASTY = ['plain', 'quote " and backslash \\ and slash /', "tab\tnew\nline\rcr\x08bs\x0cff", "ctl \x01\x1f end",
         "unicode é ü 中文 🙂", "", " leading and trailing ", "x" * 3000]


def _append(con, i, value, detail=None, **extra):
    p = {"actor_kind": "system", "category": "test.chain", "new_value": value, "old_value": "o%d" % i,
         "target": "t", "detail": detail}
    p.update(extra)
    return con.run("SELECT occ.audit_append(CAST(:p AS jsonb))", p=db.jsonb({k: v for k, v in p.items()
                                                                             if v is not None}))[0][0]


def _fill(con):
    ids = []
    details = [None, {"a": 1, "bb": [1, 2.5, "x"], "z": {"n": None, "t": True}}, {"num": 1.50}, {"long key " * 5: "v"},
               {"é": "ü", "esc": "q\"\\\n"}]
    zones = ["UTC", "America/Chicago", "Pacific/Kiritimati", "Asia/Kolkata", "America/St_Johns"]
    for i, value in enumerate(NASTY * 2):
        con.run("SET TIME ZONE '%s'" % zones[i % len(zones)])          # zone names are this test's constants
        ids.append(_append(con, i, value, details[i % len(details)], request_id="0b7c2b4e-1d3f-4a6b-9c8d-%012d" % i,
                           orig_at="2025-03-09T02:30:00-06:00" if i % 3 == 0 else None, team_id=i % 4 or None,
                           kind_id=1 if i % 2 else None, record_id=i, rid=1000 + i))
    return ids


def test_python_canonical_equals_the_database_form_in_every_time_zone(base_params):
    with scratch.scratch(base_params, suffix="ac1_%d" % os.getpid()) as name:
        con = db.connect(scratch.params_for(base_params, name))
        try:
            _fill(con)
            for zone in ("UTC", "Pacific/Kiritimati", "America/Chicago"):
                con.run("SET TIME ZONE '%s'" % zone)
                rows = con.run("SELECT occ.audit_canonical(e) FROM occ.audit_events e ORDER BY id")
                tx = db.Tx(con)
                mine = [V.canonical(r) for r in tx.all("SELECT " + V._COLS + " FROM occ.audit_events ORDER BY id")]
                assert [r[0] for r in rows] == mine
                # and the database's own check agrees with what it stored
                assert con.run("SELECT bool_and(hash = sha256(prev_hash || convert_to(occ.audit_canonical(e), "
                               "'UTF8'))) FROM occ.audit_events e")[0][0] is True
            res = V.verify(db.Tx(con))
            assert res["ok"] and res["checked"] == len(NASTY) * 2 and res["first_bad_id"] is None
        finally:
            con.close()


def test_ids_follow_the_chain_under_concurrent_writers(base_params):
    with scratch.scratch(base_params, suffix="ac2_%d" % os.getpid()) as name:
        params = scratch.params_for(base_params, name)
        errors = []

        def worker(n):
            con = db.connect(params)
            try:
                for i in range(25):
                    con.run("BEGIN")
                    _append(con, i, "w%d-%d" % (n, i))
                    con.run("COMMIT")
            except Exception as e:  # noqa: BLE001
                errors.append(e)
            finally:
                con.close()
        threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        con = db.connect(params)
        try:
            res = V.verify(db.Tx(con), batch=7)                      # several pages
            assert res["ok"] and res["checked"] == 100
        finally:
            con.close()


def _tamper(con, sql, **params):
    """Scratch copy only: switch the append-only trigger off, change the row, switch it back on."""
    con.run("ALTER TABLE occ.audit_events DISABLE TRIGGER audit_events_no_update")
    try:
        con.run(sql, **params)
    finally:
        con.run("ALTER TABLE occ.audit_events ENABLE TRIGGER audit_events_no_update")


def test_one_altered_row_is_named_by_the_verifier_and_by_x03(base_params, tmp_path):
    with scratch.scratch(base_params, suffix="ac3_%d" % os.getpid()) as name:
        params = scratch.params_for(base_params, name)
        con = db.connect(params)
        try:
            ids = _fill(con)
            pepper_file = str(tmp_path / "pepper")
            apikeys.make_pepper_file(pepper_file)
            pepper = apikeys.read_pepper(pepper_file)
            tx = db.Tx(con)
            con.run("BEGIN")
            uid = tx.val("INSERT INTO occ.users (email, firstname, lastname, validated, is_sysadmin) "
                         "VALUES ('sys@example.com', 'Sys', 'Admin', true, true) RETURNING id")
            tid = tx.val("INSERT INTO occ.teams (name) VALUES ('T') RETURNING id")
            tx.run("INSERT INTO occ.memberships (user_id, team_id) VALUES (:u, :t)", u=uid, t=tid)
            _k, key = apikeys.create(tx, pepper, uid, tid, "sys", can_write=False)
            con.run("COMMIT")
            cfg = settings_mod.Settings(database_url="postgresql:///%s" % name, api_key_pepper_file=pepper_file,
                                        files_root=str(tmp_path / "files"), base_url="http://testserver",
                                        pool_size=2, rate_burst=0)
            with TestClient(create_app(cfg)) as client:
                h = {"Authorization": key}
                good = client.get("/api/v2/occ/audit/verify", headers=h).json()
                assert good["ok"] is True and good["checked"] == len(ids) and good["first_bad_id"] is None

                victim = ids[7]
                _tamper(con, "UPDATE occ.audit_events SET new_value = new_value || '!' WHERE id = :id", id=victim)
                res = V.verify(db.Tx(con))
                assert not res["ok"] and res["first_bad_id"] == victim and "stored hash" in res["reason"]
                bad = client.get("/api/v2/occ/audit/verify", headers=h).json()
                assert bad["ok"] is False and bad["first_bad_id"] == victim
                # a partial walk that starts after the damage passes; one that covers it does not
                assert client.get("/api/v2/occ/audit/verify", params={"from": victim + 1}, headers=h).json()["ok"]
                assert not client.get("/api/v2/occ/audit/verify", params={"to": victim}, headers=h).json()["ok"]

                # a forger who also rewrites the row's own hash is caught at the next row
                _tamper(con, "UPDATE occ.audit_events SET hash = sha256(prev_hash || convert_to("
                             "occ.audit_canonical(audit_events), 'UTF8')) WHERE id = :id", id=victim)
                res = V.verify(db.Tx(con))
                assert not res["ok"] and res["first_bad_id"] == ids[8] and "prev_hash" in res["reason"]

                # only a sysadmin may ask
                con.run("UPDATE occ.users SET is_sysadmin = false WHERE id = :u", u=uid)
                assert client.get("/api/v2/occ/audit/verify", headers=h).status_code == 403
        finally:
            con.close()


def test_deleting_a_row_breaks_the_chain_at_the_next_one(base_params):
    with scratch.scratch(base_params, suffix="ac4_%d" % os.getpid()) as name:
        con = db.connect(scratch.params_for(base_params, name))
        try:
            ids = _fill(con)
            _tamper(con, "DELETE FROM occ.audit_events WHERE id = :id", id=ids[3])
            res = V.verify(db.Tx(con))
            assert not res["ok"] and res["first_bad_id"] == ids[4]
        finally:
            con.close()


def test_checkpoint_records_the_verified_head(base_params, pool, client, world):
    client.post("/api/v2/experiments", json={"title": "checkpoint"}, headers=world.h("alice"))
    with pool.tx() as tx:
        res = V.verify(tx)
        assert res["ok"] and res["checked"] > 0
        cid = V.checkpoint(tx, res)
        assert cid is not None
        cp = V.last_checkpoint(tx)
        assert cp["upto_id"] == res["last_id"] and cp["verified_ok"] == 1 and cp["upto_hash"] == res["last_hash"]
        assert V.checkpoint(tx, res) is None          # the same head is recorded once
    j = client.get("/api/v2/occ/audit/verify", headers=world.h("sys")).json()
    assert j["ok"] is True and j["last_checkpoint"]["upto_id"] == res["last_id"]


def test_audit_log_reading_follows_the_permission_rules(client, world):
    eid = int(client.post("/api/v2/experiments", json={"title": "audited"}, headers=world.h("alice"))
              .headers["location"].rsplit("/", 1)[-1])
    client.patch("/api/v2/experiments/%d" % eid, json={"title": "audited 2", "canread": '{"base": 10}'},
                 headers=world.h("alice"))
    mine = client.get("/api/v2/occ/audit", params={"kind": "experiments", "record_id": eid},
                      headers=world.h("alice")).json()["events"]
    assert {e["target"] for e in mine} >= {"title", "created"} or any(e["target"] == "title" for e in mine)
    assert mine == sorted(mine, key=lambda e: -e["id"])
    # bea (another team) cannot read the record and sees none of its events
    other = client.get("/api/v2/occ/audit", params={"kind": "experiments", "record_id": eid},
                       headers=world.h("bea")).json()["events"]
    assert other == []
    # the sysadmin sees them; the team admin of team A sees them through the team
    assert client.get("/api/v2/occ/audit", params={"record_id": eid, "kind": "experiments"},
                      headers=world.h("sys")).json()["events"]
    assert client.get("/api/v2/occ/audit", params={"record_id": eid, "kind": "experiments"},
                      headers=world.h("admin")).json()["events"]
    page = client.get("/api/v2/occ/audit", params={"limit": 2}, headers=world.h("sys")).json()
    assert len(page["events"]) == 2 and page["next"]
    nxt = client.get("/api/v2/occ/audit", params={"limit": 2, "cursor": page["next"]}, headers=world.h("sys")).json()
    assert nxt["events"][0]["id"] < page["events"][-1]["id"]
    assert client.get("/api/v2/occ/audit", params={"limit": 5000}, headers=world.h("sys")).status_code == 400
