# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Records, history and revisions (with test_smoke_api.py: an invalid write changes nothing)."""


def _new(client, world, **body):
    r = client.post("/api/v2/experiments", json=body, headers=world.h("alice"))
    return int(r.headers["location"].rsplit("/", 1)[-1])


def test_every_field_change_is_one_history_row_with_old_and_new(client, world):
    eid = _new(client, world, title="H1")
    h = world.h("alice")
    client.patch("/api/v2/experiments/%d" % eid, json={"title": "H2", "date": "2026-01-02", "rating": 5}, headers=h)
    log = client.get("/api/v2/experiments/%d" % eid, headers=h).json()["changelog"]
    rows = {(e["target"], e["old_value"], e["content"]) for e in log}
    assert ("title", "H1", "H2") in rows and ("rating", "0", "5") in rows and ("date", None, "2026-01-02") in rows or \
        any(e["target"] == "date" and e["content"] == "2026-01-02" for e in log)
    assert log[-1]["target"] == "created"                          # newest first, creation last
    assert [e["id"] for e in log] == sorted((e["id"] for e in log), reverse=True)   # newest first, as 2.x lists history


def test_unchanged_value_writes_no_history(client, world, pool):
    eid = _new(client, world, title="Same")
    with pool.tx() as tx:
        n0 = tx.val("SELECT count(*) FROM occ.audit_events")
    r = client.patch("/api/v2/experiments/%d" % eid, json={"title": "Same"}, headers=world.h("alice"))
    assert r.status_code == 200
    with pool.tx() as tx:
        assert tx.val("SELECT count(*) FROM occ.audit_events") == n0


def test_body_change_keeps_a_revision_and_restores(client, world):
    eid = _new(client, world, title="Rev", body="<p>first version of the body text</p>")
    h = world.h("alice")
    client.patch("/api/v2/experiments/%d" % eid, json={"body": "<p>second, quite different body</p>"}, headers=h)
    client.patch("/api/v2/experiments/%d" % eid, json={"body": "<p>third body, also changed a lot</p>"}, headers=h)
    revs = client.get("/api/v2/experiments/%d/revisions" % eid, headers=h).json()
    assert len(revs) == 2
    oldest = revs[-1]
    one = client.get("/api/v2/experiments/%d/revisions/%d" % (eid, oldest["id"]), headers=h).json()
    assert "first version" in one["body"]
    d = client.patch("/api/v2/experiments/%d/revisions/%d" % (eid, oldest["id"]), json={"action": "replace"},
                     headers=h).json()
    assert "first version" in d["body"]
    assert len(client.get("/api/v2/experiments/%d/revisions" % eid, headers=h).json()) == 3


def test_body_is_sanitized(client, world):
    """Stored HTML is sanitized: a script tag does not survive."""
    eid = _new(client, world, title="XSS", body='<p onclick="x()">ok<script>alert(1)</script></p>')
    body = client.get("/api/v2/experiments/%d" % eid, headers=world.h("alice")).json()["body"]
    assert "<script" not in body and "onclick" not in body and "ok" in body


def test_extrafield_update_adds_missing_field_d21(client, world):
    eid = _new(client, world, title="EF", metadata={"extra_fields": {"Probe": {"type": "text", "value": "a"}}})
    h = world.h("alice")
    d = client.patch("/api/v2/experiments/%d" % eid, json={"action": "updatemetadatafield", "Probe": "b",
                                                           "Missing": "c"}, headers=h).json()
    import json
    ef = json.loads(d["metadata"])["extra_fields"]
    assert ef["Probe"]["value"] == "b" and ef["Missing"]["value"] == "c"


def test_template_use_copies_body_tags_steps(client, world):
    h = world.h("alice")
    r = client.post("/api/v2/experiments_templates", json={"title": "Tpl", "body": "<p>tpl body</p>", "tags": ["t1"]},
                    headers=h)
    assert r.status_code == 201, r.text
    tid = int(r.headers["location"].rsplit("/", 1)[-1])
    client.post("/api/v2/experiments_templates/%d/steps" % tid, json={"body": "tpl step"}, headers=h)
    eid = _new(client, world, template=tid)
    d = client.get("/api/v2/experiments/%d" % eid, headers=h).json()
    assert "tpl body" in d["body"] and d["tags"] == "t1" and d["steps"][0]["body"] == "tpl step"
    assert d["created_from_id"] == tid


def test_duplicate_appends_I(client, world):
    eid = _new(client, world, title="Dup")
    r = client.post("/api/v2/experiments/%d" % eid, json={"action": "duplicate"}, headers=world.h("alice"))
    assert r.status_code == 201
    nid = int(r.headers["location"].rsplit("/", 1)[-1])
    assert client.get("/api/v2/experiments/%d" % nid, headers=world.h("alice")).json()["title"] == "Dup I"   # duplicate appends ' I', as 2.x does


def test_logs_carry_no_keys_bodies_or_cookies(client, world):
    """The request log lines name the route, never the key, the body or a cookie."""
    import io
    import logging
    from occ.logs import JsonFormatter
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(JsonFormatter())
    logging.getLogger("occ").addHandler(handler)
    try:
        secret_body = "body-text-that-must-not-be-logged"
        client.cookies.set("occ_session", "cookie-value-that-must-not-be-logged")
        client.post("/api/v2/experiments", json={"title": secret_body}, headers=world.h("alice"))
        client.get("/api/v2/experiments", params={"q": secret_body}, headers=world.h("alice"))
    finally:
        client.cookies.clear()
        logging.getLogger("occ").removeHandler(handler)
    out = buf.getvalue()
    assert '"route":"/api/v2/{kind:kind}"' in out and '"status":201' in out
    assert secret_body not in out and world.keys["alice"] not in out and "cookie-value-that" not in out
