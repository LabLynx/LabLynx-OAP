# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Site configuration (secret values never answered), the usage report, storage units and compounds,
batch, identity-provider writes, team stats, purging a team's records and site assets."""
import json

import pytest

from occ.people import config as CFG


def _id(r):
    assert r.status_code == 201, r.text
    return int(r.headers["location"].rsplit("/", 1)[-1])


def _audit(pool, category):
    with pool.tx() as tx:
        return tx.all("SELECT * FROM occ.audit_events WHERE category = :c ORDER BY id", c=category)


@pytest.fixture(scope="module", autouse=True)
def site_config_restored(pool):
    """The session's database is shared by every test file: put site_config back as it was."""
    with pool.tx() as tx:
        before = tx.all("SELECT name, value, is_secret, value_enc FROM occ.site_config")
    yield
    with pool.tx() as tx:
        tx.run("DELETE FROM occ.site_config")
        for r in before:
            tx.run("INSERT INTO occ.site_config (name, value, is_secret, value_enc) VALUES (:n, :v, :s, :e)",
                   n=r["name"], v=r["value"], s=r["is_secret"], e=r["value_enc"])


@pytest.fixture(scope="module")
def sealing(cfg, tmp_path_factory):
    path = str(tmp_path_factory.mktemp("seal") / "secret.key")
    CFG.make_secret_key(path)
    old = cfg.secret_key_file
    cfg.secret_key_file = path
    yield path
    cfg.secret_key_file = old


# ------------------------------------------------------------------------------------- config
def test_config_read_change_and_secrets(client, world, pool, cfg, sealing):
    assert client.get("/api/v2/config", headers=world.h("admin")).status_code == 403
    c = client.get("/api/v2/config", headers=world.h("sys")).json()
    assert c["smtp_port"] == "25" and c["max_revisions"] == "10" and c["smtp_password"] == ""
    assert c["smtp_password_is_set"] is False
    r = client.patch("/api/v2/config", json={"smtp_port": 2525, "max_revisions": "11"}, headers=world.h("sys"))
    assert r.status_code == 200 and r.json()["smtp_port"] == "2525" and r.json()["max_revisions"] == "11"
    r = client.patch("/api/v2/config", json={"no_such_setting": 1, "other_bad": 2}, headers=world.h("sys"))
    assert r.status_code == 400 and "no_such_setting" in r.json()["message"] and "other_bad" in r.json()["message"]
    # atomic: one unknown name changes nothing
    client.patch("/api/v2/config", json={"smtp_port": "26", "nope": 1}, headers=world.h("sys"))
    assert client.get("/api/v2/config", headers=world.h("sys")).json()["smtp_port"] == "2525"
    # a secret is sealed, never answered, never audited in clear
    r = client.patch("/api/v2/config", json={"smtp_password": "hunter2-very-secret"}, headers=world.h("sys"))
    assert r.status_code == 200 and r.json()["smtp_password"] == "" and r.json()["smtp_password_is_set"] is True
    assert "hunter2" not in r.text
    with pool.tx() as tx:
        row = tx.one("SELECT value, is_secret, value_enc FROM occ.site_config WHERE name = 'smtp_password'")
        assert row["value"] is None and row["is_secret"] and b"hunter2" not in bytes(row["value_enc"])
        assert CFG.secret(tx, cfg, "smtp_password") == "hunter2-very-secret"
        assert not tx.val("SELECT count(*) FROM occ.audit_events WHERE coalesce(new_value,'') LIKE '%hunter2%' "
                          "OR coalesce(detail::text,'') LIKE '%hunter2%'")
    r = client.patch("/api/v2/config", json={"smtp_password": ""}, headers=world.h("sys"))
    assert r.json()["smtp_password_is_set"] is False
    assert client.patch("/api/v2/config", json={"schema": "99"}, headers=world.h("sys")).status_code == 400
    assert client.patch("/api/v2/config", json={"smtp_port": "25", "max_revisions": "10"},
                        headers=world.h("sys")).status_code == 200
    assert [a for a in _audit(pool, "config.update") if a["target"] == "smtp_port"]


def test_secret_needs_the_sealing_key(client, world, cfg):
    old = cfg.secret_key_file
    cfg.secret_key_file = "/nonexistent/secret.key"
    try:
        assert client.patch("/api/v2/config", json={"ts_password": "x" * 20},
                            headers=world.h("sys")).status_code == 503
    finally:
        cfg.secret_key_file = old


# ------------------------------------------------------------------------------------- report
def test_report(client, world):
    r = client.get("/api/v2/reports", headers=world.h("sys"))
    assert r.json() == {"query_parameters": {"format": ["csv", "json (not implemented)"],
                                             "scope": ["instance", "team"]}}
    assert client.get("/api/v2/reports", headers=world.h("alice")).status_code == 403
    r = client.get("/api/v2/reports", params={"format": "csv"}, headers=world.h("sys"))
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "userid,firstname" in r.text and "alice@example.com" in r.text
    r = client.get("/api/v2/reports", params={"format": "csv", "scope": "team"}, headers=world.h("admin"))
    assert r.status_code == 200 and "bea@example.com" not in r.text


# ---------------------------------------------------------------------------- storage, compounds
def test_storage_units(client, world, pool):
    h = world.h("alice")
    top = _id(client.post("/api/v2/storage_units", json={"name": "Cabinet Z"}, headers=h))
    child = _id(client.post("/api/v2/storage_units", json={"name": "Shelf", "parent_id": top}, headers=h))
    units = {u["id"]: u for u in client.get("/api/v2/storage_units", headers=h).json()}
    assert units[child]["full_path"] == "Cabinet Z > Shelf" and units[top]["children_count"] == 1
    r = client.delete("/api/v2/storage_units/%d" % top, headers=h)
    assert r.status_code == 400 and r.json()["message"] == "Cannot delete a storage unit with children!"
    assert client.patch("/api/v2/storage_units/%d" % top, json={"parent_id": child}, headers=h).status_code == 400
    r = client.patch("/api/v2/storage_units/%d" % child, json={"name": "Shelf 2"}, headers=h)
    assert r.status_code == 200 and r.json()["full_path"] == "Cabinet Z > Shelf 2"
    # with the edit-rights setting on, a plain member is refused
    client.patch("/api/v2/config", json={"inventory_require_edit_rights": "1"}, headers=world.h("sys"))
    try:
        assert client.post("/api/v2/storage_units", json={"name": "No"}, headers=h).status_code == 403
    finally:
        client.patch("/api/v2/config", json={"inventory_require_edit_rights": "0"}, headers=world.h("sys"))
    assert client.delete("/api/v2/storage_units/%d" % child, headers=h).status_code == 204
    assert client.delete("/api/v2/storage_units/%d" % top, headers=h).status_code == 204
    assert client.post("/api/v2/storage_units", json={"name": "x"}, headers=world.h("alice_ro")).status_code == 403
    assert _audit(pool, "storage.create") and _audit(pool, "storage.delete")


def test_compounds(client, world, pool):
    h = world.h("alice")
    cid = _id(client.post("/api/v2/compounds", json={"name": "Ethanol", "cas_number": "64-17-5",
                                                     "molecular_weight": 46.07, "ec_number": "200-578-6",
                                                     "is_flammable": 1}, headers=h))
    c = client.get("/api/v2/compounds/%d" % cid, headers=h).json()
    assert c["name"] == "Ethanol" and c["ec_number"] == "200-578-6" and c["is_flammable"] == 1
    assert c["molecular_weight"] == 46.07
    r = client.patch("/api/v2/compounds/%d" % cid, json={"name": "Ethyl alcohol"}, headers=h)
    assert r.status_code == 200 and r.json()["name"] == "Ethyl alcohol"
    assert client.get("/api/v2/compounds/%d" % cid, headers=world.h("bea")).status_code == 404
    assert client.patch("/api/v2/compounds/%d" % cid, json={"Bad Name": 1}, headers=h).status_code == 400
    assert client.post("/api/v2/compounds", json={"iupac_name": "only"}, headers=h).status_code == 400
    assert client.delete("/api/v2/compounds/%d" % cid, headers=h).status_code == 204
    assert client.get("/api/v2/compounds/%d" % cid, headers=h).json()["state"] == 3
    assert _audit(pool, "compound.update")


# -------------------------------------------------------------------------------------- batch
def test_batch_is_atomic_audited_and_admin_only(client, world, pool):
    ha = world.h("admin")
    ids = [_id(client.post("/api/v2/experiments", json={"title": "Batch %d" % i}, headers=world.h("alice")))
           for i in range(2)]
    for i in ids:
        assert client.post("/api/v2/experiments/%d/tags" % i, json={"tag": "zz-batch-unit"},
                           headers=world.h("alice")).status_code == 201
    tag_id = client.get("/api/v2/experiments/%d/tags" % ids[0], headers=ha).json()[0]["tag_id"]
    assert client.post("/api/v2/batch", json={"action": "forcelock", "tags": [tag_id]},
                       headers=world.h("alice")).status_code == 403
    before = len(_audit(pool, "record.lock"))
    r = client.post("/api/v2/batch", json={"action": "forcelock", "tags": [tag_id]}, headers=ha)
    assert r.status_code == 201 and r.headers["location"].endswith("/batch/2")
    assert [client.get("/api/v2/experiments/%d" % i, headers=ha).json()["locked"] for i in ids] == [1, 1]
    assert len(_audit(pool, "record.lock")) == before + 2
    r = client.post("/api/v2/batch", json={"action": "forcelock", "tags": [tag_id]}, headers=ha)
    assert r.headers["location"].endswith("/batch/0")          # nothing more to change
    client.post("/api/v2/batch", json={"action": "forceunlock", "tags": [tag_id]}, headers=ha)
    client.post("/api/v2/batch", json={"action": "archive", "tags": [tag_id]}, headers=ha)
    assert [client.get("/api/v2/experiments/%d" % i, headers=ha).json()["state"] for i in ids] == [2, 2]
    client.post("/api/v2/batch", json={"action": "unarchive", "tags": [tag_id]}, headers=ha)
    assert [client.get("/api/v2/experiments/%d" % i, headers=ha).json()["state"] for i in ids] == [1, 1]
    # atomic: a bad category target fails the whole batch
    r = client.post("/api/v2/batch", json={"action": "updatecategory", "target": 999999, "tags": [tag_id]}, headers=ha)
    assert r.status_code in (400, 404)
    assert client.post("/api/v2/batch", json={"action": "nope", "tags": [tag_id]}, headers=ha).status_code == 400
    assert client.post("/api/v2/batch", json={"action": "archive"}, headers=ha).status_code == 400


# ---------------------------------------------------------------------------- identity providers
def test_identity_provider_writes(client, world, pool):
    h = world.h("sys")
    body = {"name": "ZZ test IdP", "entityid": "https://idp.example.invalid/meta", "enabled": 0,
            "certs": ["MIIBzz=="], "endpoints": [{"location": "https://idp.example.invalid/sso", "binding": 0}]}
    assert client.post("/api/v2/idps", json=body, headers=world.h("admin")).status_code == 403
    iid = _id(client.post("/api/v2/idps", json=body, headers=h))
    assert client.post("/api/v2/idps", json=body, headers=h).status_code == 400          # same entityid
    r = client.patch("/api/v2/idps/%d" % iid, json={"name": "ZZ renamed"}, headers=h)
    assert r.status_code == 200 and r.json()["name"] == "ZZ renamed" and r.json()["enabled"] == 0
    assert client.patch("/api/v2/idps/%d" % iid, json={"bogus": 1}, headers=h).status_code == 400
    # the only enabled one cannot be disabled or removed
    r = client.patch("/api/v2/idps/%d" % iid, json={"enabled": 1}, headers=h)
    assert r.json()["enabled"] == 1
    with pool.tx(readonly=True) as tx:
        only = tx.val("SELECT count(*) FROM occ.idps WHERE enabled") == 1
    if only:
        assert client.delete("/api/v2/idps/%d" % iid, headers=h).status_code == 400
        assert client.patch("/api/v2/idps/%d" % iid, json={"enabled": 0}, headers=h).status_code == 400
        with pool.tx() as tx:
            tx.run("UPDATE occ.idps SET enabled = false WHERE id = :i", i=iid)
    assert client.delete("/api/v2/idps/%d" % iid, headers=h).status_code == 204
    sid = _id(client.post("/api/v2/idps_sources", json={"url": "https://md.example.invalid/x.xml"}, headers=h))
    r = client.patch("/api/v2/idps_sources/%d" % sid, json={"auto_refresh": 1}, headers=h)
    assert r.status_code == 200 and r.json()["auto_refresh"] == 1
    # refresh is built (test_storage_idp.py); this source's .invalid address cannot be reached: 502
    assert client.patch("/api/v2/idps_sources/%d" % sid, json={"action": "refresh"}, headers=h).status_code == 502
    assert client.post("/api/v2/idps_sources", json={"url": "http://plain"}, headers=h).status_code == 400
    assert client.delete("/api/v2/idps_sources/%d" % sid, headers=h).status_code == 204


# ---------------------------------------------------------------------------------- stats, purge
def test_team_stats(client, world):
    A = world.teams["A"]
    s = client.get("/api/v2/occ/teams/%d/stats" % A, headers=world.h("admin")).json()
    for f in ("experiments", "items", "templates", "resource_templates", "members", "admins", "uploads_bytes",
              "by_category", "by_status"):
        assert f in s
    assert s["members"] >= 3 and s["admins"] >= 1
    assert client.get("/api/v2/occ/teams/%d/stats" % A, headers=world.h("alice")).status_code == 403
    assert client.get("/api/v2/occ/teams/%d/stats" % A, headers=world.h("sys")).status_code == 200


def test_purge_refusals_and_purge(client, world, pool):
    h = world.h("sys")
    tid = _id(client.post("/api/v2/teams", json={"name": "Purge me"}, headers=h))
    body = {"kinds": ["experiments"], "confirm": "Purge me"}
    r = client.post("/api/v2/occ/teams/%d/purge" % tid, json=body, headers=h)
    assert r.status_code == 403                              # allow_purge is off
    client.patch("/api/v2/config", json={"allow_purge": "1"}, headers=h)
    try:
        assert client.post("/api/v2/occ/teams/%d/purge" % tid, json=body,
                           headers=world.h("admin")).status_code == 403
        assert client.post("/api/v2/occ/teams/%d/purge" % tid, json={"kinds": ["experiments"], "confirm": "no"},
                           headers=h).status_code == 400
        with pool.tx() as tx:
            u = world.users["sys"]
            for i, signed in ((1, 0), (2, 1)):
                tx.run("INSERT INTO occ.records (kind_id, id, elabid, team_id, owner_id, created_by, title, "
                       "signature_count) VALUES (1, 900000 + :i, :e, :t, :u, :u, 'p', :s)",
                       i=i, e="20261028-%040d" % i, t=tid, u=u, s=signed)
        r = client.post("/api/v2/occ/teams/%d/purge" % tid, json=body, headers=h)
        assert r.status_code == 400 and "signed" in r.json()["message"]
        with pool.tx() as tx:
            tx.run("UPDATE occ.records SET signature_count = 0 WHERE team_id = :t", t=tid)
        r = client.post("/api/v2/occ/teams/%d/purge" % tid, json=body, headers=h)
        assert r.status_code == 200 and r.json() == {"removed": {"experiments": 2}}
        assert [a for a in _audit(pool, "purge") if a["team_id"] == tid]
    finally:
        client.patch("/api/v2/config", json={"allow_purge": "0"}, headers=h)


# ---------------------------------------------------------------------------------- site assets
PNG = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
       b"\x00\x00\x00\rIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82")


def test_site_assets(client, world):
    assert client.get("/api/v2/occ/site/assets/logo").status_code == 404
    files = {"file": ("logo.png", PNG, "image/png")}
    assert client.put("/api/v2/occ/site/assets/logo", files=files, headers=world.h("admin")).status_code == 403
    assert client.put("/api/v2/occ/site/assets/nope", files=files, headers=world.h("sys")).status_code == 404
    assert client.put("/api/v2/occ/site/assets/logo", files={"file": ("x.txt", b"hi", "text/plain")},
                      headers=world.h("sys")).status_code == 400
    r = client.put("/api/v2/occ/site/assets/logo", files=files, headers=world.h("sys"))
    assert r.status_code == 200, r.text
    g = client.get("/api/v2/occ/site/assets/logo")              # public, no key
    assert g.status_code == 200 and g.content == PNG and g.headers["content-type"] == "image/png"
    assert g.headers["x-content-type-options"] == "nosniff"
    assert json.loads(r.text)["size"] == len(PNG)
