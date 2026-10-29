# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Signature keys, signing and trusted timestamps (making a key; the sign and timestamp actions on a record).

What the OCC stores is verified OUTSIDE the OCC: with the stock minisign tool and 'openssl ts -verify'
when they are installed (OCC_MINISIGN names the tool if it is not on PATH), and always with an
independent reading of each published format. The timestamping authority is a local one this test
runs itself (tests/tsa_local.py); no public authority is ever contacted.
"""
import base64
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import zipfile

import pytest

from occ.signing import minisign, tsa

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tsa_local import LocalTSA  # noqa: E402

PASS = "a long enough passphrase"
MINISIGN = os.environ.get("OCC_MINISIGN") or shutil.which("minisign")
OPENSSL = shutil.which("openssl")


def _new(client, world, who="alice", kind="experiments", title="Signed"):
    r = client.post("/api/v2/%s" % kind, json={"title": title, "body": "<p>to sign</p>"}, headers=world.h(who))
    assert r.status_code == 201, r.text
    return int(r.headers["location"].rsplit("/", 1)[-1])


def _zip(raw):
    z = zipfile.ZipFile(io.BytesIO(raw))
    return {n: z.read(n) for n in z.namelist()}


def _independent_verify(data, sig_text, pub_text):
    """minisign's check from its published format, written here apart from occ.signing."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    pk = base64.b64decode(pub_text.strip().splitlines()[1])
    lines = sig_text.strip().splitlines()
    s = base64.b64decode(lines[1])
    if pk[:2] != b"Ed" or s[:2] != b"ED" or s[2:10] != pk[2:10]:
        return False
    key = Ed25519PublicKey.from_public_bytes(pk[10:42])
    try:
        key.verify(s[10:74], hashlib.blake2b(data, digest_size=64).digest())
        key.verify(base64.b64decode(lines[3]), s[10:74] + lines[2][len("trusted comment: "):].encode())
        return True
    except Exception:                                                    # noqa: BLE001
        return False


def _tool_verifies(tmp_path, data, sig_text, pub_text):
    (tmp_path / "data.json").write_bytes(data)
    (tmp_path / "data.json.minisig").write_text(sig_text)
    (tmp_path / "key.pub").write_text(pub_text)
    r = subprocess.run([MINISIGN, "-V", "-p", str(tmp_path / "key.pub"), "-m", str(tmp_path / "data.json")],
                       capture_output=True, text=True, timeout=30)
    return r.returncode == 0


# ------------------------------------------------------------------------------ the formats
def test_minisign_formats_round_trip_and_refuse_a_wrong_passphrase():
    kp = minisign.generate()
    sec = kp.secret_file(PASS)
    assert sec.startswith("untrusted comment: minisign encrypted secret key\n")
    again = minisign.open_secret(sec, PASS)
    assert (again.key_id, again.seed, again.public) == (kp.key_id, kp.seed, kp.public)
    with pytest.raises(minisign.BadPassphrase):
        minisign.open_secret(sec, "not the passphrase at all")
    with pytest.raises(minisign.BadPassphrase):
        kp.secret_file("too short")
    sig = kp.sign(b"data", '{"meaning":"Review"}')
    assert minisign.verify(b"data", sig, kp.public_file())
    assert _independent_verify(b"data", sig, kp.public_file())
    assert not minisign.verify(b"datA", sig, kp.public_file())
    assert not minisign.verify(b"data", sig.replace("Review", "Approval"), kp.public_file())   # trusted comment


@pytest.mark.skipif(not MINISIGN, reason="the minisign tool is not installed")
def test_the_stock_minisign_tool_reads_what_the_occ_writes_and_the_reverse(tmp_path):
    kp = minisign.generate()
    assert _tool_verifies(tmp_path, b"payload\n", kp.sign(b"payload\n", "tc"), kp.public_file())
    assert not _tool_verifies(tmp_path, b"payload!\n", kp.sign(b"payload\n", "tc"), kp.public_file())
    (tmp_path / "k.key").write_text(kp.secret_file(PASS))
    (tmp_path / "o.txt").write_bytes(b"signed by the tool\n")
    r = subprocess.run([MINISIGN, "-S", "-s", str(tmp_path / "k.key"), "-m", str(tmp_path / "o.txt"), "-t", "x"],
                       input=PASS + "\n", capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert minisign.verify(b"signed by the tool\n", (tmp_path / "o.txt.minisig").read_text(), kp.public_file())


# ------------------------------------------------------------------------------ making a signature key
def test_making_a_key_and_replacing_it(client, world):
    h = world.h("alice")
    assert client.post("/api/v2/users/me/sig_keys", json={"action": "create", "passphrase": "short"},
                       headers=h).status_code == 400
    assert client.post("/api/v2/users/me/sig_keys", json={"action": "create", "passphrase": PASS},
                       headers=world.h("alice_ro")).status_code == 403
    r = client.post("/api/v2/users/me/sig_keys", json={"action": "create", "passphrase": PASS}, headers=h)
    assert r.status_code == 201 and r.content == b""
    keys = client.get("/api/v2/users/me/sig_keys", headers=h).json()
    assert [k["state"] for k in keys] == [1]
    assert keys[0]["pubkey"].startswith("untrusted comment: minisign public key ")
    assert "privkey" not in json.dumps(keys)


def test_signing_stores_a_verifiable_archive_and_an_immutable_comment(client, world, pool, tmp_path):
    h = world.h("alice")
    eid = _new(client, world)
    assert client.patch("/api/v2/experiments/%d" % eid, json={"action": "sign", "passphrase": PASS},
                        headers=h).status_code == 400                                    # no meaning: 400, not 2.x's 500
    assert client.patch("/api/v2/experiments/%d" % eid, json={"action": "sign", "passphrase": PASS, "meaning": 20},
                        headers=world.h("bob")).status_code == 400                       # bob has no key
    assert client.patch("/api/v2/experiments/%d" % eid,
                        json={"action": "sign", "passphrase": "wrong passphrase here", "meaning": 20},
                        headers=h).status_code == 400
    assert client.patch("/api/v2/experiments/%d" % eid, json={"action": "sign", "passphrase": PASS, "meaning": 20},
                        headers=world.h("bea")).status_code in (403, 404)                # cannot read it
    r = client.patch("/api/v2/experiments/%d" % eid, json={"action": "sign", "passphrase": PASS, "meaning": 20},
                     headers=h)
    assert r.status_code == 200, r.text
    rec = r.json()
    assert rec["signature_count"] == 1 and int(rec["locked"]) == 0                     # signing does not lock
    arch = [u for u in rec["uploads"] if u["real_name"] == "signature-archive.zip"]
    assert len(arch) == 1 and int(arch[0]["immutable"]) == 1
    cms = [c for c in rec["comments"] if c["comment"].startswith("Signed by")]
    assert [c["comment"] for c in cms] == ["Signed by Alice Test (Authorship)"] and int(cms[0]["immutable"]) == 1
    raw = client.get("/api/v2/experiments/%d/uploads/%d" % (eid, arch[0]["id"]), params={"format": "binary"},
                     headers=h).content
    files = _zip(raw)
    assert set(files) == {"data.json", "data.json.minisig", "key.pub", "verify.sh"}
    data, sig, pub = files["data.json"], files["data.json.minisig"].decode(), files["key.pub"].decode()
    assert json.loads(data)[0]["id"] == eid
    assert pub.strip() == client.get("/api/v2/users/me/sig_keys", headers=h).json()[0]["pubkey"].strip()
    tc = json.loads(minisign.trusted_comment(sig))
    assert tc["firstname"] == "Alice" and tc["lastname"] == "Test" and tc["email"] == "alice@example.com"
    assert tc["meaning"] == "Authorship" and tc["created_at"][-6] in "+-"
    assert _independent_verify(data, sig, pub)
    assert not _independent_verify(data[:-1] + b"X", sig, pub)
    if MINISIGN:
        assert _tool_verifies(tmp_path, data, sig, pub)
        assert not _tool_verifies(tmp_path, data + b" ", sig, pub)
    # the archive and the comment are immutable
    assert client.delete("/api/v2/experiments/%d/uploads/%d" % (eid, arch[0]["id"]), headers=h).status_code == 403
    assert client.delete("/api/v2/experiments/%d/comments/%d" % (eid, cms[0]["id"]), headers=h).status_code == 403
    # the passphrase reaches no audit row
    with pool.tx() as tx:
        rows = tx.all("SELECT category, new_value, detail::text AS d FROM occ.audit_events WHERE record_id = :r "
                      "AND kind_id = 1", r=eid)
        assert any(r["category"] == "record.sign" and r["new_value"] == "sign (Authorship)" for r in rows)
        assert all(PASS not in (r["new_value"] or "") + (r["d"] or "") for r in rows)
        allrows = tx.val("SELECT string_agg(coalesce(new_value,'') || coalesce(detail::text,''), ' ') "
                         "FROM occ.audit_events")
        assert PASS not in allrows

    # a replaced key: the old one goes to state 2 and its signature still verifies
    assert client.post("/api/v2/users/me/sig_keys", json={"action": "create", "passphrase": PASS + "2"},
                       headers=h).status_code == 201
    keys = client.get("/api/v2/users/me/sig_keys", headers=h).json()
    assert sorted(k["state"] for k in keys) == [1, 2]
    assert _independent_verify(data, sig, pub)
    r2 = client.patch("/api/v2/experiments/%d" % eid, json={"action": "sign", "passphrase": PASS + "2", "meaning": 40},
                      headers=h)
    assert r2.status_code == 200 and r2.json()["signature_count"] == 2


def test_signing_marks_an_open_sign_request_done(client, world, pool):
    eid = _new(client, world, who="admin", title="Please sign")
    # alice can read team A's records; the admin asks her to sign
    assert client.post("/api/v2/experiments/%d/request_actions" % eid,
                       json={"target_userid": world.users["alice"], "target_action": 40},
                       headers=world.h("admin")).status_code in (200, 201)
    if not client.get("/api/v2/users/me/sig_keys", headers=world.h("alice")).json():
        client.post("/api/v2/users/me/sig_keys", json={"action": "create", "passphrase": PASS},
                    headers=world.h("alice"))
    keyp = PASS if len(client.get("/api/v2/users/me/sig_keys", headers=world.h("alice")).json()) == 1 else PASS + "2"
    r = client.patch("/api/v2/experiments/%d" % eid, json={"action": "sign", "passphrase": keyp, "meaning": 10},
                     headers=world.h("alice"))
    assert r.status_code == 200, r.text
    with pool.tx() as tx:
        rid = tx.val("SELECT rid FROM occ.records WHERE kind_id = 1 AND id = :i", i=eid)
        assert tx.val("SELECT count(*) FROM occ.request_actions WHERE rid = :r AND state = 1 AND action = 40",
                      r=rid) == 0


# ------------------------------------------------------------------------------ timestamps
def _set(pool, **values):
    with pool.tx() as tx:
        for k, v in values.items():
            tx.run("DELETE FROM occ.site_config WHERE name = :n", n=k)
            if v is not None:
                tx.run("INSERT INTO occ.site_config (name, value) VALUES (:n, :v)", n=k, v=v)


def test_timestamp_without_an_authority_is_refused(client, world, pool):
    _set(pool, ts_url=None)
    eid = _new(client, world, title="No TSA")
    r = client.patch("/api/v2/experiments/%d" % eid, json={"action": "timestamp"}, headers=world.h("alice"))
    assert r.status_code == 400 and "timestamping authority" in r.json()["message"]


def test_timestamp_from_a_local_authority_verifies_with_openssl(client, world, pool, tmp_path):
    eid = _new(client, world, title="Timestamped")
    with LocalTSA(str(tmp_path / "tsa")) as t:
        _set(pool, ts_url=t.url, ts_cert=t.ca_pem, ts_authority="custom")
        assert client.patch("/api/v2/experiments/%d" % eid, json={"action": "timestamp"},
                            headers=world.h("alice_ro")).status_code == 403
        assert client.patch("/api/v2/experiments/%d" % eid, json={"action": "timestamp"},
                            headers=world.h("bob")).status_code == 403                  # reads, cannot write
        r = client.patch("/api/v2/experiments/%d" % eid, json={"action": "timestamp"}, headers=world.h("alice"))
        assert r.status_code == 200, r.text
        assert t.served == 1
    rec = r.json()
    assert int(rec["timestamped"]) == 1
    arch = [u for u in rec["uploads"] if u["real_name"].startswith("timestamp-archive-")]
    assert len(arch) == 1 and int(arch[0]["immutable"]) == 1
    files = _zip(client.get("/api/v2/experiments/%d/uploads/%d" % (eid, arch[0]["id"]), params={"format": "binary"},
                            headers=world.h("alice")).content)
    pdf_name = next(n for n in files if n.endswith(".pdf"))
    tok_name = next(n for n in files if n.endswith(".asn1"))
    assert files[pdf_name].startswith(b"%PDF-")
    st = tsa.check(files[tok_name], hashlib.sha256(files[pdf_name]).digest(), ca_pem=t.ca_pem)
    assert st.serial
    with pool.tx() as tx:
        row = tx.one("SELECT t.serial, t.data_sha256 FROM occ.timestamps t JOIN occ.records r ON r.rid = t.rid "
                     "WHERE r.kind_id = 1 AND r.id = :i", i=eid)
        assert bytes(row["data_sha256"]) == hashlib.sha256(files[pdf_name]).digest()
    if OPENSSL:
        (tmp_path / "x.pdf").write_bytes(files[pdf_name])
        (tmp_path / "x.tsr").write_bytes(files[tok_name])
        ok = subprocess.run([OPENSSL, "ts", "-verify", "-in", str(tmp_path / "x.tsr"), "-data", str(tmp_path / "x.pdf"),
                             "-CAfile", t.ca_pem_path], capture_output=True, text=True, timeout=30)
        assert ok.returncode == 0 and "Verification: OK" in ok.stdout, ok.stderr
        (tmp_path / "x.pdf").write_bytes(files[pdf_name] + b"\n")
        bad = subprocess.run([OPENSSL, "ts", "-verify", "-in", str(tmp_path / "x.tsr"), "-data",
                              str(tmp_path / "x.pdf"), "-CAfile", t.ca_pem_path], capture_output=True, text=True,
                             timeout=30)
        assert bad.returncode != 0
    _set(pool, ts_url=None, ts_cert=None)


def test_a_refusing_authority_changes_nothing(client, world, pool, tmp_path):
    eid = _new(client, world, title="Refused")
    with LocalTSA(str(tmp_path / "tsa"), refuse=True) as t:
        _set(pool, ts_url=t.url)
        r = client.patch("/api/v2/experiments/%d" % eid, json={"action": "timestamp"}, headers=world.h("alice"))
    assert r.status_code == 502 and "refused" in r.json()["message"]
    rec = client.get("/api/v2/experiments/%d" % eid, headers=world.h("alice")).json()
    assert int(rec["timestamped"]) == 0 and rec["uploads"] == []
    _set(pool, ts_url=None)


def test_the_audit_checkpoint_carries_an_rfc3161_token(cfg, pool, tmp_path):
    from occ.worker import handlers

    class Ctx:
        pass
    ctx = Ctx()
    ctx.pool, ctx.settings, ctx.store = pool, cfg, None

    class Log:
        def error(self, *a, **k):
            raise AssertionError("the chain must verify")
    ctx.log = Log()
    with LocalTSA(str(tmp_path / "tsa")) as t:
        _set(pool, ts_url=t.url, ts_cert=t.ca_pem)
        with pool.tx() as tx:                      # one more audit row, so the head is new
            tx.val("SELECT occ.audit_append(CAST(:p AS jsonb))",
                   p=json.dumps({"actor_kind": "system", "category": "config.update", "target": "test"}))
        res = handlers.audit_verify(ctx, {"id": 0})
    assert res["ok"] and res["timestamped"] and res["checkpoint_id"]
    with pool.tx() as tx:
        cp = tx.one("SELECT upto_hash, tsa_token, verify_note FROM occ.audit_checkpoints WHERE id = :i",
                    i=res["checkpoint_id"])
    assert "timestamped" in cp["verify_note"]
    st = tsa.check(bytes(cp["tsa_token"]), bytes(cp["upto_hash"]), ca_pem=t.ca_pem)
    assert st.gen_time
    if OPENSSL:
        (tmp_path / "cp.tsr").write_bytes(bytes(cp["tsa_token"]))
        ok = subprocess.run([OPENSSL, "ts", "-verify", "-in", str(tmp_path / "cp.tsr"), "-digest",
                             bytes(cp["upto_hash"]).hex(), "-CAfile", t.ca_pem_path], capture_output=True, text=True,
                            timeout=30)
        assert ok.returncode == 0, ok.stderr
    _set(pool, ts_url=None, ts_cert=None)
    # without an authority the checkpoint is still written, and says why it has no token
    with pool.tx() as tx:
        tx.val("SELECT occ.audit_append(CAST(:p AS jsonb))",
               p=json.dumps({"actor_kind": "system", "category": "config.update", "target": "test2"}))
    res = handlers.audit_verify(ctx, {"id": 0})
    assert res["ok"] and not res["timestamped"]
    with pool.tx() as tx:
        note = tx.val("SELECT verify_note FROM occ.audit_checkpoints WHERE id = :i", i=res["checkpoint_id"])
    assert "no timestamp authority configured" in note
