# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The file store on disk and on S3, the weekly orphaned-file sweep, the
identity-provider metadata refresh (action=refresh and the idp-refresh job) and the enabled flag
on create.

The S3 store runs against a local stand-in (tests/s3_local.py: moto's server, Apache-2.0) when
OCC_TEST_MOTO names it; no cloud account is ever used."""
import hashlib
import http.server
import io
import os
import sys
import threading
import time
import zipfile

import pytest

from occ import settings as settings_mod
from occ.files import s3 as s3mod
from occ.files import store as fstore
from occ.files import sweep
from occ.people import idp_refresh

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from s3_local import LocalS3  # noqa: E402

MOTO = os.environ.get("OCC_TEST_MOTO")


@pytest.fixture(scope="module")
def s3server():
    if not MOTO:
        pytest.skip("OCC_TEST_MOTO does not name the S3 stand-in")
    with LocalS3(MOTO) as s:
        yield s


def _s3store(s3server, tmp_path, bucket="occ-test", prefix="t/"):
    st = s3mod.S3Store(s3server.endpoint, bucket, "us-east-1", s3server.access_key, s3server.secret_key,
                       prefix=prefix, spool_dir=str(tmp_path))
    st.ensure_bucket()
    return st


def _exercise(st):
    """The store contract every backend meets."""
    data = os.urandom(300000) + b"end"
    sha, size = st.put(iter([data[:100000], data[100000:]]))
    assert sha == hashlib.sha256(data).digest() and size == len(data)
    assert st.exists(sha)
    with st.open(sha) as fh:
        assert fh.read() == data
    assert st.rehash(sha) == sha
    assert st.put_bytes(data) == (sha, size)                     # same bytes, one blob
    assert sha in {s for s, _age in st.blobs()}
    with pytest.raises(fstore.TooLarge):
        st.put([b"x" * 10], max_size=5)
    st.delete(sha)
    assert not st.exists(sha)
    with pytest.raises(FileNotFoundError):
        st.open(sha)


def test_the_disk_store_meets_the_contract(tmp_path):
    _exercise(fstore.DiskStore(str(tmp_path / "files")))


def test_the_s3_store_meets_the_contract(s3server, tmp_path):
    _exercise(_s3store(s3server, tmp_path))


def test_s3_refuses_a_wrong_secret(s3server, tmp_path):
    good = _s3store(s3server, tmp_path, bucket="occ-auth")
    bad = s3mod.S3Store(s3server.endpoint, "occ-auth", "us-east-1", s3server.access_key, "wrong", spool_dir=str(tmp_path))
    sha, _n = good.put_bytes(b"signed request")
    assert good.exists(sha)
    # moto accepts any key pair unless told otherwise; what this proves is that the signature is computed
    # from the secret: the two stores send different Authorization headers for the same request.
    h1 = good._sign("GET", "/occ-auth/x", {}, {}, s3mod.EMPTY_SHA)["Authorization"]
    h2 = bad._sign("GET", "/occ-auth/x", {}, {}, s3mod.EMPTY_SHA)["Authorization"]
    assert h1.split("Signature=")[1] != h2.split("Signature=")[1]
    assert s3server.secret_key not in h1


def test_uploads_through_the_api_on_s3(s3server, cfg, world, tmp_path):
    """The stored SHA-256 equals the hash of the bytes read back through the API, on S3."""
    from fastapi.testclient import TestClient
    from occ.main import create_app
    cred = tmp_path / "s3.credentials"
    cred.write_text("%s\n%s\n" % (s3server.access_key, s3server.secret_key))
    os.chmod(cred, 0o600)
    s3cfg = settings_mod.Settings(**{**cfg.__dict__, "extra": dict(cfg.extra, OCC_FILES_BACKEND="s3",
                                                                    OCC_S3_ENDPOINT=s3server.endpoint,
                                                                    OCC_S3_BUCKET="occ-api", OCC_S3_REGION="us-east-1",
                                                                    OCC_S3_CREDENTIALS_FILE=str(cred))})
    st = fstore.for_settings(s3cfg)
    assert st.backend == "s3"
    st.ensure_bucket()
    with TestClient(create_app(s3cfg)) as client:
        h = world.h("alice")
        r = client.post("/api/v2/experiments", json={"title": "On S3"}, headers=h)
        eid = int(r.headers["location"].rsplit("/", 1)[-1])
        data = b"bytes kept in object storage\n" * 1000
        r = client.post("/api/v2/experiments/%d/uploads" % eid, files={"file": ("s3.txt", data, "text/plain")},
                        headers=h)
        assert r.status_code == 201, r.text
        uid = int(r.headers["location"].rsplit("/", 1)[-1])
        meta = client.get("/api/v2/experiments/%d/uploads/%d" % (eid, uid), headers=h).json()
        back = client.get("/api/v2/experiments/%d/uploads/%d" % (eid, uid), params={"format": "binary"}, headers=h)
        assert back.status_code == 200 and back.content == data
        assert meta["hash"] == hashlib.sha256(back.content).hexdigest()
        assert st.exists(hashlib.sha256(data).digest())
        assert not os.path.exists(os.path.join(cfg.files_root, fstore.location(hashlib.sha256(data).digest())))
        z = client.get("/api/v2/experiments/%d" % eid, params={"format": "zip"}, headers=h)
        files = zipfile.ZipFile(io.BytesIO(z.content))
        assert any(files.read(n) == data for n in files.namelist() if n.endswith("s3.txt"))


# ------------------------------------------------------------------------------ the sweep
def test_the_sweep_removes_old_unregistered_blobs_only(cfg, pool, tmp_path):
    st = fstore.DiskStore(str(tmp_path / "sw"))
    kept, _ = st.put_bytes(b"registered")
    orphan, _ = st.put_bytes(b"left by a failed transaction")
    young, _ = st.put_bytes(b"an upload about to register")
    with pool.tx() as tx:
        fstore.register(tx, st, kept, 10)
    old = time.time() - 3 * 86400
    for sha in (kept, orphan):
        os.utime(os.path.join(st.root, fstore.location(sha)), (old, old))
    os.makedirs(os.path.join(st.root, "tmp"), exist_ok=True)
    stale = os.path.join(st.root, "tmp", "half-written")
    open(stale, "wb").write(b"x")
    os.utime(stale, (old, old))
    dry = sweep.sweep(pool, cfg, store=st, dry_run=True)
    assert dry["removed"] == 1 and st.exists(orphan) and os.path.exists(stale)
    out = sweep.sweep(pool, cfg, store=st)
    assert out == {"backend": "disk", "blobs_seen": 3, "removed": 1, "unregistered_but_young": 1,
                   "temporaries_removed": 1, "dry_run": False}
    assert st.exists(kept) and st.exists(young) and not st.exists(orphan) and not os.path.exists(stale)
    # storing the same bytes again makes an old orphan young again, so an upload is never swept
    again, _ = st.put_bytes(b"left by a failed transaction")
    os.utime(os.path.join(st.root, fstore.location(again)), (old, old))
    st.put_bytes(b"left by a failed transaction")
    assert sweep.sweep(pool, cfg, store=st)["removed"] == 0 and st.exists(again)
    with pool.tx() as tx:
        a = tx.one("SELECT actor_kind, detail FROM occ.audit_events WHERE category = 'upload.sweep' ORDER BY id DESC "
                   "LIMIT 1")
    assert a["actor_kind"] == "system" and a["detail"]["sha256"] == [orphan.hex()]
    with pool.tx() as tx:
        tx.run("DELETE FROM occ.file_blobs WHERE sha256 = :s", s=kept)


def test_the_sweep_on_s3(s3server, cfg, pool, tmp_path):
    st = _s3store(s3server, tmp_path, bucket="occ-sweep", prefix="")
    kept, _ = st.put_bytes(b"registered on s3")
    orphan, _ = st.put_bytes(b"orphan on s3")
    with pool.tx() as tx:
        fstore.register(tx, st, kept, 16)
    assert sweep.sweep(pool, cfg, store=st)["removed"] == 0             # both younger than a day
    out = sweep.sweep(pool, cfg, store=st, grace_hours=0)
    assert out["removed"] == 1 and st.exists(kept) and not st.exists(orphan)
    with pool.tx() as tx:
        tx.run("DELETE FROM occ.file_blobs WHERE sha256 = :s", s=kept)


def test_the_sweep_is_a_weekly_job(cfg, pool):
    from occ.worker import handlers, jobs, schedules  # noqa: F401  (handlers registers the job kinds)
    assert ("files-sweep", "30 3 * * 0", "files-sweep") in schedules.SCHEDULES and "files-sweep" in jobs.HANDLERS


# ------------------------------------------------------------------------------ identity providers
CERT = "MIIBszCCAVmgAwIBAgIUSIGNINGCERTFORTESTSONLY" + "A" * 40
ENC = "MIIBszCCAVmgAwIBAgIUENCRYPTIONCERTTESTONLY" + "B" * 40


def _metadata(entity_a, entity_b):
    return ("""<?xml version="1.0"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui">
 <md:EntityDescriptor entityID="%s">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
   <md:Extensions><mdui:UIInfo><mdui:DisplayName xml:lang="en">Lab Login</mdui:DisplayName></mdui:UIInfo></md:Extensions>
   <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
   <md:KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
   <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.org/slo"/>
   <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.org/sso"/>
   <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.org/sso-post"/>
   <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="https://idp.example.org/art"/>
   <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://idp.example.org/plain"/>
  </md:IDPSSODescriptor>
 </md:EntityDescriptor>
 <md:EntityDescriptor entityID="%s">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
   <md:KeyDescriptor><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
   <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://other.example.org/sso"/>
  </md:IDPSSODescriptor>
  <md:Organization><md:OrganizationName xml:lang="en">Other</md:OrganizationName>
   <md:OrganizationDisplayName xml:lang="en">Other University</md:OrganizationDisplayName>
   <md:OrganizationURL xml:lang="en">https://other.example.org</md:OrganizationURL></md:Organization>
 </md:EntityDescriptor>
 <md:EntityDescriptor entityID="https://sp.example.org"><md:SPSSODescriptor protocolSupportEnumeration="x"/></md:EntityDescriptor>
</md:EntitiesDescriptor>""" % (entity_a, CERT, ENC, entity_b, CERT)).encode()


def test_parse_reads_providers_and_refuses_tricks():
    got = idp_refresh.parse(_metadata("https://a.example.org/idp", "https://b.example.org/idp"))
    assert [g["entityid"] for g in got] == ["https://a.example.org/idp", "https://b.example.org/idp"]
    a, b = got
    assert a["name"] == "Lab Login" and b["name"] == "Other University"
    assert a["certs"] == [(0, CERT), (1, ENC)] and b["certs"] == [(0, CERT), (1, CERT)]      # no use: both
    assert sorted(a["endpoints"]) == [(False, 0, "https://idp.example.org/sso"), (False, 1, "https://idp.example.org/sso-post"),
                                      (True, 0, "https://idp.example.org/slo")]
    for bad in (b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><x>&a;</x>', b"not xml", b"<other/>",
                b'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x"/>'):
        with pytest.raises(idp_refresh.RefreshError):
            idp_refresh.parse(bad)


def test_fetch_is_https_only_and_reads_a_local_source():
    body = _metadata("https://c.example.org/idp", "https://d.example.org/idp")

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):                                                # noqa: N802
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = "http://127.0.0.1:%d/md" % srv.server_address[1]
        with pytest.raises(idp_refresh.RefreshError):
            idp_refresh.fetch(url)                                       # http is refused for a real source
        assert idp_refresh.fetch(url, allow_http=True) == body
    finally:
        srv.shutdown()
        srv.server_close()


def test_refresh_through_the_api_and_the_job(client, world, pool, monkeypatch, cfg):
    h = world.h("sys")
    # an existing provider, made enabled=0 on create: the OCC honors it
    r = client.post("/api/v2/idps", json={"name": "Known", "entityid": "https://known.example.org/idp", "enabled": 0},
                    headers=h)
    assert r.status_code == 201, r.text
    known = int(r.headers["location"].rsplit("/", 1)[-1])
    with pool.tx() as tx:
        assert tx.val("SELECT enabled FROM occ.idps WHERE id = :i", i=known) is False
    r = client.post("/api/v2/idps_sources", json={"url": "https://fed.example.org/metadata.xml", "auto_refresh": 1},
                    headers=h)
    sid = int(r.headers["location"].rsplit("/", 1)[-1])
    md = _metadata("https://known.example.org/idp", "https://new.example.org/idp")
    monkeypatch.setattr(idp_refresh, "fetch", lambda url, allow_http=False: md)
    assert client.patch("/api/v2/idps_sources/%d" % sid, json={"action": "refresh"},
                        headers=world.h("admin")).status_code == 403
    r = client.patch("/api/v2/idps_sources/%d" % sid, json={"action": "refresh"}, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["last_fetched_at"]
    with pool.tx() as tx:
        rows = {x["entityid"]: x for x in tx.all("SELECT * FROM occ.idps")}
        new = rows["https://new.example.org/idp"]
        assert new["enabled"] is False and new["source_id"] == sid and new["name"] == "Other University"
        assert rows["https://known.example.org/idp"]["name"] == "Known"            # the sysadmin's name stays
        assert rows["https://known.example.org/idp"]["enabled"] is False
        eps = tx.all("SELECT location FROM occ.idp_endpoints WHERE idp_id = :i ORDER BY location", i=known)
        assert [e["location"] for e in eps] == ["https://idp.example.org/slo", "https://idp.example.org/sso",
                                                "https://idp.example.org/sso-post"]
    # the daily job does the same for sources with auto_refresh on, and reports a failing one
    from occ.worker import handlers, runner
    import logging
    wctx = runner.WorkerCtx(pool=pool, settings=cfg, store=fstore.for_settings(cfg), log=logging.getLogger("t"))
    out = handlers.idp_refresh(wctx, {})
    assert out["sources"] == 1 and out["refreshed"][0]["updated"] == 2 and not out["failed"]

    def down(url, allow_http=False):
        raise idp_refresh.RefreshError("The metadata source answered 503.")
    monkeypatch.setattr(idp_refresh, "fetch", down)
    out = handlers.idp_refresh(wctx, {})
    assert out["failed"] == {str(sid): "The metadata source answered 503."}
    assert client.patch("/api/v2/idps_sources/%d" % sid, json={"action": "refresh"}, headers=h).status_code == 502


# ------------------------------------------------------------------------------ the secret key file
def test_init_secret_key_makes_a_private_key_file_once(tmp_path, monkeypatch, capsys, scratchdb):
    from occ import cli
    path = tmp_path / "etc" / "secret.key"
    monkeypatch.setenv("OCC_SECRET_KEY_FILE", str(path))
    monkeypatch.setenv("OCC_ENV_FILE", "/nonexistent")
    assert cli.main(["--database", scratchdb, "init-secret-key"]) == 0
    assert capsys.readouterr().out.strip() == "created"
    first = path.read_bytes()
    assert len(first) == 32 and (os.stat(path).st_mode & 0o777) == 0o600
    assert cli.main(["--database", scratchdb, "init-secret-key"]) == 0
    assert capsys.readouterr().out.strip() == "exists already" and path.read_bytes() == first


def test_sweep_files_command_dry_run(tmp_path, monkeypatch, capsys, scratchdb):
    import json as _json
    from occ import cli
    monkeypatch.setenv("OCC_FILES_ROOT", str(tmp_path / "files"))
    monkeypatch.setenv("OCC_ENV_FILE", "/nonexistent")
    st = fstore.DiskStore(str(tmp_path / "files"))
    sha, _n = st.put_bytes(b"orphan for the command")
    old = time.time() - 2 * 86400
    os.utime(os.path.join(st.root, fstore.location(sha)), (old, old))
    assert cli.main(["--database", scratchdb, "sweep-files", "--dry-run"]) == 0
    out = _json.loads(capsys.readouterr().out)
    assert out["removed"] == 1 and out["dry_run"] is True and st.exists(sha)
