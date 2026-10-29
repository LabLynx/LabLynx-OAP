# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Uploads, exports (one record or a list, by format=, and the export queue) and import: files are
stored once by SHA-256, and no SQL is built from text."""
import csv
import hashlib
import io
import json
import os
import zipfile

from occ.exports import eln, pdf


def _new(client, world, who="alice", kind="experiments", **body):
    r = client.post("/api/v2/%s" % kind, json=body or {"title": "t"}, headers=world.h(who))
    assert r.status_code == 201, r.text
    return int(r.headers["location"].rsplit("/", 1)[-1])


def _upload(client, world, eid, name="a.txt", data=b"hello file\n", who="alice", kind="experiments", **form):
    return client.post("/api/v2/%s/%d/uploads" % (kind, eid), files={"file": (name, data, "text/plain")},
                       data=form, headers=world.h(who))


def _blob_path(cfg, data):
    h = hashlib.sha256(data).hexdigest()
    return os.path.join(cfg.files_root, h[:2], h[2:4], h)


def test_upload_is_stored_once_per_sha256_and_reads_back(client, world, cfg, pool):
    eid = _new(client, world, title="Files")
    data = b"same bytes " * 100
    r = _upload(client, world, eid, "one.txt", data, comment="first")
    assert r.status_code == 201 and r.content == b""
    uid = int(r.headers["location"].rsplit("/", 1)[-1])
    r2 = _upload(client, world, eid, "two.txt", data)
    assert r2.status_code == 201
    assert os.path.exists(_blob_path(cfg, data))
    with pool.tx() as tx:
        assert tx.val("SELECT count(*) FROM occ.file_blobs WHERE sha256 = :s", s=hashlib.sha256(data).digest()) == 1
        assert tx.val("SELECT count(*) FROM occ.uploads WHERE sha256 = :s", s=hashlib.sha256(data).digest()) == 2
        assert tx.val("SELECT count(*) FROM occ.audit_events WHERE category = 'upload.add' AND record_id = :r",
                      r=eid) == 2
    meta = client.get("/api/v2/experiments/%d/uploads/%d" % (eid, uid), headers=world.h("alice")).json()
    assert meta["real_name"] == "one.txt" and meta["comment"] == "first" and meta["type"] == "experiments"
    assert meta["hash"] == hashlib.sha256(data).hexdigest() and meta["filesize"] == len(data)
    b = client.get("/api/v2/experiments/%d/uploads/%d" % (eid, uid), params={"format": "binary"},
                   headers=world.h("alice"))
    assert b.status_code == 200 and b.content == data
    assert b.headers["x-content-type-options"] == "nosniff"
    assert b.headers["content-disposition"].startswith("attachment;")
    listed = client.get("/api/v2/experiments/%d/uploads" % eid, headers=world.h("alice")).json()
    assert sorted(u["real_name"] for u in listed) == ["one.txt", "two.txt"]
    rec = client.get("/api/v2/experiments/%d" % eid, headers=world.h("alice")).json()
    assert len(rec["uploads"]) == 2


def test_upload_permissions_and_names_are_never_paths(client, world, cfg):
    eid = _new(client, world, title="Perm")
    assert _upload(client, world, eid, who="bea").status_code == 404          # another team: 404, so a record's existence is not disclosed
    assert _upload(client, world, eid, who="alice_ro").status_code == 403     # read-only key
    r = _upload(client, world, eid, "../../etc/passwd", b"x")
    assert r.status_code == 201
    uid = int(r.headers["location"].rsplit("/", 1)[-1])
    meta = client.get("/api/v2/experiments/%d/uploads/%d" % (eid, uid), headers=world.h("alice")).json()
    assert meta["real_name"] == "passwd"
    assert not os.path.exists(os.path.join(cfg.files_root, "..", "etc"))
    # a member of the team can read and download; someone outside cannot
    assert client.get("/api/v2/experiments/%d/uploads/%d" % (eid, uid), params={"format": "binary"},
                      headers=world.h("bob")).status_code == 200
    assert client.get("/api/v2/experiments/%d/uploads/%d" % (eid, uid), params={"format": "binary"},
                      headers=world.h("bea")).status_code == 404


def test_upload_locked_record_refuses(client, world):
    eid = _new(client, world, title="Locked")
    assert client.patch("/api/v2/experiments/%d" % eid, json={"action": "lock"},
                        headers=world.h("alice")).status_code == 200
    assert _upload(client, world, eid, who="admin").status_code == 423


def test_upload_too_large_is_413(client, world, pool):
    eid = _new(client, world, title="Big")
    with pool.tx() as tx:
        tx.run("INSERT INTO occ.site_config (name, value) VALUES ('max_upload_size', '1000') "
               "ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value")
    try:
        r = _upload(client, world, eid, "big.bin", b"x" * 1001)
        assert r.status_code == 413
        assert client.get("/api/v2/import", headers=world.h("alice")).json()["max_filesize"] == 1000
    finally:
        with pool.tx() as tx:
            tx.run("DELETE FROM occ.site_config WHERE name = 'max_upload_size'")


def test_edit_replace_delete_and_version_chain(client, world, pool):
    eid = _new(client, world, title="Versions")
    uid = int(_upload(client, world, eid, "v.txt", b"version one").headers["location"].rsplit("/", 1)[-1])
    r = client.patch("/api/v2/experiments/%d/uploads/%d" % (eid, uid), json={"comment": "described",
                                                                              "real_name": "renamed.txt"},
                     headers=world.h("alice"))
    assert r.status_code == 200 and r.json()["comment"] == "described" and r.json()["real_name"] == "renamed.txt"
    r = client.post("/api/v2/experiments/%d/uploads/%d" % (eid, uid), files={"file": ("v2.txt", b"version two")},
                    data={"action": "replace"}, headers=world.h("alice"))
    assert r.status_code == 201
    new = int(r.headers["location"].rsplit("/", 1)[-1])
    old = client.get("/api/v2/experiments/%d/uploads/%d" % (eid, uid), headers=world.h("alice")).json()
    assert old["state"] == 2                                      # stays readable
    assert client.get("/api/v2/experiments/%d/uploads/%d" % (eid, uid), params={"format": "binary"},
                      headers=world.h("alice")).content == b"version one"
    with pool.tx() as tx:
        row = tx.one("SELECT version, replaces_id FROM occ.uploads WHERE id = :i", i=new)
    assert row == {"version": 2, "replaces_id": uid}
    current = client.get("/api/v2/experiments/%d/uploads" % eid, headers=world.h("alice")).json()
    assert [u["id"] for u in current] == [new]
    assert client.delete("/api/v2/experiments/%d/uploads/%d" % (eid, new), headers=world.h("alice")).status_code == 204
    assert client.get("/api/v2/experiments/%d/uploads" % eid, headers=world.h("alice")).json() == []
    assert client.get("/api/v2/experiments/%d/uploads/%d" % (eid, new),
                      headers=world.h("alice")).status_code == 404


def test_immutable_upload_refuses_change(client, world, pool):
    eid = _new(client, world, title="Immutable")
    uid = int(_upload(client, world, eid).headers["location"].rsplit("/", 1)[-1])
    with pool.tx() as tx:
        tx.run("UPDATE occ.uploads SET immutable = true WHERE id = :i", i=uid)
    assert client.delete("/api/v2/experiments/%d/uploads/%d" % (eid, uid), headers=world.h("alice")).status_code == 403
    r = client.post("/api/v2/experiments/%d/uploads/%d" % (eid, uid), files={"file": ("x", b"y")},
                    data={"action": "replace"}, headers=world.h("alice"))
    assert r.status_code == 403


def test_compatibility_download_keeps_migrated_links_working(client, world, pool):
    eid = _new(client, world, title="Compat")
    uid = int(_upload(client, world, eid, "c.txt", b"compat bytes").headers["location"].rsplit("/", 1)[-1])
    with pool.tx() as tx:
        sn = tx.val("SELECT storage_name FROM occ.uploads WHERE id = :i", i=uid)
    r = client.get("/app/download.php", params={"f": sn, "name": "c.txt"}, headers=world.h("bob"))
    assert r.status_code == 200 and r.content == b"compat bytes"
    assert client.get("/app/download.php", params={"f": sn}, headers=world.h("bea")).status_code == 404
    assert client.get("/app/download.php", params={"f": "zz/none.txt"}, headers=world.h("bob")).status_code == 404
    assert client.get("/app/download.php", params={"f": sn}).status_code == 401


def test_duplicate_copies_files_only_when_asked(client, world):
    eid = _new(client, world, title="Dup")
    _upload(client, world, eid, "d.txt", b"dup")
    r = client.post("/api/v2/experiments/%d" % eid, json={"action": "duplicate"}, headers=world.h("alice"))
    plain = int(r.headers["location"].rsplit("/", 1)[-1])
    r = client.post("/api/v2/experiments/%d" % eid, json={"action": "duplicate", "copyFiles": True},
                    headers=world.h("alice"))
    withf = int(r.headers["location"].rsplit("/", 1)[-1])
    assert client.get("/api/v2/experiments/%d/uploads" % plain, headers=world.h("alice")).json() == []
    up = client.get("/api/v2/experiments/%d/uploads" % withf, headers=world.h("alice")).json()
    assert [u["real_name"] for u in up] == ["d.txt"]


def _meta(**fields):
    return json.dumps({"extra_fields": {k: {"type": "text", "value": v} for k, v in fields.items()}})


def test_record_exports_csv_json_pdf_zip_eln(client, world):
    eid = _new(client, world, title="Export me", body="<p>probe body</p>", metadata=_meta(Lot="L-7"),
               tags=["alpha", "beta"])
    _upload(client, world, eid, "data.csv", b"a,b\n1,2\n")
    g = lambda fmt: client.get("/api/v2/experiments/%d" % eid, params={"format": fmt}, headers=world.h("alice"))
    r = g("csv")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    text = r.content.decode("utf-8")
    assert text.startswith("﻿id,date,title,userid,fullname,body,")
    rows = list(csv.DictReader(io.StringIO(text.lstrip("﻿"))))
    assert rows[0]["title"] == "Export me" and rows[0]["body"] == "probe body" and rows[0]["Lot"] == "L-7"
    assert rows[0]["tags"] == "alpha|beta"
    r = g("json")
    assert r.status_code == 200 and r.json()["title"] == "Export me" and r.json()["uploads"][0]["real_name"] == "data.csv"
    r = g("pdf")
    assert r.status_code == 200 and r.content.startswith(b"%PDF-1.4") and r.content.rstrip().endswith(b"%%EOF")
    assert r.headers["content-type"] == "application/pdf"
    r = g("zip")
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = z.namelist()
    assert any(n.endswith("-OCC-PDF.pdf") for n in names) and any(n.endswith("/export.json") for n in names)
    assert any(n.endswith("/data.csv") for n in names)
    r = g("eln")
    z = zipfile.ZipFile(io.BytesIO(r.content))
    meta = [n for n in z.namelist() if n.endswith("ro-crate-metadata.json")]
    assert len(meta) == 1
    crate = json.loads(z.read(meta[0]))
    assert crate["@context"] == eln.CONTEXT
    ds = [e for e in crate["@graph"] if e.get("@type") == "Dataset" and e["@id"] != "./"]
    assert ds[0]["name"] == "Export me" and ds[0]["keywords"] == "alpha,beta"
    f = [e for e in crate["@graph"] if e.get("@type") == "File" and e.get("name") == "data.csv"][0]
    assert f["sha256"] == hashlib.sha256(b"a,b\n1,2\n").hexdigest()
    r = g("pdfa")
    assert r.status_code == 200 and r.content.startswith(b"%PDF-1.7") and b"<pdfaid:part>2</pdfaid:part>" in r.content
    r = g("zipa")
    z = zipfile.ZipFile(io.BytesIO(r.content))
    pdfa = [n for n in z.namelist() if n.endswith("-OCC-PDFA.pdf")]
    assert len(pdfa) == 1 and b"/OutputIntents" in z.read(pdfa[0])
    assert any(n.endswith("/data.csv") for n in z.namelist())
    assert g("docx").status_code == 400
    assert client.get("/api/v2/experiments/%d" % eid, params={"format": "pdf"},
                      headers=world.h("bea")).status_code == 404


def test_list_export_and_sync_limit(client, world):
    _new(client, world, title="List export A")
    r = client.get("/api/v2/experiments", params={"format": "csv", "q": "List export"}, headers=world.h("alice"))
    assert r.status_code == 200
    rows = list(csv.DictReader(io.StringIO(r.content.decode("utf-8").lstrip("﻿"))))
    assert [x["title"] for x in rows] == ["List export A"]
    r = client.get("/api/v2/experiments", params={"format": "json", "q": "List export"}, headers=world.h("alice"))
    assert isinstance(r.json(), list) and r.json()[0]["title"] == "List export A"


def test_export_roundtrips_through_import(client, world):
    eid = _new(client, world, title="Round trip", body="<p>kept</p>", metadata=_meta(Batch="B1"), tags=["rt"])
    _upload(client, world, eid, "raw.bin", b"\x00\x01raw")
    data = client.get("/api/v2/experiments/%d" % eid, params={"format": "eln"}, headers=world.h("alice")).content
    r = client.post("/api/v2/import", files={"file": ("x.eln", data)}, data={"entity_type": "experiments"},
                    headers=world.h("bob"))
    assert r.status_code == 201, r.text
    assert r.headers["location"].endswith("/import/1")
    rows = client.get("/api/v2/experiments", params={"q": "Round trip", "scope": 1}, headers=world.h("bob")).json()
    assert len(rows) == 1 and rows[0]["userid"] == world.users["bob"]
    rec = client.get("/api/v2/experiments/%d" % rows[0]["id"], headers=world.h("bob")).json()
    assert "kept" in rec["body"] and "Batch" in rec["metadata"] and rec["tags"] == "rt"
    up = rec["uploads"][0]
    assert up["real_name"] == "raw.bin" and up["hash"] == hashlib.sha256(b"\x00\x01raw").hexdigest()


def test_csv_import_and_refusals(client, world):
    text = "Title,Body,Tags,Instrument\nCSV one,<p>b1</p>,x|y,HPLC-2\nCSV two,,,\n"
    r = client.post("/api/v2/import", files={"file": ("in.csv", text.encode())}, data={"entity_type": "items"},
                    headers=world.h("alice"))
    assert r.status_code == 201, r.text
    assert r.headers["location"].endswith("/import/2")
    rows = client.get("/api/v2/items", params={"q": "CSV one"}, headers=world.h("alice")).json()
    rec = client.get("/api/v2/items/%d" % rows[0]["id"], headers=world.h("alice")).json()
    assert json.loads(rec["metadata"])["extra_fields"]["Instrument"]["value"] == "HPLC-2"
    assert sorted(rec["tags"].split("|")) == ["x", "y"]
    assert client.post("/api/v2/import", files={"file": ("in.txt", b"x")}, headers=world.h("alice")).status_code == 400
    assert client.post("/api/v2/import", files={"file": ("in.csv", b"Name\nx\n")},
                       headers=world.h("alice")).status_code == 400
    assert client.post("/api/v2/import", files={"file": ("in.eln", b"not a zip")},
                       headers=world.h("alice")).status_code == 400
    assert client.post("/api/v2/import", files={"file": ("in.csv", text.encode())},
                       headers=world.h("alice_ro")).status_code == 403
    # one bad row and nothing is imported (one transaction)
    bad = "title,date\nGood row,2026-01-01\nBad row,not-a-date\n"
    assert client.post("/api/v2/import", files={"file": ("bad.csv", bad.encode())},
                       headers=world.h("alice")).status_code == 400
    assert client.get("/api/v2/experiments", params={"q": "Good row"}, headers=world.h("alice")).json() == []
    lim = client.get("/api/v2/import", headers=world.h("alice")).json()
    assert lim["allowed_extensions"] == [".eln", ".csv"] and lim["max_filesize"] == 100 * 1024 * 1024


def test_eln_reader_refuses_paths_outside_the_archive():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("x/ro-crate-metadata.json", json.dumps({"@graph": [
            {"@id": "./", "@type": "Dataset", "hasPart": [{"@id": "./r/"}]},
            {"@id": "./r/", "@type": "Dataset", "name": "R", "hasPart": [{"@id": "../../evil"}, {"@id": "./r/ok.txt"}]},
            {"@id": "../../evil", "@type": "File"}, {"@id": "./r/ok.txt", "@type": "File", "name": "ok.txt"}]}))
        z.writestr("x/r/ok.txt", "ok")
        z.writestr("evil", "no")
    buf.seek(0)
    _z, recs = eln.read(buf)
    assert recs[0]["title"] == "R" and [f[0] for f in recs[0]["files"]] == ["ok.txt"]


def test_export_queue_renders_through_the_worker(client, world, cfg, pool):
    from occ.worker import runner
    eid = _new(client, world, title="Queued export")
    r = client.post("/api/v2/exports", json={"format": "json", "experiments": [eid]}, headers=world.h("alice"))
    assert r.status_code == 201
    xid = int(r.headers["location"].rsplit("/", 1)[-1])
    st = client.get("/api/v2/exports/%d" % xid, headers=world.h("alice")).json()
    assert st["state"] == 1 and st["format"] == "json"
    assert client.get("/api/v2/exports/%d" % xid, headers=world.h("bob")).status_code == 403
    assert client.post("/api/v2/exports", json={"format": "json", "experiments": [eid]},
                       headers=world.h("bea")).status_code == 404           # not readable by bea
    assert client.post("/api/v2/exports", json={"format": "json"}, headers=world.h("alice")).status_code == 400
    runner.load_handlers()
    ctx = runner.make_ctx(cfg, pool=pool)
    runner.run_pass(ctx, "test-worker")
    st = client.get("/api/v2/exports/%d" % xid, headers=world.h("alice")).json()
    assert st["state"] == 3 and st["filesize"] > 0, st
    data = client.get("/api/v2/exports/%d" % xid, params={"format": "binary"}, headers=world.h("alice"))
    assert data.json()["title"] == "Queued export"
    assert client.delete("/api/v2/exports/%d" % xid, headers=world.h("alice")).status_code == 204
    assert client.get("/api/v2/exports/%d" % xid, headers=world.h("alice")).status_code == 404


def test_change_feed_lists_readable_changes_since_a_cursor(client, world):
    start = client.get("/api/v2/occ/changes", headers=world.h("alice")).json()
    assert start["changes"] == [] and start["next_cursor"].isdigit()
    eid = _new(client, world, title="Feed me")
    client.patch("/api/v2/experiments/%d" % eid, json={"title": "Fed"}, headers=world.h("alice"))
    page = client.get("/api/v2/occ/changes", params={"cursor": start["next_cursor"]}, headers=world.h("alice")).json()
    mine = [c for c in page["changes"] if c["kind"] == "experiments" and c["id"] == eid]
    assert len(mine) == 1 and mine[0]["op"] == "create"
    later = client.get("/api/v2/occ/changes", params={"cursor": page["next_cursor"]}, headers=world.h("alice")).json()
    assert later["changes"] == []
    other = client.get("/api/v2/occ/changes", params={"cursor": start["next_cursor"]}, headers=world.h("bea")).json()
    assert not any(c["id"] == eid and c["kind"] == "experiments" for c in other["changes"])   # not readable by bea
    assert client.get("/api/v2/occ/changes", params={"cursor": "0", "team": "1"},
                      headers=world.h("alice")).status_code == 403


def test_pdf_writer_wraps_and_paginates():
    doc = pdf.Document(title="T")
    for i in range(200):
        doc.paragraph("line %d " % i + "word " * 40)
    data = doc.bytes()
    assert data.startswith(b"%PDF-1.4") and data.count(b"/Type /Page ") > 5
    assert all(pdf.text_width(ln, 10) <= pdf.PAGE_W - 2 * pdf.MARGIN for ln in pdf.wrap("x" * 500, 495, 10))
