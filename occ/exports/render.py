# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Record exports in the 3.0.0 formats: CSV, JSON, PDF, PDF/A, ZIP, ZIP-A and .eln.

render() takes records the caller may read and returns (bytes, file name). It is used by a record
read or list with format= (synchronous, up to SYNC_LIMIT records) and by the export queue's job.
PDF/A is PDF/A-2b with embedded fonts; ZIP-A is the ZIP with PDF/A in place of
each PDF.
"""
import csv
import datetime as dt
import io
import json
import re
import zipfile

from .. import errors, timefmt
from ..files import store as fstore
from ..perms import engine
from ..records import service as S
from . import eln, pdf

SYNC_LIMIT = 500
FORMATS = ("csv", "json", "pdf", "pdfa", "zip", "zipa", "eln")
MIME = {"csv": "text/csv; charset=UTF-8", "json": "application/json", "pdf": "application/pdf",
        "pdfa": "application/pdf", "zip": "application/zip", "zipa": "application/zip",
        "eln": "application/vnd.eln+zip"}
CSV_COLUMNS = ("id", "date", "title", "userid", "fullname", "body", "category", "category_title", "category_color",
               "status", "status_title", "status_color", "custom_id", "elabid", "rating", "sharelink", "metadata",
               "tags")
_SLUG = re.compile(r"[^A-Za-z0-9._-]+")


def check_format(fmt):
    if fmt not in FORMATS:
        raise errors.bad("Incorrect value for format: one of %s" % ", ".join(FORMATS))


def slug(text, n=60):
    return (_SLUG.sub("-", str(text or "")).strip("-") or "untitled")[:n]


def records(tx, p, kind, ids, base_url, changelog=True):
    """The full read shape of each record, in the order given; 403/404 as a read would answer."""
    out = []
    for rid in ids:
        row = S.fetch(tx, p, kind, rid)
        engine.readable_or_raise(p, row, errors)
        rec = S.full_shape(tx, p, kind, row, base_url, with_changelog=changelog)
        rec["_rid"] = row["rid"]
        rec["_kind"] = kind.code
        out.append(rec)
    return out


def _public(rec):
    return {k: v for k, v in rec.items() if not k.startswith("_")}


def extra_fields(rec):
    try:
        meta = json.loads(rec.get("metadata") or "null") or {}
    except ValueError:
        return {}
    ef = meta.get("extra_fields") if isinstance(meta, dict) else None
    return ef if isinstance(ef, dict) else {}


def to_csv(recs):
    extra_names = []
    for r in recs:
        for name in extra_fields(r):
            if name not in extra_names:
                extra_names.append(name)
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(list(CSV_COLUMNS) + extra_names)
    for r in recs:
        ef = extra_fields(r)
        row = []
        for col in CSV_COLUMNS:
            if col == "body":
                row.append(S.body_text(r.get("body")) or "")
            elif col == "tags":
                row.append(r.get("tags") or "")
            else:
                v = r.get(col)
                row.append("" if v is None else v)
        for name in extra_names:
            v = (ef.get(name) or {}).get("value") if isinstance(ef.get(name), dict) else ef.get(name)
            row.append("" if v is None else (json.dumps(v) if isinstance(v, (list, dict)) else v))
        w.writerow(row)
    return ("﻿" + buf.getvalue()).encode("utf-8")


def to_pdf(recs, title, archival=False):
    doc = pdf.Document(title=title, subject="LabLynx.One OCC record export", archival=archival)
    for i, r in enumerate(recs):
        if i:
            doc._new_page()
        doc.heading(r.get("title") or "Untitled")
        for label, key in (("Type", "type"), ("Date", "date"), ("Owner", "fullname"), ("Team", "team_name"),
                           ("Category", "category_title"), ("Status", "status_title"), ("Tags", "tags"),
                           ("Custom id", "custom_id"), ("Unique id", "elabid"), ("Created", "created_at"),
                           ("Last change", "modified_at"), ("Locked", "locked"), ("Rating", "rating")):
            v = r.get(key)
            if key == "tags" and v:
                v = ", ".join(v.split("|"))
            doc.field(label, "" if v is None else v)
        doc.subheading("Main text")
        doc.paragraph(S.body_text(r.get("body")) or "(empty)")
        ef = extra_fields(r)
        if ef:
            doc.subheading("Extra fields")
            for name, spec in ef.items():
                v = spec.get("value") if isinstance(spec, dict) else spec
                if isinstance(v, (list, dict)):
                    v = json.dumps(v)
                unit = spec.get("unit") if isinstance(spec, dict) else None
                doc.field(name, ("%s %s" % (v, unit)) if unit and v not in (None, "") else ("" if v is None else v))
        if r.get("steps"):
            doc.subheading("Steps")
            for s in r["steps"]:
                doc.paragraph("[%s] %s" % ("x" if int(s.get("finished") or 0) else " ", s.get("body") or ""))
        links = (r.get("experiments_links") or []) + (r.get("items_links") or [])
        if links:
            doc.subheading("Linked records")
            for ln in links:
                doc.paragraph("%s #%s: %s" % (ln.get("page") or ln.get("type") or "", ln.get("entityid"),
                                              ln.get("title") or ""))
        if r.get("uploads"):
            doc.subheading("Attachments")
            for u in r["uploads"]:
                doc.paragraph("%s (%s bytes, SHA-256 %s)%s" % (u.get("real_name"), u.get("filesize"), u.get("hash"),
                                                               (": " + u["comment"]) if u.get("comment") else ""))
        if r.get("comments"):
            doc.subheading("Comments")
            for cm in r["comments"]:
                doc.paragraph("%s, %s: %s" % (cm.get("fullname"), cm.get("created_at"), cm.get("comment")))
        if r.get("changelog"):
            doc.subheading("Change history")
            for e in r["changelog"]:
                doc.paragraph("%s  %s  %s: %s" % (e.get("created_at"), e.get("fullname") or "", e.get("target") or "",
                                                  e.get("content") or ""), size=8, gray=0.25)
    return doc.bytes()


def _folder(r):
    return "%s - %s - %s" % (slug(r.get("category_title") or r.get("type")), slug(r.get("title")),
                             (r.get("elabid") or "")[-8:])


def files_of(tx, rec):
    rows = tx.all("SELECT id, real_name, sha256, size, mime FROM occ.uploads WHERE rid = :rid AND state = 1 "
                  "ORDER BY id", rid=rec["_rid"])
    return rows


def to_zip(tx, store, recs, title, archival=False):
    buf = io.BytesIO()
    stamp = dt.datetime.now(timefmt.zone()).strftime("%Y-%m-%d")
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for r in recs:
            folder = _folder(r)
            z.writestr("%s/%s-OCC-%s.pdf" % (folder, stamp, "PDFA" if archival else "PDF"),
                       to_pdf([r], r.get("title") or title, archival))
            z.writestr("%s/export.json" % folder, json.dumps(_public(r), ensure_ascii=False, indent=1))
            seen = set()
            for f in files_of(tx, r):
                name = f["real_name"]
                if name in seen:
                    name = "%d-%s" % (f["id"], name)
                seen.add(name)
                with store.open(bytes(f["sha256"])) as fh:
                    z.writestr("%s/%s" % (folder, name), fh.read())
    return buf.getvalue()


def render(tx, cfg, p, kind, ids, fmt, base_url, single=False, changelog=True, recs=None):
    check_format(fmt)
    if recs is None:
        recs = records(tx, p, kind, ids, base_url, changelog=changelog)
    stamp = dt.datetime.now(timefmt.zone()).strftime("%Y-%m-%d-%H%M%S")
    base = slug(recs[0].get("title")) if single and recs else "%s-export" % stamp
    if fmt == "json":
        data = json.dumps(_public(recs[0]) if single else [_public(r) for r in recs], ensure_ascii=False).encode()
    elif fmt == "csv":
        data = to_csv(recs)
    elif fmt in ("pdf", "pdfa"):
        data = to_pdf(recs, recs[0].get("title") if single and recs else "Export", fmt == "pdfa")
    elif fmt in ("zip", "zipa"):
        data = to_zip(tx, fstore.for_settings(cfg), recs, base, fmt == "zipa")
    else:   # eln
        data = eln.build(tx, fstore.for_settings(cfg), recs, stamp, base_url, files_of)
    ext = {"eln": "eln", "zip": "zip", "zipa": "zip", "pdf": "pdf", "pdfa": "pdf", "csv": "csv", "json": "json"}[fmt]
    return data, "%s.%s" % (base, ext)
