# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The .eln format: a ZIP holding an RO-Crate 1.1 (the ELN Consortium's exchange format), written and
read from the published RO-Crate and ELN file format specifications.

Layout written:
    <stamp>-export/ro-crate-metadata.json
    <stamp>-export/<record folder>/export.json      the record in the OCC's read shape
    <stamp>-export/<record folder>/<attachment>     each current attachment
In the crate graph every record is a Dataset (name, text, dateCreated, dateModified, author,
keywords, identifier, genre, variableMeasured for extra fields, hasPart for its files) and every
file a File with contentSize, encodingFormat and sha256.
"""
import io
import json
import posixpath
import zipfile

from .. import errors

CONTEXT = "https://w3id.org/ro/crate/1.1/context"
CONFORMS = "https://w3id.org/ro/crate/1.1"


def build(tx, store, recs, stamp, base_url, files_of):
    from .render import _folder, _public, extra_fields   # one folder naming for zip and eln
    root = "%s-export" % stamp
    graph = [
        {"@id": "ro-crate-metadata.json", "@type": "CreativeWork", "about": {"@id": "./"},
         "conformsTo": {"@id": CONFORMS}, "dateCreated": stamp,
         "sdPublisher": {"@id": "#publisher"}, "version": "1.0"},
        {"@id": "#publisher", "@type": "Organization", "name": "LabLynx.One OCC", "url": base_url},
    ]
    root_parts, people = [], {}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for r in recs:
            folder = _folder(r)
            ds_id = "./%s/" % folder
            root_parts.append({"@id": ds_id})
            parts = [{"@id": "./%s/export.json" % folder}]
            z.writestr("%s/%s/export.json" % (root, folder), json.dumps(_public(r), ensure_ascii=False, indent=1))
            graph.append({"@id": "./%s/export.json" % folder, "@type": "File", "name": "export.json",
                          "encodingFormat": "application/json", "description": "The record in the OCC read shape"})
            seen = set()
            for f in files_of(tx, r):
                name = f["real_name"]
                if name in seen:
                    name = "%d-%s" % (f["id"], name)
                seen.add(name)
                fid = "./%s/%s" % (folder, name)
                with store.open(bytes(f["sha256"])) as fh:
                    z.writestr("%s/%s/%s" % (root, folder, name), fh.read())
                parts.append({"@id": fid})
                graph.append({"@id": fid, "@type": "File", "name": f["real_name"], "contentSize": str(f["size"]),
                              "encodingFormat": f["mime"], "sha256": bytes(f["sha256"]).hex()})
            pid = "#person-%s" % r.get("userid")
            people[pid] = {"@id": pid, "@type": "Person", "givenName": r.get("firstname"),
                           "familyName": r.get("lastname")}
            ds = {"@id": ds_id, "@type": "Dataset", "name": r.get("title"), "text": r.get("body") or "",
                  "dateCreated": r.get("created_at"), "dateModified": r.get("modified_at"),
                  "author": {"@id": pid}, "identifier": r.get("elabid"), "genre": r.get("_kind"),
                  "keywords": ",".join((r.get("tags") or "").split("|")) if r.get("tags") else "",
                  "url": r.get("sharelink"), "hasPart": parts}
            if r.get("date"):
                ds["temporal"] = r["date"]
            if r.get("category_title"):
                ds["about"] = r["category_title"]
            ef = extra_fields(r)
            if ef:
                ds["variableMeasured"] = [
                    {"@type": "PropertyValue", "propertyID": name,
                     "value": (spec.get("value") if isinstance(spec, dict) else spec),
                     **({"unitText": spec["unit"]} if isinstance(spec, dict) and spec.get("unit") else {})}
                    for name, spec in ef.items()]
            graph.append(ds)
        graph.extend(people.values())
        graph.insert(1, {"@id": "./", "@type": "Dataset", "name": "LabLynx.One OCC export", "datePublished": stamp,
                         "hasPart": root_parts})
        z.writestr("%s/ro-crate-metadata.json" % root,
                   json.dumps({"@context": CONTEXT, "@graph": graph}, ensure_ascii=False, indent=1))
    return buf.getvalue()


def read(fileobj, max_entries=10000):
    """Parse an .eln: returns [{title, body, date, tags[], extra_fields{}, files:[(name, member, mime)]}].
    Refuses a crate without ro-crate-metadata.json, and member paths that leave the archive."""
    try:
        z = zipfile.ZipFile(fileobj)
    except zipfile.BadZipFile:
        raise errors.bad("This is not an .eln file: it is not a ZIP archive.")
    names = z.namelist()
    if len(names) > max_entries:
        raise errors.bad("This .eln file has too many entries.")
    metas = sorted((n for n in names if posixpath.basename(n) == "ro-crate-metadata.json"), key=len)
    if not metas:
        raise errors.bad("This .eln file has no ro-crate-metadata.json.")
    meta_path = metas[0]
    base = posixpath.dirname(meta_path)
    try:
        crate = json.loads(z.read(meta_path).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise errors.bad("The .eln file's ro-crate-metadata.json is not valid JSON.")
    graph = {e.get("@id"): e for e in (crate.get("@graph") or []) if isinstance(e, dict)}
    root = graph.get("./") or {}
    out = []

    def ids(v):
        v = v if isinstance(v, list) else ([v] if v else [])
        return [x.get("@id") for x in v if isinstance(x, dict) and x.get("@id")]

    for ds_id in ids(root.get("hasPart")):
        ds = graph.get(ds_id) or {}
        types = ds.get("@type") if isinstance(ds.get("@type"), list) else [ds.get("@type")]
        if "Dataset" not in types:
            continue
        kw = ds.get("keywords") or []
        tags = [t.strip() for t in (kw.split(",") if isinstance(kw, str) else kw) if str(t).strip()]
        ef = {}
        for pv in (ds.get("variableMeasured") or []):
            if isinstance(pv, dict) and pv.get("propertyID"):
                spec = {"type": "text", "value": pv.get("value")}
                if pv.get("unitText"):
                    spec["unit"] = pv["unitText"]
                ef[str(pv["propertyID"])] = spec
        files = []
        for fid in ids(ds.get("hasPart")):
            f = graph.get(fid) or {}
            if f.get("@type") != "File" or posixpath.basename(fid) == "export.json":
                continue
            member = posixpath.normpath(posixpath.join(base, fid[2:] if fid.startswith("./") else fid))
            if member.startswith("..") or member.startswith("/") or member not in names:
                continue
            files.append((f.get("name") or posixpath.basename(member), member, f.get("encodingFormat")))
        date = ds.get("temporal") or (str(ds.get("dateCreated") or "")[:10] or None)
        out.append({"title": ds.get("name") or "Untitled", "body": ds.get("text") or "", "date": date,
                    "tags": tags, "extra_fields": ef, "files": files})
    return z, out
