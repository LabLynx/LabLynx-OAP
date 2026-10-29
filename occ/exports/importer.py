# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Import: .eln and .csv up to the site's upload limit, creating records as the caller.

CSV: the first row names the columns; 'title' is required (case does not matter);
'body', 'date' and 'tags' (separated by | or ,) fill those fields; every other column becomes a text
extra field of that name. A 'category' column is used only when the form gives no category.
.eln: each Dataset the crate's root lists becomes one record (name, text, temporal or dateCreated,
keywords, variableMeasured as extra fields) with its files attached. Everything is created in one
transaction: one bad row and nothing is imported.
"""
import csv
import io
import os

from .. import errors, timefmt
from ..audit import writer as audit
from ..files import store as fstore
from ..files import uploads as U
from ..records import kinds as K
from ..records import service as S
from . import eln

MAX_ROWS = 10000
EXTENSIONS = (".eln", ".csv")
KINDS = ("experiments", "items", "experiments_templates", "items_types")


def limits(tx):
    n = U.max_bytes(tx)
    return {"allowed_extensions": list(EXTENSIONS), "max_filesize": n,
            "max_upload_size": "%dM" % (n // (1024 * 1024)) if n % (1024 * 1024) == 0 else str(n),
            "max_upload_time": 900000}


def _owner(tx, p, opts):
    v = opts.get("owner")
    if v in (None, "", "0"):
        return None
    uid = S._int_strict("owner", v)
    if uid == p.user_id:
        return None
    if p.team_id not in p.admin_teams:
        raise errors.forbidden("Only team admins can import records for someone else.")
    if not tx.val("SELECT 1 FROM occ.memberships WHERE user_id = :u AND team_id = :t AND NOT is_archived",
                  u=uid, t=p.team_id):
        raise errors.bad("Incorrect value for owner: not a member of this team")
    return uid


def _create(tx, cfg, p, actor, kind, body, owner, files=(), zf=None):
    new_id = S.create(tx, p, actor, kind, body)
    row = S.fetch(tx, p, kind, new_id, full=False, for_update=True)
    if owner:
        tx.run("UPDATE occ.records SET owner_id = :o WHERE rid = :rid", o=owner, rid=row["rid"])
        audit.write(tx, actor, "record.update", kind_id=kind.id, record_id=new_id, rid=row["rid"],
                    team_id=row["team_id"], target="userid", old=p.user_id, new=owner, detail={"import": True})
    st = fstore.for_settings(cfg)
    for name, member, mime in files:
        with zf.open(member) as fh:
            sha, size = st.put(iter(lambda: fh.read(fstore.CHUNK), b""))
        U.attach(tx, cfg, actor, kind, row, name, mime, sha, size, user_id=p.user_id)
    audit.write(tx, actor, "record.update", kind_id=kind.id, record_id=new_id, rid=row["rid"], team_id=row["team_id"],
                target="import", new="imported", detail={"files": len(files)})
    return new_id


def _common(opts):
    body = {}
    if opts.get("category") not in (None, "", "0"):
        body["category"] = opts["category"]
    for k in ("canread", "canwrite"):
        if opts.get(k) not in (None, ""):
            body[k] = opts[k]
    return body


def run(tx, cfg, p, actor, filename, fileobj, size, opts):
    S._check_can_write_key(p)
    ext = os.path.splitext(filename or "")[1].lower()
    if ext not in EXTENSIONS:
        raise errors.bad("Incorrect value for file: the importer accepts %s" % " and ".join(EXTENSIONS))
    limit = U.max_bytes(tx)
    if size > limit:
        raise errors.OCCError(413, "The file is too large.", "The site accepts files up to %d bytes." % limit)
    kind_code = opts.get("entity_type") or "experiments"
    if kind_code not in KINDS:
        raise errors.bad("Incorrect value for entity_type: one of %s" % ", ".join(KINDS))
    kind = K.get(kind_code)
    owner = _owner(tx, p, opts)
    common = _common(opts)
    fileobj.seek(0)
    n = 0
    if ext == ".csv":
        text = io.TextIOWrapper(fileobj, encoding="utf-8-sig", newline="")
        try:
            reader = csv.DictReader(text)
            cols = {c.lower().strip(): c for c in (reader.fieldnames or []) if c}
            if "title" not in cols:
                raise errors.bad("The CSV file needs a 'title' column.")
            for line in reader:
                n += 1
                if n > MAX_ROWS:
                    raise errors.bad("The CSV file has more than %d rows." % MAX_ROWS)
                body = dict(common)
                body["title"] = (line.get(cols["title"]) or "").strip() or "Untitled"
                if "body" in cols and line.get(cols["body"]):
                    body["body"] = line[cols["body"]]
                if "date" in cols and (line.get(cols["date"]) or "").strip():
                    body["date"] = line[cols["date"]].strip()
                if "category" in cols and "category" not in body and (line.get(cols["category"]) or "").strip():
                    body["category"] = line[cols["category"]].strip()
                if "tags" in cols and line.get(cols["tags"]):
                    raw = line[cols["tags"]]
                    body["tags"] = [t.strip() for t in raw.replace("|", ",").split(",") if t.strip()]
                ef = {}
                for low, orig in cols.items():
                    if low in ("title", "body", "date", "tags", "category"):
                        continue
                    v = line.get(orig)
                    if v not in (None, ""):
                        ef[orig] = {"type": "text", "value": v}
                if ef:
                    body["metadata"] = {"extra_fields": ef}
                _create(tx, cfg, p, actor, kind, body, owner)
        except (csv.Error, UnicodeDecodeError) as e:
            raise errors.bad("The CSV file cannot be read: %s" % type(e).__name__)
        finally:
            text.detach()
    else:
        zf, recs = eln.read(fileobj)
        with zf:
            for r in recs:
                body = dict(common)
                body["title"] = r["title"]
                if r["body"]:
                    body["body"] = r["body"]
                if r["date"]:
                    try:
                        timefmt.parse_date(r["date"])
                        body["date"] = r["date"]
                    except ValueError:
                        pass
                if r["tags"]:
                    body["tags"] = r["tags"]
                if r["extra_fields"]:
                    body["metadata"] = {"extra_fields": r["extra_fields"]}
                _create(tx, cfg, p, actor, kind, body, owner, r["files"], zf)
                n += 1
    if n == 0:
        raise errors.bad("Nothing to import: the file holds no records.")
    return n

