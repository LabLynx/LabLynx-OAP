# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""A record's attachments: add, read or download, replace with a new version, describe or rename,
remove, and the compatibility download for links in migrated bodies. Bytes are stored once per
SHA-256.

The bytes go into the content-addressed store first (hashed while they are written), then one
transaction registers the blob, adds the upload row and its audit row. A blob whose transaction
failed is left on disk with no file_blobs row; the same bytes uploaded again reuse it.

A file name a person gave is only ever data: it is never part of a path. A download always carries
Content-Disposition: attachment and X-Content-Type-Options: nosniff, so a browser never renders an upload as a page.
"""
import mimetypes
import os
import re
import uuid
from urllib.parse import quote

from .. import errors
from ..audit import writer as audit
from ..perms import engine
from ..records import kinds as K
from ..records import service as S
from ..records import subs
from . import store as fstore

DEFAULT_MAX_BYTES = 100 * 1024 * 1024        # 100 MB unless the site sets its own limit
_EXT = re.compile(r"^[A-Za-z0-9]{1,10}$")


def max_bytes(tx):
    """Site setting max_upload_size, in bytes; 100 MB when unset."""
    v = S._site(tx, "max_upload_size")
    try:
        n = int(str(v).strip()) if v not in (None, "") else DEFAULT_MAX_BYTES
    except ValueError:
        n = DEFAULT_MAX_BYTES
    return n if n > 0 else DEFAULT_MAX_BYTES


def storage_name_for(real_name):
    """A fresh legacy-style storage name: 'ab/<uuid>.<ext>' (2.x's long_name form, so migrated and new
    uploads look alike; the extension only when it is short and plain)."""
    u = str(uuid.uuid4())
    ext = os.path.splitext(real_name or "")[1].lstrip(".")
    return "%s/%s%s" % (u[:2], u, ("." + ext.lower()) if _EXT.match(ext or "") else "")


def clean_name(name):
    name = os.path.basename(str(name or "").replace("\\", "/")).strip()
    name = "".join(ch for ch in name if ch >= " " and ch != "\x7f")
    if not name:
        raise errors.bad("Incorrect value for file: it has no name")
    return name[:255]


def guess_mime(name, given=None):
    if given and given not in ("application/octet-stream", "") and "/" in given:
        return given[:127]
    return mimetypes.guess_type(name)[0] or "application/octet-stream"


def put_stream(cfg, chunks, limit):
    """Store the bytes; 413 when they pass the site's limit. Returns (sha256, size)."""
    st = fstore.for_settings(cfg)
    try:
        return st.put(chunks, max_size=limit)
    except fstore.TooLarge:
        raise errors.OCCError(413, "The file is too large.",
                              "The site accepts files up to %d bytes." % limit)


def _upload(tx, row, upload_id, states=(1, 2)):
    up = tx.one("SELECT * FROM occ.uploads WHERE id = :id AND rid = :rid AND state = ANY(CAST(:st AS int[]))",
                id=upload_id, rid=row["rid"], st=list(states))
    if up is None:
        raise errors.not_found("No attachment with that id on this record")
    return up


def shape(tx, row, upload_id):
    for u in subs.list_uploads(tx, row, (1, 2)):
        if u["id"] == upload_id:
            return u
    raise errors.not_found("No attachment with that id on this record")


def add(tx, cfg, p, actor, kind, rec_id, real_name, mime, sha, size, comment=None, immutable=False, state=1,
        replaces=None, version=1):
    row = subs._record(tx, p, kind, rec_id)
    return attach(tx, cfg, actor, kind, row, real_name, mime, sha, size, comment, immutable, state, replaces,
                  version, p.user_id)


def attach(tx, cfg, actor, kind, row, real_name, mime, sha, size, comment=None, immutable=False, state=1,
           replaces=None, version=1, user_id=None):
    """Adds an upload row for bytes already in the store (also used by import and duplicate)."""
    st = fstore.for_settings(cfg)
    fstore.register(tx, st, sha, size)
    name = clean_name(real_name)
    uid = tx.val("INSERT INTO occ.uploads (rid, real_name, storage_name, comment, user_id, mime, size, sha256, state, "
                 "immutable, version, replaces_id) VALUES (:rid, :rn, :sn, :c, :u, :m, :n, :s, :st, :im, :v, :rp) "
                 "RETURNING id", rid=row["rid"], rn=name, sn=storage_name_for(name), c=comment,
                 u=user_id or actor.user_id, m=guess_mime(name, mime), n=size, s=sha, st=state, im=bool(immutable),
                 v=version, rp=replaces)
    audit.write(tx, actor, "upload.replace" if replaces else "upload.add", kind_id=kind.id, record_id=row["id"],
                rid=row["rid"], team_id=row["team_id"], target="uploads", new=name,
                detail={"upload_id": uid, "sha256": sha.hex(), "size": size, "replaces": replaces})
    _touch(tx, row, user_id or actor.user_id)
    return uid


def _touch(tx, row, user_id):
    tx.run("UPDATE occ.records SET modified_at = now(), modified_by = :u WHERE rid = :rid", u=user_id, rid=row["rid"])


def replace(tx, cfg, p, actor, kind, rec_id, upload_id, real_name, mime, sha, size):
    """Replace: the old version moves to state 2 and stays readable; the new one points back at it."""
    row = subs._record(tx, p, kind, rec_id)
    old = _upload(tx, row, upload_id, states=(1,))
    if old["immutable"]:
        raise errors.forbidden("This attachment is immutable: it cannot be replaced.")
    tx.run("UPDATE occ.uploads SET state = 2 WHERE id = :id", id=old["id"])
    return attach(tx, cfg, actor, kind, row, real_name or old["real_name"], mime, sha, size, old["comment"], False, 1,
                  old["id"], old["version"] + 1, p.user_id)


def edit(tx, p, actor, kind, rec_id, upload_id, body):
    """Describe or rename: comment and/or real_name."""
    row = subs._record(tx, p, kind, rec_id)
    up = _upload(tx, row, upload_id, states=(1,))
    if not isinstance(body, dict) or not ({"comment", "real_name"} & set(body)):
        raise errors.bad("Incorrect value for target: send comment or real_name")
    if up["immutable"]:
        raise errors.forbidden("This attachment is immutable.")
    if "comment" in body:
        new = None if body["comment"] in (None, "") else str(body["comment"])
        tx.run("UPDATE occ.uploads SET comment = :c WHERE id = :id", c=new, id=up["id"])
        audit.write(tx, actor, "upload.update", kind_id=kind.id, record_id=row["id"], rid=row["rid"],
                    team_id=row["team_id"], target="comment", old=up["comment"], new=new,
                    detail={"upload_id": up["id"]})
    if "real_name" in body:
        new = clean_name(body["real_name"])
        tx.run("UPDATE occ.uploads SET real_name = :n WHERE id = :id", n=new, id=up["id"])
        audit.write(tx, actor, "upload.update", kind_id=kind.id, record_id=row["id"], rid=row["rid"],
                    team_id=row["team_id"], target="real_name", old=up["real_name"], new=new,
                    detail={"upload_id": up["id"]})
    _touch(tx, row, p.user_id)
    return shape(tx, row, up["id"])


def remove(tx, p, actor, kind, rec_id, upload_id):
    """Remove: state 3; the bytes stay (the audit log and older versions may point at them)."""
    row = subs._record(tx, p, kind, rec_id)
    up = _upload(tx, row, upload_id, states=(1, 2))
    if up["immutable"]:
        raise errors.forbidden("This attachment is immutable: it cannot be removed.")
    tx.run("UPDATE occ.uploads SET state = 3 WHERE id = :id", id=up["id"])
    audit.write(tx, actor, "upload.delete", kind_id=kind.id, record_id=row["id"], rid=row["rid"],
                team_id=row["team_id"], target="uploads", old=up["real_name"], detail={"upload_id": up["id"]})
    _touch(tx, row, p.user_id)


def for_download(tx, p, kind, rec_id, upload_id):
    row = subs._record(tx, p, kind, rec_id, right=engine.READ, for_update=False)
    return _upload(tx, row, upload_id, states=(1, 2))


def by_storage_name(tx, p, storage_name):
    """Compatibility download: the upload a migrated body's link names, with its record's read check."""
    up = tx.one("SELECT up.*, r.kind_id, r.id AS record_id FROM occ.uploads up JOIN occ.records r ON r.rid = up.rid "
                "WHERE up.storage_name = :s AND up.state IN (1, 2)", s=storage_name)
    if up is None:
        raise errors.not_found()
    row = S.fetch(tx, p, K.BY_ID[up["kind_id"]], up["record_id"], full=False)
    engine.readable_or_raise(p, row, errors)
    return up


def disposition(name):
    ascii_name = re.sub(r'[^A-Za-z0-9._ -]', "_", name) or "file"
    return "attachment; filename=\"%s\"; filename*=UTF-8''%s" % (ascii_name, quote(name, safe=""))


def download_headers(up):
    return {"Content-Disposition": disposition(up["real_name"]), "X-Content-Type-Options": "nosniff",
            "Content-Length": str(up["size"])}
