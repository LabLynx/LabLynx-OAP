# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Uploads and downloads, exports (format= on a record list or a record, and the export queue) and import.

Multipart bodies are parsed by FastAPI into a spooled temporary file; the bytes are then copied into
the content-addressed store with the hash computed during the copy (so equal bytes are stored
once), before the transaction.
"""
from typing import Any, Literal, Optional

from fastapi import APIRouter, Body, Depends, File, Form, Request, Response, UploadFile
from fastapi.responses import StreamingResponse

from ... import errors
from ...exports import importer, queue as exq, render
from ...files import store as fstore
from ...files import uploads as U
from ...records import kinds as K
from .. import convertors  # noqa: F401
from ..deps import Ctx, ctx

router = APIRouter(tags=["files"])
KindName = Literal["experiments", "items", "experiments_templates", "items_types"]


def _chunks(upload: UploadFile):
    fh = upload.file
    fh.seek(0)
    return iter(lambda: fh.read(fstore.CHUNK), b"")


def _stored(c: Ctx, upload: UploadFile):
    with c.pool.tx(readonly=True) as tx:
        limit = U.max_bytes(tx)
    return U.put_stream(c.settings, _chunks(upload), limit)


def _stream(c: Ctx, up):
    st = fstore.for_settings(c.settings)
    try:
        fh = st.open(bytes(up["sha256"]))
    except FileNotFoundError:
        raise errors.OCCError(404, "The file is missing from the store.", "the blob check reports it")
    return StreamingResponse(fstore.iter_file(fh), media_type=up["mime"] or "application/octet-stream",
                             headers=U.download_headers(up))


# --------------------------------------------------------------------------------------- uploads
@router.post("/api/v2/{kind:kind}/{rec_id}/uploads", status_code=201, summary="Attach a file")
def add_upload(kind: KindName, rec_id: int, c: Ctx = Depends(ctx), file: UploadFile = File(...),
               comment: Optional[str] = Form(None)):
    sha, size = _stored(c, file)
    with c.pool.tx() as tx:
        uid = U.add(tx, c.settings, c.principal, c.actor, K.get(kind), rec_id, file.filename, file.content_type,
                    sha, size, comment=comment or None)
    return Response(status_code=201, headers={"Location": c.location("%s/%d/uploads/%d" % (kind, rec_id, uid))})


@router.get("/api/v2/{kind:kind}/{rec_id}/uploads/{upload_id}", summary="Read an attachment, or its bytes")
def get_upload(kind: KindName, rec_id: int, upload_id: int, request: Request, c: Ctx = Depends(ctx)):
    binary = request.query_params.get("format") == "binary"
    with c.pool.tx(readonly=True) as tx:
        up = U.for_download(tx, c.principal, K.get(kind), rec_id, upload_id)
        if not binary:
            row = U.subs._record(tx, c.principal, K.get(kind), rec_id, right="r", for_update=False)
            return U.shape(tx, row, upload_id)
    return _stream(c, up)


@router.post("/api/v2/{kind:kind}/{rec_id}/uploads/{upload_id}", status_code=201,
             summary="Replace a file with a new version")
def replace_upload(kind: KindName, rec_id: int, upload_id: int, c: Ctx = Depends(ctx), file: UploadFile = File(...),
                   action: str = Form("replace")):
    if action != "replace":
        raise errors.bad("Invalid action")
    sha, size = _stored(c, file)
    with c.pool.tx() as tx:
        uid = U.replace(tx, c.settings, c.principal, c.actor, K.get(kind), rec_id, upload_id, file.filename,
                        file.content_type, sha, size)
    return Response(status_code=201, headers={"Location": c.location("%s/%d/uploads/%d" % (kind, rec_id, uid))})


@router.patch("/api/v2/{kind:kind}/{rec_id}/uploads/{upload_id}", summary="Describe or rename an attachment")
def edit_upload(kind: KindName, rec_id: int, upload_id: int, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        return U.edit(tx, c.principal, c.actor, K.get(kind), rec_id, upload_id, body or {})


@router.delete("/api/v2/{kind:kind}/{rec_id}/uploads/{upload_id}", status_code=204,
               summary="Remove an attachment")
def delete_upload(kind: KindName, rec_id: int, upload_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx() as tx:
        U.remove(tx, c.principal, c.actor, K.get(kind), rec_id, upload_id)
    return Response(status_code=204)


@router.get("/app/download.php", summary="Compatibility download for links inside migrated bodies")
def compat_download(f: str, c: Ctx = Depends(ctx), name: Optional[str] = None, storage: Optional[str] = None):
    with c.pool.tx(readonly=True) as tx:
        up = U.by_storage_name(tx, c.principal, f)
    return _stream(c, up)


# --------------------------------------------------------------------------------------- exports
@router.post("/api/v2/exports", status_code=201, summary="Queue an export")
def queue_export(c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        eid = exq.create(tx, c.principal, c.actor, body or {})
    return Response(status_code=201, headers={"Location": c.location("exports/%d" % eid)})


@router.get("/api/v2/exports/{export_id}", summary="Export status or file")
def get_export(export_id: int, request: Request, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        row = exq.get(tx, c.principal, export_id)
    if request.query_params.get("format") != "binary":
        return exq.shape(row)
    if row["state"] != 3 or row["sha256"] is None:
        raise errors.bad("This export is not ready yet.")
    fh = fstore.for_settings(c.settings).open(bytes(row["sha256"]))
    return StreamingResponse(fstore.iter_file(fh), media_type=render.MIME[row["format"]],
                             headers={"Content-Disposition": U.disposition(row["real_name"] or "export"),
                                      "X-Content-Type-Options": "nosniff"})


@router.delete("/api/v2/exports/{export_id}", status_code=204, summary="Delete an export")
def delete_export(export_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx() as tx:
        exq.delete(tx, c.settings, c.principal, c.actor, export_id)
    return Response(status_code=204)


# ---------------------------------------------------------------------------------------- import
@router.get("/api/v2/import", summary="What the importer accepts")
def import_limits(c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return importer.limits(tx)


@router.post("/api/v2/import", status_code=201, summary="Import a .eln or .csv file")
def do_import(c: Ctx = Depends(ctx), file: UploadFile = File(...), entity_type: Optional[str] = Form(None),
              category: Optional[str] = Form(None), owner: Optional[str] = Form(None),
              canread: Optional[str] = Form(None), canwrite: Optional[str] = Form(None)):
    fh = file.file
    fh.seek(0, 2)
    size = fh.tell()
    with c.pool.tx() as tx:
        n = importer.run(tx, c.settings, c.principal, c.actor, file.filename, fh, size,
                         {"entity_type": entity_type, "category": category, "owner": owner,
                          "canread": canread, "canwrite": canwrite})
    # as in 2.x, import answers 201 with the number of records created in the id position.
    return Response(status_code=201, headers={"Location": c.location("import/%d" % n)})


def export_response(c: Ctx, tx, kind, rows_or_ids, fmt, single=False, changelog=True):
    """The answer to a record list or a record with format= (synchronous up to 500 records)."""
    data, name = render.render(tx, c.settings, c.principal, kind, rows_or_ids, fmt, c.base_url, single=single,
                               changelog=changelog)
    return Response(content=data, media_type=render.MIME[fmt],
                    headers={"Content-Disposition": U.disposition(name), "X-Content-Type-Options": "nosniff"})
