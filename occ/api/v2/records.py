# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Records of every kind and their sub-resources: tags, comments, steps, links, revisions and the
upload list.

Routers are thin: parse, call one service function in one transaction, shape the
answer. {kind:kind} is experiments | items | experiments_templates | items_types.
"""
from typing import Any, Literal

from fastapi import APIRouter, Body, Depends, Request, Response

from ... import errors
from ...records import kinds as K
from ...records import service as S
from ...exports import render
from ...records import subs
from . import files
from .. import convertors  # noqa: F401  (registers {kind}, {links}, {lookup})
from ..deps import Ctx, ctx, query_dict

router = APIRouter(prefix="/api/v2", tags=["records"])
KindName = Literal["experiments", "items", "experiments_templates", "items_types"]
LinkName = Literal["experiments_links", "items_links"]


def _created(c: Ctx, path):
    return Response(status_code=201, headers={"Location": c.location(path)})


def _prefs(c: Ctx, tx):
    return tx.val("SELECT prefs FROM occ.users WHERE id = :u", u=c.principal.user_id) or {}


# --------------------------------------------------------------------------------------- records
@router.get("/{kind:kind}", summary="List records the caller can read")
def list_records(kind: KindName, request: Request, c: Ctx = Depends(ctx)):
    q = query_dict(request)
    fmt = q.pop("format", None)
    with c.pool.tx(readonly=True) as tx:
        q["_prefs"] = _prefs(c, tx)
        if not fmt:
            return S.list_records(tx, c.principal, K.get(kind), q)
        # a list exports synchronously up to 500 records; above that, 413 and /exports.
        render.check_format(fmt)
        q["limit"] = str(render.SYNC_LIMIT + 1)
        q.setdefault("offset", "0")
        ids = [r["id"] for r in S.list_records(tx, c.principal, K.get(kind), q)]
        if len(ids) > render.SYNC_LIMIT:
            raise errors.OCCError(413, "Too many records to export at once.",
                                  "Up to %d; queue a larger export with POST /api/v2/exports." % render.SYNC_LIMIT)
        return files.export_response(c, tx, K.get(kind), ids, fmt)


@router.post("/{kind:kind}", status_code=201, summary="Create a record")
def create_record(kind: KindName, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        new_id = S.create(tx, c.principal, c.actor, K.get(kind), body if body is not None else {})
    return _created(c, "%s/%d" % (kind, new_id))


@router.get("/{kind:kind}/{rec_id}", summary="Read one record")
def read_record(kind: KindName, rec_id: int, request: Request, c: Ctx = Depends(ctx)):
    fmt = request.query_params.get("format")
    with c.pool.tx(readonly=True) as tx:
        if fmt:
            return files.export_response(c, tx, K.get(kind), [rec_id], fmt, single=True,
                                         changelog=request.query_params.get("changelog") != "0")
        return S.read(tx, c.principal, K.get(kind), rec_id, c.base_url,
                      with_changelog=request.query_params.get("changelog") != "0")


@router.patch("/{kind:kind}/{rec_id}", summary="Change fields, or perform an action (atomic)")
def patch_record(kind: KindName, rec_id: int, c: Ctx = Depends(ctx), body: Any = Body(None)):
    action = body.get("action") if isinstance(body, dict) else None
    if action == "sign":
        from ...signing import service as SG
        with c.pool.tx() as tx:
            return SG.sign(tx, c.settings, c.principal, c.actor, K.get(kind), rec_id, body, c.base_url)
    if action == "timestamp":
        from ...signing import service as SG
        return SG.timestamp(c.pool, c.settings, c.principal, c.actor, K.get(kind), rec_id, c.base_url)
    with c.pool.tx() as tx:
        return S.patch(tx, c.principal, c.actor, K.get(kind), rec_id, body if body is not None else {}, c.base_url)


@router.post("/{kind:kind}/{rec_id}", status_code=201, summary="Duplicate a record")
def duplicate_record(kind: KindName, rec_id: int, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        new_id = S.duplicate(tx, c.principal, c.actor, K.get(kind), rec_id, body or {})
    return _created(c, "%s/%d" % (kind, new_id))


@router.delete("/{kind:kind}/{rec_id}", status_code=204, summary="Delete (soft)")
def delete_record(kind: KindName, rec_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx() as tx:
        S.delete(tx, c.principal, c.actor, K.get(kind), rec_id)
    return Response(status_code=204)


# ------------------------------------------------------------------------------------------- tags
@router.get("/{kind:kind}/{rec_id}/tags", summary="List a record's tags")
def list_tags(kind: KindName, rec_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return subs.list_tags(tx, c.principal, K.get(kind), rec_id)


@router.post("/{kind:kind}/{rec_id}/tags", status_code=201, summary="Add a tag")
def add_tag(kind: KindName, rec_id: int, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        tid = subs.add_tag(tx, c.principal, c.actor, K.get(kind), rec_id, body or {})
    return _created(c, "%s/%d/tags/%d" % (kind, rec_id, tid))


@router.delete("/{kind:kind}/{rec_id}/tags/{tag_id}", status_code=204, summary="Remove a tag")
def remove_tag(kind: KindName, rec_id: int, tag_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx() as tx:
        subs.remove_tag(tx, c.principal, c.actor, K.get(kind), rec_id, tag_id)
    return Response(status_code=204)


# ---------------------------------------------------------------------------------------- steps
@router.get("/{kind:kind}/{rec_id}/steps", summary="List steps")
def list_steps(kind: KindName, rec_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return subs.steps(tx, c.principal, K.get(kind), rec_id)


@router.post("/{kind:kind}/{rec_id}/steps", status_code=201, summary="Add a step")
def add_step(kind: KindName, rec_id: int, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        sid = subs.add_step(tx, c.principal, c.actor, K.get(kind), rec_id, body or {})
    return _created(c, "%s/%d/steps/%d" % (kind, rec_id, sid))


@router.patch("/{kind:kind}/{rec_id}/steps/{step_id}", summary="Edit, finish, lock or reschedule a step")
def edit_step(kind: KindName, rec_id: int, step_id: int, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        return subs.edit_step(tx, c.principal, c.actor, K.get(kind), rec_id, step_id, body or {})


@router.delete("/{kind:kind}/{rec_id}/steps/{step_id}", status_code=204, summary="Delete a step")
def delete_step(kind: KindName, rec_id: int, step_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx() as tx:
        subs.delete_step(tx, c.principal, c.actor, K.get(kind), rec_id, step_id)
    return Response(status_code=204)


# ------------------------------------------------------------------------------------- comments
@router.get("/{kind:kind}/{rec_id}/comments", summary="List comments")
def list_comments(kind: KindName, rec_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return subs.comments(tx, c.principal, K.get(kind), rec_id)


@router.post("/{kind:kind}/{rec_id}/comments", status_code=201, summary="Add a comment")
def add_comment(kind: KindName, rec_id: int, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        cid = subs.add_comment(tx, c.principal, c.actor, K.get(kind), rec_id, body or {})
    return _created(c, "%s/%d/comments/%d" % (kind, rec_id, cid))


@router.get("/{kind:kind}/{rec_id}/comments/{comment_id}", summary="Read one comment")
def get_comment(kind: KindName, rec_id: int, comment_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return subs.get_comment(tx, c.principal, K.get(kind), rec_id, comment_id)


@router.patch("/{kind:kind}/{rec_id}/comments/{comment_id}", summary="Edit own comment")
def edit_comment(kind: KindName, rec_id: int, comment_id: int, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        return subs.edit_comment(tx, c.principal, c.actor, K.get(kind), rec_id, comment_id, body or {})


@router.delete("/{kind:kind}/{rec_id}/comments/{comment_id}", status_code=204, summary="Delete own comment")
def delete_comment(kind: KindName, rec_id: int, comment_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx() as tx:
        subs.delete_comment(tx, c.principal, c.actor, K.get(kind), rec_id, comment_id)
    return Response(status_code=204)


# ------------------------------------------------------------------------------------ revisions
@router.get("/{kind:kind}/{rec_id}/revisions", summary="List body revisions")
def list_revisions(kind: KindName, rec_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return subs.revisions(tx, c.principal, K.get(kind), rec_id)


@router.get("/{kind:kind}/{rec_id}/revisions/{rev_id}", summary="Read one revision")
def get_revision(kind: KindName, rec_id: int, rev_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return subs.revision(tx, c.principal, K.get(kind), rec_id, rev_id)


@router.patch("/{kind:kind}/{rec_id}/revisions/{rev_id}", summary="Restore a revision as the current body")
def restore_revision(kind: KindName, rec_id: int, rev_id: int, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        return subs.restore_revision(tx, c.principal, c.actor, K.get(kind), rec_id, rev_id, body or {}, c.base_url)


# -------------------------------------------------------------------------------------- uploads
@router.get("/{kind:kind}/{rec_id}/uploads", summary="List attachments")
def list_uploads(kind: KindName, rec_id: int, request: Request, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return subs.uploads(tx, c.principal, K.get(kind), rec_id, request.query_params.get("state"))


# ---------------------------------------------------------------------------------------- links
@router.get("/{kind:kind}/{rec_id}/{links:links}", summary="List links to experiments or resources")
def list_links(kind: KindName, rec_id: int, links: LinkName, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return subs.links(tx, c.principal, K.get(kind), rec_id, links[:-6])


@router.post("/{kind:kind}/{rec_id}/{links:links}", status_code=201, summary="Link (body form, which 2.x answers with 500)")
def add_link_body(kind: KindName, rec_id: int, links: LinkName, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        subs.add_link(tx, c.principal, c.actor, K.get(kind), rec_id, links[:-6], None, body or {})
    return _created(c, "%s/%d/%s" % (kind, rec_id, links))


@router.post("/{kind:kind}/{rec_id}/{links:links}/{target_id}", status_code=201, summary="Link to a record")
def add_link(kind: KindName, rec_id: int, links: LinkName, target_id: int, c: Ctx = Depends(ctx),
             body: Any = Body(None)):
    with c.pool.tx() as tx:
        subs.add_link(tx, c.principal, c.actor, K.get(kind), rec_id, links[:-6], target_id, body or {})
    return _created(c, "%s/%d/%s/%d" % (kind, rec_id, links, target_id))


@router.delete("/{kind:kind}/{rec_id}/{links:links}/{target_id}", status_code=204, summary="Remove a link")
def remove_link(kind: KindName, rec_id: int, links: LinkName, target_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx() as tx:
        subs.remove_link(tx, c.principal, c.actor, K.get(kind), rec_id, links[:-6], target_id)
    return Response(status_code=204)
