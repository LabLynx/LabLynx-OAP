# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Operations: mail (queue a message, and the synchronous test email) and the sync's status and
direction. Running the sync on demand waits for the sync engine: a route that queued work nothing
can do would report a run that never happens."""
import logging
from typing import Any

from fastapi import APIRouter, Body, Depends, Response
from fastapi.responses import JSONResponse

from ... import errors, mail
from ...audit import writer as audit
from ...sync import status as sync_status
from ..deps import Ctx, ctx

router = APIRouter(tags=["ops"])
log = logging.getLogger("occ.mail")
MAX_SUBJECT = 300
MAX_TEXT = 1024 * 1024


def _clean_line(v, name, limit):
    s = str(v or "").strip()
    if not s or "\r" in s or "\n" in s or len(s) > limit:
        raise errors.bad("Incorrect value for %s" % name)
    return s


@router.post("/api/v2/occ/mail", status_code=202, summary="Send an email through the site's mail server (queued)")
def queue_mail(c: Ctx = Depends(ctx), body: Any = Body(None)):
    p = c.principal
    if not p.is_sysadmin or not (p.site_scope or p.can_write):
        raise errors.forbidden("Only a sysadmin or a site-scope key can send mail through the OCC.")
    body = body if isinstance(body, dict) else {}
    to = str(body.get("to") or "").strip()
    if not mail.valid_address(to):
        raise errors.bad("Incorrect value for to")
    subject = _clean_line(body.get("subject"), "subject", MAX_SUBJECT)
    text = body.get("text")
    if not isinstance(text, str) or not text.strip() or len(text) > MAX_TEXT:
        raise errors.bad("Incorrect value for text")
    html = body.get("html")
    if html is not None and (not isinstance(html, str) or len(html) > MAX_TEXT):
        raise errors.bad("Incorrect value for html")
    with c.pool.tx() as tx:
        oid = mail.queue(tx, to, subject, text, html or None)
        audit.write(tx, c.actor, "mail.queue", target="email_outbox", detail={"outbox_id": oid})
    return JSONResponse({"id": oid}, status_code=202)


@router.post("/api/v2/instance", summary="Send a test email through the site's mail server")
def instance_action(c: Ctx = Depends(ctx), body: Any = Body(None)):
    if not c.principal.is_sysadmin:
        raise errors.forbidden("Only a sysadmin can do that.")
    body = body if isinstance(body, dict) else {}
    if body.get("action") != "test":
        raise errors.bad("Incorrect value for action")
    to = str(body.get("email") or "").strip()
    if not mail.valid_address(to):
        raise errors.bad("Incorrect value for email")
    try:
        with c.pool.tx(readonly=True) as tx:
            cfg = mail.settings(tx, c.settings)
        mail.send(cfg, mail.build(cfg, to, "Test email", "This is a test email sent through the site's mail server."))
    except Exception as exc:  # noqa: BLE001 - the answer is 2.x's fixed message when mail cannot be sent; the type is logged
        log.error("test email failed", extra={"occ": {"event": "test email failed",
                                                      "detail": {"error": type(exc).__name__}}})
        raise errors.bad(mail.TEST_FAILED)
    return Response(status_code=200)


@router.get("/api/v2/occ/sync", summary="Sync status: direction, last run, lag, counts")
def get_sync(c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return sync_status.status(tx, c.principal)


@router.patch("/api/v2/occ/sync", summary="Set the sync direction (off, A, B); never both")
def patch_sync(c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        return sync_status.set_direction(tx, c.principal, c.actor, body)
