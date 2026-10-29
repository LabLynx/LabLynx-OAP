# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The scheduled jobs. Exports register their own handler ('export')
from the exports package; nothing here builds an export.

Each handler does its work in its own transactions and returns a small result that stays on the
job row (payload.result). System changes that touch content are audited with actor 'system'.
"""
from ..audit import verify as V
from ..audit import writer as audit
from .. import mail, timefmt
from ..db import jsonb
from ..records import kinds as K
from . import jobs

SYSTEM = audit.Actor(kind="system")
SESSION_KEEP_DAYS = 7
OUTBOX_MAX_ATTEMPTS = 5
OUTBOX_BATCH = 50
NOTIFY_BATCH = 500
# Notification categories as the mirror numbers them (seen in 2.x data: 13 is a step deadline).
CATEGORY_STEP_DEADLINE = 13
PAGES = {"experiments": "experiments.php", "items": "database.php", "experiments_templates": "templates.php",
         "items_types": "resources-templates.php"}


def _site(tx, name, default):
    v = tx.val("SELECT value FROM occ.site_config WHERE name = :n AND NOT is_secret", n=name)
    return default if v is None or v == "" else v


# ----------------------------------------------------------------------------- audit-verify
@jobs.register("audit-verify")
def audit_verify(ctx, job):
    """The whole chain, every night, and a checkpoint of the head, so tampering is found within a day."""
    with ctx.pool.tx(readonly=True) as tx:
        res = V.verify(tx)
    token, why = _checkpoint_token(ctx, res)
    with ctx.pool.tx() as tx:
        cid = V.checkpoint(tx, res, note_suffix=why, tsa_token=token)
    if not res["ok"]:
        ctx.log.error("audit chain broken", extra={"occ": {"event": "audit chain broken",
                                                           "detail": {"first_bad_id": res["first_bad_id"]}}})
    return {"ok": res["ok"], "checked": res["checked"], "first_bad_id": res["first_bad_id"], "checkpoint_id": cid,
            "timestamped": bool(token)}


def _checkpoint_token(ctx, res):
    """The authority's token over the head hash, asked for outside any transaction."""
    from ..signing import service as SG
    h = V.head_hash(res)
    if h is None:
        return None, None
    with ctx.pool.tx(readonly=True) as tx:
        cfg_tsa = SG.authority_or_none(tx, ctx.settings)
    return SG.checkpoint_token(cfg_tsa, h)


# ------------------------------------------------------------------------- sessions-cleanup
@jobs.register("sessions-cleanup")
def sessions_cleanup(ctx, job):
    with ctx.pool.tx() as tx:
        n = tx.run("DELETE FROM occ.sessions WHERE expires_at < now() - make_interval(days => :d) "
                   "OR revoked_at < now() - make_interval(days => :d)", d=SESSION_KEEP_DAYS)
    return {"deleted": n}


# --------------------------------------------------------------------------- revisions-prune
@jobs.register("revisions-prune")
def revisions_prune(ctx, job):
    """Keep the newest max_revisions per record; never remove one newer than
    min_days_revisions; max_revisions 0 keeps every revision. One audit row per record pruned."""
    with ctx.pool.tx() as tx:
        keep = int(_site(tx, "max_revisions", "10"))
        days = int(_site(tx, "min_days_revisions", "23"))
        if keep <= 0:
            return {"removed": 0, "records": 0, "note": "max_revisions is 0: every revision is kept"}
        rows = tx.all("WITH ranked AS (SELECT id, rid, created_at, row_number() OVER (PARTITION BY rid "
                      "ORDER BY created_at DESC, id DESC) AS rn FROM occ.revisions) "
                      "SELECT ranked.id, ranked.rid, r.kind_id, r.id AS record_id, r.team_id FROM ranked "
                      "JOIN occ.records r ON r.rid = ranked.rid "
                      "WHERE ranked.rn > :keep AND ranked.created_at < now() - make_interval(days => :d) "
                      "ORDER BY ranked.rid, ranked.id", keep=keep, d=days)
        by_rid = {}
        for r in rows:
            by_rid.setdefault(r["rid"], {"row": r, "ids": []})["ids"].append(r["id"])
        for rid, g in by_rid.items():
            tx.run("DELETE FROM occ.revisions WHERE id = ANY(CAST(:ids AS bigint[]))", ids=g["ids"])
            r = g["row"]
            audit.write(tx, SYSTEM, "record.revisions_prune", kind_id=r["kind_id"], record_id=r["record_id"], rid=rid,
                        team_id=r["team_id"], target="revisions",
                        detail={"removed": len(g["ids"]), "max_revisions": keep, "min_days_revisions": days})
    return {"removed": len(rows), "records": len(by_rid)}


# ------------------------------------------------------------------------------ blob-verify
@jobs.register("blob-verify")
def blob_verify(ctx, job):
    """Re-hash every stored blob. A blob whose bytes no longer hash to its name, or that is
    missing, is audited and counted; a good one gets verified_at."""
    with ctx.pool.tx(readonly=True) as tx:
        blobs = [bytes(r["sha256"]) for r in tx.all("SELECT sha256 FROM occ.file_blobs WHERE backend = :b "
                                                     "ORDER BY sha256", b=ctx.store.backend)]
    bad, good = [], 0
    for sha in blobs:
        try:
            ok = ctx.store.rehash(sha) == sha
            why = "the stored bytes no longer hash to the blob's name"
        except FileNotFoundError:
            ok, why = False, "the blob is missing from the file store"
        with ctx.pool.tx() as tx:
            if ok:
                tx.run("UPDATE occ.file_blobs SET verified_at = now() WHERE sha256 = :s", s=sha)
                good += 1
            else:
                audit.write(tx, SYSTEM, "upload.blob_mismatch", target="file_blob",
                            detail={"sha256": sha.hex(), "reason": why})
                bad.append(sha.hex())
    if bad:
        ctx.log.error("blob mismatch", extra={"occ": {"event": "blob mismatch", "detail": {"count": len(bad)}}})
    return {"checked": len(blobs), "ok": good, "mismatches": len(bad), "bad": bad[:50]}


# ----------------------------------------------------------------------------------- outbox
@jobs.register("outbox")
def outbox(ctx, job):
    """SMTP delivery with retry: 5 attempts per message, waiting 1, 2, 4, 8 minutes between."""
    sent = failed = 0
    with ctx.pool.tx(readonly=True) as tx:
        ids = [r["id"] for r in tx.all("SELECT id FROM occ.email_outbox WHERE sent_at IS NULL AND attempts < :m "
                                       "AND send_after <= now() ORDER BY send_after, id LIMIT :n",
                                       m=OUTBOX_MAX_ATTEMPTS, n=OUTBOX_BATCH)]
    if not ids:
        return {"sent": 0, "failed": 0}
    for oid in ids:
        with ctx.pool.tx() as tx:
            m = tx.one("SELECT id, to_address, subject, body_text, body_html, attempts FROM occ.email_outbox "
                       "WHERE id = :id AND sent_at IS NULL FOR UPDATE SKIP LOCKED", id=oid)
            if m is None:
                continue
            try:
                cfg = mail.settings(tx, ctx.settings)
                mail.send(cfg, mail.build(cfg, str(m["to_address"]), m["subject"], m["body_text"], m["body_html"]))
            except Exception as exc:  # noqa: BLE001 - kept on the message and retried
                failed += 1
                tx.run("UPDATE occ.email_outbox SET attempts = attempts + 1, last_error = :e, "
                       "send_after = now() + make_interval(mins => :w) WHERE id = :id",
                       id=oid, e=("%s: %s" % (type(exc).__name__, exc))[:300], w=2 ** int(m["attempts"]))
                continue
            tx.run("UPDATE occ.email_outbox SET sent_at = now(), attempts = attempts + 1, last_error = NULL "
                   "WHERE id = :id", id=oid)
            sent += 1
    return {"sent": sent, "failed": failed}


# ----------------------------------------------------------------------------- notify-email
def _notif_text(n):
    body = n["body"] or {}
    lines = ["%s: %s" % (k, body[k]) for k in sorted(body) if not isinstance(body[k], (dict, list))]
    return "Notification (category %s) of %s\n%s" % (n["category"], n["created_at"].strftime("%Y-%m-%d %H:%M UTC"),
                                                     "\n".join(lines))


@jobs.register("notify-email")
def notify_email(ctx, job):
    """Hands notifications marked send_email to the outbox: one message per person when
    email_send_grouped is on, otherwise one per notification. email_sent_at records the hand-off."""
    with ctx.pool.tx() as tx:
        rows = tx.all("SELECT n.id, n.user_id, n.category, n.body, n.created_at, u.email, "
                      "(u.archived_at IS NULL AND u.deleted_at IS NULL) AS active FROM occ.notifications n "
                      "JOIN occ.users u ON u.id = n.user_id WHERE n.send_email AND n.email_sent_at IS NULL "
                      "ORDER BY n.user_id, n.id LIMIT :n FOR UPDATE OF n SKIP LOCKED", n=NOTIFY_BATCH)
        if not rows:
            return {"queued": 0, "notifications": 0}
        grouped = str(_site(tx, "email_send_grouped", "0")) in ("1", "true")
        prefix = (_site(tx, "mail_subject_prefix", "") or "").strip()
        subj = ((prefix + " ") if prefix else "")
        queued = 0
        people = {}
        for r in rows:
            people.setdefault(r["user_id"], []).append(r)
        for uid, ns in people.items():
            if not ns[0]["active"]:
                continue
            batches = [ns] if grouped else [[n] for n in ns]
            for b in batches:
                text = "\n\n".join(_notif_text(n) for n in b)
                subject = subj + ("%d new notifications" % len(b) if len(b) > 1 else "New notification")
                mail.queue(tx, str(b[0]["email"]), subject, text, notification_id=b[0]["id"])
                queued += 1
        tx.run("UPDATE occ.notifications SET email_sent_at = now() WHERE id = ANY(CAST(:ids AS bigint[]))",
               ids=[r["id"] for r in rows])
    return {"queued": queued, "notifications": len(rows)}


# ---------------------------------------------------------------------------- step-deadlines
@jobs.register("step-deadlines")
def step_deadlines(ctx, job):
    """Steps whose deadline passed, unfinished, with deadline_notif on: the record's owner gets a
    notification (category 13), and deadline_notif is switched off so it is sent once (audited)."""
    with ctx.pool.tx() as tx:
        rows = tx.all("SELECT s.id AS step_id, s.deadline, r.rid, r.id AS record_id, r.kind_id, r.team_id, r.owner_id, "
                      "u.prefs FROM occ.steps s JOIN occ.records r ON r.rid = s.rid JOIN occ.users u ON u.id = r.owner_id "
                      "WHERE s.deadline IS NOT NULL AND s.deadline <= now() AND s.deadline_notif AND NOT s.finished "
                      "AND s.deleted_at IS NULL AND r.state <> 3 ORDER BY s.deadline LIMIT 500 FOR UPDATE OF s SKIP LOCKED")
        for r in rows:
            kind = K.BY_ID[r["kind_id"]]
            prefs = r["prefs"] or {}
            send = str(prefs.get("notif_step_deadline_email", 1)) not in ("0", "false", "False")
            body = {"step_id": r["step_id"], "deadline": timefmt.out(r["deadline"]), "entity_id": r["record_id"],
                    "entity_page": PAGES.get(kind.code, kind.page)}
            tx.run("INSERT INTO occ.notifications (user_id, category, body, send_email) "
                   "VALUES (:u, :c, CAST(:b AS jsonb), :s)", u=r["owner_id"], c=CATEGORY_STEP_DEADLINE,
                   b=jsonb(body), s=send)
            tx.run("UPDATE occ.steps SET deadline_notif = false WHERE id = :id", id=r["step_id"])
            audit.write(tx, SYSTEM, "step.update", kind_id=r["kind_id"], record_id=r["record_id"], rid=r["rid"],
                        team_id=r["team_id"], target="deadline_notif", old=True, new=False,
                        detail={"step_id": r["step_id"], "why": "deadline notification sent"})
    return {"notified": len(rows)}


# ------------------------------------------------------------------------------ idp-refresh
@jobs.register("idp-refresh")
def idp_refresh(ctx, job):
    """Every enabled source with auto_refresh on is fetched and applied (people/idp_refresh.py); a source
    that fails is reported in the result and the others still run."""
    from ..people import idp_refresh as R
    with ctx.pool.tx(readonly=True) as tx:
        ids = [r["id"] for r in tx.all("SELECT id FROM occ.idp_sources WHERE enabled AND auto_refresh ORDER BY id")]
    done, failed = [], {}
    fetcher = getattr(ctx, "idp_fetcher", None)
    for sid in ids:
        try:
            _src, counts = R.refresh(ctx.pool, SYSTEM, sid, fetcher=fetcher)
            done.append(dict(counts, source_id=sid))
        except Exception as ex:                                          # noqa: BLE001
            failed[str(sid)] = getattr(ex, "message", None) or type(ex).__name__
    if failed:
        ctx.log.error("idp refresh failed", extra={"occ": {"event": "idp refresh failed",
                                                           "detail": {"sources": sorted(failed)}}})
    return {"sources": len(ids), "refreshed": done, "failed": failed}


# ------------------------------------------------------------------------------ files-sweep
@jobs.register("files-sweep")
def files_sweep(ctx, job):
    """Blobs no file_blobs row names, older than the grace period, go (files/sweep.py)."""
    from ..files import sweep
    return sweep.sweep(ctx.pool, ctx.settings, store=ctx.store)
