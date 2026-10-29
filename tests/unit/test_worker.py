# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The background worker, mail (sending through the site's mail server, and the test e-mail) and the
sync settings (reading the sync status and setting its direction).

Jobs are claimed with FOR UPDATE SKIP LOCKED, retried with a delay and marked dead after five
failures; schedules are parsed and queue one job per due run however many workers tick; each
scheduled handler does its documented job on rows made here. Mail goes to an SMTP server this
test starts on 127.0.0.1, so nothing leaves the machine.
"""
import base64
import datetime as dt
import hashlib
import logging
import os
import socketserver
import threading
import zoneinfo

import pytest

from occ import db
from occ.audit import verify as V
from occ.files import store as store_mod
from occ.worker import handlers, jobs, runner, schedules  # noqa: F401  (handlers registers the kinds)

UTC = dt.timezone.utc
CHI = zoneinfo.ZoneInfo("America/Chicago")


@pytest.fixture(scope="module")
def wctx(cfg, pool):
    return runner.WorkerCtx(pool=pool, settings=cfg, store=store_mod.for_settings(cfg),
                            log=logging.getLogger("occ.worker.test"))


def _set(pool, **values):
    with pool.tx() as tx:
        for k, v in values.items():
            if v is None:
                tx.run("DELETE FROM occ.site_config WHERE name = :n", n=k)
            else:
                tx.run("INSERT INTO occ.site_config (name, value) VALUES (:n, :v) ON CONFLICT (name) DO UPDATE "
                       "SET value = EXCLUDED.value", n=k, v=str(v))


# ------------------------------------------------------------------------------- the queue
def test_two_workers_never_claim_the_same_job(cfg, pool):
    with pool.tx() as tx:
        a = jobs.enqueue(tx, "t-claim")
        b = jobs.enqueue(tx, "t-claim")
    c1, c2 = db.connect(cfg.db_params()), db.connect(cfg.db_params())
    try:
        c1.run("BEGIN")
        c2.run("BEGIN")
        j1 = jobs.claim(db.Tx(c1), "w1", ["t-claim"])
        j2 = jobs.claim(db.Tx(c2), "w2", ["t-claim"])          # does not wait on w1's row
        j3 = jobs.claim(db.Tx(c2), "w2", ["t-claim"])
        assert {j1["id"], j2["id"]} == {a, b} and j3 is None
        c1.run("COMMIT")
        c2.run("COMMIT")
    finally:
        c1.close()
        c2.close()
    with pool.tx() as tx:
        rows = tx.all("SELECT state, locked_by, attempts FROM occ.jobs WHERE id = ANY(CAST(:i AS bigint[])) ORDER BY id",
                      i=[a, b])
    assert all(r["state"] == "running" and r["attempts"] == 1 for r in rows)
    assert {r["locked_by"] for r in rows} == {"w1", "w2"}


def test_dedupe_key_keeps_one_copy_while_queued(pool):
    with pool.tx() as tx:
        a = jobs.enqueue(tx, "t-dedupe", dedupe_key="t-dedupe:1")
        b = jobs.enqueue(tx, "t-dedupe", dedupe_key="t-dedupe:1")
        assert a == b
        assert tx.val("SELECT count(*) FROM occ.jobs WHERE dedupe_key = 't-dedupe:1'") == 1
        jobs.finish(tx, a)
        c = jobs.enqueue(tx, "t-dedupe", dedupe_key="t-dedupe:1")   # done: a new run may queue
        assert c != a


def test_a_failing_job_is_retried_with_a_delay_then_dead(wctx, pool):
    calls = []

    @jobs.register("t-boom")
    def boom(ctx, job):
        calls.append(job["attempts"])
        raise RuntimeError("deliberate failure")

    with pool.tx() as tx:
        jid = jobs.enqueue(tx, "t-boom")
    delays = []
    for attempt in range(1, 6):
        assert jobs.run_one(wctx, "w", ["t-boom"]) == (jid, "dead" if attempt == 5 else "queued")
        with pool.tx() as tx:
            r = tx.one("SELECT state, run_at, last_error, extract(epoch FROM run_at - now()) AS wait FROM occ.jobs "
                       "WHERE id = :i", i=jid)
            if attempt < 5:
                delays.append(float(r["wait"]))
                tx.run("UPDATE occ.jobs SET run_at = now() WHERE id = :i", i=jid)    # do not wait in a test
    assert calls == [1, 2, 3, 4, 5]
    assert r["state"] == "dead" and "RuntimeError" in r["last_error"] and "deliberate failure" in r["last_error"]
    assert [round(d / 30) for d in delays] == [1, 2, 4, 8]                # 30 s, 60 s, 120 s, 240 s
    assert jobs.run_one(wctx, "w", ["t-boom"]) is None                     # a dead job is never claimed again
    with pool.tx() as tx:
        assert jobs.counts(tx)["dead"] >= 1


def test_a_job_with_no_handler_fails_and_a_stale_running_job_is_put_back(wctx, pool):
    with pool.tx() as tx:
        jid = jobs.enqueue(tx, "t-nohandler")
    assert jobs.run_one(wctx, "w", ["t-nohandler"]) == (jid, "queued")
    with pool.tx() as tx:
        assert "no handler" in tx.val("SELECT last_error FROM occ.jobs WHERE id = :i", i=jid)
        tx.run("UPDATE occ.jobs SET state = 'running', locked_by = 'gone:1', locked_at = now() - interval '2 hours' "
               "WHERE id = :i", i=jid)
        assert jobs.reap(tx) >= 1
        assert tx.val("SELECT state FROM occ.jobs WHERE id = :i", i=jid) == "queued"


def test_a_handler_result_is_kept_on_the_job(wctx, pool):
    @jobs.register("t-ok")
    def ok(ctx, job):
        return {"answer": job["payload"]["n"] * 2}

    with pool.tx() as tx:
        jid = jobs.enqueue(tx, "t-ok", {"n": 21})
    assert jobs.run_one(wctx, "w", ["t-ok"]) == (jid, "done")
    with pool.tx() as tx:
        r = tx.one("SELECT state, payload, finished_at FROM occ.jobs WHERE id = :i", i=jid)
    assert r["state"] == "done" and r["payload"]["result"] == {"answer": 42} and r["finished_at"] is not None


# ---------------------------------------------------------------------------- schedules
def test_cron_subset_parses_and_finds_the_next_run():
    t = dt.datetime(2026, 10, 28, 14, 7, 30, tzinfo=UTC)                  # 09:07:30 in Chicago
    assert schedules.next_after("* * * * *", t, CHI) == dt.datetime(2026, 10, 28, 14, 8, tzinfo=UTC)
    assert schedules.next_after("*/5 * * * *", t, CHI) == dt.datetime(2026, 10, 28, 14, 10, tzinfo=UTC)
    assert schedules.next_after("0 * * * *", t, CHI) == dt.datetime(2026, 10, 28, 15, 0, tzinfo=UTC)
    # nightly 02:30 is 02:30 in the site's time zone (CDT, UTC-5, on Oct 29)
    assert schedules.next_after("30 2 * * *", t, CHI) == dt.datetime(2026, 10, 29, 7, 30, tzinfo=UTC)
    # after the clocks change (Nov 1, 2026) the same wall time is UTC-6
    assert schedules.next_after("30 2 * * *", dt.datetime(2026, 11, 2, 0, 0, tzinfo=UTC), CHI) == \
        dt.datetime(2026, 11, 2, 8, 30, tzinfo=UTC)
    # weekly on Sunday 03:00 (0 and 7 both mean Sunday)
    for spec in ("0 3 * * 0", "0 3 * * 7"):
        assert schedules.next_after(spec, t, CHI) == dt.datetime(2026, 11, 1, 9, 0, tzinfo=UTC)
    assert schedules.next_after("15 10 1,15 * *", t, CHI) == dt.datetime(2026, 11, 1, 16, 15, tzinfo=UTC)
    assert schedules.next_after("0 9-17/4 * * *", t, CHI) == dt.datetime(2026, 10, 28, 18, 0, tzinfo=UTC)
    for bad in ("* * * *", "60 * * * *", "a * * * *", "*/0 * * * *", "5-1 * * * *", "0 0 31 2 *"):
        with pytest.raises(schedules.CronError):
            schedules.next_after(bad, t, CHI)


def test_the_nine_design_schedules_are_seeded_once(pool):
    names = {n for n, _c, _k in schedules.SCHEDULES}
    assert names == {"notify-email", "step-deadlines", "outbox", "sessions-cleanup", "revisions-prune",
                     "audit-verify", "blob-verify", "idp-refresh", "files-sweep"}
    assert all(k in jobs.HANDLERS for _n, _c, k in schedules.SCHEDULES)
    with pool.tx() as tx:
        schedules.seed(tx)
        tx.run("UPDATE occ.job_schedules SET enabled = false WHERE name = 'idp-refresh'")
        assert schedules.seed(tx) == 0                                    # idempotent, keeps the switch
        rows = {r["name"]: r for r in tx.all("SELECT * FROM occ.job_schedules")}
        assert names <= set(rows) and rows["idp-refresh"]["enabled"] is False
        assert rows["audit-verify"]["cron"] == "30 2 * * *" and rows["revisions-prune"]["cron"] == "10 2 * * *"
        tx.run("UPDATE occ.job_schedules SET enabled = true WHERE name = 'idp-refresh'")


def test_a_due_schedule_queues_one_job_however_many_workers_tick(cfg, pool):
    with pool.tx() as tx:
        tx.run("INSERT INTO occ.job_schedules (name, cron, job_kind, next_run_at) VALUES "
               "('t-sched', '* * * * *', 't-sched', now() - interval '1 minute')")
    c1, c2 = db.connect(cfg.db_params()), db.connect(cfg.db_params())
    try:
        c1.run("BEGIN")
        c2.run("BEGIN")
        q1 = [x for x in schedules.tick(db.Tx(c1)) if x[0] == "t-sched"]
        q2 = [x for x in schedules.tick(db.Tx(c2)) if x[0] == "t-sched"]  # the row is skipped, not waited on
        c1.run("COMMIT")
        c2.run("COMMIT")
    finally:
        c1.close()
        c2.close()
    assert len(q1) == 1 and q2 == []
    with pool.tx() as tx:
        # due again while the first run still waits: no second copy (dedupe)
        tx.run("UPDATE occ.job_schedules SET next_run_at = now() - interval '1 second' WHERE name = 't-sched'")
        again = [x for x in schedules.tick(tx) if x[0] == "t-sched"]
        assert again[0][1] == q1[0][1]
        assert tx.val("SELECT count(*) FROM occ.jobs WHERE kind = 't-sched'") == 1
        s = tx.one("SELECT next_run_at, last_job_id FROM occ.job_schedules WHERE name = 't-sched'")
        assert s["next_run_at"] > dt.datetime.now(UTC) and s["last_job_id"] == q1[0][1]
        tx.run("DELETE FROM occ.job_schedules WHERE name = 't-sched'")


# ------------------------------------------------------------------------------ handlers
def test_audit_verify_job_writes_a_checkpoint_and_names_an_altered_row(wctx, pool, client, world):
    client.post("/api/v2/experiments", json={"title": "worker audit"}, headers=world.h("alice"))
    with pool.tx() as tx:
        jid = jobs.enqueue(tx, "audit-verify")
    assert jobs.run_one(wctx, "w", ["audit-verify"]) == (jid, "done")
    with pool.tx() as tx:
        res = tx.val("SELECT payload->'result' FROM occ.jobs WHERE id = :i", i=jid)
        cp = tx.one("SELECT * FROM occ.audit_checkpoints ORDER BY id DESC LIMIT 1")
        head = tx.val("SELECT max(id) FROM occ.audit_events")
    assert res["ok"] is True and res["checkpoint_id"] == cp["id"]
    assert cp["verified_ok"] and cp["upto_id"] == head and cp["tsa_token"] is None
    assert "no timestamp authority configured" in cp["verify_note"]

    # one row altered (append-only trigger off for a moment, on this scratch database only)
    with pool.tx() as tx:
        victim = tx.val("SELECT max(id) FROM occ.audit_events WHERE category = 'record.create'")
        old = tx.val("SELECT new_value FROM occ.audit_events WHERE id = :i", i=victim)
        tx.run("ALTER TABLE occ.audit_events DISABLE TRIGGER audit_events_no_update")
        tx.run("UPDATE occ.audit_events SET new_value = 'forged' WHERE id = :i", i=victim)
        tx.run("ALTER TABLE occ.audit_events ENABLE TRIGGER audit_events_no_update")
        jid = jobs.enqueue(tx, "audit-verify")
    try:
        assert jobs.run_one(wctx, "w", ["audit-verify"]) == (jid, "done")
        with pool.tx() as tx:
            res = tx.val("SELECT payload->'result' FROM occ.jobs WHERE id = :i", i=jid)
            cp = tx.one("SELECT * FROM occ.audit_checkpoints ORDER BY id DESC LIMIT 1")
        assert res["ok"] is False and res["first_bad_id"] == victim
        assert cp["verified_ok"] is False and cp["upto_id"] == -victim and ("FAILED at id %d" % victim) in cp["verify_note"]
        m = client.get("/metrics").text
        assert "occ_audit_chain_ok 0" in m
    finally:
        with pool.tx() as tx:
            tx.run("ALTER TABLE occ.audit_events DISABLE TRIGGER audit_events_no_update")
            tx.run("UPDATE occ.audit_events SET new_value = :v WHERE id = :i", v=old, i=victim)
            tx.run("ALTER TABLE occ.audit_events ENABLE TRIGGER audit_events_no_update")
    client.post("/api/v2/experiments", json={"title": "worker audit after"}, headers=world.h("alice"))
    assert handlers.audit_verify(wctx, {})["ok"] is True


def test_sessions_cleanup_removes_only_old_expired_or_revoked(wctx, pool, world):
    uid, tid = world.users["alice"], world.teams["A"]
    rows = {"live": ("now() + interval '1 hour'", "NULL"), "expired-old": ("now() - interval '10 days'", "NULL"),
            "expired-new": ("now() - interval '1 day'", "NULL"),
            "revoked-old": ("now() + interval '1 hour'", "now() - interval '8 days'")}
    keys = {}
    with pool.tx() as tx:
        for name in rows:
            keys[name] = hashlib.sha256(("t-sess-" + name + str(os.getpid())).encode()).digest()
        tx.run("INSERT INTO occ.sessions (id_hash, user_id, team_id, csrf_hash, expires_at, revoked_at) VALUES "
               "(:a, :u, :t, :a, now() + interval '1 hour', NULL), (:b, :u, :t, :b, now() - interval '10 days', NULL), "
               "(:c, :u, :t, :c, now() - interval '1 day', NULL), (:d, :u, :t, :d, now() + interval '1 hour', "
               "now() - interval '8 days')", a=keys["live"], b=keys["expired-old"], c=keys["expired-new"],
               d=keys["revoked-old"], u=uid, t=tid)
    out = handlers.sessions_cleanup(wctx, {})
    with pool.tx() as tx:
        left = {bytes(r["id_hash"]) for r in tx.all("SELECT id_hash FROM occ.sessions")}
        tx.run("DELETE FROM occ.sessions WHERE id_hash = ANY(CAST(:k AS bytea[]))", k=list(keys.values()))
    assert out["deleted"] >= 2
    assert keys["live"] in left and keys["expired-new"] in left
    assert keys["expired-old"] not in left and keys["revoked-old"] not in left


def test_revisions_prune_keeps_the_newest_and_the_recent_and_is_audited(wctx, pool, client, world):
    r = client.post("/api/v2/experiments", json={"title": "prune me"}, headers=world.h("alice"))
    eid = int(r.headers["location"].rsplit("/", 1)[1])
    with pool.tx() as tx:
        rid = tx.val("SELECT rid FROM occ.records WHERE kind_id = 1 AND id = :i", i=eid)
        ids = []
        for days in (40, 30, 20, 10, 0):
            ids.append(tx.val("INSERT INTO occ.revisions (rid, body, body_sha256, user_id, created_at) VALUES "
                              "(:r, :b, :s, :u, now() - make_interval(days => :d)) RETURNING id", r=rid,
                              b="v%d" % days, s=hashlib.sha256(b"x").digest(), u=world.users["alice"], d=days))
    _set(pool, max_revisions=0, min_days_revisions=5)
    assert handlers.revisions_prune(wctx, {})["removed"] == 0                    # 0 keeps every revision
    _set(pool, max_revisions=2, min_days_revisions=5)
    try:
        out = handlers.revisions_prune(wctx, {})
    finally:
        _set(pool, max_revisions=None, min_days_revisions=None)
    with pool.tx() as tx:
        left = [x["id"] for x in tx.all("SELECT id FROM occ.revisions WHERE rid = :r ORDER BY id", r=rid)]
        a = tx.one("SELECT * FROM occ.audit_events WHERE category = 'record.revisions_prune' AND rid = :r", r=rid)
    # newest two kept (10 days, today); the three older than both the count and five days removed
    assert left == ids[3:] and out["removed"] >= 3
    assert a is not None and a["actor_kind"] == "system" and a["record_id"] == eid


def test_blob_verify_counts_a_changed_blob(wctx, pool, client):
    st = wctx.store
    sha, size = st.put_bytes(b"worker blob check %d" % os.getpid())
    with pool.tx() as tx:
        store_mod.register(tx, st, sha, size)
    out = handlers.blob_verify(wctx, {})
    assert out["mismatches"] == 0 and out["ok"] >= 1
    path = os.path.join(st.root, store_mod.location(sha))
    with open(path, "wb") as fh:
        fh.write(b"tampered")
    try:
        with pool.tx() as tx:
            jid = jobs.enqueue(tx, "blob-verify")
        assert jobs.run_one(wctx, "w", ["blob-verify"]) == (jid, "done")
        with pool.tx() as tx:
            res = tx.val("SELECT payload->'result' FROM occ.jobs WHERE id = :i", i=jid)
            a = tx.one("SELECT * FROM occ.audit_events WHERE category = 'upload.blob_mismatch' ORDER BY id DESC LIMIT 1")
        assert res["mismatches"] == 1 and res["bad"] == [sha.hex()]
        assert a["detail"]["sha256"] == sha.hex()
        assert "occ_blob_mismatches 1" in client.get("/metrics").text
    finally:
        with pool.tx() as tx:
            assert store_mod.delete_if_unreferenced(tx, st, sha)


# ------------------------------------------------------------------------------------- mail
class _SMTP(socketserver.StreamRequestHandler):
    """Just enough SMTP to receive a message."""

    def handle(self):
        srv = self.server
        self.wfile.write(b"220 test ESMTP\r\n")
        rcpt, data = [], None
        while True:
            line = self.rfile.readline()
            if not line:
                return
            cmd = line.strip().upper()
            if cmd.startswith(b"EHLO"):
                self.wfile.write(b"250-test\r\n250 AUTH PLAIN\r\n")
            elif cmd.startswith(b"HELO"):
                self.wfile.write(b"250 test\r\n")
            elif cmd.startswith(b"AUTH PLAIN "):
                srv.auth.append(base64.b64decode(line.strip()[11:]).decode())
                self.wfile.write(b"235 ok\r\n")
            elif cmd.startswith(b"MAIL FROM"):
                self.wfile.write(b"250 ok\r\n")
            elif cmd.startswith(b"RCPT TO"):
                rcpt.append(line.strip()[8:].decode())
                if srv.refuse:
                    self.wfile.write(b"550 no such user\r\n")
                else:
                    self.wfile.write(b"250 ok\r\n")
            elif cmd == b"DATA":
                self.wfile.write(b"354 go\r\n")
                buf = []
                while True:
                    ln = self.rfile.readline()
                    if ln in (b".\r\n", b".\n", b""):
                        break
                    buf.append(ln)
                data = b"".join(buf)
                srv.received.append((rcpt, data))
                self.wfile.write(b"250 queued\r\n")
            elif cmd == b"QUIT":
                self.wfile.write(b"221 bye\r\n")
                return
            else:
                self.wfile.write(b"250 ok\r\n")


@pytest.fixture
def no_smtp_password(pool):
    """Sets aside any smtp_password another test stored (configuration tests seal one), and puts
    it back afterwards."""
    with pool.tx() as tx:
        saved = tx.one("SELECT name, value, is_secret, value_enc FROM occ.site_config WHERE name = 'smtp_password'")
        tx.run("DELETE FROM occ.site_config WHERE name = 'smtp_password'")
    yield
    with pool.tx() as tx:
        tx.run("DELETE FROM occ.site_config WHERE name = 'smtp_password'")
        if saved is not None:
            tx.run("INSERT INTO occ.site_config (name, value, is_secret, value_enc) VALUES (:n, :v, :s, :e)",
                   n=saved["name"], v=saved["value"], s=saved["is_secret"], e=saved["value_enc"])


@pytest.fixture
def smtp(pool, no_smtp_password):
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _SMTP)
    srv.daemon_threads = True
    srv.received, srv.refuse, srv.auth = [], False, []
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    _set(pool, smtp_address="127.0.0.1", smtp_port=srv.server_address[1], smtp_encryption="none",
         mail_from="occ-test@example.com")
    try:
        yield srv
    finally:
        _set(pool, smtp_address=None, smtp_port=None, smtp_encryption=None, mail_from=None)
        srv.shutdown()
        srv.server_close()


def test_x14_queues_mail_and_the_outbox_delivers_it(wctx, pool, client, world, smtp):
    body = {"to": "someone@example.com", "subject": "Hello", "text": "plain words", "html": "<p>words</p>"}
    assert client.post("/api/v2/occ/mail", json=body, headers=world.h("alice")).status_code == 403
    assert client.post("/api/v2/occ/mail", json=body, headers=world.h("admin")).status_code == 403
    for bad in ({**body, "to": "no-at-sign"}, {**body, "to": "a@example.com\r\nBcc: x@example.com"},
                {**body, "subject": "two\nlines"}, {**body, "text": ""}):
        assert client.post("/api/v2/occ/mail", json=bad, headers=world.h("sys")).status_code == 400
    r = client.post("/api/v2/occ/mail", json=body, headers=world.h("sys_site"))     # a site-scope key may
    assert r.status_code == 202
    oid = r.json()["id"]
    with pool.tx() as tx:
        assert tx.val("SELECT sent_at FROM occ.email_outbox WHERE id = :i", i=oid) is None
        assert tx.val("SELECT count(*) FROM occ.audit_events WHERE category = 'mail.queue' "
                      "AND (detail->>'outbox_id')::bigint = :i", i=oid) == 1
    out = handlers.outbox(wctx, {})
    assert out["sent"] >= 1
    with pool.tx() as tx:
        assert tx.val("SELECT sent_at FROM occ.email_outbox WHERE id = :i", i=oid) is not None
    rcpt, data = smtp.received[-1]
    assert "someone@example.com" in rcpt[0] and b"Subject: Hello" in data and b"plain words" in data


def test_outbox_retries_a_refused_message_with_a_delay(wctx, pool, smtp):
    smtp.refuse = True
    with pool.tx() as tx:
        from occ import mail
        oid = mail.queue(tx, "refused@example.com", "x", "y")
    handlers.outbox(wctx, {})
    with pool.tx() as tx:
        m = tx.one("SELECT sent_at, attempts, last_error, send_after > now() AS later FROM occ.email_outbox "
                   "WHERE id = :i", i=oid)
        tx.run("UPDATE occ.email_outbox SET attempts = 5 WHERE id = :i", i=oid)    # out of the way of later tests
    assert m["sent_at"] is None and m["attempts"] == 1 and m["later"] and "SMTP" in m["last_error"]


def test_notify_email_hands_notifications_to_the_outbox(wctx, pool, world):
    uid = world.users["bob"]
    with pool.tx() as tx:
        n1 = tx.val("INSERT INTO occ.notifications (user_id, category, body, send_email) VALUES "
                    "(:u, 10, CAST('{\"entity_id\": 5}' AS jsonb), true) RETURNING id", u=uid)
        n2 = tx.val("INSERT INTO occ.notifications (user_id, category, body, send_email) VALUES "
                    "(:u, 11, CAST('{}' AS jsonb), true) RETURNING id", u=uid)
        quiet = tx.val("INSERT INTO occ.notifications (user_id, category, body, send_email) VALUES "
                       "(:u, 11, CAST('{}' AS jsonb), false) RETURNING id", u=uid)
    _set(pool, email_send_grouped=1)
    try:
        out = handlers.notify_email(wctx, {})
    finally:
        _set(pool, email_send_grouped=None)
    with pool.tx() as tx:
        sent = {r["id"]: r["email_sent_at"] for r in tx.all(
            "SELECT id, email_sent_at FROM occ.notifications WHERE id = ANY(CAST(:i AS bigint[]))", i=[n1, n2, quiet])}
        mails = tx.all("SELECT subject, body_text FROM occ.email_outbox WHERE to_address = 'bob@example.com' "
                       "AND body_text LIKE '%entity_id: 5%' ORDER BY id DESC")
        tx.run("UPDATE occ.email_outbox SET attempts = 5 WHERE to_address = 'bob@example.com' AND sent_at IS NULL")
    assert out["notifications"] >= 2
    assert sent[n1] is not None and sent[n2] is not None and sent[quiet] is None
    # grouped: bob's notifications (these two, and any other test left for him) are one message
    assert len(mails) == 1 and "new notifications" in mails[0]["subject"]
    assert mails[0]["body_text"].count("Notification (category") >= 2


def test_step_deadlines_notify_the_owner_once(wctx, pool, client, world):
    r = client.post("/api/v2/experiments", json={"title": "deadline"}, headers=world.h("alice"))
    eid = int(r.headers["location"].rsplit("/", 1)[1])
    with pool.tx() as tx:
        rid = tx.val("SELECT rid FROM occ.records WHERE kind_id = 1 AND id = :i", i=eid)
        due = tx.val("INSERT INTO occ.steps (rid, body, deadline, deadline_notif) VALUES "
                     "(:r, 'due', now() - interval '1 minute', true) RETURNING id", r=rid)
        later = tx.val("INSERT INTO occ.steps (rid, body, deadline, deadline_notif) VALUES "
                       "(:r, 'later', now() + interval '1 day', true) RETURNING id", r=rid)
    assert handlers.step_deadlines(wctx, {})["notified"] >= 1
    assert handlers.step_deadlines(wctx, {})["notified"] == 0                 # once
    with pool.tx() as tx:
        n = tx.all("SELECT category, body, send_email FROM occ.notifications WHERE user_id = :u "
                   "AND category = 13 AND (body->>'step_id')::bigint = :s", u=world.users["alice"], s=due)
        flags = {r["id"]: r["deadline_notif"] for r in tx.all("SELECT id, deadline_notif FROM occ.steps WHERE rid = :r",
                                                             r=rid)}
        a = tx.one("SELECT * FROM occ.audit_events WHERE category = 'step.update' AND rid = :r "
                   "AND target = 'deadline_notif'", r=rid)
        tx.run("UPDATE occ.notifications SET send_email = false WHERE user_id = :u AND category = 13",
               u=world.users["alice"])
    assert len(n) == 1 and n[0]["body"]["entity_id"] == eid and n[0]["body"]["entity_page"] == "experiments.php"
    assert n[0]["send_email"] is True
    assert flags[due] is False and flags[later] is True
    assert a["actor_kind"] == "system" and a["old_value"] == "1" and a["new_value"] == "0"


def test_idp_refresh_with_no_source_due_refreshes_nothing(wctx):
    out = handlers.idp_refresh(wctx, {})
    assert out["refreshed"] == [] and out["failed"] == {}          # the full refresh: tests/unit/test_storage_idp.py


def test_ins01_test_email(client, world, pool, smtp):
    ok = {"action": "test", "email": "admin@example.com"}
    assert client.post("/api/v2/instance", json=ok, headers=world.h("admin")).status_code == 403
    assert client.post("/api/v2/instance", json={"action": "nope", "email": "a@example.com"},
                       headers=world.h("sys")).status_code == 400
    r = client.post("/api/v2/instance", json=ok, headers=world.h("sys"))
    assert r.status_code == 200 and b"admin@example.com" in smtp.received[-1][0][0].encode()
    smtp.refuse = True
    r = client.post("/api/v2/instance", json=ok, headers=world.h("sys"))
    assert r.status_code == 400 and r.json()["message"] == "Could not send email! Full error message has been logged."


def test_ins01_without_a_mail_server_answers_like_the_mirror(client, world):
    r = client.post("/api/v2/instance", json={"action": "test", "email": "x@lablynx.invalid"}, headers=world.h("sys"))
    assert r.status_code == 400 and r.json() == {"code": 400, "message": "Could not send email! Full error message "
                                                 "has been logged.", "description": ""}


def test_the_smtp_password_is_used_only_sealed(pool, cfg, smtp, tmp_path):
    import dataclasses
    from occ import mail
    from occ.people import config as config_mod
    kcfg = dataclasses.replace(cfg, secret_key_file=str(tmp_path / "secret.key"))
    config_mod.make_secret_key(kcfg.secret_key_file)
    _set(pool, smtp_username="mailer")
    try:
        with pool.tx() as tx:     # stored in clear text: refused, never used
            tx.run("INSERT INTO occ.site_config (name, value) VALUES ('smtp_password', 'clear')")
            with pytest.raises(mail.MailNotConfigured, match="unsealed"):
                mail.settings(tx, kcfg)
            tx.run("DELETE FROM occ.site_config WHERE name = 'smtp_password'")
            tx.run("INSERT INTO occ.site_config (name, is_secret, value_enc) VALUES ('smtp_password', true, :e)",
                   e=b"\x00" * 40)
            with pytest.raises(mail.MailNotConfigured, match="cannot be unsealed"):
                mail.settings(tx, kcfg)
            with pytest.raises(mail.MailNotConfigured, match="no key file"):
                mail.settings(tx)
            tx.run("UPDATE occ.site_config SET value_enc = :e WHERE name = 'smtp_password'",
                   e=config_mod.seal(kcfg, "smtp_password", "s3cret-pass"))
            m = mail.settings(tx, kcfg)
        mail.send(m, mail.build(m, "who@example.com", "auth", "body"))
        assert smtp.auth[-1] == "\x00mailer\x00s3cret-pass"
    finally:
        _set(pool, smtp_username=None, smtp_password=None)


# -------------------------------------------------------------------------------------- sync
def test_x17_x19_sync_direction_is_one_way_only(client, world, pool):
    assert client.get("/api/v2/occ/sync", headers=world.h("alice")).status_code == 403
    s = client.get("/api/v2/occ/sync", headers=world.h("sys")).json()
    assert s["direction"] == "off" and s["enabled"] == 0 and s["engine"] == "phase A" and s["last_run"] is None
    assert client.patch("/api/v2/occ/sync", json={"direction": "A"}, headers=world.h("admin")).status_code == 403
    assert client.patch("/api/v2/occ/sync", json={"direction": "A"}, headers=world.h("sys_site")).status_code == 403
    for bad in ({"direction": "both"}, {"direction": "AB"}, {"direction": "A,B"}, {"direction": "a"},
                {"enabled": 1}, {}, {"direction": "A", "enabled": "maybe"}):
        r = client.patch("/api/v2/occ/sync", json=bad, headers=world.h("sys"))
        assert r.status_code == 400, bad
    r = client.patch("/api/v2/occ/sync", json={"direction": "A", "enabled": 1}, headers=world.h("sys"))
    assert r.status_code == 200 and r.json()["direction"] == "A" and r.json()["enabled"] == 1
    r = client.patch("/api/v2/occ/sync", json={"direction": "B"}, headers=world.h("sys"))
    assert r.json()["direction"] == "B" and r.json()["enabled"] == 1
    r = client.patch("/api/v2/occ/sync", json={"direction": "off"}, headers=world.h("sys"))
    assert r.json() == {**r.json(), "direction": "off", "enabled": 0}
    with pool.tx() as tx:
        rows = tx.all("SELECT target, old_value, new_value FROM occ.audit_events WHERE category = 'config.update' "
                      "AND target LIKE 'sync.%' ORDER BY id")
    assert [(r["target"], r["old_value"], r["new_value"]) for r in rows] == [
        ("sync.direction", "off", "A"), ("sync.enabled", "0", "1"), ("sync.direction", "A", "B"),
        ("sync.direction", "B", "off"), ("sync.enabled", "1", "0")]


def test_metrics_count_jobs_by_state(client):
    m = client.get("/metrics").text
    assert 'occ_jobs{state="dead"}' in m and "occ_jobs_dead " in m and "occ_blob_mismatches " in m


def test_worker_once_runs_due_work_from_the_command_line(cfg, pool, scratchdb, monkeypatch):
    from occ import cli
    with pool.tx() as tx:
        tx.run("UPDATE occ.job_schedules SET next_run_at = now() - interval '1 second' WHERE name = 'sessions-cleanup'")
    monkeypatch.setenv("OCC_ENV_FILE", "/nonexistent")
    monkeypatch.setenv("OCC_FILES_ROOT", cfg.files_root)
    assert cli.main(["--database", scratchdb, "worker", "--once"]) == 0
    with pool.tx() as tx:
        r = tx.one("SELECT j.state, j.payload FROM occ.job_schedules s JOIN occ.jobs j ON j.id = s.last_job_id "
                   "WHERE s.name = 'sessions-cleanup'")
    assert r["state"] == "done" and "deleted" in r["payload"]["result"]
