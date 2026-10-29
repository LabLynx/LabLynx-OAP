# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Signature keys, signing a record and timestamping a record (the record actions sign and
timestamp), and the timestamp on an audit checkpoint.

Signing: the person's own active key, opened with their passphrase, signs data.json (the record's
JSON export as a one-element list) in minisign's prehashed form; the trusted comment is a JSON
object {firstname, lastname, email, created_at, meaning}. The OCC stores an immutable upload
'signature-archive.zip' holding data.json, data.json.minisig, key.pub and verify.sh, an immutable
comment 'Signed by <name> (<meaning>)', and a row in occ.signatures. Signing does not lock. An open
request to this person to sign the record (action 40) is marked done.

Timestamping: the record's PDF export is hashed (SHA-256) and the configured authority (site
settings ts_url, ts_login, ts_password sealed, ts_cert) is asked for an RFC 3161 token. The call to
the authority happens outside any transaction, so no row stays locked while it answers. The OCC
stores an immutable upload 'timestamp-archive-<when>.zip' holding the PDF, the token (.asn1) and a
verify.sh, a row in occ.timestamps, and sets timestamped, timestamped_by, timestamped_at.

Passphrases never reach a log, an error message or the audit log.
"""
import datetime as dt
import hashlib
import io
import json
import zipfile

from .. import errors, timefmt
from ..audit import writer as audit
from ..exports import render as R
from ..files import uploads as U
from ..people import config as C
from ..perms import engine
from ..records import kinds as K
from ..records import service as S
from . import minisign, tsa

MEANINGS = {10: "Approval", 20: "Authorship", 30: "Responsibility", 40: "Review", 50: "Safety"}
REQUEST_SIGN = 40
VERIFY_SH = ("#!/bin/sh\n# Verify this signature with the stock minisign tool (https://jedisct1.github.io/minisign/).\n"
             "minisign -V -p key.pub -m data.json\n")


# ---------------------------------------------------------------------------- making a key
def create_key(tx, p, actor, body):
    """action=create with a passphrase of at least 12 characters. A previous active key moves to
    state 2 and keeps verifying the signatures made with it (its public part stays stored)."""
    if not p.can_write:
        raise errors.forbidden("This API key is read-only.")
    body = body if isinstance(body, dict) else {}
    if body.get("action", "create") != "create":
        raise errors.bad("Incorrect value for action: create")
    passphrase = body.get("passphrase")
    if not isinstance(passphrase, str) or len(passphrase) < minisign.MIN_PASSPHRASE:
        raise errors.bad("The passphrase needs at least %d characters." % minisign.MIN_PASSPHRASE)
    kp = minisign.generate()
    old = tx.all("SELECT id FROM occ.sig_keys WHERE user_id = :u AND state = 1 FOR UPDATE", u=p.user_id)
    tx.run("UPDATE occ.sig_keys SET state = 2 WHERE user_id = :u AND state = 1", u=p.user_id)
    kid = tx.val("INSERT INTO occ.sig_keys (user_id, key_id, pubkey, privkey_enc, type, state) "
                 "VALUES (:u, :k, :pub, :sec, 1, 1) RETURNING id", u=p.user_id, k=kp.key_id_hex,
                 pub=kp.public_file(), sec=kp.secret_file(passphrase))
    audit.write(tx, actor, "user.sigkey_create", target="sig_keys", new=kp.key_id_hex,
                detail={"sig_key_id": kid, "archived": [r["id"] for r in old]})
    return kid


# ---------------------------------------------------------------------------- signing
def _meaning(body):
    raw = body.get("meaning")
    if raw in (None, "", 0, "0"):
        raise errors.bad("meaning is required")                       # 2.x answers 500 here; 400 says why
    try:
        m = int(raw)
    except (TypeError, ValueError):
        raise errors.bad("Incorrect value for meaning: one of %s" % ", ".join(str(k) for k in MEANINGS))
    if m not in MEANINGS:
        raise errors.bad("Incorrect value for meaning: one of %s" % ", ".join(str(k) for k in MEANINGS))
    return m


def _archive(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files:
            z.writestr(name, data)
    return buf.getvalue()


def _store(cfg, data):
    return U.put_stream(cfg, [data], max(len(data), 1))


def sign(tx, cfg, p, actor, kind, rec_id, body, base_url):
    body = body if isinstance(body, dict) else {}
    meaning = _meaning(body)
    passphrase = body.get("passphrase")
    row = S.fetch(tx, p, kind, rec_id, for_update=True)
    engine.readable_or_raise(p, row, errors)
    if not p.can_write:
        raise errors.forbidden("This API key is read-only.")
    if row["state"] == 3:
        raise errors.forbidden("This entry is deleted.")
    key = tx.one("SELECT * FROM occ.sig_keys WHERE user_id = :u AND state = 1", u=p.user_id)
    if key is None:
        raise errors.bad("You have no signature key: create one first (POST /users/me/sig_keys).")
    if not isinstance(passphrase, str) or not passphrase:
        raise errors.bad("passphrase is required")
    try:
        kp = minisign.open_secret(key["privkey_enc"], passphrase)
    except minisign.BadPassphrase:
        raise errors.bad("Wrong passphrase for your signature key.")
    me = tx.one("SELECT firstname, lastname, email FROM occ.users WHERE id = :u", u=p.user_id)
    now = dt.datetime.now(dt.timezone.utc)
    rec = R.records(tx, p, kind, [rec_id], base_url)[0]
    data = json.dumps([R._public(rec)], ensure_ascii=False, indent=1).encode("utf-8")
    tc = {"firstname": me["firstname"], "lastname": me["lastname"], "email": me["email"],
          "created_at": now.astimezone(timefmt.zone()).isoformat(timespec="seconds"), "meaning": MEANINGS[meaning]}
    tc_text = json.dumps(tc, ensure_ascii=False, separators=(",", ":"))
    sig_text = kp.sign(data, tc_text)
    archive = _archive([("data.json", data), ("data.json.minisig", sig_text.encode()),
                        ("key.pub", key["pubkey"].encode()), ("verify.sh", VERIFY_SH.encode())])
    sha, size = _store(cfg, archive)
    name = ("%s %s" % (me["firstname"], me["lastname"])).strip()
    upload_id = U.attach(tx, cfg, actor, kind, row, "signature-archive.zip", "application/zip", sha, size,
                         comment="Signature archive (%s)" % MEANINGS[meaning], immutable=True, user_id=p.user_id)
    cid = tx.val("INSERT INTO occ.comments (rid, user_id, body, immutable) VALUES (:rid, :u, :b, true) RETURNING id",
                 rid=row["rid"], u=p.user_id, b="Signed by %s (%s)" % (name, MEANINGS[meaning]))
    tx.run("INSERT INTO occ.signatures (rid, user_id, sig_key_id, meaning, signed_at, data_sha256, trusted_comment, "
           "signature, archive_upload_id, comment_id) VALUES (:rid, :u, :k, :m, :at, :h, CAST(:tc AS jsonb), :s, "
           ":up, :c)", rid=row["rid"], u=p.user_id, k=key["id"], m=meaning, at=now,
           h=hashlib.sha256(data).digest(), tc=tc_text, s=sig_text, up=upload_id, c=cid)
    tx.run("UPDATE occ.records SET signature_count = signature_count + 1, last_signed_at = :at, last_signed_by = :u "
           "WHERE rid = :rid", at=now, u=p.user_id, rid=row["rid"])
    tx.run("UPDATE occ.sig_keys SET last_used_at = :at WHERE id = :k", at=now, k=key["id"])
    tx.run("UPDATE occ.request_actions SET state = 2, done_at = now() WHERE rid = :rid AND target_user_id = :u "
           "AND action = :a AND state = 1", rid=row["rid"], u=p.user_id, a=REQUEST_SIGN)
    audit.write(tx, actor, "record.sign", kind_id=kind.id, record_id=row["id"], rid=row["rid"], team_id=row["team_id"],
                target="action", new="sign (%s)" % MEANINGS[meaning],
                detail={"upload_id": upload_id, "sig_key_id": key["id"], "data_sha256": hashlib.sha256(data).hexdigest()})
    S.touch(tx, p, row["rid"])
    return S.read(tx, p, kind, rec_id, base_url)


# ---------------------------------------------------------------------------- timestamps
def authority(tx, cfg):
    """(url, login, password, ca_pem, name) from the site settings; url None when none is set."""
    url = (C.value(tx, "ts_url") or "").strip() or None
    login = (C.value(tx, "ts_login") or "").strip() or None
    password = None
    if login:
        try:
            password = C.secret(tx, cfg, "ts_password")
        except C.SealKeyMissing:
            raise errors.OCCError(503, "The timestamping password cannot be read: the server's secret key file is "
                                       "missing (occ init-secret-key).")
    ca = (C.value(tx, "ts_cert") or "").strip() or None
    name = (C.value(tx, "ts_authority") or "").strip() or "custom"
    return url, login, password, ca, name


def _stamp(url, login, password, ca, digest):
    try:
        return tsa.fetch(url, digest, login, password, ca)
    except tsa.TSAError as ex:
        raise errors.OCCError(502 if url else 400, str(ex))


def timestamp(pool, cfg, p, actor, kind, rec_id, base_url):
    """Three steps so the authority is never called inside a transaction: read and render, ask the
    authority, record. The record's write right is checked again in the last step."""
    with pool.tx(readonly=True) as tx:
        row = _timestampable(tx, p, kind, rec_id)
        url, login, password, ca, name = authority(tx, cfg)
        if not url:
            raise errors.bad("No timestamping authority is configured on this site (ts_url).")
        limit = int(str(C.value(tx, "ts_limit", "0") or "0") or 0)
        balance = int(str(C.value(tx, "ts_balance", "0") or "0") or 0)
        if limit > 0 and balance <= 0:
            raise errors.bad("The site's timestamp allowance is used up (ts_balance).")
        pdf_bytes, fname = R.render(tx, cfg, p, kind, [rec_id], "pdf", base_url, single=True)
    digest = hashlib.sha256(pdf_bytes).digest()
    st = _stamp(url, login, password, ca, digest)
    when = st.gen_time.astimezone(timefmt.zone())
    stem = "timestamp-archive-%s" % when.strftime("%Y-%m-%d-%H%M%S")
    archive = _archive([("%s.pdf" % stem, pdf_bytes), ("%s.asn1" % stem, st.response_der),
                        ("verify.sh", ("#!/bin/sh\n# Verify with OpenSSL; the authority's CA certificate is needed.\n"
                                       "openssl ts -verify -in %s.asn1 -data %s.pdf -CAfile \"${1:-tsa-ca.pem}\"\n"
                                       % (stem, stem)).encode())])
    sha, size = _store(cfg, archive)
    with pool.tx() as tx:
        row = _timestampable(tx, p, kind, rec_id, for_update=True)
        upload_id = U.attach(tx, cfg, actor, kind, row, stem + ".zip", "application/zip", sha, size,
                             comment="Timestamp archive (RFC 3161, %s)" % name, immutable=True, user_id=p.user_id)
        tx.run("INSERT INTO occ.timestamps (rid, user_id, tsa_authority, tsa_url, hash_algo, data_sha256, token, "
               "gen_time, serial, archive_upload_id) VALUES (:rid, :u, :a, :url, 'sha256', :h, :t, :g, :s, :up)",
               rid=row["rid"], u=p.user_id, a=name, url=url, h=digest, t=st.response_der, g=st.gen_time, s=st.serial,
               up=upload_id)
        tx.run("UPDATE occ.records SET timestamped = true, timestamped_by = :u, timestamped_at = :g WHERE rid = :rid",
               u=p.user_id, g=st.gen_time, rid=row["rid"])
        limit = int(str(C.value(tx, "ts_limit", "0") or "0") or 0)
        if limit > 0:
            tx.run("UPDATE occ.site_config SET value = (greatest(coalesce(nullif(value, '')::int, 0) - 1, 0))::text, "
                   "updated_at = now() WHERE name = 'ts_balance' AND NOT is_secret")
        audit.write(tx, actor, "record.timestamp", kind_id=kind.id, record_id=row["id"], rid=row["rid"],
                    team_id=row["team_id"], target="timestamped", old="1" if row["timestamped"] else "0", new="1",
                    detail={"upload_id": upload_id, "authority": name, "serial": st.serial,
                            "data_sha256": digest.hex(), "gen_time": timefmt.out(st.gen_time)})
        S.touch(tx, p, row["rid"])
        return S.read(tx, p, kind, rec_id, base_url)


def _timestampable(tx, p, kind, rec_id, for_update=False):
    """Write access is needed; a locked record can still be timestamped."""
    row = S.fetch(tx, p, kind, rec_id, for_update=for_update)
    engine.readable_or_raise(p, row, errors)
    if not p.can_write:
        raise errors.forbidden("This API key is read-only.")
    if row["state"] == 3:
        raise errors.forbidden("This entry is deleted.")
    if not engine.check(p, row, engine.WRITE):
        raise errors.forbidden()
    return row


# ---------------------------------------------------------------------------- audit checkpoints
def authority_or_none(tx, cfg):
    """authority() for the nightly job: (None, why) instead of an error."""
    try:
        return authority(tx, cfg), None
    except errors.OCCError as ex:
        return None, ex.message


def checkpoint_token(auth, upto_hash):
    """(the RFC 3161 response over a checkpoint's head hash, None), or (None, why) when no authority
    is set or it fails: the nightly job must not fail because an authority is down."""
    values, why = auth
    if values is None:
        return None, why
    url, login, password, ca, _name = values
    if not url:
        return None, "no timestamp authority configured: tsa_token not set"
    try:
        return tsa.fetch(url, bytes(upto_hash), login, password, ca).response_der, None
    except tsa.TSAError as ex:
        return None, "timestamp authority failed: %s" % ex
