# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The audit chain verifier, behind the verify endpoint and the nightly checkpoint.

It recomputes every row's hash from the STORED columns, in Python, independently of the
database's own occ.audit_canonical, and checks the links:

    hash(row) = sha256(prev_hash || canonical(row))       the canonical form below
    prev_hash(row) = hash(the row before it, by id)        zero bytes for the first row

canonical(row) is the jsonb text of {v: 1, every stored column except prev_hash and hash}, with
times as UTC 'YYYY-MM-DDTHH:MM:SS.ffffffZ'. jsonb writes object keys ordered by byte length, then
bytes, separated by ', ' and ': '; strings escape ", \\, \\b \\f \\n \\r \\t and other characters
below 0x20 as \\u00xx, and keep everything else as UTF-8. 'detail' is embedded as the database's
own jsonb text of the stored value (detail::text), which no session setting changes.
"""
import datetime as dt
import hashlib

ZERO = b"\x00" * 32
FORM = 1
_ESC = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _str(s):
    out = []
    for ch in s:
        e = _ESC.get(ch)
        if e is not None:
            out.append(e)
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _utc(t):
    if t is None:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _val(v):
    """A value already in canonical text (RawJSON) or a Python scalar."""
    if v is None:
        return "null"
    if isinstance(v, RawJSON):
        return v.text
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    return _str(str(v))


class RawJSON:
    def __init__(self, text):
        self.text = text


def canonical(row):
    """The canonical text of one stored row (a dict with the column values; detail_text is
    detail::text as the database renders it, or None)."""
    obj = {
        "v": FORM, "id": int(row["id"]), "at": _utc(row["at"]), "actor_kind": row["actor_kind"],
        "actor_user_id": row["actor_user_id"], "api_key_id": row["api_key_id"], "team_id": row["team_id"],
        "category": row["category"], "kind_id": row["kind_id"], "record_id": row["record_id"], "rid": row["rid"],
        "target": row["target"], "old_value": row["old_value"], "new_value": row["new_value"],
        "detail": RawJSON(row["detail_text"]) if row.get("detail_text") is not None else None,
        "request_id": str(row["request_id"]) if row["request_id"] is not None else None,
        "origin": row["origin"], "orig_at": _utc(row["orig_at"]),
    }
    keys = sorted(obj, key=lambda k: (len(k.encode("utf-8")), k.encode("utf-8")))
    return "{" + ", ".join("%s: %s" % (_str(k), _val(obj[k])) for k in keys) + "}"


def row_hash(prev_hash, row):
    return hashlib.sha256(bytes(prev_hash) + canonical(row).encode("utf-8")).digest()


_COLS = ("id, at, actor_kind, actor_user_id, api_key_id, team_id, category, kind_id, record_id, rid, target, "
         "old_value, new_value, detail::text AS detail_text, request_id::text AS request_id, origin, orig_at, "
         "prev_hash, hash")


def verify(tx, from_id=None, to_id=None, batch=2000):
    """Walk the chain in id order. Returns {ok, checked, first_bad_id, reason, last_id, last_hash}.

    from_id starts the walk at that row and trusts the stored hash of the row before it (a
    partial check); the nightly job and the verify endpoint without parameters walk the whole chain."""
    after = 0
    prev = ZERO
    if from_id is not None:
        before = tx.one("SELECT id, hash FROM occ.audit_events WHERE id < :f ORDER BY id DESC LIMIT 1", f=int(from_id))
        if before is not None:
            after, prev = before["id"], bytes(before["hash"])
    checked, last_id = 0, None
    while True:
        params = {"a": after, "n": int(batch)}
        cond = "id > :a"
        if to_id is not None:
            cond += " AND id <= :t"
            params["t"] = int(to_id)
        rows = tx.all("SELECT " + _COLS + " FROM occ.audit_events WHERE " + cond + " ORDER BY id LIMIT :n", **params)
        if not rows:
            break
        for r in rows:
            if bytes(r["prev_hash"]) != prev:
                return _bad(checked, r["id"], "prev_hash does not match the hash of the row before it", last_id, prev)
            if row_hash(prev, r) != bytes(r["hash"]):
                return _bad(checked, r["id"], "stored hash does not match the stored row", last_id, prev)
            prev = bytes(r["hash"])
            last_id = r["id"]
            checked += 1
        after = rows[-1]["id"]
    return {"ok": True, "checked": checked, "first_bad_id": None, "reason": None, "last_id": last_id,
            "last_hash": prev.hex() if last_id is not None else None}


def _bad(checked, bad_id, reason, last_id, prev):
    return {"ok": False, "checked": checked, "first_bad_id": bad_id, "reason": reason, "last_id": last_id,
            "last_hash": prev.hex() if last_id is not None else None}


def last_checkpoint(tx):
    r = tx.one("SELECT id, upto_id, upto_hash, created_at, verified_ok, verify_note FROM occ.audit_checkpoints "
               "ORDER BY id DESC LIMIT 1")
    if r is None:
        return None
    from .. import timefmt
    return {"id": r["id"], "upto_id": r["upto_id"], "upto_hash": bytes(r["upto_hash"]).hex(),
            "created_at": timefmt.out(r["created_at"]), "verified_ok": 1 if r["verified_ok"] else 0,
            "note": r["verify_note"]}


NO_TSA_NOTE = "no timestamp authority configured: tsa_token not set"


def checkpoint(tx, result, note_suffix=NO_TSA_NOTE, tsa_token=None):
    """Record a whole-chain verification (the nightly job, `occ audit-verify --checkpoint`).
    A passing run records the last row's id and hash. A failing one records the first bad id as a
    NEGATIVE upto_id: upto_id is unique, and a row that verified once and is
    altered later would otherwise collide with the passing checkpoint already kept for that id,
    so the failure would go unrecorded. A failure at the same id is recorded once.
    tsa_token is the RFC 3161 response over upto_hash (signing.service.checkpoint_token, asked for
    outside the transaction); without one the note says why, so a missing timestamp is never silent."""
    if result["ok"]:
        if result["last_id"] is None:
            return None
        upto, h, note = result["last_id"], bytes.fromhex(result["last_hash"]), "verified %d rows" % result["checked"]
    else:
        upto = -int(result["first_bad_id"])
        h = bytes.fromhex(result["last_hash"]) if result["last_hash"] else ZERO
        note = "FAILED at id %d: %s" % (result["first_bad_id"], result["reason"])
    if tsa_token:
        note += "; timestamped (RFC 3161)"
    elif note_suffix:
        note += "; " + note_suffix
    return tx.val("INSERT INTO occ.audit_checkpoints (upto_id, upto_hash, verified_ok, verify_note, tsa_token) "
                  "VALUES (:u, :h, :ok, :n, :t) ON CONFLICT (upto_id) DO NOTHING RETURNING id",
                  u=upto, h=h, ok=bool(result["ok"]), n=note, t=tsa_token)


def head_hash(result):
    """The hash a checkpoint of this result records (for asking the authority before writing it)."""
    if result["ok"]:
        return bytes.fromhex(result["last_hash"]) if result["last_id"] is not None else None
    return bytes.fromhex(result["last_hash"]) if result["last_hash"] else ZERO
