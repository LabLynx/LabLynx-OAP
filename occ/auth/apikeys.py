# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""API keys.

A key is 'occ_<id>_<43 url-safe characters>' and is shown once, when it is made. The database
keeps only HMAC-SHA256(pepper, key) in occ.api_keys.hash: the key text is never stored, logged or
returned again. The pepper is a file readable only by the service user (OCC_API_KEY_PEPPER_FILE).
A key is bound to a team (where it creates) and is read-only unless can_write.
"""
import hashlib
import hmac
import os
import re
import secrets

from . import principal as _principal

KEY_RE = re.compile(r"^occ_(\d{1,10})_([A-Za-z0-9_-]{43})$")


class PepperMissing(Exception):
    pass


def read_pepper(path):
    try:
        with open(path, "rb") as fh:
            data = fh.read().strip()
    except OSError:
        raise PepperMissing("the API key pepper file cannot be read")
    if len(data) < 32:
        raise PepperMissing("the API key pepper file is too short")
    return data


def make_pepper_file(path):
    """Create a pepper file (0600) if none exists. Returns True when it made one."""
    if os.path.exists(path):
        return False
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(secrets.token_urlsafe(48).encode())
    return True


def digest(pepper, key):
    return hmac.new(pepper, key.encode("utf-8"), hashlib.sha256).hexdigest()


def create(tx, pepper, user_id, team_id, name, can_write=False, site_scope=False):
    """Make a key and return (id, key text). The caller shows the text once and forgets it."""
    kid = tx.val("SELECT nextval(pg_get_serial_sequence('occ.api_keys', 'id'))")
    key = "occ_%d_%s" % (kid, secrets.token_urlsafe(32)[:43].ljust(43, "A"))
    tx.run("INSERT INTO occ.api_keys (id, user_id, team_id, name, hash_scheme, hash, can_write, site_scope) "
           "VALUES (:id, :u, :t, :n, 'hmac-sha256', :h, :w, :s)",
           id=kid, u=user_id, t=team_id, n=name, h=digest(pepper, key), w=bool(can_write), s=bool(site_scope))
    return kid, key


def from_header(value):
    """The key from an Authorization header: the raw key or 'Bearer <key>'."""
    if not value:
        return None
    v = value.strip()
    if v[:7].lower() == "bearer ":
        v = v[7:].strip()
    return v or None


def resolve(tx, pepper, key):
    """A Principal for a presented key, or None. Constant-time comparison of the stored HMAC."""
    m = KEY_RE.match(key or "")
    if not m:
        return None
    row = tx.one("SELECT id, user_id, team_id, hash, hash_scheme, can_write, site_scope, revoked_at, last_used_at "
                 "FROM occ.api_keys WHERE id = :id", id=int(m.group(1)))
    if row is None or row["revoked_at"] is not None or row["hash_scheme"] != "hmac-sha256":
        return None
    if not hmac.compare_digest(row["hash"], digest(pepper, key)):
        return None
    p = _principal.load(tx, row["user_id"], row["team_id"], api_key_id=row["id"], can_write=bool(row["can_write"]),
                        site_scope=bool(row["site_scope"]), via="apikey")
    if p is None:
        return None
    if p.site_scope and not p.is_sysadmin:
        # A site-scope key is for sysadmins only; one held by anybody else reads as an ordinary key.
        p = _principal.Principal(**{**p.__dict__, "site_scope": False})
    tx.run("UPDATE occ.api_keys SET last_used_at = now() WHERE id = :id "
           "AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')", id=row["id"])
    return p
