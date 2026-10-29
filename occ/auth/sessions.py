# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Browser sessions from single sign-on.

BUILT: reading a session, making one (create(), which the SAML half will call), and the session
additions: read the session (with the CSRF token), switch team, and sign out. The
occ_session cookie carries 32 random bytes; the database keeps only their SHA-256
(occ.sessions.id_hash), so a session is found by hashing the cookie. Expired and revoked sessions
are refused.

The CSRF token is derived, not stored, so there is no token table to keep or clean up: token =
HMAC-SHA256(pepper, "csrf:" + cookie value), url-safe base64; occ.sessions.csrf_hash keeps
SHA-256(token). Reading the session can therefore hand the same token to every tab of one session without
keeping it anywhere, and a token is worthless without the cookie it was derived from.

STAGED, NOT BUILT: making a session. A session is created only by the SAML 2.0 service provider
(/auth/saml/login, /auth/saml/acs, /auth/saml/metadata, /auth/saml/sls). That
needs the identity provider (LabLynx OpenSocial) to register the OCC's service-provider metadata
and the SP key and certificate under /etc/occ/saml, which the operators do.
TODO: implement SamlServiceProvider with python3-saml once the registration exists:
signed assertions required, audience/recipient/time/replay checks, assertion ids kept 10 minutes,
person matched by email (case-insensitive), no account created during sync phase A.
Until then the OCC accepts API keys only, and the routes below are not mounted.
"""
import base64
import datetime as dt
import hashlib
import hmac
import secrets

from . import principal as _principal

COOKIE = "occ_session"


def hash_cookie(value):
    return hashlib.sha256(value.encode("utf-8")).digest()


def resolve(tx, cookie_value):
    """A Principal for a presented session cookie, or None."""
    if not cookie_value or len(cookie_value) > 200:
        return None
    row = tx.one("SELECT user_id, team_id FROM occ.sessions WHERE id_hash = :h AND revoked_at IS NULL "
                 "AND expires_at > now()", h=hash_cookie(cookie_value))
    if row is None:
        return None
    # 12 hours idle: each use (at most once a minute) moves the expiry 12 hours on.
    tx.run("UPDATE occ.sessions SET last_seen_at = now(), expires_at = now() + make_interval(hours => :hrs) "
           "WHERE id_hash = :h AND last_seen_at < now() - interval '1 minute'", h=hash_cookie(cookie_value),
           hrs=IDLE_HOURS)
    return _principal.load(tx, row["user_id"], row["team_id"], via="session")


def csrf_token_for(pepper, cookie_value):
    mac = hmac.new(pepper, b"csrf:" + cookie_value.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")


IDLE_HOURS = 12      # 12 hours idle, as eLabFTW's cookie_validity_time


def create(tx, pepper, user_id, team_id, hours=IDLE_HOURS, idp_id=None, name_id=None, session_index=None,
           user_agent=None):
    """A new session row; returns the cookie value (shown to the browser once, never stored)."""
    cookie = secrets.token_urlsafe(32)
    token = csrf_token_for(pepper, cookie)
    tx.run("INSERT INTO occ.sessions (id_hash, user_id, team_id, csrf_hash, idp_id, saml_name_id, "
           "saml_session_index, expires_at, user_agent) VALUES (:h, :u, :t, :c, :i, :n, :s, :e, :a)",
           h=hash_cookie(cookie), u=user_id, t=team_id, c=hashlib.sha256(token.encode()).digest(), i=idp_id,
           n=name_id, s=session_index, e=dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=hours),
           a=(user_agent or "")[:300] or None)
    return cookie


def row(tx, cookie_value):
    return tx.one("SELECT user_id, team_id, expires_at, created_at FROM occ.sessions WHERE id_hash = :h "
                  "AND revoked_at IS NULL AND expires_at > now()", h=hash_cookie(cookie_value))


def switch_team(tx, cookie_value, team_id):
    tx.run("UPDATE occ.sessions SET team_id = :t WHERE id_hash = :h", t=team_id, h=hash_cookie(cookie_value))


def revoke(tx, cookie_value):
    return tx.run("UPDATE occ.sessions SET revoked_at = now() WHERE id_hash = :h AND revoked_at IS NULL",
                  h=hash_cookie(cookie_value))


class SamlServiceProvider:
    """The interface the SSO half implements (TODO: waits for the identity provider to be registered).
    Not mounted in this build."""

    def metadata_xml(self):
        raise NotImplementedError("SSO waits for the identity provider registration")

    def login_redirect(self, next_url, idp_id=None):
        raise NotImplementedError("SSO waits for the identity provider registration")

    def accept_assertion(self, saml_response, relay_state):
        """Validate the assertion and return (user_id, idp_id, name_id, session_index)."""
        raise NotImplementedError("SSO waits for the identity provider registration")

    def logout_redirect(self, session):
        raise NotImplementedError("SSO waits for the identity provider registration")
