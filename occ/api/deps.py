# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""What every route needs: the caller, the transaction, the read-only guard, and the CSRF rule for
cookie-authenticated writes."""
import hmac
import hashlib
from dataclasses import dataclass

from fastapi import Request

from .. import errors
from ..audit import writer as audit
from ..auth import apikeys, sessions

WRITE_METHODS = {"POST", "PATCH", "PUT", "DELETE"}


@dataclass
class Ctx:
    request: Request
    principal: object
    actor: object

    @property
    def pool(self):
        return self.request.app.state.pool

    @property
    def settings(self):
        return self.request.app.state.settings

    @property
    def base_url(self):
        s = self.settings
        return s.base_url + s.root_path

    def location(self, path):
        return self.base_url + "/api/v2/" + path.lstrip("/")


def _resolve(request):
    app = request.app
    key = apikeys.from_header(request.headers.get("authorization"))
    with app.state.pool.tx() as tx:
        if key:
            try:
                pepper = app.state.pepper()
            except apikeys.PepperMissing:
                raise errors.OCCError(503, "API keys cannot be checked: the server's key pepper is missing.")
            p = apikeys.resolve(tx, pepper, key)
            if p is None:
                raise errors.OCCError(401, "No corresponding API key found!")
            return p
        cookie = request.cookies.get(sessions.COOKIE)
        if cookie:
            p = sessions.resolve(tx, cookie)
            if p is not None:
                if request.method in WRITE_METHODS:
                    _csrf(tx, request, cookie)
                return p
    raise errors.OCCError(401, "No authentication method found.",
                          "Send an API key in the Authorization header.")


def _csrf(tx, request, cookie):
    """A cookie-authenticated write needs the session's CSRF token or a same-origin Origin header;
    a browser's cross-site request is refused."""
    if request.headers.get("sec-fetch-site") == "cross-site":
        raise errors.forbidden("Cross-site requests are refused.")
    token = request.headers.get("x-csrf-token")
    if token:
        want = tx.val("SELECT csrf_hash FROM occ.sessions WHERE id_hash = :h", h=sessions.hash_cookie(cookie))
        if want is not None and hmac.compare_digest(bytes(want), hashlib.sha256(token.encode()).digest()):
            return
        raise errors.forbidden("The CSRF token does not match.")
    origin = request.headers.get("origin")
    if origin is None or origin.rstrip("/") == request.app.state.settings.base_url:
        return     # server-side replay (no Origin), or same origin
    raise errors.forbidden("Cross-site requests are refused.")


def _read_only_refusal(request, p):
    """While site setting read_only is on, every write under /api/v2 is refused for a person
    who is not write_exempt (signing out and switching team are not writes of data)."""
    if request.method not in WRITE_METHODS or p.write_exempt:
        return
    path = request.url.path
    if path.endswith("/api/v2/occ/session"):
        return
    if path.endswith("/api/v2/occ/write-policy") and p.is_sysadmin:
        return     # a sysadmin can always turn read-only off again, or the site could lock itself out
    with request.app.state.pool.tx(readonly=True) as tx:
        on = tx.val("SELECT value FROM occ.site_config WHERE name = 'read_only' AND NOT is_secret")
    if str(on or "0") in ("1", "true", "yes"):
        raise errors.forbidden(errors.READ_ONLY_MESSAGE)


def ctx(request: Request) -> Ctx:
    p = _resolve(request)
    request.state.user_id = p.user_id
    request.state.team = p.team_id
    _read_only_refusal(request, p)
    return Ctx(request=request, principal=p, actor=audit.actor_for(p, request.state.request_id))


def query_dict(request):
    """Query parameters as a dict; tags[] (and tags) collected into a list."""
    q = {}
    for k, v in request.query_params.multi_items():
        if k in ("tags[]", "tags"):
            q.setdefault("tags", []).append(v)
        else:
            q[k] = v
    return q
