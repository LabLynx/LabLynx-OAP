# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Additions under /api/v2/occ/, a path eLabFTW does not use, so they can never collide with the
mirror API: reorder statuses or categories, read the audit log, verify the audit chain, the session
(read with its CSRF token, switch team, sign out), the structured read-only query, paged change
history, history notes, read many records, and the write policy."""
from typing import Any

from fastapi import APIRouter, Body, Depends, Request, Response
from fastapi.responses import JSONResponse

from ... import errors, timefmt
from ...audit import read as audit_read
from ...audit import writer as audit
from ...auth import sessions
from ...people import site as site_svc
from ...perms import engine
from ...records import kinds as K
from ...records import changes as CH
from ...records import lookups as L
from ...records import service as S
from ...records import subs
from .. import convertors  # noqa: F401
from ..deps import Ctx, ctx, query_dict

router = APIRouter(prefix="/api/v2/occ", tags=["additions"])


@router.post("/query", summary="Structured read-only query for reports and dashboards")
def structured_query(c: Ctx = Depends(ctx), body: Any = Body(None)):
    from ...query import structured
    return structured.run(c.pool, c.settings, c.principal, body)


@router.put("/teams/{team}/{lookup:lookup}/order", summary="Reorder statuses or categories in one call")
def reorder(team: str, lookup: str, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        return L.reorder(tx, c.principal, c.actor, team, lookup, body or {})


@router.get("/{kind:kind}/{rec_id}/changelog", summary="Paged change history with row ids and previous values")
def changelog(kind: str, rec_id: int, request: Request, c: Ctx = Depends(ctx)):
    q = request.query_params
    try:
        limit = min(int(q.get("limit") or 100), 1000)
        cursor = int(q["cursor"]) if q.get("cursor") else None
    except ValueError:
        raise errors.bad("limit and cursor are numbers")
    with c.pool.tx(readonly=True) as tx:
        row = S.fetch(tx, c.principal, K.get(kind), rec_id, full=False)
        engine.readable_or_raise(c.principal, row, errors)
        entries = [e for e in S.changelog(tx, row["rid"]) if cursor is None or e["id"] < cursor]
        page = entries[:limit]
        return {"entries": page, "next": str(page[-1]["id"]) if len(entries) > limit else None}


@router.post("/{kind:kind}/batch-read", summary="Read many records by id in one call")
def batch_read(kind: str, c: Ctx = Depends(ctx), body: Any = Body(None)):
    body = body or {}
    ids = body.get("ids")
    if not isinstance(ids, list) or len(ids) > 1000:
        raise errors.bad("ids: a list of at most 1000 record ids")
    fields = body.get("fields")
    out = {"records": [], "missing": [], "refused": []}
    with c.pool.tx(readonly=True) as tx:
        k = K.get(kind)
        for rid in ids:
            try:
                rid = int(rid)
            except (TypeError, ValueError):
                raise errors.bad("ids must be numbers")
            row = S.fetch(tx, c.principal, k, rid)
            if row is None:
                out["missing"].append(rid)
            elif not engine.check(c.principal, row, engine.READ):
                out["refused"].append(rid)
            else:
                rec = S.full_shape(tx, c.principal, k, row, c.base_url, with_changelog=False)
                out["records"].append({f: rec.get(f) for f in fields} if isinstance(fields, list) else rec)
    return out


@router.get("/write-policy", summary="Whether the site is read-only and who may write")
def write_policy(c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return site_svc.write_policy(tx, c.principal)


@router.patch("/write-policy", summary="Turn read-only on or off (sysadmin)")
def set_write_policy(c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        site_svc.set_write_policy(tx, c.principal, c.actor, body or {})
        return site_svc.write_policy(tx, c.principal)


# ------------------------------------------------------------------------------------- audit
@router.get("/audit", summary="Read the audit log (newest first, cursor paged)")
def audit_log(request: Request, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return audit_read.list_events(tx, c.principal, query_dict(request))


@router.get("/audit/verify", summary="Verify the audit chain (sysadmin)")
def audit_verify(request: Request, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return audit_read.verify(tx, c.principal, query_dict(request))


# ----------------------------------------------------------------------------------- session
def _session_answer(tx, request, p, cookie):
    s = sessions.row(tx, cookie) if cookie and p.via == "session" else None
    ro = site_svc.read_only_on(tx)
    teams = tx.all("SELECT t.id, t.name, m.is_admin FROM occ.memberships m JOIN occ.teams t ON t.id = m.team_id "
                   "WHERE m.user_id = :u AND NOT m.is_archived ORDER BY t.id", u=p.user_id)
    return {"userid": p.user_id, "team": p.team_id, "fullname": p.fullname, "is_sysadmin": 1 if p.is_sysadmin else 0,
            "teams": [{"id": t["id"], "name": t["name"], "is_admin": 1 if t["is_admin"] else 0} for t in teams],
            "via": p.via, "expires_at": timefmt.out(s["expires_at"]) if s else None,
            "csrf_token": sessions.csrf_token_for(request.app.state.pepper(), cookie) if s else None,
            "read_only": 1 if ro else 0, "can_write": 1 if (p.can_write and (not ro or p.write_exempt)) else 0}


@router.get("/session", summary="The current session, with its CSRF token")
def session_read(request: Request, c: Ctx = Depends(ctx)):
    with c.pool.tx() as tx:
        return _session_answer(tx, request, c.principal, request.cookies.get(sessions.COOKIE))


@router.patch("/session", summary="Switch the session's current team")
def session_switch(request: Request, c: Ctx = Depends(ctx), body: Any = Body(None)):
    p = c.principal
    if p.via != "session":
        raise errors.bad("An API key is bound to its team; switching team needs a session.")
    try:
        team = int((body or {}).get("team"))
    except (TypeError, ValueError):
        raise errors.bad("Incorrect value for team")
    if team not in p.member_teams:
        raise errors.forbidden("You are not a member of that team.")
    cookie = request.cookies.get(sessions.COOKIE)
    with c.pool.tx() as tx:
        if team != p.team_id:
            sessions.switch_team(tx, cookie, team)
            audit.write(tx, c.actor, "auth.switch_team", team_id=team, target="team", old=p.team_id, new=team)
        from ...auth import principal as _pr
        p2 = _pr.load(tx, p.user_id, team, via="session")
        return _session_answer(tx, request, p2, cookie)


@router.delete("/session", summary="Sign out: end the session and clear the cookie")
def session_end(request: Request, c: Ctx = Depends(ctx)):
    p = c.principal
    if p.via != "session":
        raise errors.bad("This request carries an API key, not a session.")
    cookie = request.cookies.get(sessions.COOKIE)
    with c.pool.tx() as tx:
        sessions.revoke(tx, cookie)
        audit.write(tx, c.actor, "auth.signout", team_id=p.team_id, target="session")
    # slo=1 asks the identity provider to end its session too: that URL comes with single sign-on.
    resp = JSONResponse({"logout_url": None})
    resp.delete_cookie(sessions.COOKIE, path="/", secure=True, httponly=True, samesite="lax")
    return resp


# ------------------------------------------------------------------------------ history notes
@router.post("/{kind:kind}/{rec_id}/notes", status_code=201, summary="Add a note to a record's history")
def history_note(kind: str, rec_id: int, c: Ctx = Depends(ctx), body: Any = Body(None)):
    body = body or {}
    target = str(body.get("target") or "").strip()
    text = str(body.get("text") or "").strip()
    if not text:
        raise errors.bad("Incorrect value for text: it is empty")
    if len(text) > 10000 or len(target) > 200:
        raise errors.bad("Incorrect value for text: at most 10000 characters (target 200)")
    k = K.get(kind)
    with c.pool.tx() as tx:
        row = subs._record(tx, c.principal, k, rec_id)
        eid = audit.write(tx, c.actor, "record.note", kind_id=k.id, record_id=row["id"], rid=row["rid"],
                          team_id=row["team_id"], target=target or "note", new=text)
    return Response(status_code=201, headers={
        "Location": c.location("occ/%s/%d/changelog?cursor=%d" % (kind, rec_id, eid + 1))})


@router.get("/changes", summary="Change feed: records changed since a cursor")
def change_feed(request: Request, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return CH.feed(tx, c.principal, query_dict(request))
