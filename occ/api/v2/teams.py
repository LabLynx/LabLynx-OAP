# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Teams, their statuses and categories, their tags; users; instance information; small lists
(unfinished steps, extra-field names)."""
from typing import Any

from fastapi import APIRouter, Body, Depends, Request, Response

from ...people import service as P
from ...records import lookups as L
from ...records import subs
from .. import convertors  # noqa: F401  (registers {lookup})
from ..deps import Ctx, ctx

router = APIRouter(prefix="/api/v2", tags=["teams and people"])


@router.get("/teams", summary="List teams")
def list_teams(c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return P.list_teams(tx, c.principal)


@router.post("/teams", status_code=201, summary="Create a team")
def create_team(c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        tid = P.create_team(tx, c.principal, c.actor, body or {})
    return Response(status_code=201, headers={"Location": c.location("teams/%d" % tid)})


@router.get("/teams/{team}", summary="Read a team ('current' allowed)")
def get_team(team: str, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return P.get_team(tx, c.principal, team)


@router.get("/teams/{team}/tags", summary="The team's tags with use counts")
def team_tags(team: str, request: Request, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return P.team_tags(tx, c.principal, team, request.query_params.get("q"))


@router.get("/teams/{team}/{lookup:lookup}", summary="List statuses or categories")
def list_lookup(team: str, lookup: str, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return L.list_lookup(tx, c.principal, team, lookup)


@router.post("/teams/{team}/{lookup:lookup}", status_code=201, summary="Create a status or category")
def create_lookup(team: str, lookup: str, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        lid = L.create_lookup(tx, c.principal, c.actor, team, lookup, body or {})
    return Response(status_code=201, headers={"Location": c.location("teams/%s/%s/%d" % (team, lookup, lid))})


@router.get("/teams/{team}/{lookup:lookup}/{lookup_id}", summary="Read one status or category")
def get_lookup(team: str, lookup: str, lookup_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return L.get_lookup(tx, c.principal, team, lookup, lookup_id)


@router.patch("/teams/{team}/{lookup:lookup}/{lookup_id}", summary="Rename, recolor, reorder, set default")
def patch_lookup(team: str, lookup: str, lookup_id: int, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        return L.patch_lookup(tx, c.principal, c.actor, team, lookup, lookup_id, body or {})


@router.delete("/teams/{team}/{lookup:lookup}/{lookup_id}", status_code=204, summary="Delete (soft)")
def delete_lookup(team: str, lookup: str, lookup_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx() as tx:
        L.delete_lookup(tx, c.principal, c.actor, team, lookup, lookup_id)
    return Response(status_code=204)


@router.get("/users", summary="List users")
def list_users(request: Request, c: Ctx = Depends(ctx)):
    q = request.query_params
    with c.pool.tx(readonly=True) as tx:
        return P.list_users(tx, c.principal, q.get("q"), q.get("limit"), q.get("offset"), q.get("team"))


@router.post("/users", status_code=201, summary="Create a user")
def create_user(c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        uid = P.create_user(tx, c.principal, c.actor, body or {})
    return Response(status_code=201, headers={"Location": c.location("users/%d" % uid)})


@router.get("/users/{user}", summary="Read a user ('me' allowed)")
def get_user(user: str, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return P.get_user(tx, c.principal, user)


@router.get("/info", summary="Instance information")
def info(c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        ro = str(tx.val("SELECT value FROM occ.site_config WHERE name = 'read_only' AND NOT is_secret") or "0") in ("1", "true")
        return P.info(tx, c.principal, ro, c.principal.can_write and (not ro or c.principal.write_exempt))


@router.get("/unfinished_steps", summary="My unfinished steps (or the team's)")
def unfinished_steps(request: Request, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return subs.unfinished_steps(tx, c.principal, request.query_params.get("scope"))


@router.get("/extra_fields_keys", summary="Extra-field names used in the team, with frequency")
def extra_fields_keys(request: Request, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return P.extra_fields_keys(tx, c.principal, request.query_params.get("q"), request.query_params.get("limit"))
