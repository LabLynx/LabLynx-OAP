# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Mirror routes for administering teams, groups, tags and users, the person's own lists, and the
read sides of site lists: API keys, to-do items, favorite tags, notifications, signature keys,
identity providers, the export queue, storage units, compounds and procurement requests."""
from typing import Any

from fastapi import APIRouter, Body, Depends, Request, Response
from fastapi.responses import JSONResponse

from ...people import admin as A
from ...people import me as M
from ...people import site as S
from ..deps import Ctx, ctx

router = APIRouter(prefix="/api/v2", tags=["administration and the person's own lists"])


# ----------------------------------------------------------------------------------- teams
@router.patch("/teams/{team}", summary="Change a team's settings (admin) or name and visibility (sysadmin)")
def patch_team(team: str, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        return A.patch_team(tx, c.principal, c.actor, team, body or {})


@router.delete("/teams/{team}", status_code=204, summary="Delete an empty team (sysadmin)")
def delete_team(team: str, c: Ctx = Depends(ctx)):
    with c.pool.tx() as tx:
        A.delete_team(tx, c.principal, c.actor, team)
    return Response(status_code=204)


@router.get("/teams/{team}/teamgroups", summary="The team's groups and their members")
def list_groups(team: str, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return A.list_groups(tx, c.principal, team)


@router.post("/teams/{team}/teamgroups", status_code=201, summary="Create a group (team admin)")
def create_group(team: str, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        gid = A.create_group(tx, c.principal, c.actor, team, body or {})
    return Response(status_code=201, headers={"Location": c.location("teams/%s/teamgroups/%d" % (team, gid))})


@router.patch("/teams/{team}/teamgroups/{group_id}", summary="Rename a group or add/remove a member")
def patch_group(team: str, group_id: int, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        return A.patch_group(tx, c.principal, c.actor, team, group_id, body or {})


@router.delete("/teams/{team}/teamgroups/{group_id}", status_code=204, summary="Delete a group")
def delete_group(team: str, group_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx() as tx:
        A.delete_group(tx, c.principal, c.actor, team, group_id)
    return Response(status_code=204)


@router.patch("/teams/{team}/tags/{tag_id}", summary="Rename a team tag (team admin)")
def patch_team_tag(team: str, tag_id: int, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        return A.patch_team_tag(tx, c.principal, c.actor, team, tag_id, body or {})


@router.delete("/teams/{team}/tags/{tag_id}", status_code=204, summary="Delete a team tag (team admin)")
def delete_team_tag(team: str, tag_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx() as tx:
        A.delete_team_tag(tx, c.principal, c.actor, team, tag_id)
    return Response(status_code=204)


@router.get("/teams/{team}/procurement_requests", summary="The team's procurement requests")
def procurement(team: str, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return S.list_procurement(tx, c.principal, team)


# ----------------------------------------------------------------------------------- users
@router.get("/users/me/notifications", summary="My notifications")
def notifications(c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return M.list_notifications(tx, c.principal)


@router.patch("/users/me/notifications", summary="Acknowledge all my notifications")
def ack_all(c: Ctx = Depends(ctx)):
    with c.pool.tx() as tx:
        return M.ack_all_notifications(tx, c.principal, c.actor)


@router.patch("/users/me/notifications/{notif_id}", summary="Acknowledge one notification")
def ack_one(notif_id: int, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        return M.ack_notification(tx, c.principal, c.actor, notif_id, body or {})


@router.get("/users/me/sig_keys", summary="My signature keys")
def sig_keys(c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return M.list_sig_keys(tx, c.principal)


@router.post("/users/me/sig_keys", summary="Create (or replace) my signature key")
def create_sig_key(c: Ctx = Depends(ctx), body: Any = Body(None)):
    from ...signing import service as SG
    with c.pool.tx() as tx:
        SG.create_key(tx, c.principal, c.actor, body or {})
    return Response(status_code=201)          # what 2.x answers (parity me.sigkeys-create, 2026-10-28)


@router.patch("/users/{user}", summary="Change a user, or a membership action")
def patch_user(user: str, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        return A.patch_user(tx, c.principal, c.actor, user, body or {})


@router.delete("/users/{user}", status_code=204, summary="Delete a user (sysadmin)")
def delete_user(user: str, c: Ctx = Depends(ctx)):
    with c.pool.tx() as tx:
        A.delete_user(tx, c.principal, c.actor, user)
    return Response(status_code=204)


# ----------------------------------------------------------------------------------- my lists
@router.get("/apikeys", summary="My API keys (the hash is always null)")
def list_keys(c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return M.list_keys(tx, c.principal)


@router.post("/apikeys", status_code=201, summary="Make an API key; its text is answered once")
def create_key(request: Request, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        kid, key = M.create_key(tx, c.principal, c.actor, request.app.state.pepper(), body or {})
    return JSONResponse({"id": kid, "key": key}, status_code=201,
                        headers={"Location": c.location("apikeys/%d" % kid), "Cache-Control": "no-store"})


@router.delete("/apikeys/{key_id}", status_code=204, summary="Revoke an API key")
def delete_key(key_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx() as tx:
        M.delete_key(tx, c.principal, c.actor, key_id)
    return Response(status_code=204)


@router.get("/todolist", summary="My to-do list")
def list_todo(c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return M.list_todo(tx, c.principal)


@router.post("/todolist", status_code=201, summary="Add a to-do item")
def create_todo(c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        tid = M.create_todo(tx, c.principal, c.actor, body or {})
    return Response(status_code=201, headers={"Location": c.location("todolist/%d" % tid)})


@router.patch("/todolist/{todo_id}", summary="Change or reorder a to-do item")
def patch_todo(todo_id: int, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        return M.patch_todo(tx, c.principal, c.actor, todo_id, body or {})


@router.delete("/todolist/{todo_id}", status_code=204, summary="Remove a to-do item")
def delete_todo(todo_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx() as tx:
        M.delete_todo(tx, c.principal, c.actor, todo_id)
    return Response(status_code=204)


@router.get("/favtags", summary="My favorite tags")
def list_favtags(c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return M.list_favtags(tx, c.principal)


@router.post("/favtags", status_code=201, summary="Add a favorite tag")
def add_favtag(c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        tid = M.add_favtag(tx, c.principal, c.actor, body or {})
    return Response(status_code=201, headers={"Location": c.location("favtags/%d" % tid)})


@router.delete("/favtags/{tag_id}", status_code=204, summary="Remove a favorite tag")
def delete_favtag(tag_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx() as tx:
        M.delete_favtag(tx, c.principal, c.actor, tag_id)
    return Response(status_code=204)


# ---------------------------------------------------------------------------- site read sides
@router.get("/idps", summary="Identity providers (sysadmin)")
def list_idps(c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return S.list_idps(tx, c.principal)


@router.get("/idps/{idp_id}", summary="One identity provider (sysadmin)")
def get_idp(idp_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return S.get_idp(tx, c.principal, idp_id)


@router.get("/idps_sources", summary="Identity provider metadata sources (sysadmin)")
def list_idp_sources(c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return S.list_idp_sources(tx, c.principal)


@router.get("/exports", summary="The export queue (own; sysadmin all)")
def list_exports(c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return S.list_exports(tx, c.principal)


@router.get("/storage_units", summary="Storage units with their full paths")
def storage_units(request: Request, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return S.list_storage_units(tx, c.principal, request.query_params.get("hierarchy"))


@router.get("/compounds", summary="Compounds of my teams")
def list_compounds(request: Request, c: Ctx = Depends(ctx)):
    q = request.query_params
    with c.pool.tx(readonly=True) as tx:
        return S.list_compounds(tx, c.principal, q.get("q"), q.get("limit"), q.get("offset"))


@router.get("/compounds/{compound_id}", summary="One compound")
def get_compound(compound_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return S.get_compound(tx, c.principal, compound_id)
