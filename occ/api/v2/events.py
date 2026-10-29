# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Bookings and request actions."""
from typing import Any, Literal

from fastapi import APIRouter, Body, Depends, Request, Response

from ...records import events as E
from ...records import kinds as K
from ...records import requests as RQ
from .. import convertors  # noqa: F401  (registers {kind})
from ..deps import Ctx, ctx, query_dict

router = APIRouter(prefix="/api/v2", tags=["events"])
KindName = Literal["experiments", "items", "experiments_templates", "items_types"]


# ------------------------------------------------------------------------------------ bookings
@router.get("/events", summary="Bookings in a time window")
def list_events(request: Request, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return E.list_events(tx, c.principal, query_dict(request))


@router.post("/events/{item_id}", status_code=201, summary="Book a resource")
def create_event(item_id: int, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        eid = E.create(tx, c.principal, c.actor, item_id, body or {})
    return Response(status_code=201, headers={"Location": c.location("event/%d" % eid)})


@router.get("/event/{event_id}", summary="Read one booking")
def read_event(event_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return E.read(tx, c.principal, event_id)


@router.patch("/event/{event_id}", summary="Move, rename or attach a booking")
def patch_event(event_id: int, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        return E.patch(tx, c.principal, c.actor, event_id, body or {})


@router.delete("/event/{event_id}", status_code=204, summary="Cancel a booking")
def delete_event(event_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx() as tx:
        E.delete(tx, c.principal, c.actor, event_id)
    return Response(status_code=204)


# ------------------------------------------------------------------------------------ request actions
@router.get("/occ/request_actions", summary="Open requests across records")
def search_requests(request: Request, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return RQ.search(tx, c.principal, query_dict(request))


@router.get("/{kind:kind}/{rec_id}/request_actions", summary="Open requests on a record")
def list_requests(kind: KindName, rec_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx(readonly=True) as tx:
        return RQ.list_on_record(tx, c.principal, K.get(kind), rec_id)


@router.post("/{kind:kind}/{rec_id}/request_actions", status_code=201,
             summary="Ask someone to sign, review, timestamp, lock or archive")
def create_request(kind: KindName, rec_id: int, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        ra = RQ.create(tx, c.principal, c.actor, K.get(kind), rec_id, body or {})
    return Response(status_code=201,
                    headers={"Location": c.location("%s/%d/request_actions/%d" % (kind, rec_id, ra))})


@router.patch("/{kind:kind}/{rec_id}/request_actions/{ra_id}", summary="Mark a request done or cancel it")
def patch_request(kind: KindName, rec_id: int, ra_id: int, c: Ctx = Depends(ctx), body: Any = Body(None)):
    with c.pool.tx() as tx:
        return RQ.patch(tx, c.principal, c.actor, K.get(kind), rec_id, ra_id, body or {})


@router.delete("/{kind:kind}/{rec_id}/request_actions/{ra_id}", status_code=204, summary="Withdraw a request")
def delete_request(kind: KindName, rec_id: int, ra_id: int, c: Ctx = Depends(ctx)):
    with c.pool.tx() as tx:
        RQ.delete(tx, c.principal, c.actor, K.get(kind), rec_id, ra_id)
    return Response(status_code=204)
