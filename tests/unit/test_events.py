# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Bookings and request actions (on a record, and across records): the booking rules, overlap 409,
who may move and cancel, both time forms (ISO 8601 and the 2.x form), and requests with their notification."""
import datetime as dt


def _id(r):
    assert r.status_code == 201, r.text
    return int(r.headers["location"].rsplit("/", 1)[-1])


def _audit(pool, category):
    with pool.tx() as tx:
        return tx.all("SELECT * FROM occ.audit_events WHERE category = :c ORDER BY id", c=category)


def _t(days=1, hour=10, minute=0):
    d = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days)).replace(hour=hour, minute=minute, second=0,
                                                                             microsecond=0)
    return d.isoformat()


def _item(client, world, **rules):
    iid = _id(client.post("/api/v2/items", json={"title": "Bookable scope"}, headers=world.h("admin")))
    body = {"is_bookable": 1}
    body.update(rules)
    r = client.patch("/api/v2/items/%d" % iid, json=body, headers=world.h("admin"))
    assert r.status_code == 200, r.text
    return iid


def test_book_read_move_title_cancel(client, world, pool):
    iid = _item(client, world)
    eid = _id(client.post("/api/v2/events/%d" % iid, json={"start": _t(2, 10), "end": _t(2, 11), "title": "Run A"},
                          headers=world.h("alice")))
    ev = client.get("/api/v2/event/%d" % eid, headers=world.h("alice")).json()
    for f in ("id", "team", "team_name", "item", "title", "title_only", "start", "end", "userid", "created_at",
              "modified_at", "event_duration_minutes", "experiment", "experiment_title", "item_link",
              "item_link_title", "book_cancel_minutes", "book_is_cancellable"):
        assert f in ev, f
    assert ev["title_only"] == "Run A" and ev["event_duration_minutes"] == 60 and ev["item"] == iid
    # both time forms are read (2.x refuses ISO 8601 with a 'T'); the answer is in site time
    s = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)).strftime("%Y-%m-%d 00:00:00")
    e = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=5)).strftime("%Y-%m-%d 00:00:00")
    lst = client.get("/api/v2/events", params={"start": s, "end": e}, headers=world.h("alice")).json()
    assert any(x["id"] == eid for x in lst)
    lst = client.get("/api/v2/events", params={"start": _t(1, 0), "end": _t(5, 0)}, headers=world.h("alice")).json()
    assert any(x["id"] == eid for x in lst)
    assert client.get("/api/v2/events", params={"start": "nope", "end": e}, headers=world.h("alice")).status_code == 400
    # a person outside the team does not see it
    assert not any(x["id"] == eid for x in client.get("/api/v2/events", params={"start": s, "end": e},
                                                       headers=world.h("bea")).json())
    r = client.patch("/api/v2/event/%d" % eid, json={"target": "datetime", "start": _t(3, 10), "end": _t(3, 12)},
                     headers=world.h("alice"))
    assert r.status_code == 200 and r.json()["event_duration_minutes"] == 120
    r = client.patch("/api/v2/event/%d" % eid, json={"target": "title", "title": "Run B"}, headers=world.h("alice"))
    assert r.json()["title_only"] == "Run B"
    # bob (same team) may not move alice's booking; the team admin may
    assert client.patch("/api/v2/event/%d" % eid, json={"target": "title", "title": "x"},
                        headers=world.h("bob")).status_code == 403
    assert client.patch("/api/v2/event/%d" % eid, json={"target": "title", "title": "Admin"},
                        headers=world.h("admin")).status_code == 200
    # attach an experiment and a resource, then remove them (cal.bind)
    xid = _id(client.post("/api/v2/experiments", json={"title": "Bound"}, headers=world.h("alice")))
    r = client.patch("/api/v2/event/%d" % eid, json={"target": "experiment", "id": xid}, headers=world.h("alice"))
    assert r.json()["experiment"] == xid and r.json()["experiment_title"] == "Bound"
    r = client.patch("/api/v2/event/%d" % eid, json={"target": "item_link", "id": iid}, headers=world.h("alice"))
    assert r.json()["item_link"] == iid
    r = client.patch("/api/v2/event/%d" % eid, json={"target": "experiment", "id": None}, headers=world.h("alice"))
    assert r.json()["experiment"] is None
    assert client.patch("/api/v2/event/%d" % eid, json={"target": "nope"}, headers=world.h("alice")).status_code == 400
    assert client.delete("/api/v2/event/%d" % eid, headers=world.h("bob")).status_code == 403
    assert client.delete("/api/v2/event/%d" % eid, headers=world.h("alice")).status_code == 204
    assert client.get("/api/v2/event/%d" % eid, headers=world.h("alice")).status_code == 404
    assert _audit(pool, "event.create") and _audit(pool, "event.update") and _audit(pool, "event.delete")


def test_booking_rules(client, world):
    iid = _item(client, world, book_can_overlap=0, book_max_minutes=90, book_max_slots=2, booking_window_days=30)
    h = world.h("alice")
    a = _id(client.post("/api/v2/events/%d" % iid, json={"start": _t(2, 10), "end": _t(2, 11)}, headers=h))
    r = client.post("/api/v2/events/%d" % iid, json={"start": _t(2, 10, 30), "end": _t(2, 11, 30)}, headers=h)
    assert r.status_code == 409
    assert client.post("/api/v2/events/%d" % iid, json={"start": _t(2, 12), "end": _t(2, 14)},
                       headers=h).status_code == 400                       # longer than 90 minutes
    assert client.post("/api/v2/events/%d" % iid, json={"start": _t(-2, 10), "end": _t(-2, 11)},
                       headers=h).status_code == 400                       # in the past
    assert client.post("/api/v2/events/%d" % iid, json={"start": _t(40, 10), "end": _t(40, 11)},
                       headers=h).status_code == 400                       # beyond the window
    assert client.post("/api/v2/events/%d" % iid, json={"start": _t(2, 11), "end": _t(2, 10)},
                       headers=h).status_code == 400                       # end before start
    _id(client.post("/api/v2/events/%d" % iid, json={"start": _t(3, 10), "end": _t(3, 11)}, headers=h))
    assert client.post("/api/v2/events/%d" % iid, json={"start": _t(4, 10), "end": _t(4, 11)},
                       headers=h).status_code == 400                       # third slot
    # moving onto another booking is an overlap too; moving within its own slot is not
    assert client.patch("/api/v2/event/%d" % a, json={"target": "datetime", "start": _t(3, 10, 30),
                                                      "end": _t(3, 11, 30)}, headers=h).status_code == 409
    assert client.patch("/api/v2/event/%d" % a, json={"target": "datetime", "start": _t(2, 10, 15),
                                                      "end": _t(2, 11, 15)}, headers=h).status_code == 200
    # a team admin may book in the past
    assert client.post("/api/v2/events/%d" % iid, json={"start": _t(-3, 10), "end": _t(-3, 11)},
                       headers=world.h("admin")).status_code == 201
    # not bookable; another team; a read-only key
    plain = _id(client.post("/api/v2/items", json={"title": "Not bookable"}, headers=world.h("admin")))
    assert client.post("/api/v2/events/%d" % plain, json={"start": _t(2), "end": _t(2, 11)},
                       headers=h).status_code == 400
    assert client.post("/api/v2/events/%d" % iid, json={"start": _t(5), "end": _t(5, 11)},
                       headers=world.h("bea")).status_code in (403, 404)
    assert client.post("/api/v2/events/%d" % iid, json={"start": _t(5), "end": _t(5, 11)},
                       headers=world.h("alice_ro")).status_code == 403


def test_cancel_window(client, world):
    iid = _item(client, world, book_cancel_minutes=24 * 60 * 3)
    eid = _id(client.post("/api/v2/events/%d" % iid, json={"start": _t(1, 10), "end": _t(1, 11)},
                          headers=world.h("bob")))
    assert client.delete("/api/v2/event/%d" % eid, headers=world.h("bob")).status_code == 403
    assert client.delete("/api/v2/event/%d" % eid, headers=world.h("admin")).status_code == 204
    with_notif = client.get("/api/v2/users/me/notifications", headers=world.h("bob")).json()
    assert any((n.get("body") or {}).get("event_id") == eid for n in with_notif)
    iid2 = _item(client, world, book_is_cancellable=0)
    eid2 = _id(client.post("/api/v2/events/%d" % iid2, json={"start": _t(6), "end": _t(6, 11)},
                           headers=world.h("bob")))
    assert client.delete("/api/v2/event/%d" % eid2, headers=world.h("bob")).status_code == 403


def test_request_actions(client, world, pool):
    xid = _id(client.post("/api/v2/experiments", json={"title": "Please sign"}, headers=world.h("alice")))
    bob = world.users["bob"]
    rid = _id(client.post("/api/v2/experiments/%d/request_actions" % xid,
                          json={"target_userid": bob, "target_action": 40}, headers=world.h("alice")))
    lst = client.get("/api/v2/experiments/%d/request_actions" % xid, headers=world.h("bob")).json()
    assert lst and lst[0]["id"] == rid and lst[0]["action"] == 40 and lst[0]["entity_page"] == "experiments.php"
    for f in ("id", "created_at", "requester_userid", "target_userid", "entity_id", "action", "state", "entity_page"):
        assert f in lst[0]
    notes = client.get("/api/v2/users/me/notifications", headers=world.h("bob")).json()
    assert any((n.get("body") or {}).get("request_action_id") == rid for n in notes)
    # a duplicate open request, an unknown action, someone who cannot read the record
    assert client.post("/api/v2/experiments/%d/request_actions" % xid, json={"target_userid": bob, "target_action": 40},
                       headers=world.h("alice")).status_code == 400
    assert client.post("/api/v2/experiments/%d/request_actions" % xid, json={"target_userid": bob, "target_action": 41},
                       headers=world.h("alice")).status_code == 400
    assert client.post("/api/v2/experiments/%d/request_actions" % xid,
                       json={"target_userid": world.users["bea"], "target_action": 40},
                       headers=world.h("alice")).status_code == 400
    # open requests across records: bob sees it as target; bea does not see others' requests
    mine = client.get("/api/v2/occ/request_actions", params={"target_userid": "me"}, headers=world.h("bob")).json()
    assert any(x["id"] == rid and x["kind"] == "experiments" for x in mine)
    assert client.get("/api/v2/occ/request_actions", params={"target_userid": bob},
                      headers=world.h("bea")).status_code == 403
    assert any(x["id"] == rid for x in client.get("/api/v2/occ/request_actions", params={"target_userid": bob},
                                                  headers=world.h("admin")).json())
    # done by the target; withdrawing is the requester's only
    r = client.patch("/api/v2/experiments/%d/request_actions/%d" % (xid, rid), json={"action": "done"},
                     headers=world.h("bob"))
    assert r.status_code == 200 and r.json()["state"] == 2
    assert client.get("/api/v2/experiments/%d/request_actions" % xid, headers=world.h("bob")).json() == []
    rid2 = _id(client.post("/api/v2/experiments/%d/request_actions" % xid,
                           json={"target_userid": bob, "target_action": 20}, headers=world.h("alice")))
    assert client.delete("/api/v2/experiments/%d/request_actions/%d" % (xid, rid2),
                         headers=world.h("bob")).status_code == 403
    assert client.delete("/api/v2/experiments/%d/request_actions/%d" % (xid, rid2),
                         headers=world.h("alice")).status_code == 204
    assert _audit(pool, "request.create") and _audit(pool, "request.update") and _audit(pool, "request.delete")
