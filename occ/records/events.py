# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Bookings: events on a bookable resource.

Rules:
  * booking needs the book right on the resource (canbook; a resource without its own canbook
    base books as it reads) and the resource to be bookable;
  * book_max_minutes > 0 caps one booking's length; book_max_slots > 0 caps how many bookings
    that are not over yet one person holds on the resource;
  * book_can_overlap off: a slot that overlaps another booking of the resource answers 409;
  * a start in the past needs book_users_can_in_past (team admins of the resource's team always may);
  * booking_window_days > 0: the start must be within that many days from now;
  * cancelling (or moving) is the booker's or a team admin's; the booker cancels only when
    book_is_cancellable and, with book_cancel_minutes > 0, at least that many minutes before
    the start (team admins always may).
Start and end are read as ISO 8601 or 'YYYY-MM-DD HH:MM:SS' in the site time zone (2.x
refuses ISO 8601; the OCC accepts both) and written as 'YYYY-MM-DD HH:MM:SS' in the site time zone,
as 2.x writes them.
"""
import datetime as dt

from .. import errors, timefmt
from ..audit import writer as audit
from ..db import jsonb
from ..perms import engine
from . import kinds as K
from . import service as S

_EVENT_SQL = """
SELECT e.id, e.team_id, e.resource_rid, e.start_at, e.end_at, e.title, e.user_id, e.experiment_rid,
       e.item_link_rid, e.created_at, e.modified_at, t.name AS team_name,
       r.id AS item, r.title AS item_title, r.team_id AS item_team, c.color AS color,
       u.firstname, u.lastname,
       x.id AS experiment, x.title AS experiment_title, l.id AS item_link, l.title AS item_link_title,
       rb.book_cancel_minutes, rb.book_is_cancellable
  FROM occ.events e
  JOIN occ.teams t ON t.id = e.team_id
  JOIN occ.records r ON r.rid = e.resource_rid
  JOIN occ.users u ON u.id = e.user_id
  LEFT JOIN occ.categories c ON c.lookup_group = r.lookup_group AND c.id = r.category_id
  LEFT JOIN occ.records x ON x.rid = e.experiment_rid
  LEFT JOIN occ.records l ON l.rid = e.item_link_rid
  LEFT JOIN occ.resource_booking rb ON rb.rid = e.resource_rid
"""


def _b(v):
    return 1 if v else 0


def shape(r):
    minutes = int((r["end_at"] - r["start_at"]).total_seconds() // 60)
    full = ("%s %s" % (r["firstname"], r["lastname"])).strip()
    return {"id": r["id"], "team": r["team_id"], "team_name": r["team_name"], "item": r["item"],
            "item_title": r["item_title"], "title": r["title"], "title_only": r["title"],
            "start": timefmt.out(r["start_at"]), "end": timefmt.out(r["end_at"]), "userid": r["user_id"],
            "fullname": full, "firstname": r["firstname"], "lastname": r["lastname"],
            "created_at": timefmt.out(r["created_at"]), "modified_at": timefmt.out(r["modified_at"]),
            "event_duration_minutes": minutes, "color": r["color"],
            "experiment": r["experiment"], "experiment_title": r["experiment_title"],
            "item_link": r["item_link"], "item_link_title": r["item_link_title"],
            "book_cancel_minutes": r["book_cancel_minutes"] or 0,
            "book_is_cancellable": _b(r["book_is_cancellable"] if r["book_is_cancellable"] is not None else True)}


def _when(v, name):
    if v in (None, ""):
        raise errors.bad("Incorrect value for %s: it is required" % name)
    try:
        return timefmt.parse_datetime(v)
    except ValueError:
        raise errors.bad("Could not understand date format!", "%s: ISO 8601 or YYYY-MM-DD HH:MM:SS" % name)


def _resource(tx, p, item_id, for_update=False):
    row = S.fetch(tx, p, K.KINDS["items"], item_id, full=False, for_update=for_update)
    engine.readable_or_raise(p, row, errors)
    rules = tx.one("SELECT * FROM occ.resource_booking WHERE rid = :rid", rid=row["rid"]) or {}
    return row, rules


def _can_book(p, row):
    if row.get("canbook_base") is None:
        return engine.check(p, row, engine.READ)
    return engine.check(p, row, engine.BOOK)


def _rules(tx, p, row, rules, start, end, user_id, exclude_id=None):
    if end <= start:
        raise errors.bad("The end must be after the start")
    admin = row["team_id"] in p.admin_teams
    now = dt.datetime.now(dt.timezone.utc)
    mx = int(rules.get("book_max_minutes") or 0)
    if mx and (end - start).total_seconds() > mx * 60:
        raise errors.bad("This booking is longer than the %d minutes this resource allows" % mx)
    if start < now and not rules.get("book_users_can_in_past") and not admin:
        raise errors.bad("This resource cannot be booked in the past")
    win = int(rules.get("booking_window_days") or 0)
    if win and start > now + dt.timedelta(days=win) and not admin:
        raise errors.bad("This resource can be booked at most %d days ahead" % win)
    slots = int(rules.get("book_max_slots") or 0)
    if slots:
        held = tx.val("SELECT count(*) FROM occ.events WHERE resource_rid = :rid AND user_id = :u AND end_at > now() "
                      "AND id <> :x", rid=row["rid"], u=user_id, x=exclude_id or 0)
        if held >= slots:
            raise errors.bad("You already hold the %d bookings this resource allows" % slots)
    can_overlap = rules.get("book_can_overlap")
    if can_overlap is None:
        can_overlap = True
    if not can_overlap:
        clash = tx.val("SELECT id FROM occ.events WHERE resource_rid = :rid AND id <> :x "
                       "AND tstzrange(start_at, end_at) && tstzrange(:s, :e) LIMIT 1",
                       rid=row["rid"], x=exclude_id or 0, s=start, e=end)
        if clash:
            raise errors.OCCError(409, "This slot overlaps another booking of this resource.")


def _event(tx, p, event_id, for_update=False):
    if for_update:
        tx.run("SELECT 1 FROM occ.events WHERE id = :id FOR UPDATE", id=event_id)
    r = tx.one(_EVENT_SQL + " WHERE e.id = :id", id=event_id)
    if r is None:
        raise errors.not_found()
    res = S.fetch(tx, p, K.KINDS["items"], r["item"], full=False)
    if res is None or not engine.check(p, res, engine.READ):
        raise errors.not_found()
    return r, res


def _manager(p, ev, res):
    if not p.can_write:
        raise errors.forbidden("This API key is read-only.")
    if ev["user_id"] != p.user_id and res["team_id"] not in p.admin_teams:
        raise errors.forbidden("Only the person who booked it or a team admin can change this booking.")


# --------------------------------------------------------------------------------- the bookings
def list_events(tx, p, q):
    start = _when(q.get("start"), "start")
    end = _when(q.get("end"), "end")
    if end <= start:
        raise errors.bad("The end must be after the start")
    cond, params = engine.list_filter(p, engine.READ, "r")
    sql = _EVENT_SQL + " WHERE " + cond + " AND tstzrange(e.start_at, e.end_at) && tstzrange(:s, :e2)"
    params.update(s=start, e2=end)
    if q.get("item") not in (None, "", "all"):
        try:
            params["item"] = int(q["item"])
        except ValueError:
            raise errors.bad("Incorrect value for item")
        sql += " AND r.id = :item"
    if str(q.get("scope") or "") == "team":
        params["team"] = p.team_id
        sql += " AND e.team_id = :team"
    return [shape(r) for r in tx.all(sql + " ORDER BY e.start_at, e.id", **params)]


def create(tx, p, actor, item_id, body):
    S._check_can_write_key(p)
    body = body or {}
    row, rules = _resource(tx, p, item_id, for_update=True)
    if row["state"] == 3:
        raise errors.forbidden("This resource is deleted.")
    if not rules.get("is_bookable"):
        raise errors.bad("This resource is not bookable.")
    if not _can_book(p, row):
        raise errors.forbidden("You cannot book this resource.")
    start, end = _when(body.get("start"), "start"), _when(body.get("end"), "end")
    _rules(tx, p, row, rules, start, end, p.user_id)
    title = str(body.get("title") or "").strip()[:255] or None
    eid = tx.val("INSERT INTO occ.events (team_id, resource_rid, start_at, end_at, title, user_id) "
                 "VALUES (:t, :rid, :s, :e, :ti, :u) RETURNING id", t=row["team_id"], rid=row["rid"], s=start,
                 e=end, ti=title, u=p.user_id)
    audit.write(tx, actor, "event.create", kind_id=K.KINDS["items"].id, record_id=row["id"], rid=row["rid"],
                team_id=row["team_id"], target="event", new="%s..%s" % (timefmt.out(start), timefmt.out(end)),
                detail={"event_id": eid, "title": title})
    return eid


def read(tx, p, event_id):
    return shape(_event(tx, p, event_id)[0])


def _linked(tx, p, kind_code, v, name):
    if v in (None, "", 0, "0", "null"):
        return None
    try:
        rid_id = int(v)
    except (TypeError, ValueError):
        raise errors.bad("Incorrect value for %s" % name)
    rec = S.fetch(tx, p, K.KINDS[kind_code], rid_id, full=False)
    if rec is None or not engine.check(p, rec, engine.READ):
        raise errors.bad("Incorrect value for %s: no %s you can read has that id" % (name, kind_code[:-1]))
    return rec["rid"]


def patch(tx, p, actor, event_id, body):
    body = body or {}
    ev, res = _event(tx, p, event_id, for_update=True)
    _manager(p, ev, res)
    target = body.get("target")
    if target == "datetime":
        start, end = _when(body.get("start"), "start"), _when(body.get("end"), "end")
        rules = tx.one("SELECT * FROM occ.resource_booking WHERE rid = :rid", rid=ev["resource_rid"]) or {}
        _rules(tx, p, res, rules, start, end, ev["user_id"], exclude_id=event_id)
        tx.run("UPDATE occ.events SET start_at = :s, end_at = :e, modified_at = now() WHERE id = :id",
               s=start, e=end, id=event_id)
        old = "%s..%s" % (timefmt.out(ev["start_at"]), timefmt.out(ev["end_at"]))
        new = "%s..%s" % (timefmt.out(start), timefmt.out(end))
        field = "datetime"
    elif target == "title":
        new = str(body.get("title") or "").strip()[:255] or None     # 2.x reads "title" and ignores "content"
        tx.run("UPDATE occ.events SET title = :t, modified_at = now() WHERE id = :id", t=new, id=event_id)
        old, field = ev["title"], "title"
    elif target == "experiment":
        rid = _linked(tx, p, "experiments", body.get("id"), "id")
        tx.run("UPDATE occ.events SET experiment_rid = :r, modified_at = now() WHERE id = :id", r=rid, id=event_id)
        old, new, field = ev["experiment"], body.get("id") if rid else None, "experiment"
    elif target == "item_link":
        rid = _linked(tx, p, "items", body.get("id"), "id")
        tx.run("UPDATE occ.events SET item_link_rid = :r, modified_at = now() WHERE id = :id", r=rid, id=event_id)
        old, new, field = ev["item_link"], body.get("id") if rid else None, "item_link"
    else:
        raise errors.bad("Incorrect value for target: datetime, title, experiment or item_link")
    audit.write(tx, actor, "event.update", kind_id=K.KINDS["items"].id, record_id=res["id"], rid=res["rid"],
                team_id=res["team_id"], target=field, old=old, new=new, detail={"event_id": event_id})
    return read(tx, p, event_id)


NOTIF_EVENT_DELETED = 30      # notification category: the booker is told a booking was cancelled


def delete(tx, p, actor, event_id):
    ev, res = _event(tx, p, event_id, for_update=True)
    _manager(p, ev, res)
    admin = res["team_id"] in p.admin_teams
    if not admin:
        if ev["book_is_cancellable"] is False:
            raise errors.forbidden("Bookings of this resource cannot be cancelled.")
        mins = int(ev["book_cancel_minutes"] or 0)
        if mins and ev["start_at"] - dt.datetime.now(dt.timezone.utc) < dt.timedelta(minutes=mins):
            raise errors.forbidden("Too late to cancel: this resource needs %d minutes' notice." % mins)
    tx.run("DELETE FROM occ.events WHERE id = :id", id=event_id)
    audit.write(tx, actor, "event.delete", kind_id=K.KINDS["items"].id, record_id=res["id"], rid=res["rid"],
                team_id=res["team_id"], target="event",
                old="%s..%s" % (timefmt.out(ev["start_at"]), timefmt.out(ev["end_at"])),
                detail={"event_id": event_id, "title": ev["title"]})
    if ev["user_id"] != p.user_id:
        tx.run("INSERT INTO occ.notifications (user_id, category, body) VALUES (:u, :c, CAST(:b AS jsonb))",
               u=ev["user_id"], c=NOTIF_EVENT_DELETED,
               b=jsonb({"event_id": event_id, "item": res["id"], "start": timefmt.out(ev["start_at"]),
                        "actor": p.user_id}))
