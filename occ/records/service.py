# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Records of every kind: list and search, read, create, change, duplicate, delete.

Rules:
  * A PATCH is atomic: every field is validated first and all are applied in one transaction, or
    none is (2.x applies fields one by one and can save some before it refuses). A bad field
    answers 400 naming it, and nothing is written, not even history.
  * Every change writes one audit row per field with the previous and the new value; the record's
    changelog is read back from those rows.
  * A body change stores the previous body as a revision when it differs by at least
    min_delta_revisions characters.
  * Delete is soft (state 3): still readable by id, gone from every list, as in 2.x;
    deleting again answers 204 (idempotent; 2.x answers 400 or 422).
"""
import datetime as dt
import hashlib
import json
import re
import secrets

import nh3

from .. import errors, timefmt
from ..audit import writer as audit
from ..db import ident, jsonb, sql_fragment
from ..perms import engine
from ..search import grammar
from . import kinds as K

# ---------------------------------------------------------------------------------------- reading
_ROW_SQL = """
SELECT r.rid, r.kind_id, r.id, r.title, r.custom_id, r.date, r.category_id, r.status_id, r.team_id, r.rating,
       r.owner_id, r.locked, r.locked_by, r.locked_at, r.state, r.canread_base, r.canwrite_base, r.canbook_base,
       r.canread_is_immutable, r.canwrite_is_immutable, r.created_at, r.modified_at, r.modified_by,
       r.signature_count, r.last_signed_at, r.last_signed_by, r.timestamped, r.timestamped_by, r.timestamped_at,
       r.elabid, r.access_key, r.hide_main_text, r.body_format, r.metadata, r.color, r.ordering, r.available,
       r.created_from_kind, r.created_from_id, r.canread_target, r.canwrite_target, {body}
       EXISTS (SELECT 1 FROM occ.pins pn WHERE pn.rid = r.rid AND pn.user_id = :p_uid) AS is_pinned,
       s.title AS status_title, s.color AS status_color, c.title AS category_title, c.color AS category_color,
       u.firstname, u.lastname, u.orcid, t.name AS team_name,
       (SELECT cm.body FROM occ.comments cm WHERE cm.rid = r.rid AND cm.deleted_at IS NULL
         ORDER BY cm.created_at DESC, cm.id DESC LIMIT 1) AS recent_comment,
       (SELECT st.body FROM occ.steps st WHERE st.rid = r.rid AND st.deleted_at IS NULL AND NOT st.finished
         ORDER BY st.ordering NULLS LAST, st.id LIMIT 1) AS next_step,
       (SELECT string_agg(tg.tag, '|' ORDER BY tg.tag) FROM occ.record_tags rt JOIN occ.tags tg ON tg.id = rt.tag_id
         WHERE rt.rid = r.rid) AS tags,
       (SELECT string_agg(tg.id::text, ',' ORDER BY tg.tag) FROM occ.record_tags rt JOIN occ.tags tg ON tg.id = rt.tag_id
         WHERE rt.rid = r.rid) AS tags_id,
       (SELECT coalesce(jsonb_agg(jsonb_build_array(ra.access_right, ra.principal, ra.principal_id)), '[]'::jsonb)
         FROM occ.record_access ra WHERE ra.rid = r.rid) AS access
  FROM occ.records r
  JOIN occ.users u ON u.id = r.owner_id
  JOIN occ.teams t ON t.id = r.team_id
  LEFT JOIN occ.statuses s ON s.lookup_group = r.lookup_group AND s.id = r.status_id
  LEFT JOIN occ.categories c ON c.lookup_group = r.lookup_group AND c.id = r.category_id
"""


@sql_fragment
def _sql(full=False):
    return _ROW_SQL.format(body="r.body, r.body_text," if full else "")


def _norm(row):
    if row is None:
        return None
    row["access"] = [tuple(a) for a in (row.get("access") or [])]
    return row


def fetch(tx, p, kind, rec_id, full=True, for_update=False):
    """The record of `kind` with public id rec_id, or None. Locks its row when for_update."""
    if for_update:
        tx.run("SELECT 1 FROM occ.records WHERE kind_id = :k AND id = :id FOR UPDATE", k=kind.id, id=rec_id)
    return _norm(tx.one(_sql(full) + " WHERE r.kind_id = :k AND r.id = :id", k=kind.id, id=rec_id,
                        p_uid=p.user_id))


def _access_json(access, right, base=None):
    """canread/canwrite/canbook as JSON text, as 2.x returns them. The base is carried inside as well (a
    field the OCC adds), so a caller that wrote {"base": 20, ...} reads the same object back."""
    d = {"teams": [], "users": [], "teamgroups": []}
    if base is not None:
        d = {"base": base, **d}
    names = {"t": "teams", "u": "users", "g": "teamgroups"}
    for (rt, kind, pid) in access:
        if rt == right:
            d[names[kind]].append(pid)
    for k in ("teams", "users", "teamgroups"):
        d[k].sort()
    return json.dumps(d)


def _b(v):
    return 1 if v else 0


def shape_row(row, full=False):
    """The list row; booleans as 0/1 and permissions and metadata as JSON text, as 2.x answers."""
    out = {
        "id": row["id"], "title": row["title"], "custom_id": row["custom_id"], "date": timefmt.out(row["date"]),
        "category": row["category_id"], "status": row["status_id"], "team": row["team_id"], "rating": row["rating"],
        "userid": row["owner_id"], "locked": _b(row["locked"]), "state": row["state"],
        "canread": _access_json(row["access"], "r", row["canread_base"]),
        "canwrite": _access_json(row["access"], "w", row["canwrite_base"]),
        "canread_base": row["canread_base"], "canwrite_base": row["canwrite_base"],
        "canread_is_immutable": _b(row["canread_is_immutable"]),
        "canwrite_is_immutable": _b(row["canwrite_is_immutable"]),
        "created_at": timefmt.out(row["created_at"]), "modified_at": timefmt.out(row["modified_at"]),
        "signature_count": row["signature_count"], "last_signed_at": timefmt.out(row["last_signed_at"]),
        "last_signed_by": row["last_signed_by"], "timestamped": _b(row["timestamped"]),
        "timestampedby": row["timestamped_by"], "is_pinned": _b(row["is_pinned"]),
        "status_title": row["status_title"], "status_color": row["status_color"],
        "category_title": row["category_title"], "category_color": row["category_color"],
        "recent_comment": row["recent_comment"], "next_step": row["next_step"],
        "firstname": row["firstname"], "lastname": row["lastname"], "orcid": row["orcid"],
        "fullname": ("%s %s" % (row["firstname"], row["lastname"])).strip(), "team_name": row["team_name"],
        "tags": row["tags"], "tags_id": row["tags_id"],
        "tags_decoded": (row["tags"] or "").split("|") if row["tags"] else [],
    }
    if row.get("canbook_base") is not None:
        out["canbook_base"] = row["canbook_base"]
        out["canbook"] = _access_json(row["access"], "b", row["canbook_base"])
    if full:
        out["body"] = row.get("body")
        out["metadata"] = json.dumps(row["metadata"]) if row.get("metadata") is not None else None
    return out


def can_read(p, row):
    return engine.check(p, row, engine.READ)


# ------------------------------------------------------------------------------------------ list
_ORDER = {"id": "r.id", "date": "r.date", "title": "r.title", "lastchange": "r.modified_at",
          "category": "c.title", "status": "s.title", "rating": "r.rating", "customid": "r.custom_id",
          "user": "u.lastname"}


def list_records(tx, p, kind, q):
    """List records. q: the query parameters as a dict (lists for repeated ones)."""
    where = ["r.kind_id = :l_kind"]
    params = {"l_kind": kind.id, "p_uid": p.user_id}

    cond, perm_params = engine.list_filter(p, engine.READ)
    where.append(cond)
    params.update(perm_params)

    states = _int_list(q.get("state"), "state") or [1]
    where.append("r.state = ANY(CAST(:l_states AS int[]))")
    params["l_states"] = [s for s in states if s in (1, 2, 3)] or [1]

    prefs = q.get("_prefs") or {}
    scope = _int1(q.get("scope"), "scope") or int(prefs.get("scope_%s" % kind.code) or 3)
    if scope == 1:
        where.append("r.owner_id = :l_me")
        params["l_me"] = p.user_id
    elif scope == 2:
        where.append("r.team_id = :l_team")
        params["l_team"] = p.team_id
    if q.get("team") not in (None, ""):
        if not p.site_scope:
            raise errors.forbidden("team= is for site-scope keys only.")
        where.append("r.team_id = :l_only_team")
        params["l_only_team"] = _int1(q.get("team"), "team")

    for name, col in (("cat", "r.category_id"), ("status", "r.status_id"), ("owner", "r.owner_id")):
        v = q.get(name)
        if v not in (None, ""):
            ids = _int_list(v, name)
            where.append("%s = ANY(CAST(:l_%s AS int[]))" % (col, name))
            params["l_" + name] = ids

    for i, tag in enumerate(q.get("tags") or []):
        where.append("EXISTS (SELECT 1 FROM occ.record_tags rt JOIN occ.tags tg ON tg.id = rt.tag_id "
                     "WHERE rt.rid = r.rid AND tg.tag = :l_tag%d)" % i)
        params["l_tag%d" % i] = tag

    search = False
    if q.get("q"):
        where.append("r.search_text ILIKE :l_q")
        params["l_q"] = "%" + grammar.like_escape(str(q["q"])) + "%"
        search = True
    if q.get("extended"):
        try:
            sql, sp = grammar.compile_extended(str(q["extended"]))
        except grammar.SearchError as e:
            raise errors.bad(str(e))
        where.append(sql)
        params.update(sp)
        search = True

    if q.get("related") not in (None, ""):
        origin = K.get(q.get("related_origin") or "experiments")
        where.append("EXISTS (SELECT 1 FROM occ.record_links lk JOIN occ.records o ON o.rid = lk.from_rid "
                     "WHERE lk.to_rid = r.rid AND o.kind_id = :l_rk AND o.id = :l_rid)")
        params["l_rk"] = origin.id
        params["l_rid"] = _int1(q.get("related"), "related")

    if kind.bookable and str(q.get("bookable") or "") in ("1", "true"):
        where.append("EXISTS (SELECT 1 FROM occ.resource_booking rb WHERE rb.rid = r.rid AND rb.is_bookable)")

    order = q.get("order") or prefs.get("orderby") or "date"
    if order not in _ORDER:
        raise errors.bad("Invalid order: %s" % order)
    sort = (q.get("sort") or prefs.get("sort") or "desc").lower()
    if sort not in SORTS:
        raise errors.bad("Invalid sort: %s" % sort)
    direction = ident(sort, SORTS)

    limit = _int1(q.get("limit"), "limit")
    if limit is None:
        limit = int(prefs.get("limit_nb") or 15)
    if limit < 0 or limit > 10000:
        raise errors.bad("limit must be between 0 and 10000")
    offset = _int1(q.get("offset"), "offset") or 0
    if offset < 0:
        raise errors.bad("offset must not be negative")

    full = search or str(q.get("full") or "") in ("1", "true")
    sql = (_sql(full) + " WHERE " + " AND ".join(where)
           + " ORDER BY %s %s NULLS LAST, r.id %s LIMIT :l_limit OFFSET :l_offset" % (_ORDER[order], direction, direction))
    params["l_limit"] = limit
    params["l_offset"] = offset
    rows = tx.all(sql, **params)
    return [shape_row(_norm(r), full=full) for r in rows]


def _int1(v, name):
    if v in (None, ""):
        return None
    if isinstance(v, list):
        v = v[0]
    try:
        return int(v)
    except (TypeError, ValueError):
        raise errors.bad("%s must be a number" % name)


def _int_list(v, name):
    if v in (None, ""):
        return []
    vals = v if isinstance(v, list) else str(v).split(",")
    try:
        return [int(x) for x in vals if str(x).strip() != ""]
    except ValueError:
        raise errors.bad("%s must be a list of numbers" % name)


# ------------------------------------------------------------------------------------------ read
def read(tx, p, kind, rec_id, base_url, with_changelog=True):
    row = fetch(tx, p, kind, rec_id)
    engine.readable_or_raise(p, row, errors)
    return full_shape(tx, p, kind, row, base_url, with_changelog)


def full_shape(tx, p, kind, row, base_url, with_changelog=True):
    from . import subs  # comments, steps, links: one module for the sub-resources
    out = shape_row(row, full=True)
    out.update({
        "body_html": row.get("body"), "content_type": row["body_format"], "elabid": row["elabid"],
        "access_key": str(row["access_key"]) if row["access_key"] else None,
        "sharelink": "%s/api/v2/%s/%d" % (base_url, kind.code, row["id"]),
        "page": kind.page, "type": kind.code, "hide_main_text": _b(row["hide_main_text"]),
        "locked_at": timefmt.out(row["locked_at"]), "lockedby": row["locked_by"], "lastchangeby": row["modified_by"],
        "timestamped_at": timefmt.out(row["timestamped_at"]),
        "created_from_id": row["created_from_id"],
        "created_from_type": K.BY_ID[row["created_from_kind"]].code if row["created_from_kind"] else None,
        "created_from_type_human": K.BY_ID[row["created_from_kind"]].singular if row["created_from_kind"] else None,
        "exclusive_edit_mode": None,
        "canread_base_human": engine.BASE_HUMAN.get(row["canread_base"]),
        "canwrite_base_human": engine.BASE_HUMAN.get(row["canwrite_base"]),
        "changelog": changelog(tx, row["rid"]) if with_changelog else [],
        "comments": subs.list_comments(tx, row),
        "steps": subs.list_steps(tx, row),
        "uploads": subs.list_uploads(tx, row),
        "experiments_links": subs.list_links(tx, row, "experiments"),
        "items_links": subs.list_links(tx, row, "items"),
        "related_experiments_links": subs.list_links(tx, row, "experiments", related=True),
        "related_items_links": subs.list_links(tx, row, "items", related=True),
        "compounds_links": [], "containers": [], "surrounding_bookers": [],
        "events_start": None, "events_start_itemid": None,
    })
    if kind.is_template:
        out["color"] = row["color"]
        out["ordering"] = row["ordering"]
        out["canread_target"] = json.dumps(row["canread_target"]) if row["canread_target"] is not None else None
        out["canwrite_target"] = json.dumps(row["canwrite_target"]) if row["canwrite_target"] is not None else None
    if kind.code in ("items", "items_types"):
        out["available"] = _b(row["available"])
        b = tx.one("SELECT * FROM occ.resource_booking WHERE rid = :rid", rid=row["rid"])
        for col in _BOOKING_COLS:
            v = (b or {}).get(col, _BOOKING_DEFAULTS[col])
            out[col] = _b(v) if isinstance(v, bool) else (float(v) if hasattr(v, "as_integer_ratio") and not isinstance(v, int) else v)
    return out


def changelog(tx, rid):
    """The whole history, newest first; rows sharing a second keep arrival order (by id)."""
    rows = tx.all("SELECT a.id, a.at, a.target, a.new_value, a.old_value, a.actor_user_id, a.origin, "
                  "u.firstname, u.lastname FROM occ.audit_events a LEFT JOIN occ.users u ON u.id = a.actor_user_id "
                  "WHERE a.rid = :rid AND a.category LIKE 'record.%' ORDER BY a.id DESC", rid=rid)
    return [{"id": r["id"], "created_at": timefmt.out(r["at"]), "target": r["target"], "content": r["new_value"],
             "old_value": r["old_value"], "fullname": ("%s %s" % (r["firstname"] or "", r["lastname"] or "")).strip(),
             "userid": r["actor_user_id"], "origin": r["origin"]} for r in rows]


# ------------------------------------------------------------------------------------ validation
_BOOKING_COLS = ("is_bookable", "book_max_minutes", "book_max_slots", "book_can_overlap", "book_users_can_in_past",
                 "book_is_cancellable", "book_cancel_minutes", "booking_window_days", "is_procurable",
                 "proc_pack_qty", "proc_price_notax", "proc_price_tax", "proc_currency")
_BOOKING_DEFAULTS = {"is_bookable": False, "book_max_minutes": 0, "book_max_slots": 0, "book_can_overlap": True,
                     "book_users_can_in_past": False, "book_is_cancellable": True, "book_cancel_minutes": 0,
                     "booking_window_days": 0, "is_procurable": False, "proc_pack_qty": 1,
                     "proc_price_notax": 0, "proc_price_tax": 0, "proc_currency": 0}
# Closed lists of identifiers that may be put into SQL text: values are always parameters.
RECORD_COLUMNS = frozenset(("title", "date", "body", "body_format", "hide_main_text", "category_id", "status_id",
                            "custom_id", "rating", "color", "ordering", "metadata", "canread_base",
                            "canwrite_base", "canbook_base", "canread_is_immutable", "canwrite_is_immutable",
                            "canread_target", "canwrite_target", "available", "owner_id", "team_id"))
BOOKING_COLUMNS = frozenset(_BOOKING_COLS)
SORTS = frozenset(("asc", "desc"))
_BOOKING_BOOL = {"is_bookable", "book_can_overlap", "book_users_can_in_past", "book_is_cancellable", "is_procurable"}

_HEX = re.compile(r"^#?([0-9A-Fa-f]{6})$")


def _bool(name, v):
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("1", "true", "on", "yes"):
        return True
    if s in ("0", "false", "off", "no", ""):
        return False
    raise errors.bad("Incorrect value for %s" % name)


def _int_strict(name, v):
    if isinstance(v, bool):
        raise errors.bad("Incorrect value for %s" % name)
    if isinstance(v, int):
        return v
    s = str(v).strip()
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    raise errors.bad("Incorrect value for %s: it must be a whole number" % name)


def sanitize_body(html):
    if html is None:
        return None
    return nh3.clean(str(html), tags=_BODY_TAGS, attributes=_BODY_ATTRS, link_rel=None,
                     url_schemes={"http", "https", "mailto", "data"})


_BODY_TAGS = {"a", "abbr", "b", "blockquote", "br", "caption", "cite", "code", "col", "colgroup", "dd", "del", "div",
              "dl", "dt", "em", "figcaption", "figure", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i", "img", "ins",
              "kbd", "li", "mark", "ol", "p", "pre", "q", "s", "samp", "small", "span", "strong", "sub", "sup",
              "table", "tbody", "td", "tfoot", "th", "thead", "tr", "u", "ul", "math", "mi", "mn", "mo", "mrow",
              "msup", "msub", "mfrac", "msqrt", "mtext", "details", "summary"}
_BODY_ATTRS = {"*": {"class", "style", "title", "id", "lang", "dir"},
               "a": {"href", "target", "name"}, "img": {"src", "alt", "width", "height"},
               "td": {"colspan", "rowspan", "align"}, "th": {"colspan", "rowspan", "align", "scope"},
               "col": {"span", "width"}, "ol": {"start", "type"}}


def body_text(html):
    if not html:
        return ""
    t = re.sub(r"<(br|/p|/div|/li|/h\d|/tr)\b[^>]*>", "\n", html, flags=re.I)
    t = re.sub(r"<[^>]+>", " ", t)
    t = (t.replace("&nbsp;", " ").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"')
         .replace("&#39;", "'").replace("&amp;", "&"))
    return re.sub(r"[ \t]+", " ", t).strip()


def _metadata(v):
    """'' or null clears (2.x answers 500 to both); an object or JSON text of an object is accepted."""
    if v is None or (isinstance(v, str) and v.strip() == ""):
        return None
    if isinstance(v, str):
        try:
            v = json.loads(v)
        except ValueError:
            raise errors.bad("Incorrect value for metadata: it is not valid JSON")
    if not isinstance(v, dict):
        raise errors.bad("Incorrect value for metadata: it must be a JSON object")
    return v


def _perm(p, row, name, v):
    """canread/canwrite/canbook: {base, teams, users, teamgroups} as an object or JSON text."""
    if isinstance(v, str):
        try:
            v = json.loads(v)
        except ValueError:
            raise errors.bad("Incorrect value for %s" % name)
    if not isinstance(v, dict):
        raise errors.bad("Incorrect value for %s" % name)
    base = v.get("base")
    try:
        base = int(base)
    except (TypeError, ValueError):
        raise errors.bad("Incorrect value for %s: base is required" % name)
    if base not in engine.BASES:
        raise errors.bad("Incorrect value for %s: base must be one of 10, 20, 30, 40, 50" % name)
    lists = {}
    for key, kind in (("teams", "t"), ("users", "u"), ("teamgroups", "g")):
        vals = v.get(key) or []
        if not isinstance(vals, list):
            raise errors.bad("Incorrect value for %s: %s must be a list" % (name, key))
        try:
            lists[kind] = sorted({int(x) for x in vals})
        except (TypeError, ValueError):
            raise errors.bad("Incorrect value for %s: %s must hold ids" % (name, key))
    return base, lists


# --------------------------------------------------------------------------------------- writing
def _check_can_write_key(p):
    if not p.can_write:
        raise errors.forbidden("This API key is read-only.")


def _writable(tx, p, kind, rec_id, unlocking=False, allow_deleted=False):
    row = fetch(tx, p, kind, rec_id, for_update=True)
    engine.readable_or_raise(p, row, errors)
    _check_can_write_key(p)
    if row["state"] == 3 and not allow_deleted:
        raise errors.forbidden("This entry is deleted: it accepts only restore.")
    probe = dict(row, state=1) if allow_deleted else row
    if not engine.check(p, probe, engine.WRITE):
        raise errors.forbidden()
    blocked = engine.write_block(p, row, unlocking=unlocking)
    if blocked:
        raise errors.OCCError(*blocked)
    return row


def _site(tx, name, default=None):
    v = tx.val("SELECT value FROM occ.site_config WHERE name = :n AND NOT is_secret", n=name)
    return default if v is None else v


LOOKUP_TABLES = frozenset(("statuses", "categories"))


def _lookup_ok(tx, p, kind, table, lookup_id, team_id):
    row = tx.one("SELECT id, team_id, is_private, state FROM occ.%s WHERE lookup_group = :g AND id = :id"
                 % ident(table, LOOKUP_TABLES), g=kind.lookup_group, id=lookup_id)
    if row is None or row["state"] == 3:
        return False
    return row["team_id"] == team_id or not row["is_private"]


def validate_fields(tx, p, kind, row, body):
    """Every field checked before anything is written. Returns [(field, column, new value)]."""
    out = []
    team_id = row["team_id"] if row else p.team_id
    for name, v in body.items():
        if name == "title":
            t = "" if v is None else str(v).strip()
            out.append(("title", "title", t or "Untitled"))
        elif name == "date":
            if v is None or str(v).strip() == "":
                out.append(("date", "date", None))
            else:
                try:
                    out.append(("date", "date", timefmt.parse_date(v)))
                except ValueError:
                    raise errors.bad("Incorrect value for date: use YYYY-MM-DD")
        elif name == "body":
            out.append(("body", "body", sanitize_body(v)))
        elif name == "content_type":
            ct = _int_strict(name, v)
            if ct not in (1, 2):
                raise errors.bad("Incorrect value for content_type: 1 (HTML) or 2 (Markdown)")
            out.append((name, "body_format", ct))
        elif name in ("category", "status"):
            if v is None or str(v).strip() == "":
                out.append((name, name + "_id", None))
            else:
                lid = _int_strict(name, v)
                table = "categories" if name == "category" else "statuses"
                if not _lookup_ok(tx, p, kind, table, lid, team_id):
                    raise errors.bad("Incorrect value for %s: no such %s in this team" % (name, name))
                out.append((name, name + "_id", lid))
        elif name == "rating":
            if v is None or str(v).strip() == "":
                out.append(("rating", "rating", 0))
            else:
                r = _int_strict(name, v)
                if r < 0 or r > 5:
                    raise errors.bad("Incorrect value for rating: it must be between 0 and 5")
                out.append(("rating", "rating", r))
        elif name == "custom_id":
            if v is None or str(v).strip() == "":
                out.append(("custom_id", "custom_id", None))
            else:
                out.append(("custom_id", "custom_id", _int_strict(name, v)))
        elif name == "metadata":
            out.append(("metadata", "metadata", _metadata(v)))
        elif name in ("canread", "canwrite", "canbook"):
            if name == "canbook" and kind.code not in ("items", "items_types"):
                raise errors.bad("Invalid update target: canbook")
            out.append((name, name, _perm(p, row, name, v)))
        elif name == "hide_main_text":
            out.append((name, name, _bool(name, v)))
        elif name == "color":
            if kind.code != "items_types":
                raise errors.bad("Invalid update target: color")
            m = _HEX.match(str(v or ""))
            if not m:
                raise errors.bad("Incorrect value for color: six hexadecimal digits")
            out.append((name, name, m.group(1).upper()))
        elif name == "ordering":
            if not kind.is_template:
                raise errors.bad("Invalid update target: ordering")
            out.append((name, name, None if v in (None, "") else _int_strict(name, v)))
        elif name == "available":
            if kind.code not in ("items", "items_types"):
                raise errors.bad("Invalid update target: available")
            out.append((name, name, _bool(name, v)))     # 2.x refuses 'available'; the OCC writes it
        elif name in _BOOKING_COLS:
            if kind.code not in ("items", "items_types"):
                raise errors.bad("Invalid update target: %s" % name)
            if name in _BOOKING_BOOL:
                out.append((name, "booking." + name, _bool(name, v)))
            else:
                n = _int_strict(name, v) if not name.startswith("proc_price") else _decimal(name, v)
                if not isinstance(n, float) and n < 0:
                    raise errors.bad("Incorrect value for %s: it must not be negative" % name)
                out.append((name, "booking." + name, n))
        elif name in ("canread_target", "canwrite_target"):
            if not kind.is_template:
                raise errors.bad("Invalid update target: %s" % name)
            base, lists = _perm(p, row, name, v)
            out.append((name, name, {"base": base, "teams": lists["t"], "users": lists["u"], "teamgroups": lists["g"]}))
        else:
            raise errors.bad("Invalid update target: %s" % name)
    for (field, _col, val) in out:
        if field in ("canread", "canwrite") and row is not None:
            imm = row.get(field + "_is_immutable")
            if imm and row["team_id"] not in p.admin_teams:
                raise errors.forbidden("%s is set as immutable: only team admins can change it." % field)
    return out


def _decimal(name, v):
    try:
        return float(v)
    except (TypeError, ValueError):
        raise errors.bad("Incorrect value for %s" % name)


def _val_text(v):
    if v is None:
        return None
    if isinstance(v, (dict, list)):
        return json.dumps(v)
    if isinstance(v, (dt.date, dt.datetime)):
        return timefmt.out(v)
    if isinstance(v, bool):
        return "1" if v else "0"
    return str(v)


def apply_fields(tx, p, actor, kind, row, fields):
    """Apply validated fields to row (locked FOR UPDATE). One audit row per changed field."""
    changed = []
    booking = {}
    for field, col, new in fields:
        if col in ("canread", "canwrite", "canbook"):
            base, lists = new
            right = {"canread": "r", "canwrite": "w", "canbook": "b"}[col]
            old_lists = {k: sorted(pid for (rt, kk, pid) in row["access"] if rt == right and kk == k) for k in "tug"}
            old_base = row[col + "_base"]
            if old_base == base and old_lists == lists:
                continue
            tx.run("UPDATE occ.records SET %s = :b WHERE rid = :rid" % ident(col + "_base", RECORD_COLUMNS), b=base,
                   rid=row["rid"])
            tx.run("DELETE FROM occ.record_access WHERE rid = :rid AND access_right = :rt", rid=row["rid"], rt=right)
            for k, ids in lists.items():
                for pid in ids:
                    tx.run("INSERT INTO occ.record_access (rid, access_right, principal, principal_id) "
                           "VALUES (:rid, :rt, :k, :pid)", rid=row["rid"], rt=right, k=k, pid=pid)
            old_t = json.dumps({"base": old_base, "teams": old_lists["t"], "users": old_lists["u"],
                                "teamgroups": old_lists["g"]})
            new_t = json.dumps({"base": base, "teams": lists["t"], "users": lists["u"], "teamgroups": lists["g"]})
            changed.append((field, old_t, new_t))
            continue
        if col.startswith("booking."):
            booking[col[8:]] = (field, new)
            continue
        old = row.get(col)
        if old == new:
            continue
        if col == "body":
            _maybe_revision(tx, p, row, old, new)
            tx.run("UPDATE occ.records SET body = :v, body_text = :t WHERE rid = :rid",
                   v=new, t=body_text(new), rid=row["rid"])
        elif col in ("metadata", "canread_target", "canwrite_target"):
            tx.run("UPDATE occ.records SET %s = CAST(:v AS jsonb) WHERE rid = :rid" % ident(col, RECORD_COLUMNS),
                   v=jsonb(new), rid=row["rid"])
        else:
            tx.run("UPDATE occ.records SET %s = :v WHERE rid = :rid" % ident(col, RECORD_COLUMNS), v=new,
                   rid=row["rid"])
        changed.append((field, _val_text(old), _val_text(new)))
    if booking:
        cur = tx.one("SELECT * FROM occ.resource_booking WHERE rid = :rid", rid=row["rid"]) or {}
        if not cur:
            tx.run("INSERT INTO occ.resource_booking (rid) VALUES (:rid)", rid=row["rid"])
        for col, (field, new) in booking.items():
            old = cur.get(col, _BOOKING_DEFAULTS[col])
            if old == new or (not isinstance(new, bool) and old is not None and float(old) == float(new)):
                continue
            tx.run("UPDATE occ.resource_booking SET %s = :v WHERE rid = :rid" % ident(col, BOOKING_COLUMNS), v=new,
                   rid=row["rid"])
            changed.append((field, _val_text(old), _val_text(new)))
    for field, old, new in changed:
        audit.write(tx, actor, "record.update", kind_id=kind.id, record_id=row["id"], rid=row["rid"],
                    team_id=row["team_id"], target=field, old=old, new=new)
    if changed:
        touch(tx, p, row["rid"])
    return changed


def touch(tx, p, rid):
    tx.run("UPDATE occ.records SET modified_at = now(), modified_by = :u WHERE rid = :rid", u=p.user_id, rid=rid)
    refresh_search(tx, rid)


def refresh_search(tx, rid):
    """search_text: title, plain body, extra-field values, tag names, custom id and elabid."""
    tx.run("""
        UPDATE occ.records r SET search_text = concat_ws(' ', r.title, r.body_text,
            (SELECT string_agg(coalesce(e.value->>'value', ''), ' ')
               FROM jsonb_each(CASE WHEN jsonb_typeof(r.metadata->'extra_fields') = 'object'
                                    THEN r.metadata->'extra_fields' ELSE '{}'::jsonb END) e),
            (SELECT string_agg(tg.tag, ' ') FROM occ.record_tags rt JOIN occ.tags tg ON tg.id = rt.tag_id
              WHERE rt.rid = r.rid),
            r.custom_id::text, r.elabid)
        WHERE r.rid = :rid""", rid=rid)


def _maybe_revision(tx, p, row, old, new):
    if old is None or old == new:
        return
    min_delta = int(_site(tx, "min_delta_revisions", "100") or 100)
    if abs(len(new or "") - len(old)) < min_delta and _char_delta(old, new or "") < min_delta:
        return
    tx.run("INSERT INTO occ.revisions (rid, body, body_format, body_sha256, user_id) "
           "VALUES (:rid, :b, :f, :h, :u)", rid=row["rid"], b=old, f=row["body_format"],
           h=hashlib.sha256(old.encode("utf-8")).digest(), u=p.user_id)


def _char_delta(a, b):
    """A cheap lower bound on how many characters differ: length change plus changed positions."""
    n = min(len(a), len(b))
    return abs(len(a) - len(b)) + sum(1 for i in range(n) if a[i] != b[i])


def patch(tx, p, actor, kind, rec_id, body, base_url):
    """Change fields, or perform one action. Answers the full record."""
    if not isinstance(body, dict):
        raise errors.bad("The request body must be a JSON object")
    action = body.get("action")
    if action is not None:
        return _action(tx, p, actor, kind, rec_id, str(action), body, base_url)
    if not body:
        raise errors.bad("Nothing to change")
    row = _writable(tx, p, kind, rec_id)
    fields = validate_fields(tx, p, kind, row, body)
    apply_fields(tx, p, actor, kind, row, fields)
    return read(tx, p, kind, rec_id, base_url)


def _action(tx, p, actor, kind, rec_id, action, body, base_url):
    if action == "lock":
        row = fetch(tx, p, kind, rec_id, for_update=True)
        engine.readable_or_raise(p, row, errors)
        _check_can_write_key(p)
        if row["state"] == 3:
            raise errors.forbidden("This entry is deleted: it accepts only restore.")
        if row["locked"]:
            if engine.write_block(p, row, unlocking=True):
                raise errors.forbidden("Only the person who locked it, its owner or a team admin can unlock it.")
            tx.run("UPDATE occ.records SET locked = false, locked_by = NULL, locked_at = NULL WHERE rid = :rid",
                   rid=row["rid"])
            audit.write(tx, actor, "record.lock", kind_id=kind.id, record_id=row["id"], rid=row["rid"],
                        team_id=row["team_id"], target="locked", old="1", new="0")
        else:
            if not engine.check(p, row, engine.WRITE):
                raise errors.forbidden()
            tx.run("UPDATE occ.records SET locked = true, locked_by = :u, locked_at = now() WHERE rid = :rid",
                   u=p.user_id, rid=row["rid"])
            audit.write(tx, actor, "record.lock", kind_id=kind.id, record_id=row["id"], rid=row["rid"],
                        team_id=row["team_id"], target="locked", old="0", new="1")
        touch(tx, p, row["rid"])
        return read(tx, p, kind, rec_id, base_url)

    if action == "pin":
        row = fetch(tx, p, kind, rec_id)
        engine.readable_or_raise(p, row, errors)
        if row["is_pinned"]:
            tx.run("DELETE FROM occ.pins WHERE user_id = :u AND rid = :rid", u=p.user_id, rid=row["rid"])
        else:
            tx.run("INSERT INTO occ.pins (user_id, rid) VALUES (:u, :rid) ON CONFLICT DO NOTHING",
                   u=p.user_id, rid=row["rid"])
        return read(tx, p, kind, rec_id, base_url)

    if action == "updatemetadatafield":
        row = _writable(tx, p, kind, rec_id)
        values = {k: v for k, v in body.items() if k != "action"}
        if not values:
            raise errors.bad("updatemetadatafield needs at least one field")
        meta = json.loads(json.dumps(row["metadata"])) if row["metadata"] else {}
        ef = meta.setdefault("extra_fields", {})
        if not isinstance(ef, dict):
            raise errors.bad("This record's extra fields are not an object")
        for name, value in values.items():
            f = ef.get(name)
            if not isinstance(f, dict):
                f = {"type": "text"}          # a field the record lacks is added (2.x drops the value)
                ef[name] = f
            f["value"] = value
        apply_fields(tx, p, actor, kind, row, [("metadata", "metadata", meta)])
        return read(tx, p, kind, rec_id, base_url)

    if action in ("archive", "unarchive"):
        row = _writable(tx, p, kind, rec_id)
        new_state = 2 if action == "archive" else 1
        if row["state"] != new_state:
            tx.run("UPDATE occ.records SET state = :s WHERE rid = :rid", s=new_state, rid=row["rid"])
            audit.write(tx, actor, "record.update", kind_id=kind.id, record_id=row["id"], rid=row["rid"],
                        team_id=row["team_id"], target="state", old=row["state"], new=new_state)
            touch(tx, p, row["rid"])
        return read(tx, p, kind, rec_id, base_url)

    if action == "destroy":
        delete(tx, p, actor, kind, rec_id)
        return read(tx, p, kind, rec_id, base_url)

    if action == "restore":
        row = _writable(tx, p, kind, rec_id, allow_deleted=True)
        if row["state"] == 3:
            tx.run("UPDATE occ.records SET state = 1 WHERE rid = :rid", rid=row["rid"])
            audit.write(tx, actor, "record.restore", kind_id=kind.id, record_id=row["id"], rid=row["rid"],
                        team_id=row["team_id"], target="state", old=3, new=1)
            touch(tx, p, row["rid"])
        return read(tx, p, kind, rec_id, base_url)

    if action == "updateowner":
        row = _writable(tx, p, kind, rec_id)
        try:
            new_owner = int(body.get("userid"))
        except (TypeError, ValueError):
            raise errors.bad("updateowner needs userid")
        team = body.get("team")
        team = int(team) if team not in (None, "") else row["team_id"]
        if row["owner_id"] != p.user_id and row["team_id"] not in p.admin_teams:
            raise errors.forbidden("Only the owner or a team admin can change the owner.")
        if team != row["team_id"] and team not in p.admin_teams and not p.is_sysadmin:
            raise errors.forbidden("Moving a record to another team needs admin rights there.")
        member = tx.val("SELECT 1 FROM occ.memberships WHERE user_id = :u AND team_id = :t AND NOT is_archived",
                        u=new_owner, t=team)
        if not member:
            raise errors.bad("The new owner is not a member of that team.")
        changes = []
        if new_owner != row["owner_id"]:
            changes.append(("userid", "owner_id", row["owner_id"], new_owner))
        if team != row["team_id"]:
            changes.append(("team", "team_id", row["team_id"], team))
        for target, col, old, new in changes:
            tx.run("UPDATE occ.records SET %s = :v WHERE rid = :rid" % ident(col, RECORD_COLUMNS), v=new,
                   rid=row["rid"])
            audit.write(tx, actor, "record.update", kind_id=kind.id, record_id=row["id"], rid=row["rid"],
                        team_id=row["team_id"], target=target, old=old, new=new)
        if changes:
            touch(tx, p, row["rid"])
        return read(tx, p, kind, rec_id, base_url)

    if action in ("forcelock", "forceunlock"):
        # A team admin of the record's team (or a sysadmin) sets the lock either
        # way whoever holds it; not a toggle, so a repeat changes nothing.
        row = fetch(tx, p, kind, rec_id, for_update=True)
        engine.readable_or_raise(p, row, errors)
        _check_can_write_key(p)
        if row["team_id"] not in p.admin_teams and not p.is_sysadmin:
            raise errors.forbidden("Only an admin of the record's team can force a lock.")
        want = action == "forcelock"
        if bool(row["locked"]) != want:
            if want:
                tx.run("UPDATE occ.records SET locked = true, locked_by = :u, locked_at = now() WHERE rid = :rid",
                       u=p.user_id, rid=row["rid"])
            else:
                tx.run("UPDATE occ.records SET locked = false, locked_by = NULL, locked_at = NULL WHERE rid = :rid",
                       rid=row["rid"])
            audit.write(tx, actor, "record.lock", kind_id=kind.id, record_id=row["id"], rid=row["rid"],
                        team_id=row["team_id"], target="locked", old="1" if row["locked"] else "0",
                        new="1" if want else "0", detail={"forced": True})
            touch(tx, p, row["rid"])
        return read(tx, p, kind, rec_id, base_url)

    if action == "setnextcustomid":
        # The next custom id is one more than the highest in use among records of
        # the same kind, team and category (1 when none); a record without a category is refused.
        row = _writable(tx, p, kind, rec_id)
        if row["category_id"] is None:
            raise errors.bad("setnextcustomid needs the record to have a category")
        nxt = tx.val("SELECT coalesce(max(custom_id), 0) + 1 FROM occ.records WHERE kind_id = :k AND team_id = :t "
                     "AND category_id = :c AND rid <> :rid", k=kind.id, t=row["team_id"], c=row["category_id"],
                     rid=row["rid"])
        apply_fields(tx, p, actor, kind, row, [("custom_id", "custom_id", nxt)])
        return read(tx, p, kind, rec_id, base_url)

    if action in ("sign", "timestamp"):
        # Served by occ/signing/service.py (it needs the file store and, for timestamps, a call to the
        # authority outside the transaction); the router sends them there.
        raise errors.bad("Invalid action: %s" % action)
    raise errors.bad("Invalid action: %s" % action)


# -------------------------------------------------------------------------------------- creating
def _new_id(tx, kind):
    floor = tx.val("SELECT local_id_floor FROM occ.sync_settings WHERE id = 1 AND enabled AND direction = 'A'")
    v = tx.val("SELECT nextval(CAST(:s AS regclass))", s=kind.sequence)
    top = tx.val("SELECT coalesce(max(id), 0) FROM occ.records WHERE kind_id = :k", k=kind.id)
    if floor and v < floor:
        v = floor
    if v <= top:
        v = top + 1
    tx.val("SELECT setval(CAST(:s AS regclass), :v)", s=kind.sequence, v=v)
    return v


def new_elabid():
    return "%s-%s" % (timefmt.today().strftime("%Y%m%d"), secrets.token_hex(20))


def _team_flags(tx, team_id):
    return tx.one("SELECT * FROM occ.teams WHERE id = :t", t=team_id)


def create(tx, p, actor, kind, body):
    """Create a record. Returns the new public id."""
    if not isinstance(body, dict):
        raise errors.bad("The request body must be a JSON object")
    _check_can_write_key(p)
    team_id = p.team_id
    if body.get("team") not in (None, ""):
        t = _int_strict("team", body["team"])
        if t != team_id:
            if t not in p.admin_teams:                        # 2.x ignores team; the OCC honors it for that team's admins
                raise errors.forbidden("Creating in another team needs admin rights there.")
            team_id = t
    if team_id not in p.member_teams:
        raise errors.forbidden("You are not a member of that team.")
    team = _team_flags(tx, team_id)
    setting = K.CREATE_SETTING[kind.code]
    if not team[setting] and team_id not in p.admin_teams:
        raise errors.forbidden("Only team admins can create %s in this team." % kind.code.replace("_", " "))

    template = None
    if body.get("template") not in (None, "", 0, "0", -1, "-1"):
        if kind.is_template:
            raise errors.bad("Invalid update target: template")
        tkind = K.get(kind.template_kind)
        tid = _int_strict("template", body["template"])
        trow = fetch(tx, p, tkind, tid)
        if trow is None or trow["state"] == 3 or not engine.check(p, trow, engine.READ):
            raise errors.bad("Incorrect value for template: no such template")
        template = (tkind, trow)
    elif not kind.is_template:
        force = team["force_exp_tpl"] if kind.code == "experiments" else team["force_res_tpl"]
        if force:
            raise errors.bad("A template is required in this team.")

    u = tx.one("SELECT default_read_base, default_write_base, default_read, default_write FROM occ.users "
               "WHERE id = :u", u=p.user_id)
    read_base, write_base = u["default_read_base"], u["default_write_base"]
    read_lists = _lists_from(u["default_read"])
    write_lists = _lists_from(u["default_write"])
    category = status = None
    tpl_body = None
    meta = None
    if template:
        tkind, trow = template
        full_t = fetch(tx, p, tkind, trow["id"], full=True)
        tpl_body = full_t["body"]
        meta = full_t["metadata"]
        category, status = trow["category_id"], trow["status_id"]
        if trow["canread_target"]:
            read_base = trow["canread_target"].get("base", read_base)
            read_lists = _lists_from(trow["canread_target"])
        if trow["canwrite_target"]:
            write_base = trow["canwrite_target"].get("base", write_base)
            write_lists = _lists_from(trow["canwrite_target"])
    else:
        category = tx.val("SELECT id FROM occ.categories WHERE team_id = :t AND lookup_group = :g AND is_default "
                          "AND state = 1", t=team_id, g=kind.lookup_group)
        status = tx.val("SELECT id FROM occ.statuses WHERE team_id = :t AND lookup_group = :g AND is_default "
                        "AND state = 1", t=team_id, g=kind.lookup_group)

    fields_in = {k: v for k, v in body.items() if k not in ("template", "team", "tags")}
    stub = {"team_id": team_id, "access": [], "canread_is_immutable": False, "canwrite_is_immutable": False}
    fields = validate_fields(tx, p, kind, stub, fields_in)      # all checked before anything is written
    vals = {"title": "Untitled", "date": None if kind.is_template else timefmt.today(), "body": tpl_body,
            "category_id": category, "status_id": status, "metadata": meta}
    extra = []
    for field, col, new in fields:
        if col in ("title", "date", "body", "category_id", "status_id", "metadata"):
            vals[col] = new
        elif col == "canread":
            read_base, read_lists = new
        elif col == "canwrite":
            write_base, write_lists = new
        else:
            extra.append((field, col, new))
    tags = body.get("tags") or []
    if isinstance(tags, str):
        tags = [t for t in tags.split(",") if t.strip()]
    if not isinstance(tags, list):
        raise errors.bad("Incorrect value for tags: a list of tag names")

    rec_id = _new_id(tx, kind)
    rid = tx.val("""
        INSERT INTO occ.records (kind_id, id, elabid, team_id, owner_id, title, date, body, body_text, category_id,
                                 status_id, metadata, canread_base, canwrite_base, canbook_base, created_by, modified_by,
                                 created_from_kind, created_from_id)
        VALUES (:k, :id, :elabid, :team, :owner, :title, :date, :body, :btext, :cat, :st, CAST(:meta AS jsonb),
                :rb, :wb, :bb, :owner, :owner, :fk, :fid)
        RETURNING rid""",
        k=kind.id, id=rec_id, elabid=new_elabid(), team=team_id, owner=p.user_id, title=vals["title"],
        date=vals["date"], body=vals["body"], btext=body_text(vals["body"]), cat=vals["category_id"],
        st=vals["status_id"], meta=jsonb(vals["metadata"]), rb=read_base, wb=write_base,
        bb=30 if kind.code in ("items", "items_types") else None,
        fk=template[0].id if template else None, fid=template[1]["id"] if template else None)
    for right, lists in (("r", read_lists), ("w", write_lists)):
        for k, ids in lists.items():
            for pid in ids:
                tx.run("INSERT INTO occ.record_access (rid, access_right, principal, principal_id) "
                       "VALUES (:rid, :rt, :k, :pid) ON CONFLICT DO NOTHING", rid=rid, rt=right, k=k, pid=pid)
    audit.write(tx, actor, "record.create", kind_id=kind.id, record_id=rec_id, rid=rid, team_id=team_id,
                target="created", new="%s was created" % kind.singular)

    from . import subs
    if template:
        tkind, trow = template
        subs.copy_children(tx, trow["rid"], rid, tags=True, steps=True, links=True)
    for t in tags:
        subs.attach_tag(tx, p, actor, kind, {"rid": rid, "id": rec_id, "team_id": team_id}, str(t))
    if extra:
        row = fetch(tx, p, kind, rec_id, for_update=True)
        apply_fields(tx, p, actor, kind, row, extra)
    refresh_search(tx, rid)
    return rec_id


def _lists_from(obj):
    obj = obj or {}
    out = {}
    for key, k in (("teams", "t"), ("users", "u"), ("teamgroups", "g")):
        try:
            out[k] = sorted({int(x) for x in (obj.get(key) or [])})
        except (TypeError, ValueError):
            out[k] = []
    return out


def duplicate(tx, p, actor, kind, rec_id, body):
    """Duplicate, as 2.x does: title + ' I', tags, body, links and steps copied, dated today; files only with copyFiles."""
    if not isinstance(body, dict) or body.get("action") != "duplicate":
        raise errors.bad("Invalid action")
    _check_can_write_key(p)
    src = fetch(tx, p, kind, rec_id, full=True)
    engine.readable_or_raise(p, src, errors)
    if p.team_id not in p.member_teams:
        raise errors.forbidden()
    copy_files = body.get("copyFiles") in (True, 1, "1", "true")
    new_id = _new_id(tx, kind)
    rid = tx.val("""
        INSERT INTO occ.records (kind_id, id, elabid, team_id, owner_id, title, date, body, body_text, body_format,
               category_id, status_id, metadata, canread_base, canwrite_base, canbook_base, color, hide_main_text,
               created_by, modified_by, created_from_kind, created_from_id)
        SELECT kind_id, :nid, :elabid, :team, :owner, title || ' I', CASE WHEN date IS NULL THEN NULL ELSE CAST(:today AS date) END,
               body, body_text, body_format, category_id, status_id, metadata, canread_base, canwrite_base,
               canbook_base, color, hide_main_text, :owner, :owner, kind_id, id
          FROM occ.records WHERE rid = :src RETURNING rid""",
        nid=new_id, elabid=new_elabid(), team=p.team_id, owner=p.user_id, today=timefmt.today(), src=src["rid"])
    tx.run("INSERT INTO occ.record_access (rid, access_right, principal, principal_id) "
           "SELECT :rid, access_right, principal, principal_id FROM occ.record_access WHERE rid = :src",
           rid=rid, src=src["rid"])
    from . import subs
    subs.copy_children(tx, src["rid"], rid, tags=True, steps=True, links=True)
    audit.write(tx, actor, "record.create", kind_id=kind.id, record_id=new_id, rid=rid, team_id=p.team_id,
                target="created", new="%s was created" % kind.singular,
                detail={"duplicate_of": {"kind": kind.code, "id": rec_id}})
    if copy_files:
        # Files only with copyFiles, as in 2.x. The copy points at the same stored bytes (stored once per SHA-256).
        from ..files import uploads as U
        for up in tx.all("SELECT real_name, comment, mime, size, sha256 FROM occ.uploads WHERE rid = :s AND state = 1 "
                         "ORDER BY id", s=src["rid"]):
            uid = tx.val("INSERT INTO occ.uploads (rid, real_name, storage_name, comment, user_id, mime, size, sha256) "
                         "VALUES (:rid, :rn, :sn, :c, :u, :m, :n, :s) RETURNING id", rid=rid, rn=up["real_name"],
                         sn=U.storage_name_for(up["real_name"]), c=up["comment"], u=p.user_id, m=up["mime"],
                         n=up["size"], s=up["sha256"])
            audit.write(tx, actor, "upload.add", kind_id=kind.id, record_id=new_id, rid=rid, team_id=p.team_id,
                        target="uploads", new=up["real_name"], detail={"upload_id": uid, "copied": True})
    refresh_search(tx, rid)
    return new_id


def delete(tx, p, actor, kind, rec_id):
    """Soft delete (state 3). Deleting a deleted record answers 204, so a repeat is harmless."""
    row = fetch(tx, p, kind, rec_id, for_update=True)
    engine.readable_or_raise(p, row, errors)
    _check_can_write_key(p)
    if row["state"] == 3:
        if not engine.check(p, dict(row, state=1), engine.WRITE):
            raise errors.forbidden()
        return
    if not engine.check(p, row, engine.WRITE):
        raise errors.forbidden()
    blocked = engine.write_block(p, row)
    if blocked:
        raise errors.OCCError(*blocked)
    tx.run("UPDATE occ.records SET state = 3 WHERE rid = :rid", rid=row["rid"])
    audit.write(tx, actor, "record.delete", kind_id=kind.id, record_id=row["id"], rid=row["rid"],
                team_id=row["team_id"], target="state", old=row["state"], new=3)
    touch(tx, p, row["rid"])
