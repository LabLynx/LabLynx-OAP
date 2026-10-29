# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""POST /api/v2/occ/query: a structured, read-only query for reports and dashboards.

Reports that read 2.x's database directly move here, so nothing needs the database itself. A
query is JSON, never SQL:

    {"from": "experiments",                      # a record kind
     "select": ["id", "title", "status.title", "meta:Batch", "tags"],
     "where": [{"field": "rating", "op": ">=", "value": 3},
               {"field": "date", "op": "between", "value": ["2026-01-01", "2026-06-30"]}],
     "group_by": ["status.title"], "aggregates": ["count", "avg:rating"],
     "order_by": [{"field": "count", "dir": "desc"}], "limit": 100, "cursor": null, "team": 4}

Answer: {"columns": [...], "rows": [[...], ...], "next": "<cursor>" or null}.

Why it cannot write or run away:
  * READ-ONLY BY CONSTRUCTION. Every field, operator and aggregate is looked up in a closed table
    written in this file, so the only SQL text is the table's own; every value the caller sends
    (including the extra-field name of meta:<name>) is a parameter. The statement runs in a READ
    ONLY transaction, so the database itself refuses a write even if one were composed.
  * PERMISSIONS FIRST. The permission engine's list filter is in the WHERE clause, so grouping
    and aggregates only ever see records the caller may read; linked records in links.<kind>.*
    are filtered the same way.
  * A COST LIMIT. The statement is planned first (EXPLAIN); a plan whose total cost is over the
    limit answers 413 without running. While it runs, a statement timeout stops it, and that
    answers 413 too. Both limits come from the process settings (OCC_QUERY_COST_LIMIT, default
    500000; OCC_QUERY_TIMEOUT_MS, default 5000).
"""
import datetime as dt
import decimal
import json
import re

from .. import errors, timefmt
from ..db import sql_fragment
from ..perms import engine
from ..records import kinds as K

MAX_LIMIT = 10000
DEFAULT_LIMIT = 100
DEFAULT_COST_LIMIT = 500000
DEFAULT_TIMEOUT_MS = 5000
MAX_SELECT = 50
MAX_WHERE = 50

# Scalar fields: name -> SQL expression over r (records) and its joins.
SCALAR = {
    "id": "r.id", "title": "r.title", "date": "r.date", "body": "r.body_text", "rating": "r.rating",
    "custom_id": "r.custom_id", "elabid": "r.elabid", "state": "r.state", "locked": "r.locked",
    "team": "r.team_id", "userid": "r.owner_id", "category": "r.category_id", "status": "r.status_id",
    "created_at": "r.created_at", "modified_at": "r.modified_at", "signature_count": "r.signature_count",
    "timestamped": "r.timestamped", "timestamped_at": "r.timestamped_at", "last_signed_at": "r.last_signed_at",
    "available": "r.available", "canread_base": "r.canread_base", "canwrite_base": "r.canwrite_base",
    "category.title": "c.title", "category.color": "c.color", "status.title": "s.title", "status.color": "s.color",
    "owner.fullname": "concat_ws(' ', u.firstname, u.lastname)", "owner.email": "u.email",
    "team.name": "tm.name",
}
# The type of each scalar (n number, d date, t time, b yes/no; anything else is text), so a comparison
# casts the caller's value to the column's type and sum/avg take numbers only.
TYPES = {"id": "n", "rating": "n", "custom_id": "n", "state": "n", "team": "n", "userid": "n", "category": "n",
         "status": "n", "signature_count": "n", "canread_base": "n", "canwrite_base": "n", "date": "d",
         "created_at": "t", "modified_at": "t", "timestamped_at": "t", "last_signed_at": "t", "locked": "b",
         "timestamped": "b", "available": "b", "uploads.count": "n", "comments.count": "n", "events.count": "n",
         "events.next_start": "t", "events.last_end": "t"}
CASTS = {"n": "numeric", "d": "date", "t": "timestamptz", "b": "boolean"}

# Values computed per record (one text each, '|'-joined like the 2.x list's tags column).
LISTS = {
    "tags": "(SELECT string_agg(tg.tag, '|' ORDER BY tg.tag) FROM occ.record_tags rt JOIN occ.tags tg "
            "ON tg.id = rt.tag_id WHERE rt.rid = r.rid)",
    "uploads.names": "(SELECT string_agg(up.real_name, '|' ORDER BY up.id) FROM occ.uploads up "
                     "WHERE up.rid = r.rid AND up.state = 1)",
    "uploads.count": "(SELECT count(*) FROM occ.uploads up WHERE up.rid = r.rid AND up.state = 1)",
    "comments.count": "(SELECT count(*) FROM occ.comments cm WHERE cm.rid = r.rid)",
    "events.count": "(SELECT count(*) FROM occ.events ev WHERE ev.resource_rid = r.rid)",
    "events.next_start": "(SELECT min(ev.start_at) FROM occ.events ev WHERE ev.resource_rid = r.rid "
                         "AND ev.start_at >= now())",
    "events.last_end": "(SELECT max(ev.end_at) FROM occ.events ev WHERE ev.resource_rid = r.rid)",
}
# links.<kind>.<field>: the linked records of one kind the caller may read, '|'-joined.
LINK_FIELDS = {"id": "o.id::text", "title": "o.title", "elabid": "o.elabid"}
LINK_KINDS = frozenset(("experiments", "items"))
OPS = {"=": "=", "!=": "<>", "<": "<", "<=": "<=", ">": ">", ">=": ">="}
AGGREGATES = {"count": "count", "min": "min", "max": "max", "sum": "sum", "avg": "avg"}
NUMERIC_AGG = frozenset(("sum", "avg"))
_META = re.compile(r"^meta:(.{1,200})$", re.S)
_LINK = re.compile(r"^links\.(experiments|items)\.(id|title|elabid)$")
JOINS = ("LEFT JOIN occ.categories c ON c.lookup_group = r.lookup_group AND c.id = r.category_id "
         "LEFT JOIN occ.statuses s ON s.lookup_group = r.lookup_group AND s.id = r.status_id "
         "JOIN occ.users u ON u.id = r.owner_id JOIN occ.teams tm ON tm.id = r.team_id")


# Placeholder names, one per value a query sends (Compiler.param hands them out in order).
MAX_PARAMS = 4000
PARAM_NAMES = tuple(":q%d" % i for i in range(MAX_PARAMS))
ORDINALS = tuple(str(i) for i in range(MAX_SELECT + 30))       # output column numbers for GROUP BY / ORDER BY


def _bad(msg):
    return errors.bad(msg)


class Compiler:
    """Builds the statement from the closed tables. Every value goes into self.params."""

    def __init__(self, p):
        self.p = p
        self.params = {}
        self._n = 0

    @sql_fragment
    def param(self, value):
        """The placeholder for one value; the value itself travels as a parameter."""
        self._n += 1
        if self._n >= MAX_PARAMS:
            raise _bad("The query has too many values.")
        self.params["q%d" % self._n] = value
        return PARAM_NAMES[self._n]

    @sql_fragment
    def field(self, name, for_where=False):
        """(SQL expression, is a list value) for a field name, or 400."""
        if not isinstance(name, str):
            raise _bad("A field name is text.")
        if name in SCALAR:
            return SCALAR[name], False, TYPES.get(name, "s")
        if name in LISTS:
            return LISTS[name], TYPES.get(name) is None, TYPES.get(name, "s")
        m = _META.match(name)
        if m:
            return "(r.metadata->'extra_fields'->CAST(%s AS text)->>'value')" % self.param(m.group(1)), False, "m"
        m = _LINK.match(name)
        if m:
            cond, perm = engine.list_filter(self.p, engine.READ, "o")
            for k, v in perm.items():
                self.params[k] = v
            return ("(SELECT string_agg(%s, '|' ORDER BY o.id) FROM occ.record_links lk JOIN occ.records o "
                    "ON o.rid = lk.to_rid WHERE lk.from_rid = r.rid AND o.kind_id = %s AND o.state <> 3 AND %s)"
                    % (LINK_FIELDS[m.group(2)], self.param(K.get(m.group(1)).id), cond)), True, "s"
        raise _bad("Unknown field: %s" % name[:80])

    @sql_fragment
    def condition(self, w):
        if not isinstance(w, dict):
            raise _bad("Each where entry is an object {field, op, value}.")
        op = str(w.get("op") or "=").lower()
        expr, is_list, typ = self.field(w.get("field"), for_where=True)
        v = w.get("value")
        if op in OPS:
            if isinstance(v, (list, dict)):
                raise _bad("%s takes one value" % op)
            if is_list and op in ("=", "!="):
                # a '|'-joined list (tags, uploads.names, links): = means "one of them is"
                cond = "%s = ANY(string_to_array(coalesce(%s, ''), '|'))" % (self.param(str(v)), expr)
                return cond if op == "=" else "NOT (%s)" % cond
            return "%s %s %s" % (self._lhs(expr, typ), OPS[op], self._typed(typ, v))
        if op == "in":
            if not isinstance(v, list) or not v or len(v) > 1000:
                raise _bad("in takes a list of 1 to 1000 values")
            return "(%s)::text = ANY(CAST(%s AS text[]))" % (expr, self.param([_text(x) for x in v]))
        if op == "like":
            if not isinstance(v, str):
                raise _bad("like takes a text pattern")
            return "(%s)::text ILIKE %s" % (expr, self.param(v))
        if op == "between":
            if not isinstance(v, list) or len(v) != 2:
                raise _bad("between takes [low, high]")
            return "%s BETWEEN %s AND %s" % (self._lhs(expr, typ), self._typed(typ, v[0]), self._typed(typ, v[1]))
        if op == "is_null":
            return ("%s IS NULL" if v in (None, True, 1, "1", "true") else "%s IS NOT NULL") % expr
        raise _bad("Unknown op: %s" % op[:20])

    @sql_fragment
    def _lhs(self, expr_sql, typ):
        """The field as compared: typed columns as they are, text and extra fields as text."""
        return expr_sql if typ in CASTS else "(%s)::text" % expr_sql

    @sql_fragment
    def _typed(self, typ, v):
        """A parameter cast to the field's type, so comparisons are numeric or by date, not by text."""
        if isinstance(v, (list, dict)):
            raise _bad("A comparison takes one value")
        if typ == "n":
            try:
                v = str(decimal.Decimal(str(v)))
            except (decimal.InvalidOperation, ValueError):
                raise _bad("Incorrect value for a number: %s" % str(v)[:40])
        if typ in CASTS:
            return "CAST(%s AS %s)" % (self.param(_text(v)), CASTS[typ])
        return "(%s)::text" % self.param(_text(v))


def _text(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    return "" if v is None else str(v)


def _agg_spec(a):
    """'count' | 'count:field' | 'sum:rating' | {fn, field} -> (fn, field or None, column label)."""
    if isinstance(a, dict):
        fn, field = str(a.get("fn") or ""), a.get("field")
    elif isinstance(a, str):
        fn, _, field = a.partition(":")
        field = field or None
    else:
        raise _bad("An aggregate is 'count', 'sum:<field>' or {fn, field}.")
    fn = fn.lower()
    if fn not in AGGREGATES:
        raise _bad("Unknown aggregate: %s" % fn[:20])
    if fn != "count" and not field:
        raise _bad("%s needs a field" % fn)
    return fn, field, ("%s(%s)" % (fn, field) if field else fn)


@sql_fragment
def compile_query(p, body):
    """(sql, params, columns) for a query body, or 400."""
    if not isinstance(body, dict):
        raise _bad("The request body must be a JSON object")
    try:
        kind = K.get(str(body.get("from") or ""))
    except Exception:                                                    # noqa: BLE001
        raise _bad("Incorrect value for from: one of %s" % ", ".join(K.KINDS))
    c = Compiler(p)
    select = body.get("select") or ["id", "title"]
    where = body.get("where") or []
    group_by = body.get("group_by") or []
    aggregates = body.get("aggregates") or []
    if not isinstance(select, list) or not isinstance(where, list) or not isinstance(group_by, list) \
            or not isinstance(aggregates, list):
        raise _bad("select, where, group_by and aggregates are lists")
    if len(select) > MAX_SELECT or len(group_by) > MAX_SELECT or len(where) > MAX_WHERE or len(aggregates) > 20:
        raise _bad("Too many fields, conditions or aggregates")
    try:
        limit = int(body.get("limit") or DEFAULT_LIMIT)
    except (TypeError, ValueError):
        raise _bad("Incorrect value for limit")
    if limit < 1 or limit > MAX_LIMIT:
        raise _bad("limit is 1 to %d" % MAX_LIMIT)
    try:
        offset = int(body.get("cursor") or 0)
    except (TypeError, ValueError):
        raise _bad("Incorrect value for cursor")
    if offset < 0:
        raise _bad("Incorrect value for cursor")

    cols, exprs = [], []
    grouped = bool(group_by or aggregates)
    if grouped:
        for g in group_by:
            e, _l, _t = c.field(g)
            cols.append(g)
            exprs.append(e)
        for a in aggregates:
            fn, field, label = _agg_spec(a)
            if field:
                e, is_list, typ = c.field(field)
                if fn in NUMERIC_AGG and typ not in ("n", "m"):
                    raise _bad("%s needs a numeric field" % fn)
                if typ == "m" and fn != "count":
                    # an extra field's value is text: only values that look like numbers are counted
                    e = "CASE WHEN %s ~ '^-?[0-9]+(\\.[0-9]+)?$' THEN (%s)::numeric END" % (e, e)
                exprs.append("%s(%s)" % (AGGREGATES[fn], e))
            else:
                exprs.append("count(*)")
            cols.append(label)
    else:
        for s in select:
            e, _l, _t = c.field(s)
            cols.append(s)
            exprs.append(e)

    conds = ["r.kind_id = %s" % c.param(kind.id)]
    perm, perm_params = engine.list_filter(p, engine.READ, "r")
    conds.append(perm)
    c.params.update(perm_params)
    if not any(isinstance(w, dict) and w.get("field") == "state" for w in where):
        conds.append("r.state = 1")
    if body.get("team") not in (None, ""):
        try:
            team = int(body["team"])
        except (TypeError, ValueError):
            raise _bad("Incorrect value for team")
        conds.append("r.team_id = %s" % c.param(team))
    for w in where:
        conds.append(c.condition(w))

    order = []
    for o in body.get("order_by") or []:
        if isinstance(o, str):
            name, desc = (o[1:], True) if o.startswith("-") else (o, False)
        elif isinstance(o, dict):
            name, desc = o.get("field"), str(o.get("dir") or "asc").lower() == "desc"
        else:
            raise _bad("order_by entries are a field name or {field, dir}")
        if name not in cols:
            raise _bad("order_by names a column the query returns: %s" % str(name)[:80])
        order.append(ORDINALS[cols.index(name) + 1] + (" DESC" if desc else " ASC"))
    if not order:
        order = ["1"] if grouped else ["r.id DESC"]
    sql = "SELECT " + ", ".join(exprs) + " FROM occ.records r " + JOINS + " WHERE " + " AND ".join(conds)
    if group_by:
        sql += " GROUP BY " + ", ".join(ORDINALS[i + 1] for i in range(len(group_by)))
    sql += " ORDER BY " + ", ".join(order) + " LIMIT %s OFFSET %s" % (c.param(limit + 1), c.param(offset))
    return sql, c.params, cols, limit, offset


def _out(v):
    if isinstance(v, (dt.datetime, dt.date)):
        return timefmt.out(v) if isinstance(v, dt.datetime) else v.isoformat()
    if isinstance(v, decimal.Decimal):
        return int(v) if v == v.to_integral_value() and abs(v) < 2 ** 53 else float(v)
    if isinstance(v, bool):
        return 1 if v else 0
    return v


def limits(cfg):
    extra = getattr(cfg, "extra", {}) or {}
    return (int(extra.get("OCC_QUERY_COST_LIMIT") or DEFAULT_COST_LIMIT),
            int(extra.get("OCC_QUERY_TIMEOUT_MS") or DEFAULT_TIMEOUT_MS))


def _timed_out(ex):
    return "57014" in str(ex) or "statement timeout" in str(ex)


def run(pool, cfg, p, body):
    sql, params, cols, limit, offset = compile_query(p, body)
    cost_limit, timeout_ms = limits(cfg)
    with pool.tx(readonly=True) as tx:
        try:
            plan = tx.val("EXPLAIN (FORMAT JSON) " + sql, **params)
            if isinstance(plan, str):
                plan = json.loads(plan)
            cost = float(plan[0]["Plan"]["Total Cost"])
            if cost > cost_limit:
                raise errors.OCCError(413, "The query is over the cost limit.",
                                      "Planned cost %.0f; the limit is %d. Narrow it with where, team or a smaller "
                                      "limit." % (cost, cost_limit))
            tx.run("SELECT set_config('statement_timeout', :t, true)", t="%dms" % timeout_ms)
            rows = tx.con.run(sql, **params)
        except errors.OCCError:
            raise
        except Exception as ex:                                          # noqa: BLE001
            if _timed_out(ex):
                raise errors.OCCError(413, "The query ran over the time limit.",
                                      "It was stopped after %d ms. Narrow it with where, team or a smaller "
                                      "limit." % timeout_ms)
            raise
    rows = [[_out(v) for v in r] for r in (rows or [])]
    nxt = str(offset + limit) if len(rows) > limit else None
    return {"columns": cols, "rows": rows[:limit], "next": nxt}
