# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Change detection on 2.x, read only.

Every cycle (15 seconds) each carried table is checked with one read-only aggregate query:

  modified     tables with a modified_at column: COUNT(*), MAX(id), MAX(modified_at). When it
               moves, the rows with modified_at at or after the last watermark minus 2 seconds
               are read (the 2.x clock has whole seconds).
  append       history tables that only grow: COUNT(*), MAX(id). New rows are id > last max.
  fingerprint  everything else: COUNT(*), MAX(id) and an order-independent checksum, the XOR of
               each row's CRC32 (BIT_XOR(CRC32(CONCAT_WS(...)))). When it moves, the same
               aggregate grouped by the table's parent column (record, person, team) finds the
               parents whose rows changed, and only their rows are read.

Rows that disappeared are found by comparing the table's source ids with occ.id_map (a key-only
read, done only when the count or highest id moved). Nothing is written to 2.x; no trigger,
table, column or replication privilege is used. The previous fingerprints live in
occ.sync_fingerprints (scope '*' for the table, a parent id for a parent's rows).

Column and table names put into the MySQL text come from mapping.TABLES and from the column list
information_schema reported for that table (source.column_list, which checks every name).
"""
import datetime as dt
import re

from ..db import ident, sql_fragment
from . import mapping as M

UTC = dt.timezone.utc
SLACK = dt.timedelta(seconds=2)
PAGE = 2000
SOURCE_NAME = re.compile(r"[a-z0-9_]{1,64}")       # a 2.x column name, as information_schema reports it


@sql_fragment
def _q(name):
    return "`%s`" % ident(name, SOURCE_NAME)


@sql_fragment
def _t(spec):
    return "`%s`" % ident(spec.src, M.TABLES)


@sql_fragment
def _row_crc(source, spec):
    cols = list(spec.fp_cols) if spec.fp_cols else source.column_list(spec.src)
    cols = [c for c in cols if c in source.columns.get(spec.src, [])]
    parts = []
    for c in cols:
        parts.append(_q(c))
        parts.append("ISNULL(%s)" % _q(c))
    return "CRC32(CONCAT_WS('|', %s))" % ", ".join(parts)


def strategy(source, spec):
    cols = source.columns.get(spec.src, [])
    if spec.detect == "append" and "id" in cols:
        return "append"
    if spec.detect == "modified" and "modified_at" in cols:
        return "modified"
    return "fingerprint"


def table_fp(source, spec):
    cols = source.columns.get(spec.src, [])
    t = _t(spec)
    mx = "COALESCE(MAX(`id`), 0)" if "id" in cols else "0"
    st = strategy(source, spec)
    if st == "modified":
        r = source.scalar_row("SELECT COUNT(*), %s, MAX(`modified_at`), 0 FROM %s" % (mx, t))
    elif st == "append":
        r = source.scalar_row("SELECT COUNT(*), %s, NULL, 0 FROM %s" % (mx, t))
    else:
        r = source.scalar_row("SELECT COUNT(*), %s, NULL, COALESCE(BIT_XOR(%s), 0) FROM %s" % (mx, _row_crc(source, spec), t))
    mod = r[2].replace(tzinfo=UTC) if isinstance(r[2], dt.datetime) else None
    return {"row_count": int(r[0]), "max_id": int(r[1] or 0), "max_modified": mod, "checksum": int(r[3] or 0)}


def parent_fps(source, spec):
    if not spec.parent or spec.parent not in source.columns.get(spec.src, []):
        return None
    p = _q(spec.parent)
    rows = source.query(spec.src, "SELECT %s AS p, COUNT(*) AS n, BIT_XOR(%s) AS c FROM %s GROUP BY %s" % (
        p, _row_crc(source, spec), _t(spec), p))
    return {str(r["p"]): (int(r["n"]), int(r["c"] or 0)) for r in rows}


def rows_modified_since(source, spec, since):
    return source.query(spec.src, "SELECT * FROM %s WHERE `modified_at` >= %%s ORDER BY %s" % (
        _t(spec), _order(source, spec)), (since.astimezone(UTC).replace(tzinfo=None),))


def rows_after_id(source, spec, last_id):
    return source.query(spec.src, "SELECT * FROM %s WHERE `id` > %%s ORDER BY `id`" % _t(spec), (last_id,))


def rows_of_parents(source, spec, parents):
    out = []
    parents = list(parents)
    for k in range(0, len(parents), 500):
        chunk = parents[k:k + 500]
        marks = ", ".join("%s" for _ in chunk)
        out += source.query(spec.src, "SELECT * FROM %s WHERE %s IN (%s) ORDER BY %s" % (
            _t(spec), _q(spec.parent), marks, _order(source, spec)), tuple(chunk))
    return out


def all_rows(source, spec):
    return source.query(spec.src, "SELECT * FROM %s ORDER BY %s" % (_t(spec), _order(source, spec)))


def source_ids(source, spec):
    """Every source id of a table, from a key-only read."""
    cols = source.columns.get(spec.src, [])
    keycols = [c.strip() for c in spec.src_order.split(",")]
    if spec.src in ("tags2entity",):
        keycols = ["item_type", "item_id", "tag_id"]
    keycols = [c for c in keycols if c in cols]
    rows = source.query(spec.src, "SELECT %s FROM %s" % (", ".join(_q(c) for c in keycols), _t(spec)))
    return {spec.source_id(r) for r in rows}


@sql_fragment
def _order(source, spec):
    cols = source.columns.get(spec.src, [])
    keys = [c.strip() for c in spec.src_order.split(",") if c.strip() in cols]
    out = ", ".join(_q(c) for c in keys)
    return out if out else "1"


def iter_full(source, spec):
    """All rows of a table: keyset pages by id where the table has one (big tables), else one read."""
    cols = source.columns.get(spec.src, [])
    if spec.src_order == "id" and "id" in cols:
        last = -1
        while True:
            rows = source.query(spec.src, "SELECT * FROM %s WHERE `id` > %%s ORDER BY `id` LIMIT %%s" % _t(spec),
                                (last, PAGE))
            if not rows:
                return
            yield from rows
            last = rows[-1]["id"]
            if len(rows) < PAGE:
                return
    else:
        rows = all_rows(source, spec)
        if spec.src == "storage_units":
            rows = _parents_first(rows)
        yield from rows


def _parents_first(rows):
    by_id = {r["id"]: r for r in rows}
    out, seen = [], set()

    def visit(r, depth=0):
        if r["id"] in seen or depth > 100:
            return
        p = r.get("parent_id")
        if p in by_id:
            visit(by_id[p], depth + 1)
        seen.add(r["id"])
        out.append(r)
    for r in rows:
        visit(r)
    return out


def known_tables(source):
    return [t for t in sorted(M.TABLES) if source.has(t)]
