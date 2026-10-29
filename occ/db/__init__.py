# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Database access: a small connection pool and one transaction per unit of work.

Every statement is parameterized: SQL text is written in the code with :name markers and the
values travel separately. Nothing outside occ/ connects to the OCC database: applications reach
the data through the API.
"""
import json
import queue
import threading
from contextlib import contextmanager

import pg8000.native as pgn

DatabaseError = pgn.DatabaseError
InterfaceError = pgn.InterfaceError


def connect(params):
    con = pgn.Connection(application_name="occ", **params)
    con.run("SET TIME ZONE 'UTC'")
    con.run("SET search_path = occ, public")
    return con


class Tx:
    """A transaction on one connection. Rows come back as dicts."""

    def __init__(self, con):
        self.con = con

    def all(self, sql, **params):
        rows = self.con.run(sql, **params)
        cols = [c["name"] for c in (self.con.columns or [])]
        return [dict(zip(cols, r)) for r in (rows or [])]

    def one(self, sql, **params):
        rows = self.all(sql, **params)
        return rows[0] if rows else None

    def val(self, sql, **params):
        rows = self.con.run(sql, **params)
        return rows[0][0] if rows else None

    def run(self, sql, **params):
        self.con.run(sql, **params)
        return self.con.row_count

    def script(self, sql):
        """Several statements, simple-query protocol (migrations only)."""
        self.con.execute_simple(sql)


def ident(name, allowed):
    """An identifier (table or column name) for SQL text, only from a closed list written in the
    code: a constant set, frozenset, tuple or dict, or a compiled pattern a name must fully match.
    Anything else raises before a statement is built. Values never go through here: they are
    always parameters, so no value can ever change the shape of a statement."""
    if not isinstance(name, str):
        raise ValueError("an SQL identifier must be text")
    ok = allowed.fullmatch(name) if hasattr(allowed, "fullmatch") else name in allowed
    if not ok:
        raise ValueError("refused SQL identifier %r: not in the closed list" % name[:40])
    return name


def sql_fragment(fn):
    """Marks a function that returns SQL text (or a tuple whose first item is SQL text). It does
    nothing at run time; tests/sqlcheck.py checks every return of such a function the way it
    checks the text handed to the database, and then trusts calls to it."""
    return fn


def jsonb(value):
    """A value for a :param::jsonb placeholder."""
    return None if value is None else json.dumps(value, separators=(",", ":"), ensure_ascii=False)


class Pool:
    def __init__(self, params, size=10):
        self.params = params
        self.size = size
        self._idle = queue.LifoQueue()
        self._made = 0
        self._lock = threading.Lock()

    def _get(self):
        try:
            return self._idle.get_nowait()
        except queue.Empty:
            pass
        with self._lock:
            if self._made < self.size:
                self._made += 1
                try:
                    return connect(self.params)
                except Exception:
                    self._made -= 1
                    raise
        return self._idle.get(timeout=30)

    def _put(self, con, broken=False):
        if broken:
            try:
                con.close()
            except Exception:
                pass
            with self._lock:
                self._made -= 1
            return
        self._idle.put(con)

    @contextmanager
    def tx(self, readonly=False):
        con = self._get()
        broken = False
        try:
            con.run("BEGIN READ ONLY" if readonly else "BEGIN")
            try:
                yield Tx(con)
            except BaseException:
                try:
                    con.run("ROLLBACK")
                except Exception:
                    broken = True
                raise
            con.run("COMMIT")
        except (InterfaceError, OSError):
            broken = True
            raise
        finally:
            self._put(con, broken)

    def close(self):
        while True:
            try:
                self._idle.get_nowait().close()
            except queue.Empty:
                break
            except Exception:
                pass
        self._made = 0
