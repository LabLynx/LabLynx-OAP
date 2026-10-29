# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The migration runner: the only way the schema changes.

Numbered SQL files in occ/migrations (0001_schema_v1.sql, 0002_..., ...) are applied in order,
each once, each inside one transaction, and recorded in occ.schema_migrations with the file's
SHA-256. Forward only: a mistake is fixed by the next migration. The runner stops, changing
nothing, when a file that was already applied has changed, when an applied version has no file,
or when a file is numbered below one already applied (a gap filled in later).
"""
import hashlib
import os
import re
import time

from . import connect

MIGRATIONS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "migrations")
NAME = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")


class MigrationError(Exception):
    pass


def files(directory=MIGRATIONS_DIR):
    out = []
    for n in sorted(os.listdir(directory)):
        m = NAME.match(n)
        if not m:
            continue
        path = os.path.join(directory, n)
        with open(path, "rb") as fh:
            data = fh.read()
        out.append({"version": int(m.group(1)), "name": m.group(2), "path": path,
                    "sha256": hashlib.sha256(data).hexdigest(), "sql": data.decode("utf-8")})
    versions = [f["version"] for f in out]
    if len(set(versions)) != len(versions):
        raise MigrationError("two migration files share a number")
    return out


def applied(con):
    if not con.run("SELECT to_regclass('occ.schema_migrations') IS NOT NULL")[0][0]:
        return []
    rows = con.run("SELECT version, name, sha256 FROM occ.schema_migrations ORDER BY version")
    return [{"version": r[0], "name": r[1], "sha256": r[2]} for r in rows]


def plan(con, directory=MIGRATIONS_DIR):
    """What would be applied, after checking that history and files agree."""
    fs = files(directory)
    by_version = {f["version"]: f for f in fs}
    done = applied(con)
    for a in done:
        f = by_version.get(a["version"])
        if f is None:
            raise MigrationError("migration %04d is recorded as applied but its file is missing" % a["version"])
        if f["sha256"] != a["sha256"]:
            raise MigrationError("migration %04d_%s changed after it was applied (recorded %s, file %s)"
                                 % (a["version"], a["name"], a["sha256"][:12], f["sha256"][:12]))
    top = max((a["version"] for a in done), default=0)
    pending = [f for f in fs if f["version"] not in {a["version"] for a in done}]
    late = [f for f in pending if f["version"] < top]
    if late:
        raise MigrationError("migration %04d is numbered below one already applied (%04d)" % (late[0]["version"], top))
    return done, pending


def migrate(params, directory=MIGRATIONS_DIR, log=print):
    """Apply every pending migration. Returns the list of versions applied."""
    con = connect(params)
    try:
        _done, pending = plan(con, directory)
        out = []
        for f in pending:
            t0 = time.monotonic()
            con.run("BEGIN")
            try:
                con.execute_simple(f["sql"])
                con.run("SET search_path = occ, public")
                ms = int((time.monotonic() - t0) * 1000)
                con.run("INSERT INTO occ.schema_migrations (version, name, sha256, duration_ms) "
                        "VALUES (:v, :n, :s, :ms)", v=f["version"], n=f["name"], s=f["sha256"], ms=ms)
                con.run("COMMIT")
            except Exception:
                con.run("ROLLBACK")
                raise
            log("applied %04d_%s (%d ms)" % (f["version"], f["name"], ms))
            out.append(f["version"])
        return out
    finally:
        con.close()


def status(params, directory=MIGRATIONS_DIR):
    con = connect(params)
    try:
        fs = files(directory)
        done = applied(con)
        head = max((f["version"] for f in fs), default=0)
        current = max((a["version"] for a in done), default=0)
        try:
            _d, pending = plan(con, directory)
            problem = None
        except MigrationError as e:
            pending, problem = [], str(e)
        return {"head": head, "current": current, "at_head": current == head and not problem,
                "pending": [f["version"] for f in pending], "problem": problem}
    finally:
        con.close()
