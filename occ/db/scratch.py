# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Scratch databases for the tests, and the fresh-build comparison (does a database built from
every migration match the target?).

A scratch database is named occ_scratch_<suffix>, made by a check and dropped by the same check.
The comparison builds a scratch database from migration 0001 to the newest and compares
`pg_dump --schema-only` of the occ schema, and the installed extensions, with a target database.
"""
import os
import re
import secrets
import subprocess
import time
from contextlib import contextmanager

from . import connect, ident, migrate

NAME_RE = re.compile(r"^occ_scratch_[a-z0-9_]{1,40}$")


def _admin(params):
    return connect(dict(params))


def create(params, suffix=None):
    name = "occ_scratch_%s" % (suffix or secrets.token_hex(4))
    if not NAME_RE.match(name):
        raise ValueError("a scratch database is named occ_scratch_<letters, digits, underscores>")
    # Making a database copies template1 and is refused while another session is copying or using
    # it; with a database per test file and other checks making theirs at the same time, that
    # happens, so a refusal is retried a few times before it counts.
    for attempt in range(6):
        con = _admin(params)
        try:
            con.run('CREATE DATABASE "%s"' % ident(name, NAME_RE))     # identifiers cannot be parameters
            return name
        except Exception as ex:                                             # noqa: BLE001
            if attempt == 5 or "being accessed by other users" not in str(ex):
                raise
        finally:
            con.close()
        time.sleep(0.5 * (attempt + 1))
    return name


def drop(params, name):
    if not NAME_RE.match(name):
        raise ValueError("refusing to drop a database that is not a scratch database: %s" % name)
    # FORCE ends other sessions on the database, but a background worker the server started there
    # (autovacuum on a database a moment old) cannot be ended by a non-superuser: "permission denied
    # to terminate process". It finishes in moments, so the drop is retried.
    for attempt in range(8):
        con = _admin(params)
        try:
            con.run('DROP DATABASE IF EXISTS "%s" WITH (FORCE)' % ident(name, NAME_RE))
            return
        except Exception as ex:                                             # noqa: BLE001
            if attempt == 7 or "permission denied to terminate" not in str(ex):
                raise
        finally:
            con.close()
        time.sleep(0.5 * (attempt + 1))


def leftovers(params):
    con = _admin(params)
    try:
        return [r[0] for r in con.run("SELECT datname FROM pg_database WHERE datname LIKE 'occ\\_scratch\\_%' "
                                      "ORDER BY datname")]
    finally:
        con.close()


def params_for(params, dbname):
    p = dict(params)
    p["database"] = dbname
    return p


@contextmanager
def scratch(params, suffix=None, migrated=True):
    """A scratch database, migrated to the newest file, dropped afterwards whatever happens."""
    name = create(params, suffix)
    try:
        if migrated:
            migrate.migrate(params_for(params, name), log=lambda *_: None)
        yield name
    finally:
        drop(params, name)


_SKIP = re.compile(r"^(--|\\restrict|\\unrestrict|SET |SELECT pg_catalog\.set_config)")


def schema_dump(params, dbname):
    """The occ schema's DDL as pg_dump writes it, without comments and session settings."""
    sock_dir = os.path.dirname(params["unix_sock"])
    out = subprocess.run(["pg_dump", "--schema-only", "--no-owner", "--no-privileges", "--schema=occ",
                          "-h", sock_dir, "-U", params["user"], "-d", dbname],
                         check=True, capture_output=True, text=True, timeout=300).stdout
    lines = [ln for ln in out.splitlines() if ln.strip() and not _SKIP.match(ln)]
    return "\n".join(lines) + "\n"


def extensions(params, dbname):
    con = connect(params_for(params, dbname))
    try:
        return sorted((r[0], r[1]) for r in con.run("SELECT extname, extversion FROM pg_extension"))
    finally:
        con.close()


def compare_fresh(params, target_db, suffix=None):
    """Build a fresh scratch database from the migrations; compare it with target_db.
    Returns (same: bool, report: dict)."""
    import difflib
    with scratch(params, suffix=suffix) as fresh:
        a = schema_dump(params, fresh)
        b = schema_dump(params, target_db)
        ea, eb = extensions(params, fresh), extensions(params, target_db)
        ma = _migrations(params, fresh)
        mb = _migrations(params, target_db)
    diff = list(difflib.unified_diff(a.splitlines(), b.splitlines(), "fresh", target_db, lineterm="", n=1))
    report = {"fresh_lines": len(a.splitlines()), "target_lines": len(b.splitlines()), "diff": diff[:200],
              "extensions_fresh": ea, "extensions_target": eb, "migrations_fresh": ma, "migrations_target": mb,
              "tables_fresh": a.count("CREATE TABLE "), "tables_target": b.count("CREATE TABLE ")}
    same = not diff and ea == eb and ma == mb
    return same, report


def _migrations(params, dbname):
    con = connect(params_for(params, dbname))
    try:
        return [(r[0], r[1], r[2]) for r in con.run("SELECT version, name, sha256 FROM occ.schema_migrations "
                                                    "ORDER BY version")]
    finally:
        con.close()
