# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Migrations. Every database here is a scratch database,
named occ_scratch_*, dropped by the test that made it."""
import os
import shutil

import pytest

from occ import db
from occ.db import migrate, scratch


def test_fresh_build_has_schema_v1(base_params):
    with scratch.scratch(base_params, suffix="m1_%d" % os.getpid()) as name:
        con = db.connect(scratch.params_for(base_params, name))
        try:
            tables = con.run("SELECT count(*) FROM pg_tables WHERE schemaname = 'occ'")[0][0]
            cols = con.run("SELECT count(*) FROM information_schema.columns c JOIN pg_tables t "
                           "ON t.schemaname = c.table_schema AND t.tablename = c.table_name WHERE c.table_schema = 'occ'")[0][0]
            fks = con.run("SELECT count(*) FROM pg_constraint WHERE contype = 'f' AND connamespace = 'occ'::regnamespace")[0][0]
            rows = con.run("SELECT version, name, sha256 FROM occ.schema_migrations ORDER BY version")
        finally:
            con.close()
        assert tables == 56                                   # schema v1 has 55 tables; 0003 adds sync_stops
        assert cols == 535                                    # v1's 526 columns; 0003 adds 7 in sync_stops and 2 more
        # 0002 adds functions and a trigger, no table or column
        assert fks > 60
        files = migrate.files()
        assert [(r[0], r[1], r[2]) for r in rows] == [(f["version"], f["name"], f["sha256"]) for f in files]  # each applied once, with its hash
        assert migrate.migrate(scratch.params_for(base_params, name), log=lambda *_: None) == []   # once only


def test_fresh_build_equals_a_migrated_database(base_params):
    """Migrations are reproducible: two databases built from the migrations compare equal, and a change
    typed by hand into one of them is found."""
    with scratch.scratch(base_params, suffix="m2_%d" % os.getpid()) as target:
        same, rep = scratch.compare_fresh(base_params, target, suffix="f1_%d" % os.getpid())
        assert same, rep["diff"][:40]
        assert rep["tables_fresh"] == rep["tables_target"] == 56
        con = db.connect(scratch.params_for(base_params, target))
        try:
            con.run("ALTER TABLE occ.tags ADD COLUMN hand_typed integer")   # scratch only: proves the check bites
        finally:
            con.close()
        same, rep = scratch.compare_fresh(base_params, target, suffix="f2_%d" % os.getpid())
        assert not same and any("hand_typed" in line for line in rep["diff"])


def _copy_migrations(tmp_path):
    d = tmp_path / "migrations"
    shutil.copytree(migrate.MIGRATIONS_DIR, d)
    return str(d)


def test_runner_refuses_changed_missing_and_late_files(base_params, tmp_path):
    with scratch.scratch(base_params, suffix="m3_%d" % os.getpid()) as name:
        p = scratch.params_for(base_params, name)
        d = _copy_migrations(tmp_path)
        with open(os.path.join(d, "0001_schema_v1.sql"), "a") as fh:
            fh.write("\n-- edited after it was applied\n")
        with pytest.raises(migrate.MigrationError, match="changed after it was applied"):
            migrate.migrate(p, d, log=lambda *_: None)
        os.remove(os.path.join(d, "0001_schema_v1.sql"))
        with pytest.raises(migrate.MigrationError, match="file is missing"):
            migrate.migrate(p, d, log=lambda *_: None)
        d2 = _copy_migrations(tmp_path / "late")
        with open(os.path.join(d2, "0000_late.sql"), "w") as fh:
            fh.write("SELECT 1;\n")
        with pytest.raises(migrate.MigrationError, match="numbered below"):
            migrate.migrate(p, d2, log=lambda *_: None)


def test_a_failing_migration_changes_nothing(base_params, tmp_path):
    with scratch.scratch(base_params, suffix="m4_%d" % os.getpid()) as name:
        p = scratch.params_for(base_params, name)
        d = _copy_migrations(tmp_path)
        head = max(f["version"] for f in migrate.files())
        with open(os.path.join(d, "%04d_broken.sql" % (head + 1)), "w") as fh:
            fh.write("CREATE TABLE occ.half_done (id int);\nSELECT * FROM occ.no_such_table;\n")
        with pytest.raises(db.DatabaseError):
            migrate.migrate(p, d, log=lambda *_: None)
        con = db.connect(p)
        try:
            assert con.run("SELECT to_regclass('occ.half_done') IS NULL")[0][0]
            assert con.run("SELECT max(version) FROM occ.schema_migrations")[0][0] == head
        finally:
            con.close()


def test_audit_log_is_append_only(base_params):
    """The audit log is append-only: UPDATE, DELETE and TRUNCATE on occ.audit_events each fail; rows chain."""
    with scratch.scratch(base_params, suffix="m5_%d" % os.getpid()) as name:
        con = db.connect(scratch.params_for(base_params, name))
        try:
            for i in range(3):
                con.run("SELECT occ.audit_append(CAST(:p AS jsonb))",
                        p=db.jsonb({"actor_kind": "system", "category": "test", "new_value": str(i)}))
            rows = con.run("SELECT prev_hash, hash FROM occ.audit_events ORDER BY id")
            assert rows[0][0] == b"\x00" * 32
            assert rows[1][0] == rows[0][1] and rows[2][0] == rows[1][1]
            for sql in ("UPDATE occ.audit_events SET new_value = 'x'", "DELETE FROM occ.audit_events",
                        "TRUNCATE occ.audit_events"):
                with pytest.raises(db.DatabaseError, match="append-only"):
                    con.run(sql)
        finally:
            con.close()


def test_no_scratch_database_left_behind(base_params):
    """Nothing is left behind: every scratch database this test run made is gone (the session's own
    one, occ_scratch_t<pid>, is dropped when the session ends). Every name this run makes carries
    its process id, so a parity run or another worktree's tests running at the same time do not
    make this fail."""
    pid = str(os.getpid())
    left = [n for n in scratch.leftovers(base_params) if pid in n and n != "occ_scratch_t" + pid]
    assert left == []
