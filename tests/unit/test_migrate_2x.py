# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The 2.x to 3.x migration tool and sync phase A.

A small 2.x stand-in (SQLite with MySQL's CRC32, BIT_XOR and ISNULL added, behind the same Source
class the real run uses) is migrated into a scratch OCC database of its own, then changed and
synced. Checked here: the mapping names all 84 eLabFTW tables exactly as mapping.json does; ids,
authors and times are kept (DATETIME from US Central, both sides of a daylight-saving change);
the reconciliation finds no difference; a second run writes nothing and reports the same result;
3.x-only ids start at the floor; a sync cycle carries an edit, a new row and a removal, records
the lag, overwrites a 3.x edit with the 2.x version and reports it, and leaves 3.x-only rows
alone; the source refuses an account that can write.
"""
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import zlib

import pytest

from occ import db, settings as settings_mod
from occ.db import scratch
from occ.files import store as store_mod
from occ.sync import apply as A, canon, detect as D, engine as E, mapping as M, source as S
from occ.sync.files import Files

HERE = os.path.dirname(os.path.abspath(__file__))
MAPPING = os.path.join(os.path.dirname(os.path.dirname(HERE)), "docs", "design", "mapping.json")
UTC = dt.timezone.utc

# --------------------------------------------------------------------------- the 2.x stand-in
TABLES = {
    "users": [("userid", "integer"), ("email", "text"), ("firstname", "text"), ("lastname", "text"),
              ("is_sysadmin", "integer"), ("validated", "integer"), ("created_at", "timestamp"),
              ("last_login", "timestamp"), ("password_hash", "text"), ("lang", "text"), ("limit_nb", "integer")],
    "teams": [("id", "integer"), ("name", "text"), ("created_at", "timestamp"), ("visible", "integer")],
    "users2teams": [("users_id", "integer"), ("teams_id", "integer"), ("is_owner", "integer"),
                    ("is_admin", "integer"), ("is_archived", "integer")],
    "experiments_categories": [("id", "integer"), ("team", "integer"), ("created_at", "timestamp"),
                               ("modified_at", "timestamp"), ("title", "text"), ("color", "text"),
                               ("is_private", "integer"), ("ordering", "integer"), ("state", "integer")],
    "experiments": [("id", "integer"), ("team", "integer"), ("title", "text"), ("date", "date"), ("body", "text"),
                    ("category", "integer"), ("status", "integer"), ("rating", "integer"), ("userid", "integer"),
                    ("elabid", "text"), ("locked", "integer"), ("canread_base", "integer"),
                    ("canwrite_base", "integer"), ("canread", "text"), ("canwrite", "text"),
                    ("content_type", "integer"), ("created_at", "timestamp"), ("modified_at", "timestamp"),
                    ("lastchangeby", "integer"), ("metadata", "text"), ("state", "integer")],
    "experiments_templates": [("id", "integer"), ("team", "integer"), ("title", "text"), ("body", "text"),
                              ("userid", "integer"), ("elabid", "text"), ("canread_base", "integer"),
                              ("canwrite_base", "integer"), ("canread_target_base", "integer"),
                              ("canread_target", "text"), ("created_at", "timestamp"), ("modified_at", "timestamp"),
                              ("state", "integer"), ("ordering", "integer")],
    "items": [("id", "integer"), ("team", "integer"), ("title", "text"), ("body", "text"), ("userid", "integer"),
              ("elabid", "text"), ("canread_base", "integer"), ("canwrite_base", "integer"),
              ("canbook_base", "integer"), ("canbook", "text"), ("is_bookable", "integer"),
              ("book_max_minutes", "integer"), ("created_at", "timestamp"), ("modified_at", "timestamp"),
              ("state", "integer"), ("available", "integer")],
    "experiments_comments": [("id", "integer"), ("created_at", "timestamp"), ("modified_at", "timestamp"),
                             ("item_id", "integer"), ("comment", "text"), ("userid", "integer"),
                             ("immutable", "integer")],
    "tags": [("id", "integer"), ("team", "integer"), ("tag", "text")],
    "tags2entity": [("id", "integer"), ("item_id", "integer"), ("tag_id", "integer"), ("item_type", "text")],
    "experiments2items": [("item_id", "integer"), ("link_id", "integer")],
    "experiments_changelog": [("id", "integer"), ("entity_id", "integer"), ("users_id", "integer"),
                              ("created_at", "timestamp"), ("modified_at", "timestamp"), ("target", "text"),
                              ("content", "text")],
    "team_events": [("id", "integer"), ("team", "integer"), ("item", "integer"), ("start", "timestamp"),
                    ("end", "timestamp"), ("title", "text"), ("userid", "integer"), ("experiment", "integer"),
                    ("item_link", "integer"), ("created_at", "timestamp"), ("modified_at", "timestamp")],
    "uploads": [("id", "integer"), ("real_name", "text"), ("long_name", "text"), ("comment", "text"),
                ("item_id", "integer"), ("userid", "integer"), ("type", "text"), ("created_at", "timestamp"),
                ("hash", "text"), ("hash_algorithm", "text"), ("storage", "integer"), ("filesize", "integer"),
                ("state", "integer"), ("immutable", "integer")],
}
DATETIME_COLS = {"team_events": {"start", "end"}, "users": {"last_login"}}
_DT = re.compile(r"^\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(\.\d+)?$")
sqlite3.register_converter("timestamp", lambda b: dt.datetime.fromisoformat(b.decode()))
sqlite3.register_converter("date", lambda b: dt.date.fromisoformat(b.decode()))
sqlite3.register_adapter(dt.datetime, lambda d: d.replace(tzinfo=None).isoformat(" "))
FILE_BYTES = b"hello from 2.x\n"
NO_BYTES = "file bytes not readable: no read-only access to the 2.x upload directory (Dev/Ops)"


def _seed():
    acl = json.dumps({"teams": [], "users": [3], "teamgroups": []})
    return {
        "users": [(1, "ada@example.com", "Ada", "One", 1, 1, "2025-01-02 03:04:05", "2026-03-08 01:30:00", "secret",
                   "en_GB", 15),
                  (2, "ben@example.com", "Ben", "Two", 0, 1, "2025-01-02 03:04:05", None, "secret", "en_GB", 15),
                  (3, "cy@example.com", "Cy", "Three", 0, 1, "2025-01-02 03:04:05", None, None, "en_GB", 15)],
        "teams": [(1, "Home", "2025-01-01 00:00:00", 1), (5, "Lab Five", "2025-01-01 00:00:00", 1)],
        "users2teams": [(1, 1, 1, 1, 0), (2, 5, 0, 0, 0), (3, 5, 0, 1, 0)],
        "experiments_categories": [(4, 5, "2025-01-01 00:00:00", "2025-01-01 00:00:00", "Assay", "#29aeb9", 0, 1, 1)],
        "experiments": [
            (7, 5, "First", "2026-01-05", "<p>Body one</p>", 4, None, 3, 2, "20260105-" + "a" * 40, 0, 30, 20, acl,
             "{}", 1, "2026-01-05 10:00:00", "2026-01-05 11:00:00", 2, '{"extra_fields": {"pH": {"value": "7"}}}', 1),
            (9, 5, "Deleted one", None, None, 99, None, 0, 3, "20260106-" + "b" * 40, 1, 30, 20, "{}", "{}", 2,
             "2026-01-06 10:00:00", "2026-01-06 10:00:00", 3, None, 3)],
        "experiments_templates": [(2, 5, "Template", "<p>t</p>", 2, None, 30, 20, 10, '{"teams": [5]}',
                                   "2025-12-01 00:00:00", "2025-12-01 00:00:00", 1, 0)],
        "items": [(3, 5, "Microscope", "", 2, "20250101-" + "c" * 40, 30, 20, 30, '{"users": [1]}', 1, 120,
                   "2025-01-01 00:00:00", "2025-01-01 00:00:00", 1, 1)],
        "experiments_comments": [(11, "2026-01-05 12:00:00", "2026-01-05 12:00:00", 7, "Looks good", 3, 0),
                                 (12, "2026-01-05 12:00:00", "2026-01-05 12:00:00", 999, "orphan", 3, 0)],
        "tags": [(21, 5, "buffer"), (22, 5, "urgent")],
        "tags2entity": [(1, 7, 21, "experiments"), (2, 7, 22, "experiments")],
        "experiments2items": [(7, 3)],
        "experiments_changelog": [(31, 7, 2, "2026-01-05 10:00:00", "2026-01-05 10:00:00", "title", "Draft"),
                                  (32, 7, 2, "2026-01-05 11:00:00", "2026-01-05 11:00:00", "title", "First")],
        "team_events": [(41, 5, 3, "2026-03-08 01:30:00", "2026-03-08 03:30:00", "Across DST", 2, 7, None,
                         "2026-03-01 00:00:00", "2026-03-01 00:00:00"),
                        (42, 5, 3, "2026-07-01 10:00:00", "2026-07-01 11:00:00", "Summer", 3, None, None,
                         "2026-03-01 00:00:00", "2026-03-01 00:00:00")],
        "uploads": [(51, "notes.txt", "ab/abcd-1.txt", None, 7, 2, "experiments", "2026-01-05 10:30:00",
                     hashlib.sha256(FILE_BYTES).hexdigest(), "sha256", 1, len(FILE_BYTES), 1, 0),
                    (52, "missing.bin", "cd/cdef-2.bin", None, 7, 2, "experiments", "2026-01-05 10:30:00",
                     "00" * 32, "sha256", 1, 10, 1, 0)],
    }


class _Cur:
    def __init__(self, cur):
        self.cur = cur

    def execute(self, sql, args=()):
        self.cur.execute(sql.replace("%s", "?").replace("ISNULL(", "IS_NULL("), tuple(args or ()))

    @property
    def description(self):
        return self.cur.description

    def _conv(self, row):
        return tuple(dt.datetime.fromisoformat(v) if isinstance(v, str) and _DT.match(v) else v for v in row)

    def fetchall(self):
        return [self._conv(r) for r in self.cur.fetchall()]

    def fetchone(self):
        r = self.cur.fetchone()
        return None if r is None else self._conv(r)

    def close(self):
        self.cur.close()


class _Con:
    def __init__(self, con):
        self.con = con

    def cursor(self):
        return _Cur(self.con.cursor())

    def close(self):
        self.con.close()


class _BitXor:
    def __init__(self):
        self.v = 0

    def step(self, x):
        if x is not None:
            self.v ^= int(x)

    def finalize(self):
        return self.v


class FakeSource(S.Source):
    """The real Source over SQLite: same reads, same conversions."""

    def __init__(self, grants=("GRANT SELECT ON `elabftw`.* TO `eln_ro`@`%`",)):
        super().__init__()
        self._grants = list(grants)
        raw = sqlite3.connect(":memory:", detect_types=sqlite3.PARSE_DECLTYPES)
        raw.create_function("CRC32", 1, lambda s: zlib.crc32(str(s).encode()) if s is not None else None)
        raw.create_function("IS_NULL", 1, lambda v: 1 if v is None else 0)       # ISNULL is an SQLite keyword
        raw.create_aggregate("BIT_XOR", 1, _BitXor)
        for t, cols in TABLES.items():
            raw.execute("CREATE TABLE `%s` (%s)" % (t, ", ".join("`%s` %s" % (c, ty) for c, ty in cols)))
        for t, rows in _seed().items():
            raw.executemany("INSERT INTO `%s` VALUES (%s)" % (t, ", ".join("?" for _ in TABLES[t])), rows)
        raw.commit()
        self.raw = raw
        self.database = "fake"

    def open(self):
        self.con = _Con(self.raw)
        self._session()
        return self

    def _session(self):
        self.grants = list(self._grants)
        for g in self.grants:
            if S._WRITE_GRANTS.search(g.upper()):
                raise S.SourceError("refused: the 2.x account can do more than SELECT")
        self.columns = {t: [c for c, _ in cols] for t, cols in TABLES.items()}
        self.datetime_cols = dict(DATETIME_COLS)

    def ping(self):
        pass

    def close(self):
        pass

    def checksums(self, tables):
        out = {}
        for t in tables:
            rows = self.raw.execute("SELECT * FROM `%s`" % t).fetchall()
            out[t] = {"checksum": zlib.crc32(repr(sorted(map(repr, rows))).encode()), "rows": len(rows)}
        return out

    def write(self, sql, *args):
        """Changes made by the test, standing in for a person using 2.x."""
        self.raw.execute(sql, args)
        self.raw.commit()


# --------------------------------------------------------------------------------- fixtures
@pytest.fixture(scope="module")
def mig(base_params, tmp_path_factory):
    with scratch.scratch(base_params, suffix="t%d_m2x" % os.getpid()) as name:
        t = tmp_path_factory.mktemp("m2x")
        updir = t / "uploads"
        (updir / "ab").mkdir(parents=True)
        (updir / "ab" / "abcd-1.txt").write_bytes(FILE_BYTES)
        cfg = settings_mod.Settings(database_url="postgresql:///%s" % name, files_root=str(t / "files"),
                                    secret_key_file=str(t / "no-secret.key"), pool_size=2)
        src = FakeSource().open()
        files = Files(store_mod.for_settings(cfg), source_dir=str(updir))
        eng = E.Engine(cfg, src, files, floor=10_000_000, quiet=True)
        first = eng.migrate_full(trigger="cli")
        yield {"eng": eng, "src": src, "cfg": cfg, "first": first, "pool": eng.pool}
        eng.close()


def _one(pool, sql, **kw):
    with pool.tx() as tx:
        return tx.one(sql, **kw)


# ------------------------------------------------------------------------------------ tests
def test_mapping_names_every_table_once_as_mapping_json_does():
    with open(MAPPING, encoding="utf-8") as fh:
        design = json.load(fh)
    assert len(design) == 84
    assert set(design) == set(M.TABLES)
    code = M.classification()
    for t, (state, _target, _why) in design.items():
        assert code[t][0] == state, t
    assert len(M.SPECS) == len(M.CARRIED) == len(set(sp.src for sp in M.SPECS))


def test_canonical_form_is_stable_across_types():
    a = {"t": dt.datetime(2026, 1, 1, 6, 0, tzinfo=UTC), "d": dt.date(2026, 1, 1), "n": __import__("decimal").Decimal("1.50"),
         "j": {"b": 1, "a": [1, 2]}, "x": b"\x01"}
    b = {"x": b"\x01", "j": {"a": [1, 2], "b": 1}, "n": 1.5, "d": dt.date(2026, 1, 1),
         "t": dt.datetime(2026, 1, 1, 0, 0, tzinfo=dt.timezone(dt.timedelta(hours=-6)))}
    assert canon.digest(a) == canon.digest(b)
    assert canon.diff({"a": 1, "b": 2}, {"a": 1, "b": 3}) == ["b"]


def test_source_refuses_an_account_that_can_write():
    with pytest.raises(S.SourceError):
        FakeSource(grants=("GRANT SELECT, INSERT ON `elabftw`.* TO `x`@`%`",)).open()


def test_source_refuses_the_read_write_env_file(tmp_path, monkeypatch):
    rw = tmp_path / "rw.env"
    rw.write_text("ELN_DB_HOST=h\nELN_DB_USER=u\nELN_DB_PASS=p\nELN_DB_NAME=n\n")
    monkeypatch.setenv("ELN_DB_RW_ENV", str(rw))
    with pytest.raises(S.SourceError):
        S.credentials(str(rw))


def test_first_run_reconciles_with_no_difference(mig):
    rec = mig["first"]["result"]["reconciliation"]
    # the one difference is the upload whose bytes do not exist: listed, with its reason, not hidden
    assert rec["differences"] == [{"table": "uploads", "source_id": "52", "difference": "missing in the OCC",
                                   "reason": NO_BYTES}]
    assert not rec["ok"]
    assert all(v.get("content_differences", 0) == 0 and v.get("extra_in_occ", 0) == 0 for v in rec["tables"].values())
    assert rec["tables"]["experiments"]["carried"] == 2
    assert rec["tables"]["experiments_comments"]["skip_reasons"] == {"its record does not exist in 2.x": 1}
    assert rec["tables"]["authfail"]["state"] == "not carried"
    assert mig["first"]["total_writes"] > 0


def test_ids_people_and_times_are_kept(mig):
    p = mig["pool"]
    r = _one(p, "SELECT title, owner_id, created_at, modified_by, category_id, metadata, elabid FROM occ.records "
                "WHERE kind_id = 1 AND id = 7")
    assert r["title"] == "First" and r["owner_id"] == 2 and r["modified_by"] == 2 and r["category_id"] == 4
    assert r["created_at"] == dt.datetime(2026, 1, 5, 10, 0, tzinfo=UTC)          # TIMESTAMP: already UTC
    assert r["elabid"] == "20260105-" + "a" * 40
    gone = _one(p, "SELECT state, category_id, locked, locked_at FROM occ.records WHERE kind_id = 1 AND id = 9")
    assert gone["state"] == 3 and gone["category_id"] is None and gone["locked"] and gone["locked_at"] is not None
    ev = {r["id"]: r for r in [_one(p, "SELECT id, start_at, end_at FROM occ.events WHERE id = :i", i=i) for i in (41, 42)]}
    assert ev[41]["start_at"] == dt.datetime(2026, 3, 8, 7, 30, tzinfo=UTC)        # CST, -6 h
    assert ev[41]["end_at"] == dt.datetime(2026, 3, 8, 8, 30, tzinfo=UTC)          # 03:30 CDT, -5 h
    assert ev[42]["start_at"] == dt.datetime(2026, 7, 1, 15, 0, tzinfo=UTC)        # CDT, -5 h
    u = _one(p, "SELECT id, email, last_login_at, prefs FROM occ.users WHERE id = 1")
    assert u["last_login_at"] == dt.datetime(2026, 3, 8, 7, 30, tzinfo=UTC)
    assert "password_hash" not in canon.json_value(u["prefs"]) and canon.json_value(u["prefs"])["lang"] == "en_GB"
    acc = _one(p, "SELECT count(*) AS n FROM occ.record_access ra JOIN occ.records r ON r.rid = ra.rid "
                  "WHERE r.kind_id = 1 AND r.id = 7 AND ra.access_right = 'r' AND ra.principal = 'u' "
                  "AND ra.principal_id = 3")
    assert acc["n"] == 1


def test_template_gets_a_stable_generated_elabid(mig):
    r = _one(mig["pool"], "SELECT elabid, canread_target FROM occ.records WHERE kind_id = 3 AND id = 2")
    assert re.fullmatch(r"20251201-[0-9a-f]{40}", r["elabid"])
    assert r["elabid"] == M.template_elabid(3, 2, dt.datetime(2025, 12, 1, tzinfo=UTC))
    assert canon.json_value(r["canread_target"]) == {"base": 10, "teams": [5], "users": [], "teamgroups": []}


def test_history_is_imported_with_origin_author_and_previous_value(mig):
    rows = []
    with mig["pool"].tx() as tx:
        rows = tx.all("SELECT target, old_value, new_value, actor_user_id, origin, orig_at FROM occ.audit_events "
                      "WHERE origin = 'elabftw-import' AND category = 'record.update' ORDER BY id")
    assert [(r["old_value"], r["new_value"]) for r in rows] == [(None, "Draft"), ("Draft", "First")]
    assert rows[0]["actor_user_id"] == 2 and rows[0]["orig_at"] == dt.datetime(2026, 1, 5, 10, 0, tzinfo=UTC)


def test_files_are_carried_with_their_hash_or_reported(mig):
    up = _one(mig["pool"], "SELECT sha256, size, storage_name FROM occ.uploads WHERE id = 51")
    assert bytes(up["sha256"]).hex() == hashlib.sha256(FILE_BYTES).hexdigest() and up["storage_name"] == "ab/abcd-1.txt"
    assert _one(mig["pool"], "SELECT count(*) AS n FROM occ.uploads WHERE id = 52")["n"] == 0
    up = mig["first"]["result"]["reconciliation"]["tables"]["uploads"]
    assert up["missing_reasons"] == {NO_BYTES: 1} and up["carried"] == 2 and up["occ_rows"] == 1


def test_second_run_writes_nothing_and_reports_the_same_result(mig):
    second = mig["eng"].migrate_full(trigger="cli")
    assert second["total_writes"] == 0
    assert second["result_sha256"] == mig["first"]["result_sha256"]


def test_3x_only_ids_start_at_the_floor(mig):
    with mig["pool"].tx() as tx:
        tid = tx.val("INSERT INTO occ.tags (team_id, tag) VALUES (5, 'made in 3.x') RETURNING id")
        assert tid >= 10_000_000
        tx.run("DELETE FROM occ.tags WHERE id = :i", i=tid)


def test_sync_cycle_carries_changes_reports_replaced_3x_edits_and_keeps_3x_rows(mig):
    eng, src, p = mig["eng"], mig["src"], mig["pool"]
    rid = _one(p, "SELECT rid FROM occ.records WHERE kind_id = 1 AND id = 7")["rid"]
    with p.tx() as tx:              # an edit made in 3.x, and a comment that exists only in 3.x
        tx.run("UPDATE occ.records SET title = 'Edited in 3.x' WHERE rid = :r", r=rid)
        only3x = tx.val("INSERT INTO occ.comments (rid, user_id, body) VALUES (:r, 3, '3.x only') RETURNING id", r=rid)
    assert eng.cycle()["tables"] == {}                       # nothing moved on 2.x yet
    now = dt.datetime.now(UTC).replace(microsecond=0, tzinfo=None)
    src.write("UPDATE experiments SET body = '<p>Body two</p>', modified_at = ? WHERE id = 7", now.isoformat(" "))
    src.write("INSERT INTO experiments_comments VALUES (13, ?, ?, 7, 'New from 2.x', 2, 0)",
              now.isoformat(" "), now.isoformat(" "))
    src.write("DELETE FROM tags2entity WHERE id = 2")
    src.write("INSERT INTO experiments_changelog VALUES (33, 7, 2, ?, ?, 'body', '<p>Body two</p>')",
              now.isoformat(" "), now.isoformat(" "))
    out = eng.cycle()
    assert set(out["tables"]) >= {"experiments", "experiments_comments", "tags2entity", "experiments_changelog"}
    r = _one(p, "SELECT title, body, search_text FROM occ.records WHERE rid = :r", r=rid)
    assert r["title"] == "First" and r["body"] == "<p>Body two</p>"          # 2.x wins: in phase A, 2.x is the source of truth
    assert "urgent" not in r["search_text"] and "buffer" in r["search_text"]
    replaced = out["replaced_3x_edits"]
    assert len(replaced) == 1 and replaced[0]["source_id"] == "7"
    assert {f["field"] for f in replaced[0]["fields"]} >= {"title"}
    assert _one(p, "SELECT body FROM occ.comments WHERE id = :i", i=only3x)["body"] == "3.x only"
    assert _one(p, "SELECT count(*) AS n FROM occ.comments WHERE body = 'New from 2.x'")["n"] == 1
    assert _one(p, "SELECT count(*) AS n FROM occ.record_tags WHERE rid = :r", r=rid)["n"] == 1
    with p.tx() as tx:
        lags = tx.all("SELECT source_table, lag_seconds FROM occ.sync_lag ORDER BY id")
    assert {x["source_table"] for x in lags} >= {"experiments", "experiments_comments"}
    assert all(0 <= float(x["lag_seconds"]) < 120 for x in lags)
    rec = eng.reconcile_now()
    assert [d["source_id"] for d in rec["differences"]] == ["52"]          # still only the file with no bytes
    assert rec["records_only_in_3x"] == 0


def test_a_deleted_upload_is_carried_without_fetching_its_bytes_again(mig, tmp_path):
    eng, src, p = mig["eng"], mig["src"], mig["pool"]
    saved = eng.files
    eng.files = Files(saved.store, source_dir=str(tmp_path))          # the bytes are gone from the source
    try:
        src.write("UPDATE uploads SET state = 3 WHERE id = 51")
        out = eng.cycle()
    finally:
        eng.files = saved
    assert out["tables"]["uploads"]["written"] == 1
    up = _one(p, "SELECT state, sha256 FROM occ.uploads WHERE id = 51")
    assert up["state"] == 3 and bytes(up["sha256"]).hex() == hashlib.sha256(FILE_BYTES).hexdigest()


def test_lag_and_last_cycle_are_exported_as_metrics(mig):
    from occ.sync import status
    with mig["pool"].tx(readonly=True) as tx:
        text = status.metrics_text(tx)
    assert 'occ_sync_lag_seconds{quantile="0.95"}' in text and "occ_sync_last_cycle_age_seconds" in text


def test_stop_after_is_three_polls_and_at_least_a_minute():
    assert E.stop_after(15) == 60 and E.stop_after(30) == 90 and E.stop_after(5) == 60


def test_a_stop_is_recorded_and_its_catch_up_is_left_out_of_the_delay(mig):
    from occ.sync import status
    eng, src, p = mig["eng"], mig["src"], mig["pool"]
    with p.tx() as tx:              # the sync last looked ten minutes ago, and this process is new
        tx.run("UPDATE occ.sync_fingerprints SET taken_at = now() - interval '10 minutes' "
               "WHERE source_table = '(cycle)' AND scope_key = '*'")
        before = status._lag(tx)
    eng.last_active = None
    # 2.x stamps a change with the time it was made; the stop is the ten minutes set above
    during = (dt.datetime.now(UTC) + dt.timedelta(seconds=1)).replace(microsecond=0, tzinfo=None)
    src.write("UPDATE experiments SET body = '<p>Made during the stop</p>', modified_at = ? WHERE id = 7",
              during.isoformat(" "))
    out = eng.cycle()
    stop = out["stop"]
    assert stop and stop["changes"] >= 1 and stop["stopped_s"] >= 590 and stop["catch_up_s"] >= 0
    with p.tx() as tx:
        rows = tx.all("SELECT catch_up, lag_seconds FROM occ.sync_lag WHERE run_id = :r", r=out["run"])
        after = status._lag(tx)
        stops = status._stops(tx)
        text = status.metrics_text(tx)
    assert rows and all(r["catch_up"] for r in rows)
    assert after == before                       # the catch-up changes do not move the delay figures
    assert stops["n"] == 1 and stops["last"]["changes"] == stop["changes"]
    assert "occ_sync_stops_24h 1" in text and "occ_sync_last_catch_up_seconds" in text
    # the next cycle in the same process is no stop, and its changes count again
    now = (dt.datetime.now(UTC) + dt.timedelta(seconds=2)).replace(microsecond=0, tzinfo=None)
    src.write("UPDATE experiments SET body = '<p>Made while running</p>', modified_at = ? WHERE id = 7",
              now.isoformat(" "))
    out2 = eng.cycle()
    assert out2["stop"] is None
    with p.tx() as tx:
        rows2 = tx.all("SELECT catch_up, lag_seconds FROM occ.sync_lag WHERE run_id = :r", r=out2["run"])
        after2 = status._lag(tx)
    assert rows2 and not any(r["catch_up"] for r in rows2) and after2["n"] == after["n"] + len(rows2)
    assert after2["max"] < 120


def test_a_second_process_is_refused_while_one_runs(mig):
    other = E.Engine(mig["cfg"], mig["src"], None, quiet=True)
    try:
        with pytest.raises(E.Busy):
            other.start_run("sync", "cli")
        assert other.run_forever(max_seconds=1, force=True) == 2
    finally:
        other.close()


def test_a_batch_with_a_bad_row_reports_it_and_carries_the_rest(mig):
    eng, src = mig["eng"], mig["src"]
    src.write("INSERT INTO teams VALUES (6, 'home', '2025-01-01 00:00:00', 1)")     # same name as team 1, other case
    src.write("INSERT INTO teams VALUES (7, 'Lab Seven', '2025-01-01 00:00:00', 1)")
    out = eng.cycle()
    assert _one(mig["pool"], "SELECT count(*) AS n FROM occ.teams WHERE id = 7")["n"] == 1
    assert _one(mig["pool"], "SELECT count(*) AS n FROM occ.teams WHERE id = 6")["n"] == 0
    assert out["tables"]["teams"]["written"] == 1


def test_sql_names_come_from_closed_lists():
    assert M.OCC_TABLES <= set(A.KEYEXPR)
    assert D.SOURCE_NAME.fullmatch("modified_at") and not D.SOURCE_NAME.fullmatch("x`; DROP")
    with pytest.raises(ValueError):
        db.ident("x; drop", M.OCC_COLUMNS)
