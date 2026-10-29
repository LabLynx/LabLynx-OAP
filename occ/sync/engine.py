# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""One engine, two uses: the 2.x to 3.x migration and demo sync phase A.

  migrate_full()  every carried table read in full and carried; rows gone from 2.x removed
                  (where the kind allows); identity sequences moved past the 2.x ids; then the
                  reconciliation, the report, and 2.x's table checksums before and after.
  cycle()         one sync cycle: detect what changed on 2.x since the last cycle (detect.py) and
                  carry only that, in the same cycle; each carried change's lag goes to occ.sync_lag.
                  The first cycle after a stop records the stop in occ.sync_stops and marks the
                  changes it carried as catch-up, which the delay target does not count.
  run_forever()   the occ-sync process: a cycle every poll_seconds while occ.sync_settings says
                  direction A and enabled; reconciliation every hour; stops on SIGTERM.

Writes go through apply.Writer in transactions of at most `batch` rows. When a batch fails, it is
rolled back and its rows are tried one at a time under savepoints, so one bad row is reported
(with the constraint it broke) instead of stopping the run.
"""
import datetime as dt
import json
import os
import signal
import sys
import time

from .. import db
from ..files import store as store_mod
from ..records import service as records_service
from . import apply as A, detect as D, mapping as M, report as R

UTC = dt.timezone.utc
LOCK_KEY = 7031103
CYCLE_ROW = "(cycle)"          # the occ.sync_fingerprints row whose taken_at is the last cycle's time
STOP_AFTER_S = 60              # idle longer than this, and three polls, and the sync counts as stopped


def stop_after(poll_seconds):
    """How long the sync may go without a cycle before the gap counts as a stop."""
    return max(3 * int(poll_seconds or 15), STOP_AFTER_S)


def log(event, **kw):
    sys.stdout.write(json.dumps({"ts": dt.datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "svc": "occ-sync",
                                 "event": event, **kw}, default=str) + "\n")
    sys.stdout.flush()


class Busy(Exception):
    pass


class Engine:
    def __init__(self, cfg, source, files=None, floor=None, batch=500, quiet=False):
        self.cfg = cfg
        self.pool = db.Pool(cfg.db_params(), size=2)
        self.source = source
        self.files = files
        self.floor = floor
        self.batch = batch
        self.quiet = quiet
        self.can_seal = bool(cfg.secret_key_file) and os.path.exists(cfg.secret_key_file)
        self.ctx = None
        self.last_reconcile = 0.0
        self._lock_con = None
        self.last_active = None          # when this process last finished a cycle or a full pass

    def close(self):
        self.release_lock()
        self.pool.close()

    # -- one process at a time ------------------------------------------------------------------
    def take_lock(self):
        """Every migration, reconciliation and sync process holds the sync advisory lock for as long
        as it runs, on a connection of its own; a second one is refused, so two writers never race
        over the same rows."""
        if self._lock_con is not None:
            return
        con = db.connect(self.cfg.db_params())
        if not con.run("SELECT pg_try_advisory_lock(:k)", k=LOCK_KEY)[0][0]:
            con.close()
            raise Busy("another migration, reconciliation or occ-sync process is running")
        self._lock_con = con

    def release_lock(self):
        if self._lock_con is not None:
            try:
                self._lock_con.run("SELECT pg_advisory_unlock(:k)", k=LOCK_KEY)
                self._lock_con.close()
            except Exception:
                pass
            self._lock_con = None

    def _log(self, event, **kw):
        if not self.quiet:
            log(event, **kw)

    def _new_ctx(self):
        with self.pool.tx() as tx:
            self.ctx = A.Ctx(tx, self.source, self.can_seal)
        return self.ctx

    # -- runs ------------------------------------------------------------------------------------
    def start_run(self, mode, trigger):
        self.take_lock()              # holding it, a 'running' row can only be a dead process's
        with self.pool.tx() as tx:
            stale = tx.all("SELECT id FROM occ.sync_runs WHERE state = 'running'")
            if stale:
                tx.run("UPDATE occ.sync_runs SET state = 'failed', finished_at = now(), "
                       "error = 'abandoned: the process ended before finishing' WHERE state = 'running'")
            return tx.val("INSERT INTO occ.sync_runs (direction, mode, trigger) VALUES ('A', :m, :t) RETURNING id",
                          m=mode, t=trigger)

    def finish_run(self, run_id, state, counts, report_sha=None, error=None):
        with self.pool.tx() as tx:
            tx.run("UPDATE occ.sync_runs SET state = :s, finished_at = now(), counts = CAST(:c AS jsonb), "
                   "report_sha256 = :r, error = :e WHERE id = :id", s=state, c=db.jsonb(counts), r=report_sha,
                   e=error, id=run_id)

    # -- applying rows ---------------------------------------------------------------------------
    def apply_rows(self, spec, rows, run_id, report, actor_kind, lag_at=None, changed_at=None):
        if not rows:
            return 0
        sids = [spec.source_id(r) for r in rows]
        with self.pool.tx() as tx:
            w = A.Writer(tx, self.ctx, run_id, actor_kind, self.files, self.cfg, report)
            existing = w.id_map(spec) if len(rows) > 300 else w.id_map(spec, sids)
        written = 0
        for k in range(0, len(rows), self.batch):
            chunk = rows[k:k + self.batch]
            try:
                written += self._chunk(spec, chunk, existing, run_id, report, actor_kind, lag_at, changed_at)
            except db.DatabaseError as e:
                self._log("batch_failed", table=spec.src, code=_code(e), constraint=_constraint(e))
                full = self.ctx.full
                self._new_ctx()
                self.ctx.full = full
                written += self._chunk(spec, chunk, existing, run_id, report, actor_kind, lag_at, changed_at,
                                       one_by_one=True)
        return written

    def _chunk(self, spec, chunk, existing, run_id, report, actor_kind, lag_at, changed_at, one_by_one=False):
        written, outcomes, sub = 0, [], R.Report()
        with self.pool.tx() as tx:
            w = A.Writer(tx, self.ctx, run_id, actor_kind, self.files, self.cfg, sub, lag=lag_at)
            for r in chunk:
                sid = spec.source_id(r)
                ch = changed_at(r) if changed_at else None
                if one_by_one:
                    tx.run("SAVEPOINT occ_row")
                    try:
                        out = w.apply(spec, r, existing.get(sid), ch)
                        tx.run("RELEASE SAVEPOINT occ_row")
                    except db.DatabaseError as e:
                        tx.run("ROLLBACK TO SAVEPOINT occ_row")
                        sub.skip(spec, sid, "could not be written (%s %s)" % (_code(e), _constraint(e) or ""))
                        out = "skipped"
                else:
                    out = w.apply(spec, r, existing.get(sid), ch)
                outcomes.append(out)
                if out in ("inserted", "updated"):
                    written += 1
            for rid in sorted(w.touched_rids):
                records_service.refresh_search(tx, rid)
            if written:
                A.write_batch_audit(tx, actor_kind, run_id, spec.src,
                                    {"written": written, "rows": len(chunk)})
        report.merge(sub)             # counted only once the transaction committed
        for out in outcomes:
            report.count(spec, out)
        return written

    def removals(self, spec, present_sids, run_id, report, actor_kind):
        removed = 0
        with self.pool.tx() as tx:
            w = A.Writer(tx, self.ctx, run_id, actor_kind, self.files, self.cfg, report)
            idm = w.id_map(spec)
            gone = sorted(set(idm) - set(present_sids))
            touched = set()
            for sid in gone:
                occ_id = idm[sid]["occ_id"]
                if spec.occ == "record_tags":
                    touched.add(int(occ_id.split(":")[0]))
                if w.remove(spec, sid, occ_id):
                    removed += 1
                    report.count(spec, "removed")
            for rid in sorted(touched):
                records_service.refresh_search(tx, rid)
            if removed:
                A.write_batch_audit(tx, actor_kind, run_id, spec.src, {"removed": removed})
        return removed

    # -- fingerprints ----------------------------------------------------------------------------
    def snapshot(self):
        snap = {}
        for spec in M.SPECS:
            if not self.source.has(spec.src):
                continue
            snap[(spec.src, "*")] = D.table_fp(self.source, spec)
            if D.strategy(self.source, spec) == "fingerprint":
                for p, (n, c) in (D.parent_fps(self.source, spec) or {}).items():
                    snap[(spec.src, p)] = {"row_count": n, "max_id": None, "max_modified": None, "checksum": c}
        return snap

    def store_fps(self, fps, replace_all=False, drop=()):
        with self.pool.tx() as tx:
            if replace_all:
                tx.run("DELETE FROM occ.sync_fingerprints")
            for (t, scope) in drop:
                tx.run("DELETE FROM occ.sync_fingerprints WHERE source_table = :t AND scope_key = :s", t=t, s=scope)
            for (t, scope), f in fps.items():
                tx.run("INSERT INTO occ.sync_fingerprints (source_table, scope_key, row_count, max_id, max_modified, "
                       "checksum, taken_at) VALUES (:t, :s, :n, :m, :mm, :c, now()) ON CONFLICT (source_table, scope_key) "
                       "DO UPDATE SET row_count = EXCLUDED.row_count, max_id = EXCLUDED.max_id, "
                       "max_modified = EXCLUDED.max_modified, checksum = EXCLUDED.checksum, taken_at = now()",
                       t=t, s=scope, n=f["row_count"], m=f["max_id"], mm=f["max_modified"], c=_signed(f["checksum"]))

    def stored_fps(self):
        with self.pool.tx(readonly=True) as tx:
            return {(r["source_table"], r["scope_key"]): r for r in tx.all(
                "SELECT source_table, scope_key, row_count, max_id, max_modified, checksum, taken_at "
                "FROM occ.sync_fingerprints")}

    # -- the full migration ----------------------------------------------------------------------
    def migrate_full(self, trigger="cli", do_reconcile=True, proof=True):
        t0 = time.time()
        started = dt.datetime.now(UTC)
        tables = D.known_tables(self.source)
        before = self.source.checksums(tables) if proof else None
        fps = self.snapshot()                      # taken before reading: the first cycle catches what moves
        run_id = self.start_run("migrate", trigger)
        report = R.Report()
        self._new_ctx()
        self.ctx.full = True
        actor = "migration" if trigger != "timer" else "sync"
        try:
            for spec in M.SPECS:
                if not self.source.has(spec.src):
                    continue
                ts = time.time()
                present, buf = set(), []
                for row in D.iter_full(self.source, spec):
                    present.add(spec.source_id(row))
                    buf.append(row)
                    if len(buf) >= self.batch * 4:
                        self.apply_rows(spec, buf, run_id, report, actor)
                        buf = []
                self.apply_rows(spec, buf, run_id, report, actor)
                self.removals(spec, present, run_id, report, actor)
                self._log("table_done", table=spec.src, rows=len(present), seconds=round(time.time() - ts, 2),
                          **report.writes.get(spec.src, {}))
            with self.pool.tx() as tx:
                seqs = A.bump_sequences(tx, self.floor)
            fps[(CYCLE_ROW, "*")] = {"row_count": len(tables), "max_id": None, "max_modified": None, "checksum": 0}
            self.store_fps(fps, replace_all=True)
            self.ctx.full = False
            rec = self.reconcile_now(report.skipped_ids) if do_reconcile else None
            after = self.source.checksums(tables) if proof else None
            unchanged = _compare(before, after) if proof else None
            finished = dt.datetime.now(UTC)
            run = {"id": run_id, "mode": "migrate", "trigger": trigger, "started_at": started, "finished_at": finished,
                   "duration_s": round(time.time() - t0, 1), "source": self._source_info(),
                   "target_database": self.cfg.database_name, "sequences": seqs, "floor": self.floor,
                   "files": self.files.describe() if self.files else None}
            rep = R.build(run, rec, report, unchanged)
            sha = self._store_report(rep)
            ok = rec is None or rec["ok"]
            self.finish_run(run_id, "ok", {"writes": report.total_writes(), "reconciled": ok,
                                           "result_sha256": rep["result_sha256"]}, sha)
            rep["report_sha256"] = sha.hex() if sha else None
            self.last_active = dt.datetime.now(UTC)
            return rep
        except BaseException as e:
            self.finish_run(run_id, "failed", {"writes": report.total_writes()}, error=type(e).__name__)
            raise

    def reconcile_now(self, skipped_ids=None):
        with self.pool.tx(readonly=True) as tx:
            return R.reconcile(tx, self.source, self.cfg, lambda spec: D.iter_full(self.source, spec), self.can_seal,
                               skipped_ids)

    def reconcile_run(self, trigger="cli"):
        t0 = time.time()
        started = dt.datetime.now(UTC)
        run_id = self.start_run("reconcile", trigger)
        try:
            rec = self.reconcile_now()
            run = {"id": run_id, "mode": "reconcile", "trigger": trigger, "started_at": started,
                   "finished_at": dt.datetime.now(UTC), "duration_s": round(time.time() - t0, 1),
                   "source": self._source_info(), "target_database": self.cfg.database_name}
            rep = R.build(run, rec, R.Report())
            sha = self._store_report(rep)
            self.finish_run(run_id, "ok", {"reconciled": rec["ok"], "result_sha256": rep["result_sha256"]}, sha)
            return rep
        except BaseException as e:
            self.finish_run(run_id, "failed", {}, error=type(e).__name__)
            raise

    def _source_info(self):
        return {"system": "eLabFTW 5.6.12 (MySQL)", "database": getattr(self.source, "database", None),
                "grants": self.source.grants, "session": "READ ONLY, time_zone +00:00"}

    def _store_report(self, rep):
        data = json.dumps(rep, indent=1, default=str, ensure_ascii=False).encode("utf-8")
        if self.files is None:
            return None
        sha, size = self.files.store.put_bytes(data)
        with self.pool.tx() as tx:
            store_mod.register(tx, self.files.store, sha, size)
        return sha

    # -- one sync cycle --------------------------------------------------------------------------
    def cycle(self):
        stored = self.stored_fps()
        if not any(k[1] == "*" and k[0] != CYCLE_ROW for k in stored):
            self._log("no_fingerprints", action="full pass first")
            rep = self.migrate_full(trigger="timer", do_reconcile=False, proof=False)
            return {"full_pass": True, "writes": rep["total_writes"]}
        if self.ctx is None:
            self._new_ctx()
        detected = dt.datetime.now(UTC)
        report, run_id, new_fps, drop = R.Report(), None, {}, []
        summary, checked = {}, 0
        # where 2.x keeps no change time, the change happened after the previous cycle looked
        last = stored.get((CYCLE_ROW, "*"))
        prev_at = last["taken_at"] if last is not None else detected
        # a stop: this process has not been running cycles (a new process, or the sync was switched
        # off) and nothing has looked at 2.x for longer than stop_after()
        with self.pool.tx(readonly=True) as tx:
            poll = tx.val("SELECT poll_seconds FROM occ.sync_settings WHERE id = 1")
        active = self.last_active or (prev_at if last is not None else None)
        stopped_at = active if active is not None and \
            (detected - active).total_seconds() > stop_after(poll) else None
        for spec in M.SPECS:
            if not self.source.has(spec.src):
                continue
            checked += 1
            cur = D.table_fp(self.source, spec)
            prev = stored.get((spec.src, "*"))
            if prev is not None and _same(cur, prev):
                continue
            st = D.strategy(self.source, spec)
            if prev is None:
                rows, changed = D.all_rows(self.source, spec), (lambda r, t=prev_at: t)
            elif st == "modified":
                since = (prev["max_modified"] or dt.datetime(1970, 1, 1, tzinfo=UTC)) - D.SLACK
                rows = D.rows_modified_since(self.source, spec, since)
                changed = lambda r, t=prev_at: r.get("modified_at") or t          # noqa: E731
            elif st == "append":
                rows = D.rows_after_id(self.source, spec, int(prev["max_id"] or 0))
                changed = lambda r, t=prev_at: r.get("created_at") or t           # noqa: E731
            else:
                pf = D.parent_fps(self.source, spec)
                if pf is None:
                    rows = D.all_rows(self.source, spec)
                else:
                    old = {k[1]: v for k, v in stored.items() if k[0] == spec.src and k[1] != "*"}
                    moved = [p for p, (n, c) in pf.items()
                             if p not in old or int(old[p]["row_count"]) != n or _signed(c) != int(old[p]["checksum"])]
                    rows = D.rows_of_parents(self.source, spec, moved) if moved else []
                    for p in moved:
                        new_fps[(spec.src, p)] = {"row_count": pf[p][0], "max_id": None, "max_modified": None,
                                                  "checksum": pf[p][1]}
                    drop += [(spec.src, p) for p in old if p not in pf]
                changed = lambda r, t=prev_at: t                                  # noqa: E731
            if run_id is None:
                run_id = self.start_run("sync", "timer")
            n = self.apply_rows(spec, rows, run_id, report, "sync", lag_at=detected, changed_at=changed)
            removed = 0
            if prev is None or st == "fingerprint" or int(cur["row_count"]) != int(prev["row_count"]) or \
                    int(cur["max_id"]) != int(prev["max_id"] or 0):
                if spec.removable:
                    removed = self.removals(spec, D.source_ids(self.source, spec), run_id, report, "sync")
            new_fps[(spec.src, "*")] = cur
            if n or removed:
                summary[spec.src] = {"written": n, "removed": removed, "read": len(rows)}
        # the cycle's own heartbeat: the sync status reports it as last_cycle, and the next cycle's lag uses it
        new_fps[(CYCLE_ROW, "*")] = {"row_count": checked, "max_id": None, "max_modified": None, "checksum": 0}
        self.store_fps(new_fps, drop=drop)
        if run_id is not None:
            self.finish_run(run_id, "ok", {"writes": report.total_writes(), "tables": summary,
                                           "replaced_3x_edits": report.replaced_edits[:50],
                                           "skips": {t: {r: e["count"] for r, e in v.items()}
                                                     for t, v in report.skips.items()}})
        stop = self._record_stop(run_id, stopped_at, detected) if stopped_at is not None else None
        self.last_active = dt.datetime.now(UTC)
        if summary:
            self._log("cycle", run=run_id, tables=summary, replaced=len(report.replaced_edits),
                      seconds=round((dt.datetime.now(UTC) - detected).total_seconds(), 2))
        return {"run": run_id, "tables": summary, "replaced_3x_edits": report.replaced_edits, "stop": stop}

    def _record_stop(self, run_id, stopped_at, resumed_at):
        """The first cycle after a stop: mark what it carried as catch-up and record the stop."""
        with self.pool.tx() as tx:
            n = 0
            if run_id is not None:
                n = tx.val("WITH u AS (UPDATE occ.sync_lag SET catch_up = true WHERE run_id = :r RETURNING 1) "
                           "SELECT count(*) FROM u", r=run_id)
            row = tx.one("INSERT INTO occ.sync_stops (run_id, stopped_at, resumed_at, caught_up_at, changes, catch_up_s) "
                         "VALUES (:r, :s, :d, clock_timestamp(), :n, round(CAST(extract(epoch FROM clock_timestamp() - "
                         "CAST(:d AS timestamptz)) AS numeric), 2)) RETURNING id, catch_up_s",
                         r=run_id, s=stopped_at, d=resumed_at, n=int(n or 0))
        out = {"id": row["id"], "stopped_s": round((resumed_at - stopped_at).total_seconds(), 2),
               "changes": int(n or 0), "catch_up_s": float(row["catch_up_s"])}
        self._log("resumed_after_stop", **out)
        return out

    # -- the occ-sync process --------------------------------------------------------------------
    def run_forever(self, reconcile_every=3600, max_seconds=None, force=False):
        stop = {"now": False}

        def _stop(*_):
            stop["now"] = True
        try:
            self.take_lock()
        except Busy:
            log("refused", why="another migration, reconciliation or occ-sync process holds the sync lock")
            return 2
        old = {sig: signal.signal(sig, _stop) for sig in (signal.SIGTERM, signal.SIGINT)}
        try:
            self.last_reconcile = time.time()
            t_end = time.time() + max_seconds if max_seconds else None
            log("started", poll="sync_settings.poll_seconds", reconcile_every=reconcile_every)
            while not stop["now"] and (t_end is None or time.time() < t_end):
                t0 = time.time()
                with self.pool.tx(readonly=True) as tx:
                    s = tx.one("SELECT direction, enabled, poll_seconds FROM occ.sync_settings WHERE id = 1")
                poll = int(s["poll_seconds"] or 15)
                if force or (s["enabled"] and s["direction"] == "A"):
                    try:
                        self.source.ping()
                        self.cycle()
                        if reconcile_every and time.time() - self.last_reconcile >= reconcile_every:
                            rep = self.reconcile_run(trigger="timer")
                            log("reconciled", ok=rep["result"]["reconciliation"]["ok"])
                            self.last_reconcile = time.time()
                            self.last_active = dt.datetime.now(UTC)      # a long reconciliation is not a stop
                    except Busy:
                        log("busy", why="a migration run holds the run slot")
                    except Exception as e:
                        log("cycle_failed", error=type(e).__name__, where=_where(e))
                        self.ctx = None
                while not stop["now"] and time.time() - t0 < poll:
                    time.sleep(0.5)
            log("stopped")
            return 0
        finally:
            for sig, handler in old.items():
                signal.signal(sig, handler)
            self.release_lock()


def _same(cur, prev):
    pm = prev["max_modified"]
    return (int(cur["row_count"]) == int(prev["row_count"]) and int(cur["max_id"]) == int(prev["max_id"] or 0)
            and _signed(cur["checksum"]) == int(prev["checksum"])
            and (cur["max_modified"] == pm or (cur["max_modified"] is None and pm is None)))


def _signed(c):
    """BIT_XOR of CRC32 values fits in 32 bits unsigned; stored in a bigint as is."""
    return int(c or 0)


def _compare(before, after):
    changed = {}
    for t in before:
        b, a = before[t], after.get(t) or {}
        if b.get("checksum") == a.get("checksum") and b.get("rows") == a.get("rows"):
            continue
        changed[t] = {"before": b, "after": a}
        if b.get("stable") is not None and b.get("stable") == a.get("stable") and b.get("rows") == a.get("rows"):
            changed[t]["only"] = ("only %s changed, which eLabFTW itself stamps when an account or key is used; every "
                                  "other column is identical" % ", ".join(a.get("volatile") or []))
    return {"tables_checked": len(before), "tables_changed_during_run": changed,
            "how": "CHECKSUM TABLE and COUNT(*) on every 2.x table before and after, read-only; the migration's "
                   "2.x account holds SELECT only and its session is READ ONLY"}


def _code(e):
    a = e.args[0] if e.args else None
    return a.get("C") if isinstance(a, dict) else type(e).__name__


def _constraint(e):
    a = e.args[0] if e.args else None
    return a.get("n") if isinstance(a, dict) else None


def _where(e):
    tb = e.__traceback__
    while tb is not None and tb.tb_next is not None:
        tb = tb.tb_next
    return "%s:%s" % (os.path.basename(tb.tb_frame.f_code.co_filename), tb.tb_lineno) if tb else None
