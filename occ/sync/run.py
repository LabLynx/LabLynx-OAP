# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The migration tool and the occ-sync process.

    python -m occ.sync.run [run]          the occ-sync service: a cycle every poll_seconds while
                                          occ.sync_settings says direction A and enabled
         run --force --max-seconds N      cycle regardless of the setting, for N seconds (checks)
    python -m occ.sync.run migrate        the full 2.x to 3.x migration, then reconciliation
         --floor                          leave 3.x-only ids at 10,000,000 and up (demo sync phase A)
    python -m occ.sync.run once           one sync cycle
    python -m occ.sync.run reconcile      the reconciliation alone
    python -m occ.sync.run enable|disable direction A on or off (occ.sync_settings), audited
    python -m occ.sync.run lag [--since ISO]  lag statistics from occ.sync_lag

Common options: --database NAME (another database on the same socket, e.g. a scratch one),
--report PATH (also write the report there), --files-root PATH, --no-api-files (do not use the
eLabFTW API for file bytes). 2.x is read with the read-only credentials only (source.py).
"""
import argparse
import json
import os
import sys

from .. import db, settings as settings_mod
from ..audit import writer as audit
from ..files import store as store_mod
from . import engine as E, source as S
from .files import Files


def _cfg(args):
    cfg = settings_mod.load()
    if args.database:
        cfg.database_url = "postgresql:///%s" % args.database
    if args.files_root:
        cfg.files_root = args.files_root
    return cfg


def _write(path, rep):
    if path:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(rep, fh, indent=1, default=str, ensure_ascii=False)


def _set(cfg, enabled):
    pool = db.Pool(cfg.db_params(), size=1)
    try:
        with pool.tx() as tx:
            cur = tx.one("SELECT direction, enabled FROM occ.sync_settings WHERE id = 1 FOR UPDATE")
            direction = "A" if enabled else cur["direction"]
            actor = audit.Actor(kind="sync")
            if cur["direction"] != direction:
                audit.write(tx, actor, "config.update", target="sync.direction", old=cur["direction"], new=direction)
            if bool(cur["enabled"]) != enabled:
                audit.write(tx, actor, "config.update", target="sync.enabled", old=bool(cur["enabled"]), new=enabled)
            tx.run("UPDATE occ.sync_settings SET direction = :d, enabled = :e, updated_at = now() WHERE id = 1",
                   d=direction, e=enabled)
            return {"direction": direction, "enabled": enabled}
    finally:
        pool.close()


def lag_stats(cfg, since=None):
    pool = db.Pool(cfg.db_params(), size=1)
    try:
        with pool.tx(readonly=True) as tx:
            # the delay target counts changes made while the sync ran; catch-up after a stop is
            # reported with the stops, against its own limit
            r = tx.one("SELECT count(*) AS n, percentile_cont(0.95) WITHIN GROUP (ORDER BY lag_seconds) AS p95, "
                       "max(lag_seconds) AS max, min(lag_seconds) AS min, avg(lag_seconds) AS avg, "
                       "count(*) FILTER (WHERE lag_seconds <= 60) AS within60, "
                       "count(*) FILTER (WHERE lag_seconds > 120) AS over120 FROM occ.sync_lag "
                       "WHERE applied_at >= coalesce(CAST(:s AS timestamptz), '-infinity') AND NOT catch_up", s=since)
            rows = tx.all("SELECT source_table, source_id, source_changed, detected_at, applied_at, lag_seconds, "
                          "catch_up FROM occ.sync_lag WHERE applied_at >= coalesce(CAST(:s AS timestamptz), "
                          "'-infinity') ORDER BY id", s=since)
            stops = tx.all("SELECT stopped_at, resumed_at, caught_up_at, changes, catch_up_s FROM occ.sync_stops "
                           "WHERE resumed_at >= coalesce(CAST(:s AS timestamptz), '-infinity') ORDER BY id", s=since)
            target = tx.val("SELECT catch_up_target_s FROM occ.sync_settings WHERE id = 1")
        stats = {k: (float(v) if v is not None and k not in ("n", "within60", "over120") else v) for k, v in r.items()}
        stats["stops"] = len(stops)
        stats["catch_up_target_s"] = target
        stats["catch_up_over_target"] = sum(1 for x in stops if float(x["catch_up_s"]) > target)
        return stats, rows + [dict(x, stop=True) for x in stops]
    finally:
        pool.close()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="occ-sync")
    ap.add_argument("--database")
    ap.add_argument("--files-root")
    ap.add_argument("--report")
    ap.add_argument("--no-api-files", action="store_true")
    ap.add_argument("cmd", nargs="?", default="run",
                    choices=("run", "migrate", "once", "reconcile", "enable", "disable", "lag"))
    ap.add_argument("--floor", action="store_true")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--max-seconds", type=float)
    ap.add_argument("--reconcile-every", type=int, default=3600)
    ap.add_argument("--since")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)
    cfg = _cfg(args)

    if args.cmd in ("enable", "disable"):
        print(json.dumps(_set(cfg, args.cmd == "enable")))
        return 0
    if args.cmd == "lag":
        stats, rows = lag_stats(cfg, args.since)
        print(json.dumps({"stats": stats, "rows": rows}, indent=1, default=str))
        return 0

    source = S.Source().open()
    store = store_mod.for_settings(cfg)
    files = Files.from_env(store, use_api=not args.no_api_files)
    floor = None
    eng = E.Engine(cfg, source, files, quiet=args.quiet)
    with eng.pool.tx(readonly=True) as tx:
        s = tx.one("SELECT local_id_floor, direction FROM occ.sync_settings WHERE id = 1")
    if args.floor or args.cmd in ("run", "once") or s["direction"] == "A":
        floor = int(s["local_id_floor"])
    eng.floor = floor
    try:
        if args.cmd == "migrate":
            rep = eng.migrate_full()
            _write(args.report, rep)
            rec = rep["result"]["reconciliation"]
            print(json.dumps({"run": rep["run"]["id"], "duration_s": rep["run"]["duration_s"],
                              "total_writes": rep["total_writes"], "reconciled": rec["ok"],
                              "differences": rec.get("difference_count"), "result_sha256": rep["result_sha256"],
                              "report_sha256": rep.get("report_sha256"),
                              "source_tables_changed_during_run":
                                  sorted(rep["source_unchanged"]["tables_changed_during_run"])}, indent=1, default=str))
            return 0 if rec["ok"] else 1
        if args.cmd == "reconcile":
            rep = eng.reconcile_run()
            _write(args.report, rep)
            print(json.dumps({"reconciled": rep["result"]["reconciliation"]["ok"],
                              "result_sha256": rep["result_sha256"]}, indent=1))
            return 0 if rep["result"]["reconciliation"]["ok"] else 1
        if args.cmd == "once":
            print(json.dumps(eng.cycle(), default=str))
            return 0
        eng.ctx = None
        return eng.run_forever(reconcile_every=args.reconcile_every, max_seconds=args.max_seconds, force=args.force)
    except E.Busy as e:
        print(json.dumps({"refused": str(e)}))
        return 2
    finally:
        eng.close()
        source.close()


if __name__ == "__main__":
    sys.exit(main())
