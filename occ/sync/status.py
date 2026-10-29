# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Sync status and direction: occ.sync_settings, one row.

The direction is one setting: off, A (2.x to 3.x) or B (3.x to 2.x). Nothing that means both
directions is accepted, because a two-way sync could lose edits: the database constraint allows only the three values, and this
module refuses anything else before it gets there. 'engine' names the engine that is built
(phase A, one way 2.x to 3.x) and 'last_cycle' says when occ-sync last looked at 2.x, so the
status never implies a sync is running when the process is stopped.

The delay ('lag_p95_s', 'lag_max_s') counts only changes made while the sync was running. Changes
the first cycle after a stop carried are catch-up (occ.sync_lag.catch_up): they are reported with
the stop they followed ('stops_24h', 'last_stop'), against their own limit ('catch_up_target_s').
"""
from .. import errors, timefmt
from ..audit import writer as audit

DIRECTIONS = ("off", "A", "B")
ENGINE = "phase A"


def _sysadmin(p):
    if not p.is_sysadmin:
        raise errors.forbidden("Only a sysadmin can do that.")


def status(tx, p):
    _sysadmin(p)
    s = tx.one("SELECT direction, enabled, poll_seconds, lag_target_s, source_label, updated_at FROM occ.sync_settings "
               "WHERE id = 1")
    last = tx.one("SELECT id, direction, mode, trigger, state, started_at, finished_at FROM occ.sync_runs "
                  "ORDER BY id DESC LIMIT 1")
    s = dict(s)
    s["catch_up_target_s"] = tx.val("SELECT catch_up_target_s FROM occ.sync_settings WHERE id = 1")
    lag = _lag(tx)
    stops = _stops(tx)
    last_cycle = tx.val("SELECT taken_at FROM occ.sync_fingerprints WHERE source_table = '(cycle)' AND scope_key = '*'")
    pending = tx.val("SELECT count(*) FROM occ.jobs WHERE kind IN ('sync', 'reconcile') AND state IN ('queued', 'running')")
    return {"direction": s["direction"], "enabled": 1 if s["enabled"] else 0,
            "last_run": None if last is None else {
                "id": last["id"], "direction": last["direction"], "mode": last["mode"], "trigger": last["trigger"],
                "state": last["state"], "started_at": timefmt.out(last["started_at"]),
                "finished_at": timefmt.out(last["finished_at"])},
            "lag_p95_s": lag["p95"], "lag_max_s": lag["max"], "lag_changes_24h": lag["n"],
            "pending": int(pending or 0),
            "poll_seconds": s["poll_seconds"], "lag_target_s": s["lag_target_s"], "source": s["source_label"],
            "catch_up_target_s": s["catch_up_target_s"], "stops_24h": stops["n"], "last_stop": stops["last"],
            "engine": ENGINE, "last_cycle": timefmt.out(last_cycle)}


def _lag(tx):
    """The delay over the last 24 hours, catch-up after a stop left out."""
    r = tx.one("SELECT count(*) AS n, percentile_cont(0.95) WITHIN GROUP (ORDER BY lag_seconds) AS p95, "
               "max(lag_seconds) AS mx FROM occ.sync_lag WHERE applied_at > now() - interval '24 hours' "
               "AND NOT catch_up")
    return {"n": int(r["n"] or 0), "p95": float(r["p95"]) if r["p95"] is not None else None,
            "max": float(r["mx"]) if r["mx"] is not None else None}


def _stops(tx):
    """The stops the sync resumed from in the last 24 hours, and the latest one."""
    n = tx.val("SELECT count(*) FROM occ.sync_stops WHERE resumed_at > now() - interval '24 hours'")
    r = tx.one("SELECT stopped_at, resumed_at, caught_up_at, changes, catch_up_s FROM occ.sync_stops "
               "ORDER BY resumed_at DESC LIMIT 1")
    last = None if r is None else {
        "stopped_at": timefmt.out(r["stopped_at"]), "resumed_at": timefmt.out(r["resumed_at"]),
        "caught_up_at": timefmt.out(r["caught_up_at"]),
        "stopped_s": round((r["resumed_at"] - r["stopped_at"]).total_seconds(), 2),
        "changes": int(r["changes"]), "catch_up_s": float(r["catch_up_s"])}
    return {"n": int(n or 0), "last": last}


def metrics_text(tx):
    """Prometheus lines for /metrics: the sync delay over the last 24 hours (catch-up after a stop
    left out), the stops and the latest catch-up, and how long ago occ-sync last looked at 2.x
    (absent until it has run)."""
    r = _lag(tx)
    stops = _stops(tx)
    age = tx.val("SELECT extract(epoch FROM now() - taken_at) FROM occ.sync_fingerprints "
                 "WHERE source_table = '(cycle)' AND scope_key = '*'")
    text = "# TYPE occ_sync_changes_24h gauge\nocc_sync_changes_24h %d\n" % r["n"]
    if r["n"]:
        text += ("# TYPE occ_sync_lag_seconds gauge\n"
                 'occ_sync_lag_seconds{quantile="0.95"} %.2f\nocc_sync_lag_seconds{quantile="1"} %.2f\n'
                 % (r["p95"], r["max"]))
    text += "# TYPE occ_sync_stops_24h gauge\nocc_sync_stops_24h %d\n" % stops["n"]
    if stops["last"]:
        text += ("# TYPE occ_sync_last_catch_up_seconds gauge\nocc_sync_last_catch_up_seconds %.2f\n"
                 % stops["last"]["catch_up_s"])
    if age is not None:
        text += "# TYPE occ_sync_last_cycle_age_seconds gauge\nocc_sync_last_cycle_age_seconds %.1f\n" % float(age)
    return text


def _flag(v):
    t = str(v).strip().lower()
    if t in ("1", "true"):
        return True
    if t in ("0", "false"):
        return False
    raise errors.bad("Incorrect value for enabled: 0 or 1")


def set_direction(tx, p, actor, body):
    _sysadmin(p)
    if not p.can_write:
        raise errors.forbidden("This API key is read-only.")
    body = body if isinstance(body, dict) else {}
    if "direction" not in body and "enabled" not in body:
        raise errors.bad("Nothing to change: send direction and/or enabled")
    cur = tx.one("SELECT direction, enabled FROM occ.sync_settings WHERE id = 1 FOR UPDATE")
    direction = cur["direction"]
    if "direction" in body:
        direction = str(body["direction"]).strip()
        if direction not in DIRECTIONS:
            raise errors.bad("Incorrect value for direction: off, A (2.x to 3.x) or B (3.x to 2.x)",
                             "The sync runs one way only; it never runs in both directions.")
    enabled = _flag(body["enabled"]) if "enabled" in body else bool(cur["enabled"])
    if direction == "off":
        enabled = False if "enabled" not in body else enabled
    if enabled and direction == "off":
        raise errors.bad("Incorrect value for enabled: set a direction (A or B) first")
    for target, old, new in (("sync.direction", cur["direction"], direction),
                             ("sync.enabled", bool(cur["enabled"]), enabled)):
        if old != new:
            audit.write(tx, actor, "config.update", target=target, old=old, new=new)
    tx.run("UPDATE occ.sync_settings SET direction = :d, enabled = :e, updated_at = now(), updated_by = :u WHERE id = 1",
           d=direction, e=enabled, u=p.user_id)
    return status(tx, p)
