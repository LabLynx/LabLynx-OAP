# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The occ-worker loop: one process, one job at a time.

    occ worker               run until SIGTERM or SIGINT; the job in hand finishes first
    occ worker --once        queue what is due, run every job that is due now, then stop
    occ worker --seconds N   stop after about N seconds (checks)

Each pass: seed any schedule this build adds, queue due schedules, run due jobs until none is
left, then sleep IDLE_S. The handler modules are imported here so their kinds are registered.
"""
import importlib
import logging
import os
import signal
import socket
import time
from dataclasses import dataclass

from .. import db, logs, timefmt
from ..files import store as store_mod
from . import jobs, schedules

IDLE_S = 2.0
# Modules whose @jobs.register calls this worker needs. A module that is not in this build yet is
# skipped (and its jobs fail as 'no handler' until it is).
HANDLER_MODULES = ("occ.worker.handlers", "occ.exports.jobs")


@dataclass
class WorkerCtx:
    pool: object
    settings: object
    store: object
    log: object


def load_handlers():
    loaded = []
    for name in HANDLER_MODULES:
        try:
            importlib.import_module(name)
            loaded.append(name)
        except ModuleNotFoundError as e:
            if e.name is None or not name.startswith(e.name):
                raise
    return loaded


def make_ctx(cfg, pool=None):
    log = logging.getLogger("occ.worker")
    return WorkerCtx(pool=pool or db.Pool(cfg.db_params(), size=2), settings=cfg,
                     store=store_mod.for_settings(cfg), log=log)


def run_pass(ctx, worker_id, max_jobs=1000, kinds=None):
    """Queue due schedules and run every job that is due (of `kinds` only, when given).
    Returns {queued, ran: [(id, outcome)]}."""
    with ctx.pool.tx() as tx:
        schedules.seed(tx)
        queued = schedules.tick(tx)
    ran = []
    while len(ran) < max_jobs:
        r = jobs.run_one(ctx, worker_id, kinds)
        if r is None:
            break
        ran.append(r)
    return {"queued": queued, "ran": ran}


def run(cfg, once=False, seconds=None):
    timefmt.set_zone(cfg.timezone)
    logs.setup(cfg.log_level)
    load_handlers()
    ctx = make_ctx(cfg)
    worker_id = "%s:%d" % (socket.gethostname(), os.getpid())
    stop = {"now": False}

    def _stop(signum, frame):
        stop["now"] = True
    before = {s: signal.signal(s, _stop) for s in (signal.SIGTERM, signal.SIGINT)}
    t_end = time.monotonic() + seconds if seconds else None
    ctx.log.info("worker started", extra={"occ": {"event": "worker started", "detail": {"worker": worker_id}}})
    try:
        while True:
            run_pass(ctx, worker_id)
            if once or stop["now"] or (t_end and time.monotonic() >= t_end):
                break
            slept = 0.0
            while slept < IDLE_S and not stop["now"]:
                time.sleep(0.2)
                slept += 0.2
            if stop["now"]:
                break
    finally:
        for s, h in before.items():
            signal.signal(s, h)
        ctx.pool.close()
        ctx.log.info("worker stopped", extra={"occ": {"event": "worker stopped", "detail": {"worker": worker_id}}})
    return 0
