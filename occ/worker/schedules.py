# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Schedules: rows in occ.job_schedules, each turning into a job when due.

Times in a schedule are wall-clock times in the site time zone (OCC_TIMEZONE), so "02:30
nightly" is 02:30 where the laboratory is, and follows daylight saving. The cron subset is the five classic
fields, minute hour day-of-month month day-of-week (0 or 7 = Sunday), each '*', '*/n', a number,
a range a-b (optionally /n) or a comma list of those.

tick() takes the due schedule rows with FOR UPDATE SKIP LOCKED, queues one job each with the
dedupe key 'schedule:<name>' and moves next_run_at on in the same transaction, so two workers
never queue the same run twice, and a run still waiting is not queued again.
"""
import datetime as dt

from .. import timefmt
from . import jobs

# name, cron, job kind. Exports run on demand (queued by an export request), not on a schedule.
SCHEDULES = (
    ("notify-email", "* * * * *", "notify-email"),
    ("step-deadlines", "*/5 * * * *", "step-deadlines"),
    ("outbox", "* * * * *", "outbox"),
    ("sessions-cleanup", "0 * * * *", "sessions-cleanup"),
    ("revisions-prune", "10 2 * * *", "revisions-prune"),
    ("audit-verify", "30 2 * * *", "audit-verify"),
    ("blob-verify", "0 3 * * 0", "blob-verify"),
    ("idp-refresh", "0 4 * * *", "idp-refresh"),
    ("files-sweep", "30 3 * * 0", "files-sweep"),         # weekly, after blob-verify has run
)

_RANGES = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))


class CronError(ValueError):
    pass


def _field(text, lo, hi):
    out = set()
    for part in text.split(","):
        step = 1
        if "/" in part:
            part, s = part.split("/", 1)
            if not s.isdigit() or int(s) < 1:
                raise CronError("bad step %r" % s)
            step = int(s)
        if part == "*":
            a, b = lo, hi
        elif "-" in part:
            x, y = part.split("-", 1)
            if not (x.isdigit() and y.isdigit()):
                raise CronError("bad range %r" % part)
            a, b = int(x), int(y)
        elif part.isdigit():
            a = b = int(part)
            if step != 1:
                b = hi
        else:
            raise CronError("bad field %r" % part)
        if a < lo or b > hi or a > b:
            raise CronError("%r is outside %d-%d" % (part, lo, hi))
        out.update(range(a, b + 1, step))
    return frozenset(out)


def parse(cron):
    parts = str(cron).split()
    if len(parts) != 5:
        raise CronError("a schedule has five fields: minute hour day month weekday")
    f = [_field(p, lo, hi) for p, (lo, hi) in zip(parts, _RANGES)]
    dow = frozenset(0 if d == 7 else d for d in f[4])
    # Classic cron: when both day fields are restricted, either one matching is enough.
    return {"min": f[0], "hour": f[1], "dom": f[2], "mon": f[3], "dow": dow,
            "dom_any": parts[2] == "*", "dow_any": parts[4] == "*"}


def _day_ok(c, d):
    dom_ok = d.day in c["dom"]
    dow_ok = (d.isoweekday() % 7) in c["dow"]
    if c["dom_any"] and c["dow_any"]:
        return True
    if c["dom_any"]:
        return dow_ok
    if c["dow_any"]:
        return dom_ok
    return dom_ok or dow_ok


def next_after(cron, after, zone=None):
    """The first matching minute strictly after `after` (aware), as an aware UTC datetime."""
    c = parse(cron)
    zone = zone or timefmt.zone()
    t = after.astimezone(zone).replace(second=0, microsecond=0) + dt.timedelta(minutes=1)
    limit = t + dt.timedelta(days=366 * 5)
    while t < limit:
        if t.month not in c["mon"] or not _day_ok(c, t):
            t = (t + dt.timedelta(days=1)).replace(hour=0, minute=0)
            continue
        if t.hour not in c["hour"]:
            t = (t + dt.timedelta(hours=1)).replace(minute=0)
            continue
        if t.minute not in c["min"]:
            t += dt.timedelta(minutes=1)
            continue
        # Normalize through UTC so a wall time that does not exist (spring forward) still moves on.
        return t.astimezone(dt.timezone.utc)
    raise CronError("the schedule %r never matches" % cron)


def seed(tx, now=None):
    """Add the schedules this build knows; an existing row (and its enabled flag) is left alone."""
    now = now or jobs.utcnow()
    added = 0
    for name, cron, kind in SCHEDULES:
        added += tx.run("INSERT INTO occ.job_schedules (name, cron, job_kind, next_run_at) VALUES (:n, :c, :k, :t) "
                        "ON CONFLICT (name) DO NOTHING", n=name, c=cron, k=kind, t=next_after(cron, now))
    return added


def tick(tx, now=None):
    """Queue every due schedule's job. Returns [(schedule name, job id)]."""
    now = now or jobs.utcnow()
    due = tx.all("SELECT name, cron, job_kind FROM occ.job_schedules WHERE enabled AND next_run_at <= :now "
                 "ORDER BY next_run_at FOR UPDATE SKIP LOCKED", now=now)
    out = []
    for s in due:
        jid = jobs.enqueue(tx, s["job_kind"], {"schedule": s["name"]}, dedupe_key="schedule:" + s["name"])
        tx.run("UPDATE occ.job_schedules SET last_run_at = :now, next_run_at = :nx, last_job_id = :j WHERE name = :n",
               now=now, nx=next_after(s["cron"], now), j=jid, n=s["name"])
        out.append((s["name"], jid))
    return out
