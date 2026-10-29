# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Times: stored UTC, written 'YYYY-MM-DD HH:MM:SS' in the site time zone (as 2.x writes
them), read as that or as ISO 8601 (2.x refuses ISO 8601 with a 'T'; the OCC accepts both)."""
import datetime as dt
import re
from zoneinfo import ZoneInfo

_tz = {"zone": ZoneInfo("America/Chicago")}


def set_zone(name):
    _tz["zone"] = ZoneInfo(name)


def zone():
    return _tz["zone"]


def out(value):
    if value is None:
        return None
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=dt.timezone.utc)
        return value.astimezone(_tz["zone"]).strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(value, dt.date):
        return value.strftime("%Y-%m-%d")
    return str(value)


def today():
    return dt.datetime.now(_tz["zone"]).date()


_DATE = re.compile(r"^(\d{4})-?(\d{2})-?(\d{2})$")


def parse_date(text):
    """'YYYY-MM-DD' or 'YYYYMMDD' -> date; raises ValueError on anything else, so a
    bad date is a 400, not a 500 as in 2.x."""
    m = _DATE.match(str(text).strip())
    if not m:
        raise ValueError("not a date")
    return dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))


def parse_datetime(text):
    """'YYYY-MM-DD HH:MM:SS' (site time) or ISO 8601 -> aware datetime."""
    s = str(text).strip()
    try:
        v = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("not a date and time")
    if v.tzinfo is None:
        v = v.replace(tzinfo=_tz["zone"])
    return v
