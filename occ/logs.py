# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Logging: one JSON object per line, to standard error (the journal under systemd).

A request line carries the request id, method, route template, status, duration, user id and team.
It never carries a request body, a query string, a header, a passphrase, a key or a cookie: the
only things passed in are the named fields below, so there is no path for one to arrive.
"""
import json
import logging
import sys
import time

_ALLOWED = ("request_id", "method", "route", "status", "duration_ms", "user_id", "team", "event", "detail")


class JsonFormatter(logging.Formatter):
    def format(self, record):
        out = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
               "level": record.levelname.lower(), "logger": record.name}
        fields = getattr(record, "occ", None) or {}
        for k in _ALLOWED:
            if k in fields and fields[k] is not None:
                out[k] = fields[k]
        if not fields:
            out["message"] = record.getMessage()
        if record.exc_info:
            # The exception's type and the place it was raised; never its arguments, which may
            # carry values from a request.
            et = record.exc_info[0]
            tb = record.exc_info[2]
            while tb is not None and tb.tb_next is not None:
                tb = tb.tb_next
            out["error"] = et.__name__ if et else "error"
            if tb is not None:
                out["where"] = "%s:%d" % (tb.tb_frame.f_code.co_filename.rsplit("/occ/", 1)[-1], tb.tb_lineno)
        return json.dumps(out, separators=(",", ":"))


def setup(level="INFO"):
    root = logging.getLogger("occ")
    root.setLevel(level)
    if not any(isinstance(h.formatter, JsonFormatter) for h in root.handlers):
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(JsonFormatter())
        root.addHandler(h)
    root.propagate = False
    return root


def request_line(**fields):
    logging.getLogger("occ.request").info("request", extra={"occ": fields})
