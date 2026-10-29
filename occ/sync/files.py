# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Reading 2.x file bytes, read only.

Two sources, tried in order:

  dir   eLabFTW's upload directory, opened read-only (OCC_SOURCE_UPLOADS_DIR). The path is the
        upload's long_name under that directory. This is the preferred source; the account that
        runs the sync needs read-only access to it.
  api   eLabFTW's API download (GET .../{type}/{id}/uploads/{upload id}?format=binary) with a
        read-only use of a key (OCC_SOURCE_API_BASE, OCC_SOURCE_API_KEY_ENV naming
        the variable that holds the key). Only GETs. An eLabFTW key reads only records its team
        may read, so this carries what that key can see and reports the rest.

A file that cannot be read is skipped with the reason and listed in the report; nothing is
invented. The key is never logged or written anywhere.
"""
import os
import urllib.error
import urllib.request


class Files:
    def __init__(self, store, source_dir=None, api_base=None, api_key=None, max_bytes=200 * 1024 * 1024):
        self.store = store
        self.source_dir = source_dir
        self.api_base = (api_base or "").rstrip("/") or None
        self._key = api_key
        self.max_bytes = max_bytes
        self.api_team = None
        self.api_calls = 0
        self._probed = False

    @classmethod
    def from_env(cls, store, use_api=True):
        d = os.environ.get("OCC_SOURCE_UPLOADS_DIR") or None
        # no built-in fallback: the API source is used only when the settings name it
        base = os.environ.get("OCC_SOURCE_API_BASE") if use_api else None
        key_var = os.environ.get("OCC_SOURCE_API_KEY_ENV")
        key = os.environ.get(key_var) if use_api and key_var else None
        return cls(store, source_dir=d if d and os.path.isdir(d) else None, api_base=base, api_key=key)

    def describe(self):
        return {"dir": bool(self.source_dir), "api": bool(self.api_base and self._key), "api_team": self.api_team,
                "api_calls": self.api_calls}

    def _get(self, path):
        req = urllib.request.Request(self.api_base + path, headers={"Authorization": self._key}, method="GET")
        self.api_calls += 1
        return urllib.request.urlopen(req, timeout=60)

    def _probe(self):
        """Which team the key belongs to: only that team's records are worth asking for."""
        self._probed = True
        if not (self.api_base and self._key):
            return
        try:
            import json
            with self._get("/users/me") as r:
                me = json.loads(r.read().decode("utf-8"))
            self.api_team = int(me.get("team")) if me.get("team") is not None else None
        except Exception:
            self.api_team = None

    def fetch(self, tx, rid, f, values):
        """(bytes, None) or (None, reason)."""
        if self.source_dir:
            path = os.path.realpath(os.path.join(self.source_dir, f["long_name"]))
            if os.path.commonpath([path, os.path.realpath(self.source_dir)]) != os.path.realpath(self.source_dir):
                return None, "its stored name points outside the upload directory"
            try:
                with open(path, "rb") as fh:
                    data = fh.read(self.max_bytes + 1)
                if len(data) > self.max_bytes:
                    return None, "larger than the migration's per-file limit"
                return data, None
            except OSError:
                pass
        if not (self.api_base and self._key):
            return None, "file bytes not readable: no read-only access to the 2.x upload directory (Dev/Ops)"
        if not self._probed:
            self._probe()
        rec = tx.one("SELECT team_id, canread_base FROM occ.records WHERE rid = :r", r=rid)
        if rec is None:
            return None, "its record is not in the OCC"
        if self.api_team is not None and rec["team_id"] != self.api_team and rec["canread_base"] < 40:
            return None, ("file bytes not readable: the eLabFTW key reads team %s only, and no read-only access to "
                          "the 2.x upload directory (Dev/Ops)" % self.api_team)
        try:
            with self._get("/%s/%d/uploads/%d?format=binary" % (f["type"], int(f["record_id"]), int(values["id"]))) as r:
                data = r.read(self.max_bytes + 1)
            if len(data) > self.max_bytes:
                return None, "larger than the migration's per-file limit"
            return data, None
        except urllib.error.HTTPError as e:
            return None, "file bytes not readable through the eLabFTW API (HTTP %d)" % e.code
        except Exception as e:
            return None, "file bytes not readable through the eLabFTW API (%s)" % type(e).__name__
