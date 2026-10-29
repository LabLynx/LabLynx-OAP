# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Rate limits: per API key or session, in each worker process.

Two limits apply together to one caller:
    burst      at most `burst` requests in any one-second window (60): the 61st in a second answers 429
    sustained  a token bucket refilled at `sustained` per second (20) holding at most `burst` tokens,
               so a caller may burst to 60 and then keeps 20 a second
File downloads (/app/download.php, and uploads read with format=binary) have their own window of
200 a second instead. A refused request answers 429 with Retry-After in whole seconds and uses
no allowance. The caller is identified by a SHA-256 of the Authorization header or the session
cookie, never the text itself; a request with neither is counted by client address. Health
routes are not limited.
"""
import hashlib
import math
import threading
import time
from collections import deque

EXEMPT_PATHS = ("/healthz", "/readyz", "/metrics")


class _Caller:
    __slots__ = ("window", "tokens", "stamp", "dl_window", "seen")

    def __init__(self, burst, now):
        self.window = deque()
        self.tokens = float(burst)
        self.stamp = now
        self.dl_window = deque()
        self.seen = now


class Limiter:
    def __init__(self, burst=60, sustained=20, downloads=200, clock=time.monotonic):
        self.burst = int(burst)
        self.sustained = float(sustained)
        self.downloads = int(downloads)
        self.clock = clock
        self._callers = {}
        self._lock = threading.Lock()
        self._last_sweep = clock()
        self.refused = 0

    @property
    def enabled(self):
        return self.burst > 0 and self.sustained > 0

    def check(self, who, download=False):
        """None when allowed (and counted), or the Retry-After seconds when refused."""
        if not self.enabled:
            return None
        now = self.clock()
        with self._lock:
            self._sweep(now)
            c = self._callers.get(who)
            if c is None:
                c = self._callers[who] = _Caller(self.burst, now)
            c.seen = now
            if download:
                return self._window(c.dl_window, self.downloads, now)
            # refill the bucket
            c.tokens = min(float(self.burst), c.tokens + (now - c.stamp) * self.sustained)
            c.stamp = now
            while c.window and c.window[0] <= now - 1.0:
                c.window.popleft()
            wait = 0.0
            if len(c.window) >= self.burst:
                wait = c.window[0] + 1.0 - now
            if c.tokens < 1.0:
                wait = max(wait, (1.0 - c.tokens) / self.sustained)
            if wait > 0:
                self.refused += 1
                return max(1, int(math.ceil(wait)))
            c.tokens -= 1.0
            c.window.append(now)
            return None

    def _window(self, window, limit, now):
        while window and window[0] <= now - 1.0:
            window.popleft()
        if len(window) >= limit:
            self.refused += 1
            return max(1, int(math.ceil(window[0] + 1.0 - now)))
        window.append(now)
        return None

    def _sweep(self, now):
        if now - self._last_sweep < 60:
            return
        self._last_sweep = now
        for k in [k for k, c in self._callers.items() if now - c.seen > 120]:
            del self._callers[k]


def caller_id(request, cookie_name):
    auth = request.headers.get("authorization")
    if auth:
        return "k:" + hashlib.sha256(auth.strip().encode("utf-8", "replace")).hexdigest()
    cookie = request.cookies.get(cookie_name)
    if cookie:
        return "s:" + hashlib.sha256(cookie.encode("utf-8", "replace")).hexdigest()
    host = request.client.host if request.client else "unknown"
    return "a:" + host


def is_download(request):
    path = request.url.path
    return path.endswith("/app/download.php") or (
        "/uploads/" in path and request.method == "GET" and request.query_params.get("format") == "binary")
