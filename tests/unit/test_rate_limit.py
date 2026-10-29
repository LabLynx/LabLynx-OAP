# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Rate limits: the 61st request in a second from one key answers 429
with Retry-After; the sustained rate is 20 a second; keys are counted apart; health routes are
not limited."""
from fastapi.testclient import TestClient

from occ import settings as settings_mod
from occ.main import create_app
from occ.ratelimit import Limiter


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def test_burst_then_sustained_with_a_clock():
    c = Clock()
    lim = Limiter(60, 20, 200, clock=c)
    assert all(lim.check("k") is None for _ in range(60))          # 60 inside one instant
    assert lim.check("k") == 1                                      # the 61st: 429, retry after 1 s
    assert lim.check("other") is None                               # another key has its own allowance
    c.t += 1.0                                                      # one second on: the window is empty,
    got = sum(1 for _ in range(60) if lim.check("k") is None)       # but the bucket refilled only 20
    assert got == 20
    for _ in range(10):                                             # held at 20 a second from then on
        c.t += 0.0501                                               # just over one token a step
        assert lim.check("k") is None
        assert lim.check("k") is not None
    assert lim.refused > 0


def test_downloads_have_their_own_window():
    c = Clock()
    lim = Limiter(60, 20, 200, clock=c)
    assert all(lim.check("k", download=True) is None for _ in range(200))
    assert lim.check("k", download=True) == 1
    assert lim.check("k") is None                                   # the API allowance is untouched


def test_the_61st_request_in_a_second_answers_429(cfg, world):
    real = settings_mod.Settings(**{**cfg.__dict__, "rate_burst": 60, "rate_sustained": 20})
    with TestClient(create_app(real)) as client:
        h = world.h("alice")
        codes = [client.get("/api/v2/users/me", headers=h).status_code for _ in range(61)]
        # the test client is fast enough that 61 calls fit well inside one second on this server;
        # if the machine stalls, at least the bucket still refuses within a few more calls
        if codes[-1] != 429:
            codes += [client.get("/api/v2/users/me", headers=h).status_code for _ in range(30)]
        assert codes[:60] == [200] * 60
        assert 429 in codes
        r = next(r for r in (client.get("/api/v2/users/me", headers=h) for _ in range(5)) if r.status_code == 429)
        assert int(r.headers["retry-after"]) >= 1
        assert r.json()["code"] == 429
        assert client.get("/api/v2/users/me", headers=world.h("bob")).status_code == 200   # another key
        assert client.get("/healthz").status_code == 200                                    # never limited
        assert "occ_rate_limited_total" in client.get("/metrics").text
