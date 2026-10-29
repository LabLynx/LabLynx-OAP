# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Shared fixtures: one scratch database per test FILE (occ_scratch_t<pid>_<n>), built from the
migrations and dropped when the file finishes whatever happens, so no run leaves a database
behind and no file sees another file's site settings, rows or audit ids; an API key pepper and
file root in a
temporary folder; a small world of people and teams made through the OCC's own code."""
import itertools
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
OCC_ROOT = os.path.dirname(HERE)
if OCC_ROOT not in sys.path:
    sys.path.insert(0, OCC_ROOT)
os.environ["OCC_NO_AUTOAPP"] = "1"

from occ import db, settings as settings_mod  # noqa: E402
from occ.auth import apikeys  # noqa: E402
from occ.db import scratch  # noqa: E402


@pytest.fixture(scope="session")
def base_params():
    return settings_mod.load(env_file="/nonexistent").db_params()


_FILE_NO = itertools.count(1)


@pytest.fixture(scope="module")
def scratchdb(base_params):
    with scratch.scratch(base_params, suffix="t%d_%d" % (os.getpid(), next(_FILE_NO))) as name:
        yield name


@pytest.fixture(scope="module")
def cfg(scratchdb, tmp_path_factory):
    t = tmp_path_factory.mktemp("occ")
    c = settings_mod.Settings(database_url="postgresql:///%s" % scratchdb, api_key_pepper_file=str(t / "pepper"),
                              files_root=str(t / "files"), base_url="http://testserver", timezone="America/Chicago",
                              pool_size=4, rate_burst=0)
    apikeys.make_pepper_file(c.api_key_pepper_file)
    return c


@pytest.fixture(scope="module")
def pool(cfg):
    p = db.Pool(cfg.db_params(), size=4)
    yield p
    p.close()


class World:
    """Teams A and B; in A an admin, two members and a group; in B one member; one outsider with
    no team; one sysadmin. Keys for each, read-write unless named ro."""

    def __init__(self, cfg, pool):
        pepper = apikeys.read_pepper(cfg.api_key_pepper_file)
        self.keys, self.users, self.teams = {}, {}, {}
        with pool.tx() as tx:
            for name in ("A", "B", "C"):
                self.teams[name] = tx.val("INSERT INTO occ.teams (name) VALUES (:n) RETURNING id", n="Team " + name)
            people = (("sys", "C", False, True), ("admin", "A", True, False), ("alice", "A", False, False),
                      ("bob", "A", False, False), ("bea", "B", False, False), ("out", "C", False, False))
            for (who, team, admin, sysadmin) in people:
                uid = tx.val("INSERT INTO occ.users (email, firstname, lastname, validated, is_sysadmin) "
                             "VALUES (:e, :f, 'Test', true, :s) RETURNING id", e=who + "@example.com", f=who.title(),
                             s=sysadmin)
                self.users[who] = uid
                tx.run("INSERT INTO occ.memberships (user_id, team_id, is_admin) VALUES (:u, :t, :a)",
                       u=uid, t=self.teams[team], a=admin)
                _kid, key = apikeys.create(tx, pepper, uid, self.teams[team], who, can_write=True)
                self.keys[who] = key
            _kid, self.keys["alice_ro"] = apikeys.create(tx, pepper, self.users["alice"], self.teams["A"], "ro",
                                                         can_write=False)
            _kid, self.keys["sys_site"] = apikeys.create(tx, pepper, self.users["sys"], self.teams["C"], "site",
                                                         can_write=False, site_scope=True)
            self.group = tx.val("INSERT INTO occ.team_groups (team_id, name) VALUES (:t, 'Readers') RETURNING id",
                                t=self.teams["A"])
            tx.run("INSERT INTO occ.team_group_members (group_id, user_id) VALUES (:g, :u)", g=self.group,
                   u=self.users["bob"])
            tx.run("INSERT INTO occ.site_config (name, value) VALUES ('read_only', '0'), ('min_delta_revisions', '10')")

    def h(self, who):
        return {"Authorization": self.keys[who]}


@pytest.fixture(scope="module")
def world(cfg, pool):
    return World(cfg, pool)


@pytest.fixture(scope="module")
def client(cfg, world):
    from fastapi.testclient import TestClient
    from occ.main import create_app
    with TestClient(create_app(cfg)) as c:
        yield c
