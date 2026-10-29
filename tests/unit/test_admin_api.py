# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Teams, groups, team tags, users, the person's own lists, sessions and the write policy:
administering teams, groups and users, API keys, to-do lists, favorite tags, notifications, signature
keys, the audit log read, the session (read, switch team, sign out), history notes and read-only mode."""
import json

from occ.auth import apikeys, sessions


def _id(r):
    assert r.status_code == 201, r.text
    return int(r.headers["location"].rsplit("/", 1)[-1])


def _audit(pool, category, **where):
    with pool.tx() as tx:
        rows = tx.all("SELECT * FROM occ.audit_events WHERE category = :c ORDER BY id", c=category)
    return [r for r in rows if all(r.get(k) == v for k, v in where.items())]


# ------------------------------------------------------------------------------------- teams
def test_team_settings_by_admin_and_name_by_sysadmin_only(client, world, pool):
    A = world.teams["A"]
    r = client.patch("/api/v2/teams/%d" % A, json={"user_create_tag": 0, "announcement": "Hello"},
                     headers=world.h("admin"))
    assert r.status_code == 200 and r.json()["user_create_tag"] == 0 and r.json()["announcement"] == "Hello"
    assert client.get("/api/v2/teams/%d" % A, headers=world.h("alice")).json()["user_create_tag"] == 0
    assert client.patch("/api/v2/teams/%d" % A, json={"user_create_tag": 1}, headers=world.h("alice")).status_code == 403
    assert client.patch("/api/v2/teams/%d" % A, json={"name": "Renamed"}, headers=world.h("admin")).status_code == 403
    assert client.patch("/api/v2/teams/%d" % A, json={"no_such": 1}, headers=world.h("admin")).status_code == 400
    # atomic: one bad field changes nothing
    r = client.patch("/api/v2/teams/%d" % A, json={"announcement": "Changed", "newcomer_threshold": "x"},
                     headers=world.h("admin"))
    assert r.status_code == 400
    assert client.get("/api/v2/teams/%d" % A, headers=world.h("alice")).json()["announcement"] == "Hello"
    assert client.patch("/api/v2/teams/%d" % A, json={"user_create_tag": 1}, headers=world.h("admin")).status_code == 200
    assert _audit(pool, "team.update", team_id=A, target="announcement")


def test_team_delete_is_refused_while_not_empty(client, world):
    tid = _id(client.post("/api/v2/teams", json={"name": "Scratch team for delete"}, headers=world.h("sys")))
    uid = _id(client.post("/api/v2/users", json={"email": "tdel@example.com", "firstname": "T", "lastname": "Del",
                                                 "team": tid}, headers=world.h("sys")))
    r = client.delete("/api/v2/teams/%d" % tid, headers=world.h("sys"))
    assert r.status_code == 400 and r.json()["message"] == "The team is not empty! Aborting deletion!"
    assert client.delete("/api/v2/teams/%d" % tid, headers=world.h("admin")).status_code == 403
    client.patch("/api/v2/users/%d" % uid, json={"action": "add", "team": world.teams["C"]}, headers=world.h("sys"))
    assert client.patch("/api/v2/users/%d" % uid, json={"action": "unreference", "team": tid},
                        headers=world.h("sys")).status_code == 200
    assert client.delete("/api/v2/teams/%d" % tid, headers=world.h("sys")).status_code == 204
    assert all(t["id"] != tid for t in client.get("/api/v2/teams", headers=world.h("sys")).json())


# ------------------------------------------------------------------------------------ groups
def test_groups_create_rename_members_delete(client, world, pool):
    A = world.teams["A"]
    gid = _id(client.post("/api/v2/teams/%d/teamgroups" % A, json={"name": "Probe group"}, headers=world.h("admin")))
    assert client.post("/api/v2/teams/%d/teamgroups" % A, json={"name": "x"}, headers=world.h("alice")).status_code == 403
    r = client.patch("/api/v2/teams/%d/teamgroups/%d" % (A, gid), json={"name": "Probe group 2", "action": "ignored"},
                     headers=world.h("admin"))
    assert r.status_code == 200 and r.json()["name"] == "Probe group 2"
    r = client.patch("/api/v2/teams/%d/teamgroups/%d" % (A, gid), json={"userid": world.users["alice"], "how": "add"},
                     headers=world.h("admin"))
    assert [u["userid"] for u in r.json()["users"]] == [world.users["alice"]]
    # someone outside the team cannot be added
    assert client.patch("/api/v2/teams/%d/teamgroups/%d" % (A, gid), json={"userid": world.users["bea"], "how": "add"},
                        headers=world.h("admin")).status_code == 400
    groups = client.get("/api/v2/teams/%d/teamgroups" % A, headers=world.h("bob")).json()
    assert isinstance(groups, dict) and str(gid) in groups          # keyed by id, as 2.x answers
    g = groups[str(gid)]
    assert g["team"] == A and g["users"][0]["fullname"] == "Alice Test"
    # membership in the group grants what a record names it for (one permission engine decides both)
    eid = _id(client.post("/api/v2/experiments", json={"title": "for the group"}, headers=world.h("bob")))
    client.patch("/api/v2/experiments/%d" % eid,
                 json={"canread": json.dumps({"base": 10, "teams": [], "users": [], "teamgroups": [gid]})},
                 headers=world.h("bob"))
    assert client.get("/api/v2/experiments/%d" % eid, headers=world.h("alice")).status_code == 200
    r = client.patch("/api/v2/teams/%d/teamgroups/%d" % (A, gid), json={"userid": world.users["alice"], "how": "rm"},
                     headers=world.h("admin"))
    assert r.json()["users"] == []
    assert client.get("/api/v2/experiments/%d" % eid, headers=world.h("alice")).status_code == 403
    assert client.get("/api/v2/teams/%d/teamgroups" % A, headers=world.h("bea")).status_code == 403
    assert client.delete("/api/v2/teams/%d/teamgroups/%d" % (A, gid), headers=world.h("admin")).status_code == 204
    assert str(gid) not in client.get("/api/v2/teams/%d/teamgroups" % A, headers=world.h("bob")).json()
    cats = {r["category"] for r in _audit(pool, "group.create") + _audit(pool, "group.member_add")
            + _audit(pool, "group.delete")}
    assert cats == {"group.create", "group.member_add", "group.delete"}


# --------------------------------------------------------------------------------- team tags
def test_team_tag_rename_merge_and_delete(client, world):
    A = world.teams["A"]
    h = world.h("alice")
    e1 = _id(client.post("/api/v2/experiments", json={"title": "tag one"}, headers=h))
    e2 = _id(client.post("/api/v2/experiments", json={"title": "tag two"}, headers=h))
    client.post("/api/v2/experiments/%d/tags" % e1, json={"tag": "ttg-old"}, headers=h)
    client.post("/api/v2/experiments/%d/tags" % e2, json={"tag": "ttg-target"}, headers=h)
    tags = {t["tag"]: t["id"] for t in client.get("/api/v2/teams/%d/tags" % A, headers=h).json()}
    assert client.patch("/api/v2/teams/%d/tags/%d" % (A, tags["ttg-old"]), json={"tag": "x"}, headers=h).status_code == 403
    r = client.patch("/api/v2/teams/%d/tags/%d" % (A, tags["ttg-old"]), json={"tag": "ttg-renamed"},
                     headers=world.h("admin"))
    assert r.status_code == 200 and r.json()["tag"] == "ttg-renamed"
    assert [t["tag"] for t in client.get("/api/v2/experiments/%d/tags" % e1, headers=h).json()] == ["ttg-renamed"]
    found = client.get("/api/v2/experiments", params={"q": "ttg-renamed"}, headers=h).json()
    assert any(x["id"] == e1 for x in found)                         # search follows the rename
    r = client.patch("/api/v2/teams/%d/tags/%d" % (A, tags["ttg-old"]), json={"tag": "ttg-target"},
                     headers=world.h("admin"))
    assert r.json()["id"] == tags["ttg-target"]                      # merged into the existing tag
    assert [t["tag"] for t in client.get("/api/v2/experiments/%d/tags" % e1, headers=h).json()] == ["ttg-target"]
    assert client.delete("/api/v2/teams/%d/tags/%d" % (A, tags["ttg-target"]), headers=world.h("admin")).status_code == 204
    assert client.get("/api/v2/experiments/%d/tags" % e2, headers=h).json() == []


# ------------------------------------------------------------------------------------- users
def test_user_edits_by_self_admin_and_sysadmin(client, world, pool):
    alice = world.users["alice"]
    r = client.patch("/api/v2/users/me", json={"lastname": "Tested", "limit_nb": 25}, headers=world.h("alice"))
    assert r.status_code == 200 and r.json()["lastname"] == "Tested" and r.json()["limit_nb"] == 25
    assert client.patch("/api/v2/users/me", json={"limit_nb": 0}, headers=world.h("alice")).status_code == 400
    assert client.patch("/api/v2/users/me", json={"is_sysadmin": 1}, headers=world.h("alice")).status_code == 403
    assert client.patch("/api/v2/users/me", json={"favorite_color": 1}, headers=world.h("alice")).status_code == 400
    # the team admin cannot rename a member, the sysadmin can
    assert client.patch("/api/v2/users/%d" % alice, json={"lastname": "X"}, headers=world.h("admin")).status_code == 403
    assert client.patch("/api/v2/users/%d" % alice, json={"lastname": "Test"}, headers=world.h("sys")).json()["lastname"] == "Test"
    assert client.patch("/api/v2/users/%d" % alice, json={"lastname": "X"}, headers=world.h("bea")).status_code == 403
    # membership: the team admin makes alice an admin of team A and back
    r = client.patch("/api/v2/users/%d" % alice, json={"action": "patchuser2team", "team": world.teams["A"],
                                                       "target": "is_admin", "content": 1}, headers=world.h("admin"))
    assert r.status_code == 200 and next(t for t in r.json()["teams"] if t["id"] == world.teams["A"])["is_admin"] == 1
    client.patch("/api/v2/users/%d" % alice, json={"action": "patchuser2team", "team": world.teams["A"],
                                                   "target": "is_admin", "content": 0}, headers=world.h("admin"))
    # a team admin cannot add people to a team they do not administer
    assert client.patch("/api/v2/users/%d" % alice, json={"action": "add", "team": world.teams["B"]},
                        headers=world.h("admin")).status_code == 403
    rows = _audit(pool, "membership.update", target="is_admin")
    assert [(r["old_value"], r["new_value"]) for r in rows[-2:]] == [("0", "1"), ("1", "0")]


def test_user_lifecycle_create_validate_archive_delete(client, world):
    h = world.h("sys")
    uid = _id(client.post("/api/v2/users", json={"email": "life@example.com", "firstname": "Life", "lastname": "Cycle",
                                                 "team": world.teams["A"]}, headers=h))
    assert client.patch("/api/v2/users/%d" % uid, json={"action": "validate"}, headers=h).json()["validated"] == 1
    r = client.patch("/api/v2/users/%d" % uid, json={"action": "archive"}, headers=world.h("admin"))
    assert r.status_code == 200 and r.json()["archived"] == 1
    assert next(t for t in r.json()["teams"] if t["id"] == world.teams["A"])["is_archived"] == 1
    r = client.patch("/api/v2/users/%d" % uid, json={"action": "unarchive"}, headers=world.h("admin"))
    assert r.json()["archived"] == 0
    assert client.patch("/api/v2/users/%d" % uid, json={"is_sysadmin": 1}, headers=h).json()["is_sysadmin"] == 1
    assert client.patch("/api/v2/users/%d" % uid, json={"is_sysadmin": 0}, headers=h).json()["is_sysadmin"] == 0
    assert client.delete("/api/v2/users/%d" % uid, headers=world.h("admin")).status_code == 403
    assert client.delete("/api/v2/users/%d" % uid, headers=h).status_code == 204
    assert client.get("/api/v2/users/%d" % uid, headers=h).status_code == 404
    assert all(u["userid"] != uid for u in client.get("/api/v2/users", headers=h).json())


# ---------------------------------------------------------------------------- my own lists
def test_api_keys_are_shown_once_and_never_stored(client, world, pool):
    h = world.h("bob")
    r = client.post("/api/v2/apikeys", json={"name": "probe key", "canwrite": 0}, headers=h)
    assert r.status_code == 201 and r.headers["location"].endswith("/apikeys/%d" % r.json()["id"])
    key = r.json()["key"]
    assert apikeys.KEY_RE.match(key)
    with pool.tx() as tx:
        assert not tx.val("SELECT count(*) FROM occ.api_keys WHERE hash = :k OR name = :k", k=key)
        assert not tx.val("SELECT count(*) FROM occ.audit_events WHERE position(:k in coalesce(new_value, '') || "
                          "coalesce(old_value, '') || coalesce(detail::text, '')) > 0", k=key)
    listed = client.get("/api/v2/apikeys", headers=h).json()
    mine = next(k for k in listed if k["name"] == "probe key")
    assert mine["hash"] is None and mine["can_write"] == 0                       # a key's stored hash is never returned
    assert client.get("/api/v2/users/me", headers={"Authorization": "Bearer " + key}).status_code == 200   # the new key works at once
    assert client.post("/api/v2/todolist", json={"content": "x"}, headers={"Authorization": key}).status_code == 403
    assert client.post("/api/v2/apikeys", json={"name": "x", "team": world.teams["B"]}, headers=h).status_code == 403
    assert client.post("/api/v2/apikeys", json={"name": "x", "site_scope": 1}, headers=h).status_code == 403
    assert client.delete("/api/v2/apikeys/%d" % mine["id"], headers=world.h("alice")).status_code == 403
    assert client.delete("/api/v2/apikeys/%d" % mine["id"], headers=h).status_code == 204
    assert client.get("/api/v2/users/me", headers={"Authorization": key}).status_code == 401


def test_todo_favtags_notifications_sigkeys(client, world, pool):
    h = world.h("bob")
    tid = _id(client.post("/api/v2/todolist", json={"content": "first thing"}, headers=h))
    assert client.patch("/api/v2/todolist/%d" % tid, json={"content": "first thing, edited", "ordering": 2},
                        headers=h).json()["body"] == "first thing, edited"
    assert any(t["id"] == tid for t in client.get("/api/v2/todolist", headers=h).json())
    assert client.patch("/api/v2/todolist/%d" % tid, json={"content": "x"}, headers=world.h("alice")).status_code == 404
    assert client.delete("/api/v2/todolist/%d" % tid, headers=h).status_code == 204
    assert all(t["id"] != tid for t in client.get("/api/v2/todolist", headers=h).json())

    eid = _id(client.post("/api/v2/experiments", json={"title": "fav"}, headers=h))
    client.post("/api/v2/experiments/%d/tags" % eid, json={"tag": "fav-tag"}, headers=h)
    fid = _id(client.post("/api/v2/favtags", json={"tag": "fav-tag"}, headers=h))
    assert client.get("/api/v2/favtags", headers=h).json() == [{"tags_id": fid, "tag": "fav-tag"}]
    assert client.post("/api/v2/favtags", json={"tag": "no-such-tag"}, headers=h).status_code == 400
    assert client.delete("/api/v2/favtags/%d" % fid, headers=h).status_code == 204
    assert client.get("/api/v2/favtags", headers=h).json() == []

    with pool.tx() as tx:
        nid = tx.val("INSERT INTO occ.notifications (user_id, category, body) VALUES (:u, 90, CAST(:b AS jsonb)) "
                     "RETURNING id", u=world.users["bob"], b='{"action": "review"}')
        tx.val("INSERT INTO occ.notifications (user_id, category, body) VALUES (:u, 20, '{}') RETURNING id",
               u=world.users["bob"])
    n = client.get("/api/v2/users/me/notifications", headers=h).json()
    assert {x["id"] for x in n} >= {nid} and next(x for x in n if x["id"] == nid)["body"] == {"action": "review"}
    assert client.patch("/api/v2/users/me/notifications/%d" % nid, json={}, headers=h).json()["is_ack"] == 1
    assert all(x["is_ack"] == 1 for x in client.patch("/api/v2/users/me/notifications", headers=h).json())
    assert client.get("/api/v2/users/me/notifications", headers=world.h("alice")).json() == []
    assert client.get("/api/v2/users/me/sig_keys", headers=h).json() == []


# ---------------------------------------------------------------------------------- sessions
def test_session_read_switch_and_sign_out(client, world, pool, cfg):
    pepper = apikeys.read_pepper(cfg.api_key_pepper_file)
    with pool.tx() as tx:
        tx.run("INSERT INTO occ.memberships (user_id, team_id) VALUES (:u, :t) ON CONFLICT DO NOTHING",
               u=world.users["bea"], t=world.teams["C"])
        cookie = sessions.create(tx, pepper, world.users["bea"], world.teams["B"])
    jar = {sessions.COOKIE: cookie}
    s = client.get("/api/v2/occ/session", cookies=jar).json()
    assert s["userid"] == world.users["bea"] and s["team"] == world.teams["B"] and s["via"] == "session"
    assert s["csrf_token"] == sessions.csrf_token_for(pepper, cookie) and s["expires_at"]
    # a cookie write needs the token or a same-origin Origin; a cross-site browser request is refused
    assert client.post("/api/v2/todolist", json={"content": "x"}, cookies=jar,
                       headers={"Origin": "https://evil.example"}).status_code == 403
    assert client.post("/api/v2/todolist", json={"content": "x"}, cookies=jar,
                       headers={"Sec-Fetch-Site": "cross-site", "X-CSRF-Token": s["csrf_token"]}).status_code == 403
    assert client.post("/api/v2/todolist", json={"content": "x"}, cookies=jar,
                       headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert client.post("/api/v2/todolist", json={"content": "with token"}, cookies=jar,
                       headers={"X-CSRF-Token": s["csrf_token"]}).status_code == 201
    # switch team: only to a team the person belongs to
    assert client.patch("/api/v2/occ/session", json={"team": world.teams["A"]}, cookies=jar,
                        headers={"X-CSRF-Token": s["csrf_token"]}).status_code == 403
    r = client.patch("/api/v2/occ/session", json={"team": world.teams["C"]}, cookies=jar,
                     headers={"X-CSRF-Token": s["csrf_token"]})
    assert r.status_code == 200 and r.json()["team"] == world.teams["C"]
    assert client.get("/api/v2/users/me", cookies=jar).json()["team"] == world.teams["C"]
    assert _audit(pool, "auth.switch_team", actor_user_id=world.users["bea"])
    # an API key cannot switch or sign out: it is bound to its team
    assert client.patch("/api/v2/occ/session", json={"team": world.teams["A"]}, headers=world.h("alice")).status_code == 400
    assert client.get("/api/v2/occ/session", headers=world.h("alice")).json()["csrf_token"] is None
    r = client.delete("/api/v2/occ/session", cookies=jar, headers={"X-CSRF-Token": s["csrf_token"]})
    assert r.status_code == 200 and "occ_session=" in r.headers.get("set-cookie", "")
    assert client.get("/api/v2/occ/session", cookies=jar).status_code == 401
    assert _audit(pool, "auth.signout", actor_user_id=world.users["bea"])


# ------------------------------------------------------------------------------ write policy
def test_write_policy_switch_and_read_only_refusal(client, world, pool):
    assert client.patch("/api/v2/occ/write-policy", json={"read_only": 1}, headers=world.h("admin")).status_code == 403
    r = client.patch("/api/v2/occ/write-policy", json={"read_only": 1}, headers=world.h("sys"))
    assert r.status_code == 200 and r.json()["read_only"] == 1
    try:
        r = client.post("/api/v2/todolist", json={"content": "x"}, headers=world.h("alice"))
        assert r.status_code == 403 and r.json()["message"] == "This is a read-only preview of LabLynx.One 3.x."
        assert client.get("/api/v2/occ/write-policy", headers=world.h("alice")).json()["banner"] == \
            "LabLynx.One 3.x on OCC: read-only preview"
    finally:
        # the sysadmin is not write_exempt in this world and can still turn it off, so read-only mode can never lock everybody out
        r = client.patch("/api/v2/occ/write-policy", json={"read_only": 0}, headers=world.h("sys"))
        assert r.status_code == 200 and r.json()["read_only"] == 0
    assert client.get("/api/v2/occ/write-policy", headers=world.h("alice")).json()["banner"] == \
        "LabLynx.One 3.x on OCC: changes made here stay in 3.x"
    assert [r["new_value"] for r in _audit(pool, "config.update", target="read_only")][-2:] == ["1", "0"]


# ----------------------------------------------------------------------------- history notes
def test_history_note_lands_in_the_changelog(client, world):
    h = world.h("alice")
    eid = _id(client.post("/api/v2/experiments", json={"title": "noted"}, headers=h))
    r = client.post("/api/v2/occ/experiments/%d/notes" % eid, json={"target": "title", "text": "Typo fixed"}, headers=h)
    assert r.status_code == 201 and "/changelog?cursor=" in r.headers["location"]
    log = client.get("/api/v2/experiments/%d" % eid, headers=h).json()["changelog"]
    assert log[0]["target"] == "title" and log[0]["content"] == "Typo fixed"
    assert client.post("/api/v2/occ/experiments/%d/notes" % eid, json={"text": "x"},
                       headers=world.h("bea")).status_code in (403, 404)
    assert client.post("/api/v2/occ/experiments/%d/notes" % eid, json={"text": ""}, headers=h).status_code == 400


# ------------------------------------------------------------------------ site read sides
def test_site_lists_answer_and_are_guarded(client, world, pool):
    with pool.tx() as tx:
        tx.run("INSERT INTO occ.idps (name, entityid) VALUES ('Test IdP', 'https://idp.example/metadata')")
        root = tx.val("INSERT INTO occ.storage_units (name) VALUES ('Building 1') RETURNING id")
        tx.run("INSERT INTO occ.storage_units (name, parent_id) VALUES ('Room 2', :p)", p=root)
        tx.run("INSERT INTO occ.compounds (team_id, user_id, name, cas_number, created_by, modified_by, identifiers) "
               "VALUES (:t, :u, 'Acetone', '67-64-1', :u, :u, '{\"ec_number\": \"200-662-2\"}')",
               t=world.teams["A"], u=world.users["alice"])
    idps = client.get("/api/v2/idps", headers=world.h("sys")).json()
    assert idps[0]["name"] == "Test IdP" and idps[0]["enabled"] == 1
    assert client.get("/api/v2/idps/%d" % idps[0]["id"], headers=world.h("sys")).json()["entityid"]
    assert client.get("/api/v2/idps", headers=world.h("admin")).status_code == 403
    assert client.get("/api/v2/idps_sources", headers=world.h("sys")).json() == []
    assert client.get("/api/v2/exports", headers=world.h("alice")).json() == []
    units = client.get("/api/v2/storage_units", headers=world.h("bea")).json()
    assert [u["full_path"] for u in units] == ["Building 1", "Building 1 > Room 2"]
    comps = client.get("/api/v2/compounds", headers=world.h("alice")).json()
    assert comps[0]["name"] == "Acetone" and comps[0]["ec_number"] == "200-662-2" and comps[0]["chebi_id"] is None
    assert client.get("/api/v2/compounds", headers=world.h("bea")).json() == []
    assert client.get("/api/v2/compounds/%d" % comps[0]["id"], headers=world.h("bea")).status_code == 404
    assert client.get("/api/v2/teams/current/procurement_requests", headers=world.h("alice")).json() == []


# ------------------------------------------------------------------- remaining record actions
def test_forcelock_and_setnextcustomid(client, world):
    h = world.h("alice")
    eid = _id(client.post("/api/v2/experiments", json={"title": "force"}, headers=h))
    assert client.patch("/api/v2/experiments/%d" % eid, json={"action": "forcelock"}, headers=h).status_code == 403
    r = client.patch("/api/v2/experiments/%d" % eid, json={"action": "forcelock"}, headers=world.h("admin"))
    assert r.status_code == 200 and r.json()["locked"] == 1
    assert client.patch("/api/v2/experiments/%d" % eid, json={"action": "forcelock"},
                        headers=world.h("admin")).json()["locked"] == 1                  # not a toggle
    assert client.patch("/api/v2/experiments/%d" % eid, json={"title": "x"}, headers=h).status_code == 423
    assert client.patch("/api/v2/experiments/%d" % eid, json={"action": "forceunlock"},
                        headers=world.h("admin")).json()["locked"] == 0
    cat = _id(client.post("/api/v2/teams/current/experiments_categories", json={"name": "Numbered"},
                          headers=world.h("admin")))
    assert client.patch("/api/v2/experiments/%d" % eid, json={"action": "setnextcustomid"}, headers=h).status_code == 400
    client.patch("/api/v2/experiments/%d" % eid, json={"category": cat}, headers=h)
    assert client.patch("/api/v2/experiments/%d" % eid, json={"action": "setnextcustomid"},
                        headers=h).json()["custom_id"] == 1
    e2 = _id(client.post("/api/v2/experiments", json={"title": "force 2"}, headers=h))
    client.patch("/api/v2/experiments/%d" % e2, json={"category": cat, "custom_id": 7}, headers=h)
    e3 = _id(client.post("/api/v2/experiments", json={"title": "force 3"}, headers=h))
    client.patch("/api/v2/experiments/%d" % e3, json={"category": cat}, headers=h)
    assert client.patch("/api/v2/experiments/%d" % e3, json={"action": "setnextcustomid"},
                        headers=h).json()["custom_id"] == 8
