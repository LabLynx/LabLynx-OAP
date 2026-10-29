# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The signed-in person's own lists: API keys, to-do list, favorite tags, notifications and
signature keys (making one is in occ/signing/service.py).

Every write here is the caller's own and is audited. A key's text is shown once, in the
answer that makes it, and never stored, logged or returned again; listing keys answers hash: null
(2.x returns the stored hash; the OCC never does).
"""
from .. import errors, timefmt
from ..audit import writer as audit
from ..auth import apikeys


def _int(v, name):
    try:
        return int(v)
    except (TypeError, ValueError):
        raise errors.bad("Incorrect value for %s" % name)


def _writer(p):
    if not p.can_write:
        raise errors.forbidden("This API key is read-only.")


def _flag(v, name):
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off", ""):
        return False
    raise errors.bad("Incorrect value for %s" % name)


# ------------------------------------------------------------------------------------- API keys
def list_keys(tx, p):
    rows = tx.all("SELECT k.id, k.name, k.created_at, k.last_used_at, k.can_write, k.site_scope, k.team_id, "
                  "t.name AS team_name FROM occ.api_keys k JOIN occ.teams t ON t.id = k.team_id "
                  "WHERE k.user_id = :u AND k.revoked_at IS NULL ORDER BY k.id", u=p.user_id)
    return [{"id": r["id"], "name": r["name"], "created_at": timefmt.out(r["created_at"]),
             "last_used_at": timefmt.out(r["last_used_at"]), "hash": None, "can_write": 1 if r["can_write"] else 0,
             "team": r["team_id"], "team_name": r["team_name"], "userid": p.user_id,
             "site_scope": 1 if r["site_scope"] else 0} for r in rows]


def create_key(tx, p, actor, pepper, body):
    """Make a key: name, canwrite, team (any team the caller belongs to; 2.x always uses the calling key's
    team), site_scope (sysadmins)."""
    _writer(p)
    body = body or {}
    name = str(body.get("name") or "").strip()
    if not name:
        raise errors.bad("Incorrect value for name: it is empty")
    can_write = _flag(body.get("canwrite", body.get("can_write", 0)), "canwrite")
    team = _int(body.get("team") or p.team_id, "team")
    if team not in p.member_teams:
        raise errors.forbidden("You are not a member of that team.")
    site_scope = _flag(body.get("site_scope", 0), "site_scope")
    if site_scope and not p.is_sysadmin:
        raise errors.forbidden("Only a sysadmin can make a site-scope key.")
    kid, key = apikeys.create(tx, pepper, p.user_id, team, name, can_write=can_write, site_scope=site_scope)
    audit.write(tx, actor, "apikey.create", team_id=team, target="api_key", new=name,
                detail={"api_key_id": kid, "can_write": can_write, "site_scope": site_scope})
    return kid, key


def delete_key(tx, p, actor, key_id):
    _writer(p)
    r = tx.one("SELECT id, user_id, team_id, name FROM occ.api_keys WHERE id = :id AND revoked_at IS NULL", id=key_id)
    if r is None:
        raise errors.not_found()
    if r["user_id"] != p.user_id and not p.is_sysadmin:
        raise errors.forbidden("That key is not yours.")
    tx.run("UPDATE occ.api_keys SET revoked_at = now() WHERE id = :id", id=key_id)
    audit.write(tx, actor, "apikey.delete", team_id=r["team_id"], target="api_key", old=r["name"],
                detail={"api_key_id": key_id, "userid": r["user_id"]})


# ------------------------------------------------------------------------------------ to-do list
def _todo_shape(r):
    return {"id": r["id"], "body": r["body"], "creation_time": timefmt.out(r["created_at"]),
            "ordering": r["ordering"], "userid": r["user_id"]}


def list_todo(tx, p):
    return [_todo_shape(r) for r in tx.all("SELECT * FROM occ.todo_items WHERE user_id = :u "
                                           "ORDER BY ordering NULLS LAST, id DESC", u=p.user_id)]


def create_todo(tx, p, actor, body):
    _writer(p)
    text = str((body or {}).get("content") or (body or {}).get("body") or "").strip()
    if not text:
        raise errors.bad("Incorrect value for content: it is empty")
    tid = tx.val("INSERT INTO occ.todo_items (user_id, body) VALUES (:u, :b) RETURNING id", u=p.user_id, b=text)
    audit.write(tx, actor, "todo.create", target="todo", new=text, detail={"todo_id": tid})
    return tid


def _own_todo(tx, p, todo_id):
    r = tx.one("SELECT * FROM occ.todo_items WHERE id = :id AND user_id = :u", id=todo_id, u=p.user_id)
    if r is None:
        raise errors.not_found()
    return r


def patch_todo(tx, p, actor, todo_id, body):
    _writer(p)
    r = _own_todo(tx, p, todo_id)
    body = body or {}
    if "content" in body or "body" in body:
        text = str(body.get("content", body.get("body")) or "").strip()
        if not text:
            raise errors.bad("Incorrect value for content: it is empty")
        if text != r["body"]:
            tx.run("UPDATE occ.todo_items SET body = :b WHERE id = :id", b=text, id=todo_id)
            audit.write(tx, actor, "todo.update", target="body", old=r["body"], new=text, detail={"todo_id": todo_id})
    if "ordering" in body:
        o = None if body["ordering"] in (None, "") else _int(body["ordering"], "ordering")
        if o != r["ordering"]:
            tx.run("UPDATE occ.todo_items SET ordering = :o WHERE id = :id", o=o, id=todo_id)
            audit.write(tx, actor, "todo.update", target="ordering", old=r["ordering"], new=o,
                        detail={"todo_id": todo_id})
    return _todo_shape(_own_todo(tx, p, todo_id))


def delete_todo(tx, p, actor, todo_id):
    _writer(p)
    r = _own_todo(tx, p, todo_id)
    tx.run("DELETE FROM occ.todo_items WHERE id = :id", id=todo_id)
    audit.write(tx, actor, "todo.delete", target="todo", old=r["body"], detail={"todo_id": todo_id})


# --------------------------------------------------------------------------------- favorite tags
def list_favtags(tx, p):
    rows = tx.all("SELECT f.tag_id, t.tag FROM occ.favorite_tags f JOIN occ.tags t ON t.id = f.tag_id "
                  "WHERE f.user_id = :u ORDER BY t.tag", u=p.user_id)
    return [{"tags_id": r["tag_id"], "tag": r["tag"]} for r in rows]


def add_favtag(tx, p, actor, body):
    """Add a favorite tag {tag}: a tag of the caller's current team, by text (or its id)."""
    _writer(p)
    tag = (body or {}).get("tag")
    if tag in (None, ""):
        raise errors.bad("Incorrect value for tag: it is empty")
    row = None
    if isinstance(tag, int) or (isinstance(tag, str) and tag.isdigit()):
        row = tx.one("SELECT id, tag FROM occ.tags WHERE id = :id AND team_id = ANY(CAST(:t AS int[]))",
                     id=int(tag), t=sorted(p.member_teams))
    if row is None:
        row = tx.one("SELECT id, tag FROM occ.tags WHERE team_id = :t AND tag = :g", t=p.team_id, g=str(tag).strip())
    if row is None:
        raise errors.bad("Incorrect value for tag: the team has no such tag")
    if tx.run("INSERT INTO occ.favorite_tags (user_id, tag_id) VALUES (:u, :t) ON CONFLICT DO NOTHING",
              u=p.user_id, t=row["id"]):
        audit.write(tx, actor, "favtag.add", target="tag", new=row["tag"], detail={"tag_id": row["id"]})
    return row["id"]


def delete_favtag(tx, p, actor, tag_id):
    _writer(p)
    tag = tx.val("SELECT t.tag FROM occ.favorite_tags f JOIN occ.tags t ON t.id = f.tag_id "
                 "WHERE f.user_id = :u AND f.tag_id = :t", u=p.user_id, t=tag_id)
    if tag is None:
        raise errors.not_found()
    tx.run("DELETE FROM occ.favorite_tags WHERE user_id = :u AND tag_id = :t", u=p.user_id, t=tag_id)
    audit.write(tx, actor, "favtag.delete", target="tag", old=tag, detail={"tag_id": tag_id})


# --------------------------------------------------------------------------------- notifications
def _notif_shape(r):
    return {"id": r["id"], "category": r["category"], "body": r["body"], "is_ack": 1 if r["is_ack"] else 0,
            "created_at": timefmt.out(r["created_at"]), "userid": r["user_id"]}


def list_notifications(tx, p):
    return [_notif_shape(r) for r in tx.all("SELECT * FROM occ.notifications WHERE user_id = :u "
                                            "ORDER BY created_at DESC, id DESC", u=p.user_id)]


def ack_notification(tx, p, actor, notif_id, body):
    """Acknowledge one notification (is_ack, default 1)."""
    _writer(p)
    r = tx.one("SELECT * FROM occ.notifications WHERE id = :id AND user_id = :u", id=notif_id, u=p.user_id)
    if r is None:
        raise errors.not_found()
    ack = _flag((body or {}).get("is_ack", 1), "is_ack")
    if ack != r["is_ack"]:
        tx.run("UPDATE occ.notifications SET is_ack = :a WHERE id = :id", a=ack, id=notif_id)
        audit.write(tx, actor, "notification.update", target="is_ack", old=r["is_ack"], new=ack,
                    detail={"notification_id": notif_id})
    return _notif_shape(tx.one("SELECT * FROM occ.notifications WHERE id = :id", id=notif_id))


def ack_all_notifications(tx, p, actor):
    """Acknowledge every notification of the caller."""
    _writer(p)
    n = tx.run("UPDATE occ.notifications SET is_ack = true WHERE user_id = :u AND NOT is_ack", u=p.user_id)
    if n:
        audit.write(tx, actor, "notification.update", target="is_ack", new=True, detail={"count": n})
    return list_notifications(tx, p)


# ------------------------------------------------------------------------------ signature keys
def list_sig_keys(tx, p):
    rows = tx.all("SELECT id, key_id, pubkey, type, state, created_at, last_used_at FROM occ.sig_keys "
                  "WHERE user_id = :u ORDER BY id DESC", u=p.user_id)
    return [{"id": r["id"], "userid": p.user_id, "pubkey": r["pubkey"], "key_id": r["key_id"].strip(),
             "type": r["type"], "state": r["state"], "created_at": timefmt.out(r["created_at"]),
             "last_used_at": timefmt.out(r["last_used_at"])} for r in rows]
