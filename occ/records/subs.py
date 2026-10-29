# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""A record's sub-resources: tags, comments, steps, links, revisions and the read
side of uploads.

Every write adds audit rows in the same transaction. A comment can be added by anybody who
can read the record; everything else here needs write access to the record.
"""
from .. import errors, timefmt
from ..db import ident
from ..audit import writer as audit
from ..perms import engine
from . import kinds as K
from . import service as S


STEP_FLAGS = frozenset(("is_immutable", "deadline_notif"))


def _b(v):
    return 1 if v else 0


def _record(tx, p, kind, rec_id, right=engine.WRITE, for_update=True):
    row = S.fetch(tx, p, kind, rec_id, full=False, for_update=for_update)
    engine.readable_or_raise(p, row, errors)
    if right == engine.WRITE:
        S._check_can_write_key(p)
        if row["state"] == 3:
            raise errors.forbidden("This entry is deleted: it accepts only restore.")
        if not engine.check(p, row, engine.WRITE):
            raise errors.forbidden()
        blocked = engine.write_block(p, row)
        if blocked:
            raise errors.OCCError(*blocked)
    return row


def _audit(tx, actor, kind_id, row, category, target, old=None, new=None, detail=None):
    audit.write(tx, actor, category, kind_id=kind_id, record_id=row["id"], rid=row["rid"], team_id=row["team_id"],
                target=target, old=old, new=new, detail=detail)


# ------------------------------------------------------------------------------------------- tags
def list_tags(tx, p, kind, rec_id):
    row = _record(tx, p, kind, rec_id, right=engine.READ, for_update=False)
    rows = tx.all("SELECT tg.id, tg.tag, EXISTS (SELECT 1 FROM occ.favorite_tags f WHERE f.tag_id = tg.id "
                  "AND f.user_id = :u) AS fav FROM occ.record_tags rt JOIN occ.tags tg ON tg.id = rt.tag_id "
                  "WHERE rt.rid = :rid ORDER BY tg.tag", rid=row["rid"], u=p.user_id)
    return [{"tag_id": r["id"], "tag": r["tag"], "is_favorite": _b(r["fav"])} for r in rows]


def attach_tag(tx, p, actor, kind, row, tag):
    """As in 2.x, a tag belongs to the record's team; an unknown one is created there (team setting
    user_create_tag = 0 limits creating new tags to team admins)."""
    tag = (tag or "").strip()
    if not tag:
        raise errors.bad("Incorrect value for tag: it is empty")
    tid = tx.val("SELECT id FROM occ.tags WHERE team_id = :t AND tag = :tag", t=row["team_id"], tag=tag)
    if tid is None:
        allowed = tx.val("SELECT user_create_tag FROM occ.teams WHERE id = :t", t=row["team_id"])
        if not allowed and row["team_id"] not in p.admin_teams:
            raise errors.forbidden("Only team admins can create new tags in this team.")
        tid = tx.val("INSERT INTO occ.tags (team_id, tag) VALUES (:t, :tag) RETURNING id", t=row["team_id"], tag=tag)
    n = tx.run("INSERT INTO occ.record_tags (rid, tag_id) VALUES (:rid, :tid) ON CONFLICT DO NOTHING",
               rid=row["rid"], tid=tid)
    if n:
        _audit(tx, actor, kind.id, row, "tag.add", "tag", new=tag)
    return tid


def add_tag(tx, p, actor, kind, rec_id, body):
    row = _record(tx, p, kind, rec_id)
    tid = attach_tag(tx, p, actor, kind, row, str((body or {}).get("tag") or ""))
    S.touch(tx, p, row["rid"])
    return tid


def remove_tag(tx, p, actor, kind, rec_id, tag_id):
    row = _record(tx, p, kind, rec_id)
    tag = tx.val("SELECT tg.tag FROM occ.record_tags rt JOIN occ.tags tg ON tg.id = rt.tag_id "
                 "WHERE rt.rid = :rid AND rt.tag_id = :tid", rid=row["rid"], tid=tag_id)
    if tag is None:
        raise errors.not_found("This record has no tag with that id")
    tx.run("DELETE FROM occ.record_tags WHERE rid = :rid AND tag_id = :tid", rid=row["rid"], tid=tag_id)
    _audit(tx, actor, kind.id, row, "tag.remove", "tag", old=tag)
    S.touch(tx, p, row["rid"])


# --------------------------------------------------------------------------------------- comments
_COMMENT_SQL = ("SELECT cm.id, cm.created_at, cm.modified_at, cm.body, cm.user_id, cm.immutable, "
                "u.firstname, u.lastname, u.orcid, u.email FROM occ.comments cm JOIN occ.users u ON u.id = cm.user_id ")


def _comment_shape(r, rec_id):
    return {"id": r["id"], "created_at": timefmt.out(r["created_at"]), "modified_at": timefmt.out(r["modified_at"]),
            "item_id": rec_id, "comment": r["body"], "userid": r["user_id"], "immutable": _b(r["immutable"]),
            "fullname": ("%s %s" % (r["firstname"], r["lastname"])).strip(), "firstname": r["firstname"],
            "lastname": r["lastname"], "orcid": r["orcid"], "email": r["email"]}


def list_comments(tx, row):
    rows = tx.all(_COMMENT_SQL + "WHERE cm.rid = :rid AND cm.deleted_at IS NULL ORDER BY cm.created_at, cm.id",
                  rid=row["rid"])
    return [_comment_shape(r, row["id"]) for r in rows]


def comments(tx, p, kind, rec_id):
    row = _record(tx, p, kind, rec_id, right=engine.READ, for_update=False)
    return list_comments(tx, row)


def _comment(tx, row, comment_id):
    c = tx.one(_COMMENT_SQL + "WHERE cm.rid = :rid AND cm.id = :id AND cm.deleted_at IS NULL",
               rid=row["rid"], id=comment_id)
    if c is None:
        raise errors.not_found("No comment with that id on this record")
    return c


def get_comment(tx, p, kind, rec_id, comment_id):
    row = _record(tx, p, kind, rec_id, right=engine.READ, for_update=False)
    return _comment_shape(_comment(tx, row, comment_id), row["id"])


def add_comment(tx, p, actor, kind, rec_id, body):
    row = _record(tx, p, kind, rec_id, right=engine.READ)
    S._check_can_write_key(p)
    text = str((body or {}).get("comment") or "").strip()
    if not text:
        raise errors.bad("Incorrect value for comment: it is empty")
    immutable = S._bool("immutable", (body or {}).get("immutable", False))   # honored here; 2.x ignores it
    cid = tx.val("INSERT INTO occ.comments (rid, user_id, body, immutable) VALUES (:rid, :u, :b, :i) RETURNING id",
                 rid=row["rid"], u=p.user_id, b=text, i=immutable)
    _audit(tx, actor, kind.id, row, "comment.add", "comment", new=text, detail={"comment_id": cid})
    return cid


def _own_comment(tx, p, kind, rec_id, comment_id):
    row = _record(tx, p, kind, rec_id, right=engine.READ, for_update=False)
    S._check_can_write_key(p)
    c = _comment(tx, row, comment_id)
    if c["user_id"] != p.user_id:
        raise errors.forbidden("Only the author can change a comment.")
    if c["immutable"]:
        raise errors.forbidden("This comment is immutable.")
    return row, c


def edit_comment(tx, p, actor, kind, rec_id, comment_id, body):
    row, c = _own_comment(tx, p, kind, rec_id, comment_id)
    text = str((body or {}).get("comment") or "").strip()
    if not text:
        raise errors.bad("Incorrect value for comment: it is empty")
    if text != c["body"]:
        tx.run("UPDATE occ.comments SET body = :b, modified_at = now() WHERE id = :id", b=text, id=comment_id)
        _audit(tx, actor, kind.id, row, "comment.update", "comment", old=c["body"], new=text,
               detail={"comment_id": comment_id})
    return get_comment(tx, p, kind, rec_id, comment_id)


def delete_comment(tx, p, actor, kind, rec_id, comment_id):
    row, c = _own_comment(tx, p, kind, rec_id, comment_id)
    tx.run("UPDATE occ.comments SET deleted_at = now() WHERE id = :id", id=comment_id)
    _audit(tx, actor, kind.id, row, "comment.delete", "comment", old=c["body"], detail={"comment_id": comment_id})


# ------------------------------------------------------------------------------------------ steps
_STEP_SQL = ("SELECT id, body, ordering, finished, finished_at, deadline, deadline_notif, is_immutable "
             "FROM occ.steps ")


def _step_shape(r, rec_id):
    return {"id": r["id"], "item_id": rec_id, "body": r["body"], "ordering": r["ordering"],
            "finished": _b(r["finished"]), "finished_time": timefmt.out(r["finished_at"]),
            "deadline": timefmt.out(r["deadline"]), "deadline_notif": _b(r["deadline_notif"]),
            "is_immutable": _b(r["is_immutable"])}


def list_steps(tx, row):
    rows = tx.all(_STEP_SQL + "WHERE rid = :rid AND deleted_at IS NULL ORDER BY ordering NULLS LAST, id", rid=row["rid"])
    return [_step_shape(r, row["id"]) for r in rows]


def steps(tx, p, kind, rec_id):
    row = _record(tx, p, kind, rec_id, right=engine.READ, for_update=False)
    return list_steps(tx, row)


def add_step(tx, p, actor, kind, rec_id, body):
    row = _record(tx, p, kind, rec_id)
    text = str((body or {}).get("body") or "").strip()
    if not text:
        raise errors.bad("Incorrect value for body: it is empty")
    order = tx.val("SELECT coalesce(max(ordering), 0) + 1 FROM occ.steps WHERE rid = :rid AND deleted_at IS NULL",
                   rid=row["rid"])
    sid = tx.val("INSERT INTO occ.steps (rid, body, ordering) VALUES (:rid, :b, :o) RETURNING id",
                 rid=row["rid"], b=text, o=order)
    _audit(tx, actor, kind.id, row, "step.add", "step", new=text, detail={"step_id": sid})
    S.touch(tx, p, row["rid"])
    return sid


def _step(tx, row, step_id):
    s = tx.one(_STEP_SQL + "WHERE rid = :rid AND id = :id AND deleted_at IS NULL", rid=row["rid"], id=step_id)
    if s is None:
        raise errors.not_found("No step with that id on this record")
    return s


def edit_step(tx, p, actor, kind, rec_id, step_id, body):
    row = _record(tx, p, kind, rec_id)
    s = _step(tx, row, step_id)
    body = body or {}
    changes = []
    action = body.get("action")
    if action == "finish":
        fin = not s["finished"]
        tx.run("UPDATE occ.steps SET finished = :f, finished_at = CASE WHEN :f THEN now() ELSE NULL END WHERE id = :id",
               f=fin, id=step_id)
        changes.append(("finished", _b(s["finished"]), _b(fin)))
    elif action not in (None, ""):
        raise errors.bad("Invalid action: %s" % action)
    for name, v in body.items():
        if name == "action":
            continue
        if name == "body":
            if s["is_immutable"]:
                raise errors.forbidden("This step is immutable.")
            text = str(v or "").strip()
            if not text:
                raise errors.bad("Incorrect value for body: it is empty")
            changes.append(("body", s["body"], text))
            tx.run("UPDATE occ.steps SET body = :b WHERE id = :id", b=text, id=step_id)
        elif name in ("is_immutable", "deadline_notif"):
            val = S._bool(name, v)
            changes.append((name, _b(s[name]), _b(val)))
            tx.run("UPDATE occ.steps SET %s = :v WHERE id = :id" % ident(name, STEP_FLAGS), v=val, id=step_id)
        elif name == "deadline":
            if v in (None, ""):
                val = None
            else:
                try:
                    val = timefmt.parse_datetime(v)
                except ValueError:
                    raise errors.bad("Incorrect value for deadline")
            changes.append(("deadline", timefmt.out(s["deadline"]), timefmt.out(val)))
            tx.run("UPDATE occ.steps SET deadline = :v WHERE id = :id", v=val, id=step_id)
        elif name == "ordering":
            val = S._int_strict(name, v)
            changes.append(("ordering", s["ordering"], val))
            tx.run("UPDATE occ.steps SET ordering = :v WHERE id = :id", v=val, id=step_id)
        elif name == "finished":
            fin = S._bool(name, v)
            tx.run("UPDATE occ.steps SET finished = :f, finished_at = CASE WHEN :f THEN coalesce(finished_at, now()) "
                   "ELSE NULL END WHERE id = :id", f=fin, id=step_id)
            changes.append(("finished", _b(s["finished"]), _b(fin)))
        else:
            raise errors.bad("Invalid update target: %s" % name)
    for target, old, new in changes:
        _audit(tx, actor, kind.id, row, "step.update", "step." + target, old=old, new=new, detail={"step_id": step_id})
    if changes:
        S.touch(tx, p, row["rid"])
    return _step_shape(_step(tx, row, step_id), row["id"])


def delete_step(tx, p, actor, kind, rec_id, step_id):
    row = _record(tx, p, kind, rec_id)
    s = _step(tx, row, step_id)
    tx.run("UPDATE occ.steps SET deleted_at = now() WHERE id = :id", id=step_id)
    _audit(tx, actor, kind.id, row, "step.delete", "step", old=s["body"], detail={"step_id": step_id})
    S.touch(tx, p, row["rid"])


def unfinished_steps(tx, p, scope=None):
    """My unfinished steps, or the team's with scope=team."""
    out = {"experiments": [], "items": []}
    for code in ("experiments", "items"):
        kind = K.KINDS[code]
        cond, params = engine.list_filter(p, engine.READ)
        who = "r.team_id = :team" if scope == "team" else "r.owner_id = :me"
        rows = tx.all("SELECT r.rid, r.id, r.title FROM occ.records r WHERE r.kind_id = :k AND r.state = 1 AND "
                      + who + " AND " + cond + " AND EXISTS (SELECT 1 FROM occ.steps st WHERE st.rid = r.rid AND "
                      "NOT st.finished AND st.deleted_at IS NULL) ORDER BY r.id DESC",
                      k=kind.id, team=p.team_id, me=p.user_id, **params)
        for r in rows:
            sts = [s for s in list_steps(tx, r) if not s["finished"]]
            out[code].append({"id": r["id"], "title": r["title"], "steps": sts})
    return out


# ------------------------------------------------------------------------------------------ links
def list_links(tx, row, target_code, related=False):
    target = K.KINDS[target_code]
    if related:
        join = "lk.from_rid = t.rid AND lk.to_rid = :rid"
    else:
        join = "lk.to_rid = t.rid AND lk.from_rid = :rid"
    rows = tx.all("SELECT t.id, t.title, t.custom_id, t.elabid, t.state, t.category_id, t.status_id, "
                  "c.title AS ct, c.color AS cc, s.title AS st, s.color AS sc, "
                  "EXISTS (SELECT 1 FROM occ.resource_booking rb WHERE rb.rid = t.rid AND rb.is_bookable) AS bookable "
                  "FROM occ.record_links lk JOIN occ.records t ON " + join +
                  " LEFT JOIN occ.categories c ON c.lookup_group = t.lookup_group AND c.id = t.category_id "
                  "LEFT JOIN occ.statuses s ON s.lookup_group = t.lookup_group AND s.id = t.status_id "
                  "WHERE t.kind_id = :k ORDER BY t.title, t.id", rid=row["rid"], k=target.id)
    page = "experiments.php" if target_code == "experiments" else "database.php"
    return [{"entityid": r["id"], "title": r["title"], "custom_id": r["custom_id"], "elabid": r["elabid"],
             "link_state": r["state"], "is_bookable": _b(r["bookable"]), "page": page, "type": target_code,
             "category_id": r["category_id"], "category_title": r["ct"], "category_color": r["cc"],
             "status_id": r["status_id"], "status_title": r["st"], "status_color": r["sc"]} for r in rows]


def links(tx, p, kind, rec_id, target_code):
    row = _record(tx, p, kind, rec_id, right=engine.READ, for_update=False)
    return list_links(tx, row, target_code)


def add_link(tx, p, actor, kind, rec_id, target_code, target_id, body):
    """Link to an experiment or resource. The path form and the body forms {id} and {target} all create
    the link."""
    body = body or {}
    if target_id is None:
        target_id = body.get("id", body.get("target"))
        if target_id in (None, ""):
            raise errors.bad("Which record to link to? Give its id in the path or as id.")
        target_id = S._int_strict("id", target_id)
    row = _record(tx, p, kind, rec_id)
    tkind = K.KINDS[target_code]
    trow = S.fetch(tx, p, tkind, target_id, full=False)
    if trow is None or trow["state"] == 3:
        raise errors.not_found("No %s with that id" % tkind.singular.lower())
    if not engine.check(p, trow, engine.READ):
        raise errors.forbidden("You cannot read the record you are linking to.")
    if trow["rid"] == row["rid"]:
        raise errors.bad("A record cannot link to itself.")
    made = []
    n = tx.run("INSERT INTO occ.record_links (from_rid, to_rid, created_by) VALUES (:f, :t, :u) ON CONFLICT DO NOTHING",
               f=row["rid"], t=trow["rid"], u=p.user_id)
    if n:
        made.append((target_code, target_id))
    if body.get("action") == "duplicate":
        rows = tx.all("SELECT lk.to_rid, t.kind_id, t.id FROM occ.record_links lk JOIN occ.records t ON t.rid = lk.to_rid "
                      "WHERE lk.from_rid = :t AND lk.to_rid <> :f", t=trow["rid"], f=row["rid"])
        for r in rows:
            if tx.run("INSERT INTO occ.record_links (from_rid, to_rid, created_by) VALUES (:f, :t, :u) "
                      "ON CONFLICT DO NOTHING", f=row["rid"], t=r["to_rid"], u=p.user_id):
                made.append((K.BY_ID[r["kind_id"]].code, r["id"]))
    for code, tid in made:
        _audit(tx, actor, kind.id, row, "link.add", code + "_links", new=str(tid))
    if made:
        S.touch(tx, p, row["rid"])


def remove_link(tx, p, actor, kind, rec_id, target_code, target_id):
    row = _record(tx, p, kind, rec_id)
    tkind = K.KINDS[target_code]
    trid = tx.val("SELECT rid FROM occ.records WHERE kind_id = :k AND id = :id", k=tkind.id, id=target_id)
    n = tx.run("DELETE FROM occ.record_links WHERE from_rid = :f AND to_rid = :t", f=row["rid"], t=trid) if trid else 0
    if not n:
        raise errors.not_found("This record has no such link")
    _audit(tx, actor, kind.id, row, "link.remove", target_code + "_links", old=str(target_id))
    S.touch(tx, p, row["rid"])


def copy_children(tx, src_rid, dst_rid, tags=True, steps=True, links=True):
    if tags:
        tx.run("INSERT INTO occ.record_tags (rid, tag_id) SELECT :d, tag_id FROM occ.record_tags WHERE rid = :s "
               "ON CONFLICT DO NOTHING", d=dst_rid, s=src_rid)
    if steps:
        tx.run("INSERT INTO occ.steps (rid, body, ordering, deadline, deadline_notif) SELECT :d, body, ordering, "
               "deadline, deadline_notif FROM occ.steps WHERE rid = :s AND deleted_at IS NULL ORDER BY ordering, id",
               d=dst_rid, s=src_rid)
    if links:
        tx.run("INSERT INTO occ.record_links (from_rid, to_rid, created_by) SELECT :d, to_rid, created_by "
               "FROM occ.record_links WHERE from_rid = :s AND to_rid <> :d ON CONFLICT DO NOTHING", d=dst_rid, s=src_rid)


# ---------------------------------------------------------------------------------------- uploads
def list_uploads(tx, row, states=(1,)):
    rows = tx.all("SELECT up.id, up.real_name, up.storage_name, up.comment, up.user_id, up.mime, up.created_at, "
                  "encode(up.sha256, 'hex') AS hash, up.size, up.state, up.immutable, u.firstname, u.lastname "
                  "FROM occ.uploads up JOIN occ.users u ON u.id = up.user_id WHERE up.rid = :rid "
                  "AND up.state = ANY(CAST(:st AS int[])) ORDER BY up.created_at, up.id", rid=row["rid"], st=list(states))
    return [{"id": r["id"], "real_name": r["real_name"], "long_name": r["storage_name"], "comment": r["comment"],
             "item_id": row["id"], "userid": r["user_id"], "type": K.BY_ID[row["kind_id"]].code, "mime": r["mime"],
             "created_at": timefmt.out(r["created_at"]),
             "hash": r["hash"], "hash_algorithm": "sha256", "storage": 1, "filesize": r["size"], "state": r["state"],
             "immutable": _b(r["immutable"]), "fullname": ("%s %s" % (r["firstname"], r["lastname"])).strip()}
            for r in rows]


def uploads(tx, p, kind, rec_id, state=None):
    row = _record(tx, p, kind, rec_id, right=engine.READ, for_update=False)
    states = S._int_list(state, "state") or [1]
    return list_uploads(tx, row, [s for s in states if s in (1, 2)] or [1])


# -------------------------------------------------------------------------------------- revisions
def revisions(tx, p, kind, rec_id):
    row = _record(tx, p, kind, rec_id, right=engine.READ, for_update=False)
    rows = tx.all("SELECT rv.id, rv.created_at, rv.user_id, rv.body_format, u.firstname, u.lastname "
                  "FROM occ.revisions rv JOIN occ.users u ON u.id = rv.user_id WHERE rv.rid = :rid "
                  "ORDER BY rv.created_at DESC, rv.id DESC", rid=row["rid"])
    return [{"id": r["id"], "created_at": timefmt.out(r["created_at"]), "userid": r["user_id"],
             "fullname": ("%s %s" % (r["firstname"], r["lastname"])).strip(), "content_type": r["body_format"]}
            for r in rows]


def revision(tx, p, kind, rec_id, rev_id):
    row = _record(tx, p, kind, rec_id, right=engine.READ, for_update=False)
    r = tx.one("SELECT id, body, body_format, created_at, user_id FROM occ.revisions WHERE rid = :rid AND id = :id",
               rid=row["rid"], id=rev_id)
    if r is None:
        raise errors.not_found("No revision with that id on this record")
    return {"id": r["id"], "body": r["body"], "content_type": r["body_format"],
            "created_at": timefmt.out(r["created_at"]), "userid": r["user_id"]}


def restore_revision(tx, p, actor, kind, rec_id, rev_id, body, base_url):
    if (body or {}).get("action") != "replace":
        raise errors.bad("Invalid action: use replace")
    probe = S.fetch(tx, p, kind, rec_id, full=False)
    if probe is not None and probe["locked"] and engine.check(p, probe, engine.READ):
        # reproduced from 2.x: 400, not the 423 other writes answer
        raise errors.bad("You cannot restore a revision of a locked item!")
    row = S._writable(tx, p, kind, rec_id)
    r = tx.one("SELECT body FROM occ.revisions WHERE rid = :rid AND id = :id", rid=row["rid"], id=rev_id)
    if r is None:
        raise errors.not_found("No revision with that id on this record")
    full = S.fetch(tx, p, kind, rec_id, full=True)
    cur = full["body"]
    if cur is not None and cur != r["body"]:
        import hashlib
        tx.run("INSERT INTO occ.revisions (rid, body, body_format, body_sha256, user_id) VALUES (:rid, :b, :f, :h, :u)",
               rid=row["rid"], b=cur, f=full["body_format"], h=hashlib.sha256(cur.encode("utf-8")).digest(), u=p.user_id)
    if cur != r["body"]:
        tx.run("UPDATE occ.records SET body = :b, body_text = :t WHERE rid = :rid",
               b=r["body"], t=S.body_text(r["body"]), rid=row["rid"])
        audit.write(tx, actor, "record.update", kind_id=kind.id, record_id=row["id"], rid=row["rid"],
                    team_id=row["team_id"], target="body", old=cur, new=r["body"], detail={"restored_revision": rev_id})
        S.touch(tx, p, row["rid"])
    return S.read(tx, p, kind, rec_id, base_url)
