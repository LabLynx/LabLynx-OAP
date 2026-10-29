# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Writes to inventory lists (storage units and compounds), the usage report and site assets (the
logos, favicon and sign-in image).

Inventory rights: while site setting inventory_require_edit_rights (or
compounds_require_edit_rights) is off, any member of a team may add, change and delete; while it
is on, only people with can_manage_inventory_locations (can_manage_compounds) and sysadmins.
"""
import csv
import io
import re

from .. import errors
from ..audit import writer as audit
from ..db import ident
from ..files import store as store_mod
from . import config
from . import site


def _writer(p):
    if not p.can_write:
        raise errors.forbidden("This API key is read-only.")
    if not p.member_teams and not p.is_sysadmin:
        raise errors.forbidden("You are not a member of any team.")


def _right(tx, p, setting, column):
    _writer(p)
    if p.is_sysadmin or not config.flag(tx, setting):
        return
    if not tx.val("SELECT %s FROM occ.users WHERE id = :u" % ident(column, _RIGHT_COLUMNS), u=p.user_id):
        raise errors.forbidden("Sorry, you are not allowed to perform that action.")


_RIGHT_COLUMNS = frozenset(("can_manage_inventory_locations", "can_manage_compounds"))


# ------------------------------------------------------------------------------ storage units
def _unit_name(v):
    t = "" if v is None else str(v).strip()
    if not t or len(t) > 255:
        raise errors.bad("Incorrect value for name")
    return t


def _parent(tx, v, self_id=None):
    if v in (None, "", 0, "0"):
        return None
    try:
        pid = int(v)
    except (TypeError, ValueError):
        raise errors.bad("Incorrect value for parent_id")
    if not tx.val("SELECT 1 FROM occ.storage_units WHERE id = :i", i=pid):
        raise errors.bad("Incorrect value for parent_id: no such storage unit")
    if self_id is not None:
        # moving under itself or one of its own descendants would make a loop
        loop = tx.val("""WITH RECURSIVE up AS (SELECT id, parent_id FROM occ.storage_units WHERE id = :p
                          UNION ALL SELECT s.id, s.parent_id FROM occ.storage_units s JOIN up ON s.id = up.parent_id)
                         SELECT 1 FROM up WHERE id = :me LIMIT 1""", p=pid, me=self_id)
        if loop:
            raise errors.bad("A storage unit cannot be moved inside itself")
    return pid


def create_unit(tx, p, actor, body):
    _right(tx, p, "inventory_require_edit_rights", "can_manage_inventory_locations")
    body = body or {}
    name = _unit_name(body.get("name"))
    parent = _parent(tx, body.get("parent_id"))
    uid = tx.val("INSERT INTO occ.storage_units (name, parent_id) VALUES (:n, :p) RETURNING id", n=name, p=parent)
    audit.write(tx, actor, "storage.create", target="storage_unit", new=name, detail={"unit_id": uid, "parent": parent})
    return uid


def _unit(tx, unit_id):
    r = tx.one("SELECT * FROM occ.storage_units WHERE id = :i FOR UPDATE", i=unit_id)
    if r is None:
        raise errors.not_found()
    return r


def patch_unit(tx, p, actor, unit_id, body):
    _right(tx, p, "inventory_require_edit_rights", "can_manage_inventory_locations")
    body = body or {}
    r = _unit(tx, unit_id)
    if "name" in body:
        name = _unit_name(body["name"])
        if name != r["name"]:
            tx.run("UPDATE occ.storage_units SET name = :n WHERE id = :i", n=name, i=unit_id)
            audit.write(tx, actor, "storage.update", target="name", old=r["name"], new=name, detail={"unit_id": unit_id})
    if "parent_id" in body:
        parent = _parent(tx, body["parent_id"], self_id=unit_id)
        if parent != r["parent_id"]:
            tx.run("UPDATE occ.storage_units SET parent_id = :p WHERE id = :i", p=parent, i=unit_id)
            audit.write(tx, actor, "storage.update", target="parent_id", old=r["parent_id"], new=parent,
                        detail={"unit_id": unit_id})
    if "name" not in body and "parent_id" not in body:
        raise errors.bad("Nothing to change: send name or parent_id")
    return next(u for u in site.list_storage_units(tx, p) if u["id"] == unit_id)


def delete_unit(tx, p, actor, unit_id):
    _right(tx, p, "inventory_require_edit_rights", "can_manage_inventory_locations")
    r = _unit(tx, unit_id)
    if tx.val("SELECT 1 FROM occ.storage_units WHERE parent_id = :i LIMIT 1", i=unit_id):
        raise errors.bad("Cannot delete a storage unit with children!")
    if tx.val("SELECT 1 FROM occ.record_containers WHERE storage_unit_id = :i LIMIT 1", i=unit_id):
        raise errors.bad("Cannot delete a storage unit that holds containers!")
    tx.run("DELETE FROM occ.storage_units WHERE id = :i", i=unit_id)
    audit.write(tx, actor, "storage.delete", target="storage_unit", old=r["name"], detail={"unit_id": unit_id})


# ---------------------------------------------------------------------------------- compounds
COMPOUND_TEXT = frozenset(("name", "iupac_name", "molecular_formula", "cas_number", "inchi", "inchi_key", "smiles"))
COMPOUND_NUM = frozenset(("molecular_weight", "pubchem_cid"))
COMPOUND_COLUMNS = COMPOUND_TEXT | COMPOUND_NUM
_EXTRA_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_LIMITS = {"cas_number": 20, "inchi_key": 27}


def _compound_values(body):
    cols, ids, haz = {}, {}, {}
    for k, v in body.items():
        if k in ("id", "team", "userid", "state", "created_at", "created_by", "modified_at", "modified_by"):
            continue
        if k in COMPOUND_TEXT:
            t = None if v in (None, "") else str(v).strip()
            if t is not None and k in _LIMITS and len(t) > _LIMITS[k]:
                raise errors.bad("Incorrect value for %s: too long" % k)
            cols[k] = t
        elif k == "molecular_weight":
            try:
                cols[k] = round(float(v or 0), 2)
            except (TypeError, ValueError):
                raise errors.bad("Incorrect value for molecular_weight")
        elif k == "pubchem_cid":
            try:
                cols[k] = None if v in (None, "") else int(v)
            except (TypeError, ValueError):
                raise errors.bad("Incorrect value for pubchem_cid")
        elif _EXTRA_NAME.match(k):
            if k.startswith("is_"):
                haz[k] = str(v).strip().lower() in ("1", "true", "on", "yes")
            else:
                ids[k] = None if v in (None, "") else str(v)
        else:
            raise errors.bad("Unknown compound field: %s" % k[:64])
    return cols, ids, haz


def _compound_team(p):
    return p.team_id if p.team_id in p.member_teams else (min(p.member_teams) if p.member_teams else None)


def create_compound(tx, p, actor, body):
    _right(tx, p, "compounds_require_edit_rights", "can_manage_compounds")
    body = body or {}
    cols, ids, haz = _compound_values(body)
    if not cols.get("name") and not cols.get("cas_number") and not cols.get("smiles"):
        raise errors.bad("A compound needs at least a name, a CAS number or a SMILES")
    team = _compound_team(p)
    if team is None:
        raise errors.forbidden("You are not a member of any team.")
    cid = tx.val("INSERT INTO occ.compounds (team_id, user_id, created_by, modified_by, identifiers, hazards) "
                 "VALUES (:t, :u, :u, :u, CAST(:i AS jsonb), CAST(:h AS jsonb)) RETURNING id", t=team, u=p.user_id,
                 i=_json(ids), h=_json(haz))
    for k, v in cols.items():
        tx.run("UPDATE occ.compounds SET %s = :v WHERE id = :i" % ident(k, COMPOUND_COLUMNS), v=v, i=cid)
    audit.write(tx, actor, "compound.create", team_id=team, target="compound", new=cols.get("name"),
                detail={"compound_id": cid})
    return cid


def _json(d):
    from ..db import jsonb
    return jsonb(d)


def _compound(tx, p, compound_id):
    r = tx.one("SELECT * FROM occ.compounds WHERE id = :i FOR UPDATE", i=compound_id)
    if r is None or r["state"] == 3 or (r["team_id"] not in p.member_teams and not p.is_sysadmin):
        raise errors.not_found()
    return r


def patch_compound(tx, p, actor, compound_id, body):
    _right(tx, p, "compounds_require_edit_rights", "can_manage_compounds")
    r = _compound(tx, p, compound_id)
    cols, ids, haz = _compound_values(body or {})
    if not (cols or ids or haz):
        raise errors.bad("Nothing to change")
    for k, v in cols.items():
        old = r[k]
        if (float(old) if k == "molecular_weight" and old is not None else old) == v:
            continue
        tx.run("UPDATE occ.compounds SET %s = :v WHERE id = :i" % ident(k, COMPOUND_COLUMNS), v=v, i=compound_id)
        audit.write(tx, actor, "compound.update", team_id=r["team_id"], target=k, old=old, new=v,
                    detail={"compound_id": compound_id})
    for field, extra, col in (("identifiers", ids, "identifiers"), ("hazards", haz, "hazards")):
        if not extra:
            continue
        merged = dict(r[col] or {})
        for k, v in extra.items():
            if merged.get(k) != v:
                audit.write(tx, actor, "compound.update", team_id=r["team_id"], target=k, old=merged.get(k), new=v,
                            detail={"compound_id": compound_id})
                merged[k] = v
        if col == "identifiers":
            tx.run("UPDATE occ.compounds SET identifiers = CAST(:v AS jsonb) WHERE id = :i", v=_json(merged),
                   i=compound_id)
        else:
            tx.run("UPDATE occ.compounds SET hazards = CAST(:v AS jsonb) WHERE id = :i", v=_json(merged), i=compound_id)
    tx.run("UPDATE occ.compounds SET modified_at = now(), modified_by = :u WHERE id = :i", u=p.user_id, i=compound_id)
    return site.get_compound(tx, p, compound_id)


def delete_compound(tx, p, actor, compound_id):
    _right(tx, p, "compounds_require_edit_rights", "can_manage_compounds")
    r = _compound(tx, p, compound_id)
    tx.run("UPDATE occ.compounds SET state = 3, modified_at = now(), modified_by = :u WHERE id = :i",
           u=p.user_id, i=compound_id)
    audit.write(tx, actor, "compound.delete", team_id=r["team_id"], target="state", old=r["state"], new=3,
                detail={"compound_id": compound_id})


# -------------------------------------------------------------------------------- usage report
REPORT_HELP = {"query_parameters": {"format": ["csv", "json (not implemented)"], "scope": ["instance", "team"]}}
REPORT_COLUMNS = ("userid", "firstname", "lastname", "email", "team", "team_name", "is_admin", "is_sysadmin",
                  "validated", "archived", "experiments", "items", "templates", "uploads", "uploads_size",
                  "last_login")


def report(tx, p, q):
    """Without format: what the report accepts (reproduced). format=csv: one row per person and team
    with their counts; scope=instance (sysadmin) or team (the caller's current team, team admin)."""
    fmt = q.get("format")
    scope = q.get("scope") or "instance"
    if scope not in ("instance", "team"):
        raise errors.bad("Incorrect value for scope: instance or team")
    if scope == "instance" and not p.is_sysadmin:
        raise errors.forbidden("Sorry, you are not allowed to perform that action.")
    if scope == "team" and not (p.is_sysadmin or p.team_id in p.admin_teams):
        raise errors.forbidden("Sorry, you are not allowed to perform that action.")
    if not fmt:
        return REPORT_HELP
    if fmt != "csv":
        raise errors.bad("Incorrect value for format: csv (json is not implemented)")
    params = {}
    where = ""
    if scope == "team":
        where = " WHERE m.team_id = :t"
        params["t"] = p.team_id
    rows = tx.all("""
        SELECT u.id AS userid, u.firstname, u.lastname, u.email, m.team_id AS team, t.name AS team_name,
               m.is_admin, u.is_sysadmin, u.validated, m.is_archived AS archived, u.last_login_at AS last_login,
               (SELECT count(*) FROM occ.records r WHERE r.owner_id = u.id AND r.team_id = m.team_id
                  AND r.kind_id = 1 AND r.state <> 3) AS experiments,
               (SELECT count(*) FROM occ.records r WHERE r.owner_id = u.id AND r.team_id = m.team_id
                  AND r.kind_id = 2 AND r.state <> 3) AS items,
               (SELECT count(*) FROM occ.records r WHERE r.owner_id = u.id AND r.team_id = m.team_id
                  AND r.kind_id IN (3, 4) AND r.state <> 3) AS templates,
               (SELECT count(*) FROM occ.uploads up JOIN occ.records r ON r.rid = up.rid
                 WHERE up.user_id = u.id AND r.team_id = m.team_id AND up.state <> 3) AS uploads,
               (SELECT coalesce(sum(up.size), 0) FROM occ.uploads up JOIN occ.records r ON r.rid = up.rid
                 WHERE up.user_id = u.id AND r.team_id = m.team_id AND up.state <> 3) AS uploads_size
          FROM occ.memberships m JOIN occ.users u ON u.id = m.user_id JOIN occ.teams t ON t.id = m.team_id""" +
                  where + " ORDER BY m.team_id, u.id", **params)
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(REPORT_COLUMNS)
    for r in rows:
        w.writerow([_csv(r[c]) for c in REPORT_COLUMNS])
    return buf.getvalue()


def _csv(v):
    if isinstance(v, bool):
        return 1 if v else 0
    if v is None:
        return ""
    if hasattr(v, "strftime"):
        from .. import timefmt
        return timefmt.out(v)
    return v


# --------------------------------------------------------------------------------- site assets
ASSET_NAMES = frozenset(("logo", "logo_dark", "favicon", "login_image"))
ASSET_TYPES = {"image/png", "image/jpeg", "image/svg+xml", "image/webp", "image/gif", "image/x-icon",
               "image/vnd.microsoft.icon"}
ASSET_MAX = 5 * 1024 * 1024


def asset_name(name):
    if name not in ASSET_NAMES:
        raise errors.not_found("No site asset with that name")
    return name


def read_asset(tx, store, name):
    asset_name(name)
    r = tx.one("SELECT mime, sha256 FROM occ.site_assets WHERE name = :n", n=name)
    if r is None:
        raise errors.not_found("No site asset with that name")
    return r["mime"], store.open(bytes(r["sha256"]))


def put_asset(tx, p, actor, store, name, data, mime):
    if not p.is_sysadmin:
        raise errors.forbidden("Only a sysadmin can do that.")
    if not p.can_write:
        raise errors.forbidden("This API key is read-only.")
    asset_name(name)
    mime = (mime or "").split(";")[0].strip().lower()
    if mime not in ASSET_TYPES:
        raise errors.bad("Incorrect file type: an image (PNG, JPEG, SVG, WebP, GIF or ICO)")
    if not data:
        raise errors.bad("The file is empty")
    if len(data) > ASSET_MAX:
        raise errors.OCCError(413, "The file is larger than the %d MB a site asset may be." % (ASSET_MAX >> 20))
    sha, size = store.put_bytes(data)
    store_mod.register(tx, store, sha, size)
    old = tx.one("SELECT sha256 FROM occ.site_assets WHERE name = :n FOR UPDATE", n=name)
    tx.run("INSERT INTO occ.site_assets (name, mime, sha256, updated_by) VALUES (:n, :m, :s, :u) "
           "ON CONFLICT (name) DO UPDATE SET mime = EXCLUDED.mime, sha256 = EXCLUDED.sha256, updated_at = now(), "
           "updated_by = EXCLUDED.updated_by", n=name, m=mime, s=sha, u=p.user_id)
    audit.write(tx, actor, "config.update", target="asset.%s" % name,
                old=bytes(old["sha256"]).hex() if old else None, new=sha.hex(), detail={"size": size, "mime": mime})
    if old and bytes(old["sha256"]) != sha:
        store_mod.delete_if_unreferenced(tx, store, bytes(old["sha256"]))
    return {"name": name, "mime": mime, "size": size, "sha256": sha.hex()}
