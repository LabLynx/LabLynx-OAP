# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Read sides of site and team lists the administration screens open: identity providers, the
export queue, storage units, compounds and procurement requests; and the write policy switch
(read-only mode).

Writes to identity providers are in config.py, and to storage units and compounds in siteops.py.
"""
from .. import errors, timefmt
from ..audit import writer as audit


def _int(v, name):
    try:
        return int(v)
    except (TypeError, ValueError):
        raise errors.bad("Incorrect value for %s" % name)


def _b(v):
    return 1 if v else 0


def _sysadmin(p):
    if not p.is_sysadmin:
        raise errors.forbidden("Only a sysadmin can do that.")


# ------------------------------------------------------------------------- identity providers
def _idp_shape(r):
    return {"id": r["id"], "name": r["name"], "entityid": r["entityid"], "enabled": _b(r["enabled"]),
            "source": r["source_id"], "email_attr": r["email_attr"], "team_attr": r["team_attr"] or "",
            "fname_attr": r["fname_attr"], "lname_attr": r["lname_attr"], "orgid_attr": r["orgid_attr"],
            "orcid_attr": r["orcid_attr"], "created_at": timefmt.out(r["created_at"]),
            "modified_at": timefmt.out(r["modified_at"])}


def list_idps(tx, p):
    _sysadmin(p)
    return [_idp_shape(r) for r in tx.all("SELECT * FROM occ.idps ORDER BY id")]


def get_idp(tx, p, idp_id):
    _sysadmin(p)
    r = tx.one("SELECT * FROM occ.idps WHERE id = :id", id=idp_id)
    if r is None:
        raise errors.not_found()
    return _idp_shape(r)


def list_idp_sources(tx, p):
    _sysadmin(p)
    return [{"id": r["id"], "url": r["url"], "auto_refresh": _b(r["auto_refresh"]), "enabled": _b(r["enabled"]),
             "last_fetched_at": timefmt.out(r["last_fetched_at"])}
            for r in tx.all("SELECT * FROM occ.idp_sources ORDER BY id")]


# ------------------------------------------------------------------------------------- exports
def list_exports(tx, p):
    sql = "SELECT * FROM occ.exports"
    params = {}
    if not p.is_sysadmin:
        sql += " WHERE requester_id = :u"
        params["u"] = p.user_id
    rows = tx.all(sql + " ORDER BY id DESC", **params)
    return [{"id": r["id"], "created_at": timefmt.out(r["created_at"]), "requester_userid": r["requester_id"],
             "state": r["state"], "format": r["format"], "real_name": r["real_name"], "filesize": r["filesize"],
             "hash": bytes(r["sha256"]).hex() if r["sha256"] is not None else None, "error": r["error"],
             "team": r["team_id"], "modified_at": timefmt.out(r["modified_at"])} for r in rows]


# ------------------------------------------------------------------------------ storage units
def list_storage_units(tx, p, hierarchy=None):
    rows = tx.all("""
        WITH RECURSIVE tree AS (
            SELECT id, name, parent_id, name::text AS full_path, 0 AS depth FROM occ.storage_units WHERE parent_id IS NULL
            UNION ALL
            SELECT s.id, s.name, s.parent_id, tree.full_path || ' > ' || s.name, tree.depth + 1
            FROM occ.storage_units s JOIN tree ON s.parent_id = tree.id WHERE tree.depth < 50)
        SELECT t.id, t.name, t.parent_id, t.full_path, t.depth,
               (SELECT count(*) FROM occ.storage_units c WHERE c.parent_id = t.id) AS children_count
        FROM tree t ORDER BY t.full_path, t.id""")
    return [{"id": r["id"], "name": r["name"], "parent_id": r["parent_id"], "full_path": r["full_path"],
             "level_depth": r["depth"], "children_count": r["children_count"]} for r in rows]


# ---------------------------------------------------------------------------------- compounds
# Registry identifiers always present in the answer, as the filed probe answer shows them; the other
# registry identifiers appear when stored.
_IDENT = ("ec_number", "chebi_id")


def _compound_shape(r):
    out = {"id": r["id"], "created_at": timefmt.out(r["created_at"]), "created_by": r["created_by"],
           "modified_at": timefmt.out(r["modified_at"]), "modified_by": r["modified_by"], "userid": r["user_id"],
           "team": r["team_id"], "state": r["state"], "name": r["name"], "iupac_name": r["iupac_name"],
           "molecular_formula": r["molecular_formula"], "molecular_weight": float(r["molecular_weight"] or 0),
           "cas_number": r["cas_number"], "pubchem_cid": r["pubchem_cid"], "inchi": r["inchi"],
           "inchi_key": r["inchi_key"], "smiles": r["smiles"]}
    ids = r["identifiers"] or {}
    for k in _IDENT:
        out[k] = ids.get(k)
    for k, v in ids.items():
        out.setdefault(k, v)
    for k, v in (r["hazards"] or {}).items():
        out[k] = _b(v) if isinstance(v, bool) else v
    return out


def _compound_teams(p):
    if not p.member_teams and not p.site_scope:
        raise errors.forbidden("You are not a member of any team.")
    return sorted(p.member_teams)


def list_compounds(tx, p, q=None, limit=None, offset=None):
    params = {}
    sql = "SELECT * FROM occ.compounds c WHERE c.state <> 3"
    if not p.site_scope:
        sql += " AND c.team_id = ANY(CAST(:t AS int[]))"
        params["t"] = _compound_teams(p)
    if q:
        sql += " AND (c.name ILIKE :q OR c.cas_number ILIKE :q OR c.molecular_formula ILIKE :q OR c.iupac_name ILIKE :q)"
        params["q"] = "%" + str(q).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    sql += " ORDER BY c.name NULLS LAST, c.id"
    if limit not in (None, ""):
        sql += " LIMIT :lim"
        params["lim"] = _int(limit, "limit")
    if offset not in (None, ""):
        sql += " OFFSET :off"
        params["off"] = _int(offset, "offset")
    return [_compound_shape(r) for r in tx.all(sql, **params)]


def get_compound(tx, p, compound_id):
    r = tx.one("SELECT * FROM occ.compounds WHERE id = :id", id=compound_id)
    if r is None or (not p.site_scope and r["team_id"] not in p.member_teams):
        raise errors.not_found()
    return _compound_shape(r)


# ------------------------------------------------------------------------ procurement requests
def list_procurement(tx, p, team):
    team_id = p.team_id if str(team) == "current" else _int(team, "team")
    if team_id not in p.member_teams and not p.is_sysadmin and not p.site_scope:
        raise errors.forbidden("You are not a member of that team.")
    rows = tx.all("SELECT pr.*, r.id AS entity_id, r.title AS entity_title, u.firstname, u.lastname "
                  "FROM occ.procurement_requests pr JOIN occ.records r ON r.rid = pr.rid "
                  "JOIN occ.users u ON u.id = pr.requester_id WHERE pr.team_id = :t ORDER BY pr.id DESC", t=team_id)
    return [{"id": r["id"], "team": r["team_id"], "requester_userid": r["requester_id"],
             "requester_fullname": ("%s %s" % (r["firstname"], r["lastname"])).strip(), "entity_id": r["entity_id"],
             "entity_title": r["entity_title"], "qty_ordered": r["qty_ordered"], "qty_received": r["qty_received"],
             "body": r["body"], "quote": r["quote"], "email_sent_at": timefmt.out(r["email_sent_at"]),
             "state": r["state"], "created_at": timefmt.out(r["created_at"])} for r in rows]


# ------------------------------------------------------------------------------- write policy
def read_only_on(tx):
    return str(tx.val("SELECT value FROM occ.site_config WHERE name = 'read_only' AND NOT is_secret") or "0") \
        in ("1", "true", "yes")


def set_write_policy(tx, p, actor, body):
    """Set read-only mode (sysadmin): {read_only: 0|1, banner?}. The banner texts are fixed, so every
    site says the same thing; a banner sent here is kept as a note shown under them, '' removes it."""
    _sysadmin(p)
    if not p.can_write:
        raise errors.forbidden("This API key is read-only.")
    body = body or {}
    if "read_only" not in body and "banner" not in body:
        raise errors.bad("Nothing to change: send read_only and/or banner")
    for name, value in (("read_only", body.get("read_only")), ("write_policy_note", body.get("banner"))):
        if name == "read_only" and "read_only" in body:
            v = str(value).strip().lower()
            if v not in ("0", "1", "true", "false"):
                raise errors.bad("Incorrect value for read_only: 0 or 1")
            new = "1" if v in ("1", "true") else "0"
        elif name == "write_policy_note" and "banner" in body:
            new = str(value or "").strip()[:500]
        else:
            continue
        old = tx.val("SELECT value FROM occ.site_config WHERE name = :n", n=name)
        if old == new:
            continue
        tx.run("INSERT INTO occ.site_config (name, value, updated_by) VALUES (:n, :v, :u) ON CONFLICT (name) DO "
               "UPDATE SET value = EXCLUDED.value, updated_at = now(), updated_by = EXCLUDED.updated_by",
               n=name, v=new, u=p.user_id)
        audit.write(tx, actor, "config.update", target=name, old=old, new=new)


def write_policy(tx, p):
    ro = read_only_on(tx)
    can = bool(p.can_write and (not ro or p.write_exempt))
    banner = ("LabLynx.One 3.x on OCC: changes made here stay in 3.x" if can
              else "LabLynx.One 3.x on OCC: read-only preview")
    note = tx.val("SELECT value FROM occ.site_config WHERE name = 'write_policy_note' AND NOT is_secret") or None
    return {"read_only": 1 if ro else 0, "banner": banner, "caller_can_write": 1 if can else 0, "note": note}
