# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The eLabFTW 5.6.12 to OCC data mapping (docs/design/mapping.json).

Every one of the 84 eLabFTW tables is named here exactly once: carried (with a Spec saying how
each row becomes OCC values), derived, or not carried with the reason. tests/unit/test_migrate_2x.py
proves this list equals mapping.json.

A Spec's build(row, ctx) turns one 2.x row into the OCC values it writes, ids resolved through ctx
and times in UTC; the same dict, normalized by canon.py, is the row's canonical form and content
hash. build() returns a Skip with a reason for a row that cannot be carried (its parent record
does not exist in 2.x, its file bytes cannot be read, ...); a skip is reported, never silent.
Transformations that keep a row but change a value (a category that does not exist in 2.x
becomes none, a template's missing elabid is generated) are noted through ctx.note().

Styles:
  keep    the 2.x id is the OCC key, so links and URLs keep working: users, teams, groups, lookups, records, tags, uploads,
          events, storage units, compounds, keys, identity providers, settings, assets
  new     the OCC numbers the row; occ.id_map keeps the 2.x id (comments, steps, revisions,
          request actions, containers, notifications, to-do items)
  pair    an association with a composite key (memberships, group members, record tags, links,
          pins, favorite tags, record compounds)
  audit   history, appended to occ.audit_events and never changed (changelogs, audit log,
          storage moves)
"""
import base64
import datetime as dt
import hashlib
import json
import mimetypes
import re
import uuid
from dataclasses import dataclass, field

from . import canon

# ----------------------------------------------------------------------------- 2.x kinds and tables
KIND_IDS = {"experiments": 1, "items": 2, "experiments_templates": 3, "items_types": 4}
LOOKUP_GROUP = {1: 1, 2: 2, 3: 1, 4: 2}

NOT_CARRIED = {
    "authfail": "password sign-in failures; the OCC has no password sign-in",
    "lockout_devices": "password sign-in lockout; no password sign-in",
    "experiments_edit_mode": "transient editing lock; expires",
    "experiments_templates_edit_mode": "transient editing lock; expires",
    "items_edit_mode": "transient editing lock; expires",
    "items_types_edit_mode": "transient editing lock; expires",
    "exports": "export queue files are regenerated on demand",
    "instance2rors": "empty; research-organization registry links are not used by 2.x New",
    "teams2rors": "empty; not used by 2.x New",
    "users2rors": "empty; not used by 2.x New",
}
DERIVED = {
    "compounds_fingerprints": "structure-search index; rebuilt if structure search is ever added",
}


class Skip:
    __slots__ = ("reason",)

    def __init__(self, reason):
        self.reason = reason


@dataclass
class Spec:
    src: str                       # 2.x table
    occ: str                       # OCC table
    style: str                     # keep | new | pair | audit
    cols: tuple                    # OCC columns written and compared
    build: object                  # (row, ctx) -> dict | Skip
    key: tuple = ("id",)           # OCC key columns (keep, pair)
    sid: object = None             # row -> source id text (default: str(row["id"]))
    detect: str = "fingerprint"    # modified | append | fingerprint
    parent: str = None             # fingerprint narrowing: a 2.x column (or expression name in PARENTS)
    removable: bool = True         # a row gone from 2.x is removed from the OCC
    written_only: tuple = ()       # OCC columns written but not compared (derived from compared ones)
    kind: int = None               # record kind, for record specs
    fp_cols: tuple = None          # 2.x columns the fingerprint covers (default: all)
    src_order: str = "id"
    extra: dict = field(default_factory=dict)

    def source_id(self, row):
        return self.sid(row) if self.sid else str(row["id"])


# ------------------------------------------------------------------------------------- helpers
def b(v):
    return None if v is None else bool(v)


def i(v):
    return None if v is None else int(v)


def text(v):
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray)):
        v = v.decode("utf-8", "replace")
    return str(v).replace("\x00", "")


def lists_of(obj):
    obj = canon.json_value(obj)
    obj = obj if isinstance(obj, dict) else {}
    out = {}
    for key in ("teams", "users", "teamgroups"):
        vals = obj.get(key) or []
        try:
            out[key] = sorted({int(x) for x in vals if str(x).strip().lstrip("-").isdigit()})
        except (TypeError, ValueError):
            out[key] = []
    return out


def access_rows(row):
    """canread/canwrite/canbook lists as (right, principal, id) rows, the form record_access holds."""
    out = set()
    for col, right in (("canread", "r"), ("canwrite", "w"), ("canbook", "b")):
        if col not in row:
            continue
        ls = lists_of(row[col])
        for key, pr in (("teams", "t"), ("users", "u"), ("teamgroups", "g")):
            for pid in ls[key]:
                out.add((right, pr, pid))
    return sorted([list(x) for x in out])


def template_elabid(kind, rec_id, created_at):
    """2.x templates have no elabid; the OCC gives every record one. Generated from the 2.x identity
    so a re-run produces the same value instead of a new one each time."""
    day = (created_at or dt.datetime(2000, 1, 1, tzinfo=dt.timezone.utc)).strftime("%Y%m%d")
    return "%s-%s" % (day, hashlib.sha1(("elabftw-5.6.12:%d:%d" % (kind, rec_id)).encode()).hexdigest())


def minisign_key_id(pubkey):
    """The minisign key id (hex, as minisign prints it) from a public key file's text."""
    try:
        lines = [x for x in (pubkey or "").splitlines() if x.strip() and not x.startswith("untrusted comment")]
        raw = base64.b64decode(lines[-1].strip())
        return raw[2:10][::-1].hex().upper()
    except Exception:
        return None


def mime_of(name):
    return mimetypes.guess_type(name or "")[0] or "application/octet-stream"


# ------------------------------------------------------------------------------ identity, teams
USER_PREF_SKIP = frozenset(("userid", "password_hash", "password_modified_at", "mfa_secret", "token",
                            "token_created_at", "auth_lock_time", "firstname", "lastname", "email", "is_sysadmin",
                            "orcid", "orgid", "created_at", "validated", "valid_until", "auth_service",
                            "default_read_base", "default_write_base", "default_read", "default_write",
                            "can_manage_users2teams", "can_manage_compounds", "can_manage_inventory_locations",
                            "last_login"))
_DEFAULT_LISTS = {"teams": [], "users": [], "teamgroups": []}


def build_user(r, ctx):
    prefs = {k: canon.norm(v) for k, v in r.items() if k not in USER_PREF_SKIP}
    return {"id": r["userid"], "email": text(r["email"]).strip(), "firstname": text(r["firstname"]) or "",
            "lastname": text(r["lastname"]) or "", "orcid": text(r.get("orcid")) or None,
            "orgid": text(r.get("orgid")) or None, "is_sysadmin": bool(r.get("is_sysadmin")),
            "validated": bool(r.get("validated")), "valid_until": r.get("valid_until"),
            "auth_service": i(r.get("auth_service")),
            "can_manage_users2teams": bool(r.get("can_manage_users2teams")),
            "can_manage_compounds": bool(r.get("can_manage_compounds")),
            "can_manage_inventory_locations": bool(r.get("can_manage_inventory_locations")),
            "default_read_base": i(r.get("default_read_base")) or 30,
            "default_write_base": i(r.get("default_write_base")) or 20,
            "default_read": lists_of(r.get("default_read")) if r.get("default_read") else dict(_DEFAULT_LISTS),
            "default_write": lists_of(r.get("default_write")) if r.get("default_write") else dict(_DEFAULT_LISTS),
            "prefs": prefs, "created_at": r.get("created_at"), "last_login_at": r.get("last_login")}


TEAM_BOOLS = ("visible", "user_create_tag", "force_exp_tpl", "force_res_tpl", "users_canwrite_experiments",
              "users_canwrite_experiments_categories", "users_canwrite_experiments_status",
              "users_canwrite_experiments_templates", "users_canwrite_resources",
              "users_canwrite_resources_categories", "users_canwrite_resources_status",
              "users_canwrite_resources_templates", "onboarding_email_active", "newcomer_banner_active")
TEAM_TEXTS = ("orgid", "announcement", "onboarding_email_subject", "onboarding_email_body", "newcomer_banner")


def build_team(r, ctx):
    out = {"id": r["id"], "name": text(r["name"]), "created_at": r.get("created_at")}
    for c in TEAM_BOOLS:
        out[c] = bool(r.get(c)) if r.get(c) is not None else (c not in ("force_exp_tpl", "force_res_tpl"))
    for c in TEAM_TEXTS:
        out[c] = text(r.get(c))
    out["newcomer_threshold"] = i(r.get("newcomer_threshold")) if r.get("newcomer_threshold") is not None else 15
    return out


def build_membership(r, ctx):
    if not ctx.has("users", r["users_id"]) or not ctx.has("teams", r["teams_id"]):
        return Skip("its person or team does not exist in 2.x")
    return {"user_id": r["users_id"], "team_id": r["teams_id"], "is_admin": bool(r.get("is_admin")),
            "is_owner": bool(r.get("is_owner")), "is_archived": bool(r.get("is_archived"))}


def build_group(r, ctx):
    if not ctx.has("teams", r["team"]):
        return Skip("its team does not exist in 2.x")
    return {"id": r["id"], "team_id": r["team"], "name": text(r["name"]) or ""}


def build_group_member(r, ctx):
    if not ctx.has("team_groups", r["groupid"]) or not ctx.has("users", r["userid"]):
        return Skip("its group or person does not exist in 2.x")
    return {"group_id": r["groupid"], "user_id": r["userid"]}


# ------------------------------------------------------------------------------------- lookups
def lookup_builder(group, kind_name):
    table = "categories" if kind_name == "categories" else "statuses"

    def build(r, ctx):
        if not ctx.has("teams", r["team"]):
            return Skip("its team does not exist in 2.x")
        color = (text(r.get("color")) or "29AEB9").lstrip("#")
        if not re.fullmatch(r"[0-9A-Fa-f]{6}", color):
            ctx.note("color_replaced", "%s %s: color %r is not 6 hex digits; 29AEB9 used" % (table, r["id"], color))
            color = "29AEB9"
        state = i(r.get("state")) or 1
        return {"lookup_group": group, "id": r["id"], "team_id": r["team"], "title": text(r["title"]) or "",
                "color": color, "is_private": bool(r.get("is_private")), "is_default": False,
                "ordering": i(r.get("ordering")), "state": state if state in (1, 2, 3) else 1,
                "created_at": r.get("created_at"), "modified_at": r.get("modified_at")}
    return build


# ------------------------------------------------------------------------------------- records
RECORD_COLS = ("kind_id", "id", "elabid", "team_id", "owner_id", "title", "date", "body", "body_format",
               "hide_main_text", "category_id", "status_id", "custom_id", "rating", "color", "ordering", "metadata",
               "state", "canread_base", "canwrite_base", "canbook_base", "canread_is_immutable",
               "canwrite_is_immutable", "canread_target", "canwrite_target", "available", "access_key", "locked",
               "locked_by", "locked_at", "signature_count", "last_signed_at", "last_signed_by", "timestamped",
               "timestamped_by", "timestamped_at", "created_from_kind", "created_from_id", "created_at",
               "created_by", "modified_at", "modified_by")
BOOKING_COLS = ("is_bookable", "book_max_minutes", "book_max_slots", "book_can_overlap", "book_users_can_in_past",
                "book_is_cancellable", "book_cancel_minutes", "booking_window_days", "booking_hourly_rate_notax",
                "booking_hourly_rate_tax", "booking_hourly_rate_currency", "is_procurable", "proc_pack_qty",
                "proc_price_notax", "proc_price_tax", "proc_currency")
BOOKING_BOOLS = frozenset(("is_bookable", "book_can_overlap", "book_users_can_in_past", "book_is_cancellable",
                           "is_procurable"))
BASES = (10, 20, 30, 40, 50)


def _user_or_none(ctx, uid, what, where):
    if uid is None or uid == 0:
        return None
    if ctx.has("users", uid):
        return int(uid)
    ctx.note("missing_user", "%s: %s %s is not a 2.x person; left empty" % (where, what, uid))
    return None


def _base(v, default, ctx, where, what):
    v = i(v)
    if v in BASES:
        return v
    if v is not None:
        ctx.note("base_replaced", "%s: %s %s is not a permission base; %s used" % (where, what, v, default))
    return default


def record_builder(kind_name):
    kind = KIND_IDS[kind_name]
    group = LOOKUP_GROUP[kind]
    is_template = kind in (3, 4)
    bookable = kind in (2, 4)

    def build(r, ctx):
        where = "%s %s" % (kind_name, r["id"])
        if not ctx.has("teams", r["team"]):
            return Skip("its team does not exist in 2.x")
        if not ctx.has("users", r["userid"]):
            return Skip("its owner does not exist in 2.x")
        cat = i(r.get("category"))
        if cat is not None and not ctx.has("categories", (group, cat)):
            ctx.note("missing_category", "%s: category %s does not exist in 2.x; left empty" % (where, cat))
            cat = None
        st = i(r.get("status"))
        if st is not None and not ctx.has("statuses", (group, st)):
            ctx.note("missing_status", "%s: status %s does not exist in 2.x; left empty" % (where, st))
            st = None
        elabid = text(r.get("elabid"))
        if not elabid:
            elabid = template_elabid(kind, r["id"], r.get("created_at"))
            if not is_template:
                ctx.note("elabid_generated", "%s: no elabid in 2.x; one was generated" % where)
        meta = canon.json_value(r.get("metadata"))
        if meta is not None and not isinstance(meta, dict):
            ctx.note("metadata_dropped", "%s: metadata is not a JSON object; left empty" % where)
            meta = None
        ak = text(r.get("access_key"))
        if ak:
            try:
                ak = str(uuid.UUID(ak))
            except ValueError:
                ctx.note("access_key_dropped", "%s: access key is not a UUID; left empty" % where)
                ak = None
        else:
            ak = None
        locked = bool(r.get("locked"))
        locked_at = r.get("locked_at")
        if locked and locked_at is None:
            locked_at = r.get("modified_at") or r.get("created_at")
            ctx.note("locked_at_filled", "%s: locked with no lock time; its modified time used" % where)
        rating = i(r.get("rating")) or 0
        cft, cfi = i(r.get("created_from_type")), i(r.get("created_from_id"))
        out = {
            "kind_id": kind, "id": r["id"], "elabid": elabid, "team_id": r["team"], "owner_id": r["userid"],
            "title": text(r.get("title")) if r.get("title") is not None else "Untitled",
            "date": r.get("date"), "body": text(r.get("body")),
            "body_format": 2 if i(r.get("content_type")) == 2 else 1,
            "hide_main_text": bool(r.get("hide_main_text")), "category_id": cat, "status_id": st,
            "custom_id": i(r.get("custom_id")), "rating": rating if 0 <= rating <= 5 else 0,
            "color": None, "ordering": i(r.get("ordering")) if is_template else None,
            "metadata": meta, "state": i(r.get("state")) if i(r.get("state")) in (1, 2, 3) else 1,
            "canread_base": _base(r.get("canread_base"), 30, ctx, where, "canread_base"),
            "canwrite_base": _base(r.get("canwrite_base"), 20, ctx, where, "canwrite_base"),
            "canbook_base": _base(r.get("canbook_base"), 30, ctx, where, "canbook_base") if bookable else None,
            "canread_is_immutable": bool(r.get("canread_is_immutable")),
            "canwrite_is_immutable": bool(r.get("canwrite_is_immutable")),
            "canread_target": None, "canwrite_target": None,
            "available": bool(r["available"]) if r.get("available") is not None else True,
            "access_key": ak, "locked": locked, "locked_by": _user_or_none(ctx, i(r.get("lockedby")), "lockedby", where),
            "locked_at": locked_at, "signature_count": i(r.get("signature_count")) or 0,
            "last_signed_at": r.get("last_signed_at"),
            "last_signed_by": _user_or_none(ctx, i(r.get("last_signed_by")), "last_signed_by", where),
            "timestamped": bool(r.get("timestamped")),
            "timestamped_by": _user_or_none(ctx, i(r.get("timestampedby")), "timestampedby", where),
            "timestamped_at": r.get("timestamped_at"),
            "created_from_kind": cft if cft in (1, 2, 3, 4) else None,
            "created_from_id": cfi if cft in (1, 2, 3, 4) else None,
            "created_at": r.get("created_at"), "created_by": r["userid"], "modified_at": r.get("modified_at"),
            "modified_by": _user_or_none(ctx, i(r.get("lastchangeby")), "lastchangeby", where),
            "_access": access_rows(r),
        }
        if kind == 4:
            c = (text(r.get("color")) or "").lstrip("#")
            out["color"] = c if re.fullmatch(r"[0-9A-Fa-f]{6}", c) else None
        if is_template:
            for col in ("canread", "canwrite"):
                tb = r.get(col + "_target_base")
                tl = r.get(col + "_target")
                if tb is not None or tl is not None:
                    out[col + "_target"] = {"base": i(tb) if i(tb) in BASES else None, **lists_of(tl)}
        if bookable:
            bk = {}
            for c in BOOKING_COLS:
                if c in r:
                    v = r[c]
                    bk[c] = bool(v) if c in BOOKING_BOOLS else (v if v is not None else 0)
            out["_booking"] = bk
        return out
    return build


# ---------------------------------------------------------------------------- record children
def _rid(ctx, kind, rec_id):
    return ctx.rid(kind, rec_id)


def tag_link_builder():
    def build(r, ctx):
        kind = KIND_IDS.get(r.get("item_type"))
        if kind is None:
            return Skip("unknown item_type %r" % r.get("item_type"))
        rid = _rid(ctx, kind, r["item_id"])
        if rid is None:
            return Skip("its record does not exist in 2.x")
        if not ctx.has("tags", r["tag_id"]):
            return Skip("its tag does not exist in 2.x")
        return {"rid": rid, "tag_id": r["tag_id"]}
    return build


def link_builder(from_kind, to_kind):
    def build(r, ctx):
        a, z = _rid(ctx, from_kind, r["item_id"]), _rid(ctx, to_kind, r["link_id"])
        if a is None or z is None:
            return Skip("one of the linked records does not exist in 2.x")
        if a == z:
            return Skip("a record linked to itself")
        return {"from_rid": a, "to_rid": z}
    return build


def pin_builder(kind):
    def build(r, ctx):
        rid = _rid(ctx, kind, r["entity_id"])
        if rid is None or not ctx.has("users", r["users_id"]):
            return Skip("its record or person does not exist in 2.x")
        return {"user_id": r["users_id"], "rid": rid}
    return build


def favtag_build(r, ctx):
    if not ctx.has("users", r["users_id"]) or not ctx.has("tags", r["tags_id"]):
        return Skip("its person or tag does not exist in 2.x")
    return {"user_id": r["users_id"], "tag_id": r["tags_id"]}


def comment_builder(kind):
    def build(r, ctx):
        rid = _rid(ctx, kind, r["item_id"])
        if rid is None:
            return Skip("its record does not exist in 2.x")
        if not ctx.has("users", r["userid"]):
            return Skip("its author does not exist in 2.x")
        body = text(r.get("comment")) or ""
        if not body.strip():
            return Skip("an empty comment")
        return {"rid": rid, "user_id": r["userid"], "body": body, "immutable": bool(r.get("immutable")),
                "created_at": r.get("created_at"), "modified_at": r.get("modified_at") or r.get("created_at")}
    return build


def step_builder(kind):
    def build(r, ctx):
        rid = _rid(ctx, kind, r["item_id"])
        if rid is None:
            return Skip("its record does not exist in 2.x")
        finished = bool(r.get("finished"))
        if finished and r.get("finished_time") is None:
            return Skip("finished with no finish time")
        return {"rid": rid, "body": text(r.get("body")) or "", "ordering": i(r.get("ordering")),
                "finished": finished, "finished_at": r.get("finished_time") if finished else r.get("finished_time"),
                "deadline": r.get("deadline"), "deadline_notif": bool(r.get("deadline_notif")),
                "is_immutable": bool(r.get("is_immutable"))}
    return build


def revision_builder(kind):
    def build(r, ctx):
        rid = _rid(ctx, kind, r["item_id"])
        if rid is None:
            return Skip("its record does not exist in 2.x")
        if not ctx.has("users", r["userid"]):
            return Skip("its author does not exist in 2.x")
        body = text(r.get("body")) or ""
        return {"rid": rid, "body": body, "body_format": 2 if i(r.get("content_type")) == 2 else 1,
                "body_sha256": hashlib.sha256(body.encode("utf-8")).digest(), "user_id": r["userid"],
                "created_at": r.get("created_at")}
    return build


def request_action_builder(kind):
    def build(r, ctx):
        rid = _rid(ctx, kind, r["entity_id"])
        if rid is None:
            return Skip("its record does not exist in 2.x")
        if not ctx.has("users", r["requester_userid"]) or not ctx.has("users", r["target_userid"]):
            return Skip("its requester or target person does not exist in 2.x")
        st = i(r.get("state")) or 1
        return {"rid": rid, "requester_id": r["requester_userid"], "target_user_id": r["target_userid"],
                "action": i(r["action"]), "state": st if st in (1, 2, 3) else 1, "created_at": r.get("created_at")}
    return build


def upload_build(r, ctx):
    kind = KIND_IDS.get(r.get("type"))
    if kind is None:
        return Skip("unknown record type %r" % r.get("type"))
    rid = _rid(ctx, kind, r["item_id"])
    if rid is None:
        return Skip("its record does not exist in 2.x")
    if not ctx.has("users", r["userid"]):
        return Skip("its uploader does not exist in 2.x")
    st = i(r.get("state")) or 1
    return {"id": r["id"], "rid": rid, "real_name": text(r.get("real_name")) or "", "storage_name": text(r["long_name"]),
            "comment": text(r.get("comment")), "user_id": r["userid"], "mime": mime_of(text(r.get("real_name"))),
            "size": i(r.get("filesize")) or 0, "legacy_hash": text(r.get("hash")),
            "legacy_hash_algo": text(r.get("hash_algorithm")), "state": st if st in (1, 2, 3) else 1,
            "immutable": bool(r.get("immutable")), "created_at": r.get("created_at"),
            "_file": {"kind": kind, "record_id": r["item_id"], "type": r.get("type"), "long_name": text(r["long_name"])}}


def event_build(r, ctx):
    res = _rid(ctx, 2, r["item"])
    if res is None:
        return Skip("its resource does not exist in 2.x")
    if not ctx.has("teams", r["team"]) or not ctx.has("users", r["userid"]):
        return Skip("its team or person does not exist in 2.x")
    if r.get("start") is None or r.get("end") is None or r["end"] <= r["start"]:
        return Skip("its end is not after its start")
    exp = _rid(ctx, 1, r["experiment"]) if r.get("experiment") else None
    lnk = _rid(ctx, 2, r["item_link"]) if r.get("item_link") else None
    return {"id": r["id"], "team_id": r["team"], "resource_rid": res, "start_at": r["start"], "end_at": r["end"],
            "title": text(r.get("title")), "user_id": r["userid"], "experiment_rid": exp, "item_link_rid": lnk,
            "created_at": r.get("created_at"), "modified_at": r.get("modified_at") or r.get("created_at")}


# ---------------------------------------------------------------------------------- inventory
def storage_build(r, ctx):
    p = i(r.get("parent_id"))
    if p is not None and not ctx.has("storage_units", p):
        return Skip("its parent storage unit does not exist in 2.x")
    return {"id": r["id"], "name": text(r.get("name")) or "", "parent_id": p}


def container_builder(kind):
    def build(r, ctx):
        rid = _rid(ctx, kind, r["item_id"])
        if rid is None:
            return Skip("its record does not exist in 2.x")
        if not ctx.has("storage_units", r["storage_id"]):
            return Skip("its storage unit does not exist in 2.x")
        return {"rid": rid, "storage_unit_id": r["storage_id"], "qty_stored": r.get("qty_stored") or 0,
                "qty_unit": (text(r.get("qty_unit")) or "•")[:10], "created_at": r.get("created_at"),
                "modified_at": r.get("modified_at") or r.get("created_at")}
    return build


COMPOUND_IDS = ("ec_number", "chebi_id", "chembl_id", "dea_number", "drugbank_id", "dsstox_id", "hmdb_id", "kegg_id",
                "metabolomics_wb_id", "nci_code", "nikkaji_number", "pharmgkb_id", "pharos_ligand_id", "rxcui",
                "unii", "wikidata", "wikipedia")


def compound_build(r, ctx):
    if not ctx.has("teams", r["team"]) or not ctx.has("users", r["userid"]):
        return Skip("its team or person does not exist in 2.x")
    ids = {c: text(r[c]) for c in COMPOUND_IDS if r.get(c) not in (None, "")}
    haz = {c: bool(r[c]) for c in sorted(r) if c.startswith("is_") and r[c] is not None}
    cb = r.get("created_by") if ctx.has("users", r.get("created_by")) else r["userid"]
    mb = r.get("modified_by") if ctx.has("users", r.get("modified_by")) else cb
    st = i(r.get("state")) or 1
    return {"id": r["id"], "team_id": r["team"], "user_id": r["userid"], "name": text(r.get("name")),
            "iupac_name": text(r.get("iupac_name")), "molecular_formula": text(r.get("molecular_formula")),
            "molecular_weight": r.get("molecular_weight") or 0, "cas_number": text(r.get("cas_number")),
            "pubchem_cid": i(r.get("pubchem_cid")), "inchi": text(r.get("inchi")),
            "inchi_key": text(r.get("inchi_key")), "smiles": text(r.get("smiles")), "identifiers": ids,
            "hazards": haz, "state": st if st in (1, 2, 3) else 1, "created_at": r.get("created_at"),
            "created_by": cb, "modified_at": r.get("modified_at") or r.get("created_at"), "modified_by": mb}


def compound_link_builder(kind):
    def build(r, ctx):
        rid = _rid(ctx, kind, r["entity_id"])
        if rid is None or not ctx.has("compounds", r["compound_id"]):
            return Skip("its record or compound does not exist in 2.x")
        return {"rid": rid, "compound_id": r["compound_id"]}
    return build


def procurement_build(r, ctx):
    rid = _rid(ctx, 2, r["entity_id"])
    if rid is None:
        return Skip("its resource does not exist in 2.x")
    if not ctx.has("teams", r["team"]) or not ctx.has("users", r["requester_userid"]):
        return Skip("its team or requester does not exist in 2.x")
    return {"id": r["id"], "team_id": r["team"], "requester_id": r["requester_userid"], "rid": rid,
            "qty_ordered": i(r.get("qty_ordered")) or 1, "qty_received": i(r.get("qty_received")) or 0,
            "body": text(r.get("body")), "quote": i(r.get("quote")), "email_sent_at": r.get("email_sent_at"),
            "state": i(r.get("state")) or 10, "created_at": r.get("created_at")}


# ------------------------------------------------------------------------------ personal lists
def notification_build(r, ctx):
    if not ctx.has("users", r["userid"]):
        return Skip("its person does not exist in 2.x")
    body = canon.json_value(r.get("body"))
    return {"user_id": r["userid"], "category": i(r["category"]), "body": body if body is not None else {},
            "send_email": bool(r.get("send_email")), "email_sent_at": r.get("email_sent_at"),
            "is_ack": bool(r.get("is_ack")), "created_at": r.get("created_at")}


def todo_build(r, ctx):
    if not ctx.has("users", r["userid"]):
        return Skip("its person does not exist in 2.x")
    return {"user_id": r["userid"], "body": text(r.get("body")) or "", "ordering": i(r.get("ordering")),
            "created_at": r.get("creation_time")}


# ------------------------------------------------------------------------ keys, idps, settings
def sigkey_build(r, ctx):
    if not ctx.has("users", r["userid"]):
        return Skip("its person does not exist in 2.x")
    kid = minisign_key_id(text(r.get("pubkey")))
    if kid is None:
        return Skip("its public key cannot be read")
    st = i(r.get("state")) or 1
    return {"id": r["id"], "user_id": r["userid"], "key_id": kid, "pubkey": text(r.get("pubkey")) or "",
            "privkey_enc": text(r.get("privkey")) or "", "type": i(r.get("type")) or 1,
            "state": st if st in (1, 2, 3) else 1, "created_at": r.get("created_at"),
            "last_used_at": r.get("last_used_at")}


def apikey_build(r, ctx):
    if not ctx.has("users", r["userid"]) or not ctx.has("teams", r["team"]):
        return Skip("its person or team does not exist in 2.x")
    h = text(r.get("hash")) or ""
    if not h.startswith(("$2y$", "$2b$", "$2a$")):
        return Skip("its hash is not bcrypt; the key is re-issued in 3.x")
    # Carried inert: the OCC accepts only hmac-sha256 keys, so a migrated key authenticates nobody
    # until legacy-bcrypt verification is decided; it is kept so the decision can be made later.
    return {"id": r["id"], "user_id": r["userid"], "team_id": r["team"], "name": text(r.get("name")) or "",
            "hash_scheme": "legacy-bcrypt", "hash": h, "can_write": bool(r.get("can_write")),
            "created_at": r.get("created_at")}


def idp_source_build(r, ctx):
    return {"id": r["id"], "url": text(r.get("url")) or "", "auto_refresh": bool(r.get("auto_refresh")),
            "enabled": bool(r.get("enabled")) if r.get("enabled") is not None else True,
            "last_fetched_at": r.get("last_fetched_at"), "created_at": r.get("created_at")}


def idp_build(r, ctx):
    src = i(r.get("source"))
    return {"id": r["id"], "name": text(r.get("name")) or "", "entityid": text(r.get("entityid")) or "",
            "enabled": bool(r.get("enabled")), "source_id": src if ctx.has("idp_sources", src) else None,
            "email_attr": text(r.get("email_attr")) or "email", "team_attr": text(r.get("team_attr")),
            "fname_attr": text(r.get("fname_attr")), "lname_attr": text(r.get("lname_attr")),
            "orgid_attr": text(r.get("orgid_attr")), "orcid_attr": text(r.get("orcid_attr"))}


def idp_cert_build(r, ctx):
    if not ctx.has("idps", r["idp"]):
        return Skip("its identity provider does not exist in 2.x")
    return {"id": r["id"], "idp_id": r["idp"], "purpose": i(r.get("purpose")) or 0, "x509": text(r.get("x509")) or "",
            "sha256": text(r.get("sha256")) or "", "not_before": r.get("not_before"), "not_after": r.get("not_after"),
            "created_at": r.get("created_at"), "modified_at": r.get("modified_at") or r.get("created_at")}


def idp_endpoint_build(r, ctx):
    if not ctx.has("idps", r["idp"]):
        return Skip("its identity provider does not exist in 2.x")
    return {"id": r["id"], "idp_id": r["idp"], "is_slo": bool(r.get("is_slo")), "binding": i(r.get("binding")) or 0,
            "location": text(r.get("location")) or "", "created_at": r.get("created_at"),
            "modified_at": r.get("modified_at") or r.get("created_at")}


# Settings the OCC owns, never taken from 2.x; and secret settings (sealed only with the key file).
OCC_OWNED = frozenset(("read_only", "allow_purge", "write_policy_note", "s3_access_key", "s3_secret_key"))
SECRET_NAMES = frozenset(("smtp_password", "ldap_password", "dspace_password", "ts_password", "saml_privatekey",
                          "s3_access_key", "s3_secret_key"))


def config_build(r, ctx):
    name = text(r["conf_name"])
    if name in OCC_OWNED:
        return Skip("an OCC-owned setting; 3.x keeps its own value")
    if name in SECRET_NAMES:
        val = text(r.get("conf_value"))
        if not val:
            return Skip("a secret setting with no value in 2.x")
        if not ctx.can_seal:
            return Skip("a secret setting; carried only when the OCC's secret key file exists")
        return {"name": name, "is_secret": True, "value": None,
                "_secret_sha256": hashlib.sha256(val.encode("utf-8")).hexdigest(), "_secret": val}
    return {"name": name, "is_secret": False, "value": text(r.get("conf_value"))}


def branding_build(r, ctx):
    data = r.get("data")
    if data is None:
        return Skip("no image data")
    data = bytes(data)
    return {"name": "elabftw_branding_%d" % r["id"], "mime": text(r.get("content_type")) or "application/octet-stream",
            "sha256": hashlib.sha256(data).digest(), "_bytes": data}


# ----------------------------------------------------------------------------------- history
def changelog_builder(kind):
    def build(r, ctx):
        rid = _rid(ctx, kind, r["entity_id"])
        return {"category": "record.update", "kind_id": kind, "record_id": r["entity_id"], "rid": rid,
                "target": text(r.get("target")), "new_value": text(r.get("content")),
                "actor_user_id": r["users_id"] if ctx.has("users", r["users_id"]) else None,
                "orig_at": r.get("created_at"), "_old": ctx.previous_value(kind, r)}
    return build


def audit_log_build(r, ctx):
    return {"category": "elabftw.audit.%d" % i(r.get("category") or 0), "kind_id": None, "record_id": None,
            "rid": None, "target": None, "new_value": None,
            "actor_user_id": r.get("requester_userid") if ctx.has("users", r.get("requester_userid")) else None,
            "orig_at": r.get("created_at"),
            "detail": {"elabftw_audit_id": r["id"], "target_userid": i(r.get("target_userid")),
                       "body": text(r.get("body"))}}


def storage_history_build(r, ctx):
    return {"category": "storage.move", "kind_id": None, "record_id": None, "rid": None,
            "target": "storage_unit:%s" % r.get("storage_unit_id"), "new_value": text(r.get("new_parent_id")),
            "actor_user_id": r.get("users_id") if ctx.has("users", r.get("users_id")) else None,
            "orig_at": r.get("created_at"), "detail": {"old_parent_id": i(r.get("old_parent_id"))}}


# --------------------------------------------------------------------------------- the specs
_LOOKUP_COLS = ("lookup_group", "id", "team_id", "title", "color", "is_private", "is_default", "ordering", "state",
                "created_at", "modified_at")
_AUDIT_COLS = ("category", "kind_id", "record_id", "target", "new_value", "actor_user_id", "orig_at", "detail")
_USER_COLS = ("id", "email", "firstname", "lastname", "orcid", "orgid", "is_sysadmin", "validated", "valid_until",
              "auth_service", "can_manage_users2teams", "can_manage_compounds", "can_manage_inventory_locations",
              "default_read_base", "default_write_base", "default_read", "default_write", "prefs", "created_at",
              "last_login_at")
_TEAM_COLS = ("id", "name", "created_at", "newcomer_threshold") + TEAM_BOOLS + TEAM_TEXTS
_KIND_NAMES = ("experiments", "items", "experiments_templates", "items_types")


def _sid_pair(*cols):
    return lambda r: ":".join(str(r[c]) for c in cols)


def _specs():
    s = [
        Spec("users", "users", "keep", _USER_COLS, build_user, sid=lambda r: str(r["userid"]), src_order="userid",
             removable=False),
        Spec("teams", "teams", "keep", _TEAM_COLS, build_team, removable=False),
        Spec("users2teams", "memberships", "pair", ("user_id", "team_id", "is_admin", "is_owner", "is_archived"),
             build_membership, key=("user_id", "team_id"), sid=_sid_pair("users_id", "teams_id"), parent="users_id",
             src_order="users_id, teams_id"),
        Spec("team_groups", "team_groups", "keep", ("id", "team_id", "name"), build_group, parent="team"),
        Spec("users2team_groups", "team_group_members", "pair", ("group_id", "user_id"), build_group_member,
             key=("group_id", "user_id"), sid=_sid_pair("groupid", "userid"), parent="groupid",
             src_order="groupid, userid"),
        Spec("idps_sources", "idp_sources", "keep",
             ("id", "url", "auto_refresh", "enabled", "last_fetched_at", "created_at"), idp_source_build),
        Spec("idps", "idps", "keep", ("id", "name", "entityid", "enabled", "source_id", "email_attr", "team_attr",
                                      "fname_attr", "lname_attr", "orgid_attr", "orcid_attr"), idp_build),
        Spec("idps_certs", "idp_certs", "keep", ("id", "idp_id", "purpose", "x509", "sha256", "not_before", "not_after",
                                                 "created_at", "modified_at"), idp_cert_build, detect="modified"),
        Spec("idps_endpoints", "idp_endpoints", "keep", ("id", "idp_id", "is_slo", "binding", "location", "created_at",
                                                         "modified_at"), idp_endpoint_build, detect="modified"),
        Spec("experiments_categories", "categories", "keep", _LOOKUP_COLS, lookup_builder(1, "categories"),
             key=("lookup_group", "id"), detect="modified"),
        Spec("items_categories", "categories", "keep", _LOOKUP_COLS, lookup_builder(2, "categories"),
             key=("lookup_group", "id"), detect="modified"),
        Spec("experiments_status", "statuses", "keep", _LOOKUP_COLS, lookup_builder(1, "statuses"),
             key=("lookup_group", "id"), detect="modified"),
        Spec("items_status", "statuses", "keep", _LOOKUP_COLS, lookup_builder(2, "statuses"),
             key=("lookup_group", "id"), detect="modified"),
        Spec("storage_units", "storage_units", "keep", ("id", "name", "parent_id"), storage_build),
        Spec("compounds", "compounds", "keep",
             ("id", "team_id", "user_id", "name", "iupac_name", "molecular_formula", "molecular_weight", "cas_number",
              "pubchem_cid", "inchi", "inchi_key", "smiles", "identifiers", "hazards", "state", "created_at",
              "created_by", "modified_at", "modified_by"), compound_build, detect="modified"),
    ]
    for k in ("items_types", "experiments_templates", "items", "experiments"):
        s.append(Spec(k, "records", "keep", RECORD_COLS, record_builder(k), key=("kind_id", "id"), detect="modified",
                      kind=KIND_IDS[k], removable=False))
    s += [
        Spec("tags", "tags", "keep", ("id", "team_id", "tag"),
             lambda r, ctx: {"id": r["id"], "team_id": r["team"], "tag": text(r["tag"])}
             if ctx.has("teams", r["team"]) else Skip("its team does not exist in 2.x"), parent="team"),
        Spec("tags2entity", "record_tags", "pair", ("rid", "tag_id"), tag_link_builder(), key=("rid", "tag_id"),
             sid=_sid_pair("item_type", "item_id", "tag_id"), parent="item_id"),
        Spec("favtags2users", "favorite_tags", "pair", ("user_id", "tag_id"), favtag_build, key=("user_id", "tag_id"),
             sid=_sid_pair("users_id", "tags_id"), parent="users_id", src_order="users_id, tags_id"),
    ]
    for k in _KIND_NAMES:
        s.append(Spec("pin_%s2users" % k, "pins", "pair", ("user_id", "rid"), pin_builder(KIND_IDS[k]),
                      key=("user_id", "rid"), sid=_sid_pair("users_id", "entity_id"), parent="users_id",
                      src_order="users_id, entity_id"))
    for a, z in (("experiments", "experiments"), ("experiments", "items"), ("items", "experiments"), ("items", "items"),
                 ("experiments_templates", "experiments"), ("experiments_templates", "items"),
                 ("items_types", "experiments"), ("items_types", "items")):
        s.append(Spec("%s2%s" % (a, z), "record_links", "pair", ("from_rid", "to_rid"),
                      link_builder(KIND_IDS[a], KIND_IDS[z]), key=("from_rid", "to_rid"),
                      sid=_sid_pair("item_id", "link_id"), parent="item_id", src_order="item_id, link_id"))
    for k in _KIND_NAMES:
        kd = KIND_IDS[k]
        s += [
            Spec("%s_comments" % k, "comments", "new",
                 ("rid", "user_id", "body", "immutable", "created_at", "modified_at"), comment_builder(kd),
                 detect="modified"),
            Spec("%s_steps" % k, "steps", "new", ("rid", "body", "ordering", "finished", "finished_at", "deadline",
                                                  "deadline_notif", "is_immutable"), step_builder(kd), parent="item_id"),
            Spec("%s_revisions" % k, "revisions", "new",
                 ("rid", "body", "body_format", "body_sha256", "user_id", "created_at"), revision_builder(kd),
                 detect="modified"),
            Spec("%s_request_actions" % k, "request_actions", "new",
                 ("rid", "requester_id", "target_user_id", "action", "state", "created_at"),
                 request_action_builder(kd), parent="entity_id"),
        ]
    s += [
        Spec("uploads", "uploads", "keep", ("id", "rid", "real_name", "storage_name", "comment", "user_id", "mime",
                                            "size", "legacy_hash", "legacy_hash_algo", "state", "immutable",
                                            "created_at"), upload_build, parent="item_id",
             written_only=("sha256",)),
        Spec("team_events", "events", "keep", ("id", "team_id", "resource_rid", "start_at", "end_at", "title",
                                               "user_id", "experiment_rid", "item_link_rid", "created_at",
                                               "modified_at"), event_build, detect="modified"),
    ]
    for k in _KIND_NAMES:
        s.append(Spec("containers2%s" % k, "record_containers", "new",
                      ("rid", "storage_unit_id", "qty_stored", "qty_unit", "created_at", "modified_at"),
                      container_builder(KIND_IDS[k]), detect="modified"))
    for k in _KIND_NAMES:
        s.append(Spec("compounds2%s" % k, "record_compounds", "pair", ("rid", "compound_id"),
                      compound_link_builder(KIND_IDS[k]), key=("rid", "compound_id"),
                      sid=_sid_pair("entity_id", "compound_id"), parent="entity_id",
                      src_order="entity_id, compound_id"))
    s += [
        Spec("procurement_requests", "procurement_requests", "keep",
             ("id", "team_id", "requester_id", "rid", "qty_ordered", "qty_received", "body", "quote",
              "email_sent_at", "state", "created_at"), procurement_build, parent="team"),
        Spec("notifications", "notifications", "new",
             ("user_id", "category", "body", "send_email", "email_sent_at", "is_ack", "created_at"),
             notification_build, parent="userid"),
        Spec("todolist", "todo_items", "new", ("user_id", "body", "ordering", "created_at"), todo_build,
             parent="userid"),
        Spec("sig_keys", "sig_keys", "keep", ("id", "user_id", "key_id", "pubkey", "privkey_enc", "type", "state",
                                              "created_at", "last_used_at"), sigkey_build),
        Spec("api_keys", "api_keys", "keep", ("id", "user_id", "team_id", "name", "hash_scheme", "hash", "can_write",
                                              "created_at"), apikey_build,
             fp_cols=("id", "name", "hash", "can_write", "userid", "team")),
        Spec("config", "site_config", "keep", ("name", "is_secret", "value"), config_build, key=("name",),
             sid=lambda r: str(r["conf_name"]), src_order="conf_name"),
        Spec("branding", "site_assets", "keep", ("name", "mime", "sha256"), branding_build, key=("name",)),
    ]
    for k in _KIND_NAMES:
        s.append(Spec("%s_changelog" % k, "audit_events", "audit", _AUDIT_COLS, changelog_builder(KIND_IDS[k]),
                      detect="append", removable=False, kind=KIND_IDS[k]))
    s += [
        Spec("audit_logs", "audit_events", "audit", _AUDIT_COLS, audit_log_build, detect="append", removable=False),
        Spec("storage_units_history", "audit_events", "audit", _AUDIT_COLS, storage_history_build, detect="append",
             removable=False),
    ]
    return s


SPECS = _specs()
BY_SOURCE = {sp.src: sp for sp in SPECS}
CARRIED = frozenset(BY_SOURCE)
TABLES = frozenset(CARRIED | set(NOT_CARRIED) | set(DERIVED))
# Every OCC table and column the mapping may name in SQL text: closed lists, never data.
OCC_TABLES = frozenset(sp.occ for sp in SPECS) | frozenset(("resource_booking", "record_access"))
OCC_COLUMNS = frozenset(c for sp in SPECS for c in sp.cols + sp.key + sp.written_only) | frozenset(
    BOOKING_COLS) | frozenset(("rid", "body_text", "access_right", "principal", "principal_id", "value_enc"))


def classification():
    """{table: (state, target or reason)} for every table the mapping knows."""
    out = {t: ("carried", BY_SOURCE[t].occ) for t in CARRIED}
    out.update({t: ("not carried", r) for t, r in NOT_CARRIED.items()})
    out.update({t: ("derived", r) for t, r in DERIVED.items()})
    return out


def json_cols():
    """OCC columns that hold JSON."""
    return frozenset(("metadata", "canread_target", "canwrite_target", "default_read", "default_write", "prefs",
                      "identifiers", "hazards", "body", "detail"))


JSON_COLS = {"records": ("metadata", "canread_target", "canwrite_target"),
             "users": ("default_read", "default_write", "prefs"), "compounds": ("identifiers", "hazards"),
             "notifications": ("body",), "audit_events": ("detail",)}


def strip_private(values):
    """The values written and hashed, without the mapping's private helper fields (leading _)."""
    return {k: v for k, v in values.items() if not k.startswith("_")}


def dumps(v):
    return json.dumps(canon.norm(v), sort_keys=True)
