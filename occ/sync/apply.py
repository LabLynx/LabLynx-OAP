# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Writing 2.x rows into the OCC.

This is OCC code and writes through the OCC's own database layer (db.Tx, db.ident, the audit
chain's occ.audit_append): parameterized statements whose table and column names come only from
the mapping's closed lists, never from data. It keeps the 2.x ids, authors and times.

For every carried source row, occ.id_map holds the OCC row it became and the SHA-256 of the row's
canonical form. A row whose hash is unchanged is not written (a second run writes nothing). A row
whose OCC copy changed since the sync last wrote it (an edit made in 3.x) is overwritten by the
2.x version and the replaced edit is reported: while the sync runs one way, 2.x is the record.
Rows that exist only in 3.x (no id_map row) are never touched.
"""
import hashlib

from ..db import ident, jsonb
from ..records import service as records_service
from . import canon, mapping as M

KEYEXPR = {
    "records": "t.rid::text",
    "categories": "t.lookup_group::text || ':' || t.id::text",
    "statuses": "t.lookup_group::text || ':' || t.id::text",
    "site_config": "t.name",
    "site_assets": "t.name",
    "memberships": "t.user_id::text || ':' || t.team_id::text",
    "team_group_members": "t.group_id::text || ':' || t.user_id::text",
    "record_tags": "t.rid::text || ':' || t.tag_id::text",
    "favorite_tags": "t.user_id::text || ':' || t.tag_id::text",
    "pins": "t.user_id::text || ':' || t.rid::text",
    "record_links": "t.from_rid::text || ':' || t.to_rid::text",
    "record_compounds": "t.rid::text || ':' || t.compound_id::text",
}
DEFAULT_KEYEXPR = "t.id::text"
for _t in M.OCC_TABLES:
    KEYEXPR.setdefault(_t, DEFAULT_KEYEXPR)
CHANGELOG_TABLE = {1: "experiments_changelog", 2: "items_changelog", 3: "experiments_templates_changelog",
                   4: "items_types_changelog"}
# canonical fields beyond the written columns
CANON_EXTRA = {"records": ("_access", "_booking"), "site_config": ("_secret_sha256",)}
# caches of what exists in the OCC, by OCC table
CACHE_OF = {"users": "users", "teams": "teams", "team_groups": "team_groups", "tags": "tags",
            "storage_units": "storage_units", "compounds": "compounds", "idps": "idps", "idp_sources": "idp_sources",
            "categories": "categories", "statuses": "statuses"}
SEQ_TABLES = frozenset(("users", "teams", "team_groups", "categories", "statuses", "tags", "uploads", "events",
                        "storage_units", "compounds", "procurement_requests", "sig_keys", "api_keys", "idps",
                        "idp_sources", "idp_certs", "idp_endpoints"))
RECORD_SEQS = {1: "occ.record_id_experiments", 2: "occ.record_id_items", 3: "occ.record_id_experiments_templates",
               4: "occ.record_id_items_types"}
CHAR_COLS = frozenset(("inchi_key", "color", "key_id", "sha256"))
_PAIRS = {"memberships", "team_group_members", "record_tags", "favorite_tags", "pins", "record_links",
          "record_compounds"}
_TEXT_KEYS = {"site_config", "site_assets"}


def canonical(spec, values):
    out = {c: values.get(c) for c in spec.cols}
    for c in CANON_EXTRA.get(spec.occ, ()):
        if c in values:
            out[c] = values[c]
    return out


def occ_id_of(spec, values, returned=None):
    if spec.occ == "records" or spec.style in ("new", "audit"):
        return str(returned)
    return ":".join(str(values[k]) for k in spec.key)


def _key_values(spec, occ_id):
    if spec.occ == "records" or spec.style in ("new", "audit"):
        return {"id": int(occ_id)} if spec.occ != "records" else {"rid": int(occ_id)}
    if spec.occ in _TEXT_KEYS:
        return {spec.key[0]: occ_id}
    parts = occ_id.split(":")
    return {k: int(v) for k, v in zip(spec.key, parts)}


class Ctx:
    """What exists in the OCC, for resolving ids while building rows; notes about transformations."""

    def __init__(self, tx, source=None, can_seal=False):
        self.tx = tx
        self.source = source
        self.can_seal = can_seal
        self.caches = {}
        self.rids = {}
        self.notes = {}
        self.prev = {}
        self.full = False             # a full pass in id order: no need to ask 2.x for previous values
        self.load()

    def load(self):
        tx = self.tx
        for t in ("users", "teams", "team_groups", "tags", "storage_units", "compounds", "idps", "idp_sources"):
            self.caches[t] = {r["id"] for r in tx.all("SELECT id FROM occ.%s" % ident(t, M.OCC_TABLES))}
        for t in ("categories", "statuses"):
            self.caches[t] = {(r["lookup_group"], r["id"]) for r in
                              tx.all("SELECT lookup_group, id FROM occ.%s" % ident(t, M.OCC_TABLES))}
        self.rids = {(r["kind_id"], r["id"]): r["rid"] for r in tx.all("SELECT kind_id, id, rid FROM occ.records")}

    def has(self, name, key):
        if key is None:
            return False
        return key in self.caches.get(name, ())

    def rid(self, kind, rec_id):
        if rec_id is None:
            return None
        return self.rids.get((kind, int(rec_id)))

    def add(self, name, key):
        self.caches.setdefault(name, set()).add(key)

    def note(self, code, text):
        n = self.notes.setdefault(code, {"count": 0, "examples": []})
        n["count"] += 1
        if len(n["examples"]) < 20:
            n["examples"].append(text)

    def previous_value(self, kind, row):
        """The value this field had before a changelog row: the previous row for the same record
        and field (mapping.json: old_value derived from the previous row)."""
        k = (kind, row["entity_id"], row.get("target"))
        if k in self.prev:
            old = self.prev[k]
        elif self.full:
            old = None
        elif self.source is not None and row.get("id") is not None:
            got = self.source.scalar_row(
                "SELECT content FROM `%s` WHERE entity_id = %%s AND target = %%s AND id < %%s ORDER BY id DESC LIMIT 1"
                % CHANGELOG_TABLE[kind], (row["entity_id"], row.get("target"), row["id"]))
            old = M.text(got[0]) if got else None
        else:
            old = None
        self.prev[k] = M.text(row.get("content"))
        return old


class Writer:
    """Applies built rows of one spec inside the caller's transaction."""

    def __init__(self, tx, ctx, run_id, actor_kind, files=None, cfg=None, report=None, lag=None):
        self.tx = tx
        self.ctx = ctx
        self.run_id = run_id
        self.actor_kind = actor_kind          # 'migration' or 'sync'
        self.files = files
        self.cfg = cfg
        self.report = report
        self.lag = lag                        # None, or (detected_at) for sync mode
        self.touched_rids = set()

    # -- id map ----------------------------------------------------------------------------------
    def id_map(self, spec, sids=None):
        tx = self.tx
        if sids is None:
            rows = tx.all("SELECT source_id, occ_id, source_hash, occ_hash FROM occ.id_map "
                               "WHERE system = 'elabftw' AND source_table = :t", t=spec.src)
        else:
            rows = tx.all("SELECT source_id, occ_id, source_hash, occ_hash FROM occ.id_map "
                               "WHERE system = 'elabftw' AND source_table = :t AND source_id = ANY(:s)",
                               t=spec.src, s=list(sids))
        return {r["source_id"]: r for r in rows}

    def _map(self, spec, sid, occ_id, h):
        tx = self.tx
        tx.run("INSERT INTO occ.id_map (system, source_table, source_id, occ_table, occ_id, source_hash, occ_hash, "
                    "last_run_id, last_synced_at) VALUES ('elabftw', :st, :sid, :ot, :oid, :h, :h, :run, now()) "
                    "ON CONFLICT (system, source_table, source_id) DO UPDATE SET occ_id = EXCLUDED.occ_id, "
                    "source_hash = EXCLUDED.source_hash, occ_hash = EXCLUDED.occ_hash, last_run_id = EXCLUDED.last_run_id, "
                    "last_synced_at = now()", st=spec.src, sid=sid, ot=spec.occ, oid=occ_id, h=h, run=self.run_id)

    # -- projection (the OCC row read back in canonical form) -------------------------------------
    def project(self, spec, occ_id):
        tx = self.tx
        cols = ", ".join("t." + ident(c, M.OCC_COLUMNS) for c in spec.cols)
        row = tx.one("SELECT %s FROM occ.%s t WHERE %s = :k" % (
            cols, ident(spec.occ, M.OCC_TABLES), KEYEXPR[spec.occ]), k=occ_id)
        if row is None:
            return None
        return finish_projection(self.tx, spec, {occ_id: row}, self.ctx, self.cfg)[occ_id]

    # -- writing ---------------------------------------------------------------------------------
    def apply(self, spec, row, existing, changed_at=None):
        """One source row. Returns 'unchanged', 'inserted', 'updated' or 'skipped'."""
        sid = spec.source_id(row)
        values = spec.build(row, self.ctx)
        if isinstance(values, M.Skip):
            self.report.skip(spec, sid, values.reason)
            return "skipped"
        can = canonical(spec, values)
        h = canon.digest(can)
        if existing is not None and bytes(existing["source_hash"]) == h:
            return "unchanged"
        if existing is not None and spec.style != "audit":
            cur = self.project(spec, existing["occ_id"])
            if cur is None:
                self.report.replaced(spec, sid, existing["occ_id"], "removed in 3.x; restored from 2.x", [])
            elif existing["occ_hash"] is not None and canon.digest(cur) != bytes(existing["occ_hash"]):
                self.report.replaced(spec, sid, existing["occ_id"], "edited in 3.x; 2.x version applied",
                                     [{"field": f, "3.x": canon.norm(cur.get(f)), "2.x": canon.norm(can.get(f))}
                                      for f in canon.diff(cur, can)])
        if spec.occ == "uploads":
            # The bytes are fetched only for a new file: a change to an upload's state, comment or
            # name keeps the stored bytes when 2.x's hash and stored name are the same (a deleted
            # upload's bytes are no longer served by eLabFTW's API, so fetching again would fail).
            tx = self.tx
            have = tx.one("SELECT sha256, legacy_hash, storage_name FROM occ.uploads WHERE id = :i", i=values["id"])
            if have is not None and have["legacy_hash"] == values.get("legacy_hash") and \
                    have["storage_name"] == values.get("storage_name"):
                values["sha256"] = bytes(have["sha256"])
            else:
                got = self._file(spec, values, sid)
                if got is None:
                    return "skipped"
                values["sha256"] = got
        occ_id = self._write(spec, values, existing)
        if occ_id is None:
            return "skipped"
        self._map(spec, sid, occ_id, h)
        if self.lag is not None and changed_at is not None:
            tx = self.tx
            tx.run("INSERT INTO occ.sync_lag (run_id, source_table, source_id, source_changed, detected_at, "
                        "applied_at, lag_seconds) VALUES (:run, :t, :sid, :ch, :det, clock_timestamp(), "
                        "round(CAST(extract(epoch FROM clock_timestamp() - CAST(:ch AS timestamptz)) AS numeric), 2))",
                        run=self.run_id, t=spec.src, sid=sid, ch=changed_at, det=self.lag)
        return "updated" if existing is not None else "inserted"

    def _file(self, spec, values, sid):
        f = values["_file"]
        if self.files is None:
            self.report.skip(spec, sid, "file bytes not read in this run")
            return None
        data, why = self.files.fetch(self.tx, values["rid"], f, values)
        if data is None:
            self.report.skip(spec, sid, why)
            return None
        sha, size = self.files.store.put_bytes(data)
        from ..files import store as store_mod
        store_mod.register(self.tx, self.files.store, sha, size)
        if (values.get("legacy_hash_algo") or "").lower() == "sha256" and values.get("legacy_hash") and \
                values["legacy_hash"].lower() != sha.hex():
            self.report.file_problem(sid, "SHA-256 of the bytes differs from the hash 2.x recorded")
        if size != values.get("size"):
            self.report.file_problem(sid, "size %d differs from the %s bytes 2.x recorded" % (size, values.get("size")))
        self.report.file_ok()
        return sha

    def _params(self, spec, values, cols):
        jc = M.JSON_COLS.get(spec.occ, ())
        return {c: (jsonb(values.get(c)) if c in jc else values.get(c)) for c in cols}

    def _write(self, spec, values, existing):
        tx, occ = self.tx, spec.occ
        jc = M.JSON_COLS.get(occ, ())
        if spec.style == "audit":
            return self._audit(spec, values)
        if occ == "records":
            return self._record(spec, values)
        if occ == "site_config" and values.get("is_secret"):
            return self._secret(values)
        if occ == "site_assets":
            from ..files import store as store_mod
            if self.files is None:
                self.report.skip(spec, values["name"], "asset bytes not stored in this run")
                return None
            sha, size = self.files.store.put_bytes(values["_bytes"])
            store_mod.register(tx, self.files.store, sha, size)
        cols = [c for c in spec.cols + spec.written_only if c in values]
        names = ", ".join(ident(c, M.OCC_COLUMNS) for c in cols)
        marks = ", ".join(("CAST(:%s AS jsonb)" if c in jc else ":%s") % ident(c, M.OCC_COLUMNS) for c in cols)
        table = ident(occ, M.OCC_TABLES)
        params = self._params(spec, values, cols)
        if spec.style in ("keep", "pair"):
            keys = ", ".join(ident(k, M.OCC_COLUMNS) for k in spec.key)
            rest = [c for c in cols if c not in spec.key]
            if rest:
                sets = ", ".join("%s = EXCLUDED.%s" % (ident(c, M.OCC_COLUMNS), ident(c, M.OCC_COLUMNS)) for c in rest)
                tx.run("INSERT INTO occ.%s (%s) VALUES (%s) ON CONFLICT (%s) DO UPDATE SET %s" % (
                    table, names, marks, keys, sets), **params)
            else:
                tx.run("INSERT INTO occ.%s (%s) VALUES (%s) ON CONFLICT (%s) DO NOTHING" % (table, names, marks, keys),
                       **params)
            cache = CACHE_OF.get(occ)
            if cache:
                self.ctx.add(cache, (values["lookup_group"], values["id"]) if occ in ("categories", "statuses")
                             else values["id"])
            return occ_id_of(spec, values)
        # new: the OCC numbers the row
        if existing is not None:
            sets = ", ".join(("%s = CAST(:%s AS jsonb)" if c in jc else "%s = :%s") % (
                ident(c, M.OCC_COLUMNS), ident(c, M.OCC_COLUMNS)) for c in cols)
            n = tx.run("UPDATE occ.%s SET %s WHERE id = :occ_id" % (table, sets), occ_id=int(existing["occ_id"]),
                       **params)
            if n:
                return existing["occ_id"]
        new_id = tx.val("INSERT INTO occ.%s (%s) VALUES (%s) RETURNING id" % (table, names, marks), **params)
        return str(new_id)

    def _record(self, spec, values):
        tx = self.tx
        values = dict(values)
        values["body_text"] = records_service.body_text(values.get("body"))
        cols = [c for c in M.RECORD_COLS] + ["body_text"]
        names = ", ".join(ident(c, M.OCC_COLUMNS) for c in cols)
        marks = ", ".join(("CAST(:%s AS jsonb)" if c in M.JSON_COLS["records"] else ":%s") % ident(c, M.OCC_COLUMNS)
                          for c in cols)
        sets = ", ".join("%s = EXCLUDED.%s" % (ident(c, M.OCC_COLUMNS), ident(c, M.OCC_COLUMNS))
                         for c in cols if c not in ("kind_id", "id"))
        rid = tx.val("INSERT INTO occ.records (%s) VALUES (%s) ON CONFLICT (kind_id, id) DO UPDATE SET %s "
                     "RETURNING rid" % (names, marks, sets), **self._params(spec, values, cols))
        tx.run("DELETE FROM occ.record_access WHERE rid = :rid", rid=rid)
        for right, principal, pid in values.get("_access") or []:
            tx.run("INSERT INTO occ.record_access (rid, access_right, principal, principal_id) VALUES (:r, :a, :p, :i) "
                   "ON CONFLICT DO NOTHING", r=rid, a=right, p=principal, i=pid)
        bk = values.get("_booking")
        if bk is not None:
            bcols = [c for c in M.BOOKING_COLS if c in bk]
            if bcols:
                bn = ", ".join(ident(c, M.OCC_COLUMNS) for c in bcols)
                bm = ", ".join(":" + ident(c, M.OCC_COLUMNS) for c in bcols)
                bs = ", ".join("%s = EXCLUDED.%s" % (ident(c, M.OCC_COLUMNS), ident(c, M.OCC_COLUMNS)) for c in bcols)
                tx.run("INSERT INTO occ.resource_booking (rid, %s) VALUES (:rid, %s) ON CONFLICT (rid) DO UPDATE SET %s"
                       % (bn, bm, bs), rid=rid, **{c: bk[c] for c in bcols})
            else:
                tx.run("INSERT INTO occ.resource_booking (rid) VALUES (:rid) ON CONFLICT (rid) DO NOTHING", rid=rid)
        self.ctx.rids[(values["kind_id"], values["id"])] = rid
        self.touched_rids.add(rid)
        return str(rid)

    def _secret(self, values):
        from ..people import config as config_mod
        blob = config_mod.seal(self.cfg, values["name"], values["_secret"])
        tx = self.tx
        tx.run("INSERT INTO occ.site_config (name, value, is_secret, value_enc) VALUES (:n, NULL, true, :v) "
                    "ON CONFLICT (name) DO UPDATE SET value = NULL, is_secret = true, value_enc = EXCLUDED.value_enc, "
                    "updated_at = now()", n=values["name"], v=blob)
        return values["name"]

    def _audit(self, spec, values):
        payload = {"actor_kind": "user" if values.get("actor_user_id") else "system",
                   "actor_user_id": values.get("actor_user_id"), "category": values["category"],
                   "kind_id": values.get("kind_id"), "record_id": values.get("record_id"), "rid": values.get("rid"),
                   "target": values.get("target"), "new_value": values.get("new_value"),
                   "old_value": values.get("_old"), "detail": canon.norm(values.get("detail")),
                   "origin": "elabftw-import", "orig_at": canon.norm(values.get("orig_at"))}
        payload = {k: v for k, v in payload.items() if v is not None}
        tx = self.tx
        return str(tx.val("SELECT occ.audit_append(CAST(:p AS jsonb))", p=jsonb(payload)))

    def remove(self, spec, sid, occ_id):
        if not spec.removable:
            self.report.kept(spec, sid, occ_id)
            return False
        tx = self.tx
        kv = _key_values(spec, occ_id)
        where = " AND ".join("%s = :%s" % (ident(k, M.OCC_COLUMNS), ident(k, M.OCC_COLUMNS)) for k in kv)
        tx.run("DELETE FROM occ.%s WHERE %s" % (ident(spec.occ, M.OCC_TABLES), where), **kv)
        tx.run("DELETE FROM occ.id_map WHERE system = 'elabftw' AND source_table = :t AND source_id = :s",
                    t=spec.src, s=sid)
        cache = CACHE_OF.get(spec.occ)
        if cache:
            self.ctx.caches.get(cache, set()).discard(
                tuple(kv.values()) if spec.occ in ("categories", "statuses") else kv.get("id"))
        return True


# ------------------------------------------------------------------------------- projections
def finish_projection(tx, spec, rows_by_occ_id, ctx, cfg):
    """Raw OCC rows -> canonical dicts (records gain their access list and booking settings)."""
    jc = M.JSON_COLS.get(spec.occ, ())
    out = {}
    for oid, row in rows_by_occ_id.items():
        d = {c: (canon.json_value(row[c]) if c in jc else row[c]) for c in spec.cols}
        for c in CHAR_COLS.intersection(d):          # char(n) pads with spaces; the source value has none
            if isinstance(d[c], str):
                d[c] = d[c].rstrip(" ")
        out[oid] = d
    if spec.occ == "records" and out:
        rids = [int(x) for x in out]
        acc = {}
        for r in tx.all("SELECT rid, access_right, principal, principal_id FROM occ.record_access WHERE rid = ANY(:r)",
                        r=rids):
            acc.setdefault(str(r["rid"]), []).append([r["access_right"], r["principal"], r["principal_id"]])
        for oid in out:
            out[oid]["_access"] = sorted(acc.get(oid, []))
        if spec.kind in (2, 4):
            present = booking_cols(ctx, spec.src)
            bcols = ", ".join(ident(c, M.OCC_COLUMNS) for c in present)
            bk = {str(r["rid"]): r for r in tx.all(
                "SELECT rid, %s FROM occ.resource_booking WHERE rid = ANY(:r)" % bcols, r=rids)} if present else {}
            for oid in out:
                b = bk.get(oid)
                out[oid]["_booking"] = {c: b[c] for c in present} if b else ({} if not present else None)
    if spec.occ == "site_config":
        for oid in out:
            if out[oid].get("is_secret"):
                out[oid]["_secret_sha256"] = _secret_hash(tx, cfg, oid)
    return out


def booking_cols(ctx, table):
    """The booking settings this 2.x table has (resource templates carry none in 5.6.12)."""
    src = getattr(ctx, "source", None)
    have = set(src.columns.get(table, [])) if src is not None else set(M.BOOKING_COLS)
    return [c for c in M.BOOKING_COLS if c in have]


def _secret_hash(tx, cfg, name):
    try:
        from ..people import config as config_mod
        v = config_mod.secret(tx, cfg, name)
        return hashlib.sha256(v.encode("utf-8")).hexdigest() if v is not None else None
    except Exception:
        return None


def project_all(tx, spec, ctx, cfg):
    """{source_id: (occ_id, canonical)} for every id_map row of this spec whose OCC row exists."""
    cols = ", ".join("t." + ident(c, M.OCC_COLUMNS) for c in spec.cols)
    rows = tx.all("SELECT m.source_id AS m_source_id, m.occ_id AS m_occ_id, %s FROM occ.id_map m JOIN occ.%s t ON %s "
                  "= m.occ_id WHERE m.system = 'elabftw' AND m.source_table = :st" % (
                      cols, ident(spec.occ, M.OCC_TABLES), KEYEXPR[spec.occ]), st=spec.src)
    by_occ = {r["m_occ_id"]: r for r in rows}
    canon_rows = finish_projection(tx, spec, by_occ, ctx, cfg)
    return {r["m_source_id"]: (r["m_occ_id"], canon_rows[r["m_occ_id"]]) for r in rows}


# ---------------------------------------------------------------------------------- sequences
def bump_sequences(tx, floor=None):
    """After carrying rows with their 2.x ids, the identity sequences continue after the highest id;
    while sync phase A runs they start at the local floor (3.x-only objects from 10,000,000), so
    an id made in 3.x can never collide with one 2.x makes later."""
    out = {}
    for t in sorted(SEQ_TABLES):
        seq = tx.val("SELECT pg_get_serial_sequence(:t, 'id')", t="occ." + t)
        top = tx.val("SELECT coalesce(max(id), 0) FROM occ.%s" % ident(t, SEQ_TABLES)) or 0
        target = max(int(top), (floor - 1) if floor else 0)
        if seq and target > 0:
            cur = tx.val("SELECT last_value FROM pg_sequences WHERE schemaname || '.' || sequencename = :s", s=seq)
            if cur is None or int(cur) < target:
                tx.val("SELECT setval(CAST(:s AS regclass), :v)", s=seq, v=target)
                out[t] = target
    for kind, seq in RECORD_SEQS.items():
        top = tx.val("SELECT coalesce(max(id), 0) FROM occ.records WHERE kind_id = :k", k=kind) or 0
        target = max(int(top), (floor - 1) if floor else 0)
        if target > 0:
            cur = tx.val("SELECT last_value FROM pg_sequences WHERE schemaname || '.' || sequencename = :s", s=seq)
            if cur is None or int(cur) < target:
                tx.val("SELECT setval(CAST(:s AS regclass), :v)", s=seq, v=target)
                out[seq] = target
    return out


def write_batch_audit(tx, actor_kind, run_id, table, counts):
    from ..audit import writer as audit
    audit.write(tx, audit.Actor(kind=actor_kind), "%s.batch" % actor_kind, target=table,
                detail={"run_id": run_id, "source_table": table, **counts})

