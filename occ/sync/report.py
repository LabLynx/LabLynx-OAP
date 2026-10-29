# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The run report and the reconciliation.

The reconciliation compares, for every carried table, the 2.x rows (read now, built with the
mapping, hashed in canonical form) with their OCC projections (read back from the OCC, hashed
the same way): row counts, and each row's content hash. Every difference is listed: a 2.x row
missing in the OCC, an OCC row whose 2.x row is gone, and a row whose content differs (with the
fields that differ). Rows the mapping does not carry are counted with their reason.

The report has a 'result' part that depends only on the data (counts, differences, skips), and
a 'run' part (times, writes). Two runs over unchanged data give the same result_sha256.
"""
import datetime as dt
import hashlib
import json

from ..db import ident
from . import apply as A, canon, mapping as M

MAX_LISTED = 200


class Report:
    def __init__(self):
        self.writes = {}
        self.skips = {}
        self.skipped_ids = {}          # table -> {source id: reason}, complete (the reconciliation names reasons)
        self.replaced_edits = []
        self.kept_rows = []
        self.file_problems = []
        self.files_carried = 0

    # called by the writer
    def count(self, spec, outcome):
        w = self.writes.setdefault(spec.src, {"inserted": 0, "updated": 0, "unchanged": 0, "skipped": 0, "removed": 0})
        w[outcome] = w.get(outcome, 0) + 1

    def skip(self, spec, sid, reason):
        self.skipped_ids.setdefault(spec.src, {})[sid] = reason
        t = self.skips.setdefault(spec.src, {})
        e = t.setdefault(reason, {"count": 0, "ids": []})
        e["count"] += 1
        if len(e["ids"]) < 25:
            e["ids"].append(sid)

    def replaced(self, spec, sid, occ_id, what, fields):
        self.replaced_edits.append({"table": spec.src, "source_id": sid, "occ_table": spec.occ, "occ_id": occ_id,
                                    "what": what, "fields": fields[:20]})

    def kept(self, spec, sid, occ_id):
        self.kept_rows.append({"table": spec.src, "source_id": sid, "occ_id": occ_id,
                               "why": "gone from 2.x; this kind is never removed from 3.x by the sync"})

    def file_problem(self, sid, text):
        self.file_problems.append({"upload": sid, "problem": text})

    def file_ok(self):
        self.files_carried += 1

    def merge(self, other):
        """Takes another report's findings (a batch's, once its transaction committed)."""
        for t, ids in other.skipped_ids.items():
            self.skipped_ids.setdefault(t, {}).update(ids)
        for t, reasons in other.skips.items():
            for reason, e in reasons.items():
                mine = self.skips.setdefault(t, {}).setdefault(reason, {"count": 0, "ids": []})
                mine["count"] += e["count"]
                mine["ids"] = (mine["ids"] + e["ids"])[:25]
        self.replaced_edits += other.replaced_edits
        self.kept_rows += other.kept_rows
        self.file_problems += other.file_problems
        self.files_carried += other.files_carried

    def total_writes(self):
        return sum(v.get("inserted", 0) + v.get("updated", 0) + v.get("removed", 0) for v in self.writes.values())


def reconcile(tx, source, cfg, rows_of, can_seal=False, skipped_ids=None):
    """{'tables': {...}, 'differences': [...], 'transformations': {...}, 'ok': bool}.
    rows_of(spec) yields the 2.x rows of a table, read now. skipped_ids (the run's writer skips,
    {table: {source id: reason}}) gives the reason a 2.x row is missing in the OCC, where known."""
    skipped_ids = skipped_ids or {}
    ctx = A.Ctx(tx, source, can_seal)
    ctx.full = True
    tables, diffs = {}, []
    for spec in M.SPECS:
        if not source.has(spec.src):
            tables[spec.src] = {"state": "carried", "occ": spec.occ, "note": "table absent in this 2.x"}
            continue
        expected, skipped, n_src = {}, {}, 0
        for row in rows_of(spec):
            n_src += 1
            values = spec.build(row, ctx)
            sid = spec.source_id(row)
            if isinstance(values, M.Skip):
                skipped[values.reason] = skipped.get(values.reason, 0) + 1
                continue
            expected[sid] = A.canonical(spec, values)
        got = A.project_all(tx, spec, ctx, cfg)
        missing = sorted(set(expected) - set(got), key=_natural)
        extra = sorted(set(got) - set(expected), key=_natural)
        changed = []
        for sid in expected:
            if sid in got and canon.digest(expected[sid]) != canon.digest(got[sid][1]):
                changed.append(sid)
        changed.sort(key=_natural)
        # a skipped row that the OCC still holds from an earlier run is not a difference here,
        # it is listed under 'extra' only when 2.x no longer has the row at all
        why = skipped_ids.get(spec.src, {})
        missing_reasons = {}
        for sid in missing:
            r = why.get(sid, "not known to this run")
            missing_reasons[r] = missing_reasons.get(r, 0) + 1
        tables[spec.src] = {"state": "carried", "occ": spec.occ, "source_rows": n_src, "carried": len(expected),
                            "skipped": sum(skipped.values()), "skip_reasons": dict(sorted(skipped.items())),
                            "occ_rows": len(got), "missing_in_occ": len(missing), "extra_in_occ": len(extra),
                            "content_differences": len(changed)}
        if missing_reasons:
            tables[spec.src]["missing_reasons"] = dict(sorted(missing_reasons.items()))
        for sid in missing[:MAX_LISTED]:
            d = {"table": spec.src, "source_id": sid, "difference": "missing in the OCC"}
            if sid in why:
                d["reason"] = why[sid]
            diffs.append(d)
        for sid in extra[:MAX_LISTED]:
            diffs.append({"table": spec.src, "source_id": sid, "occ_id": got[sid][0],
                          "difference": "in the OCC, not (or no longer) in 2.x"})
        for sid in changed[:MAX_LISTED]:
            fields = canon.diff(expected[sid], got[sid][1])
            diffs.append({"table": spec.src, "source_id": sid, "occ_id": got[sid][0], "difference": "content differs",
                          "fields": [{"field": f, "2.x": _short(canon.norm(expected[sid].get(f))),
                                      "3.x": _short(canon.norm(got[sid][1].get(f)))} for f in fields[:10]]})
    for t, (state, why) in sorted(M.classification().items()):
        if state != "carried":
            tables[t] = {"state": state, "reason": why,
                         "source_rows": _count(source, t) if source.has(t) else None}
    only3x = tx.val("SELECT count(*) FROM occ.records r WHERE NOT EXISTS (SELECT 1 FROM occ.id_map m WHERE "
                    "m.system = 'elabftw' AND m.occ_table = 'records' AND m.occ_id = r.rid::text)")
    ok = all(v.get("missing_in_occ", 0) == 0 and v.get("extra_in_occ", 0) == 0 and v.get("content_differences", 0) == 0
             for v in tables.values())
    total = sum(v.get("missing_in_occ", 0) + v.get("extra_in_occ", 0) + v.get("content_differences", 0)
                for v in tables.values())
    return {"ok": ok, "difference_count": total, "differences_listed_max_per_kind": MAX_LISTED,
            "tables": dict(sorted(tables.items())), "differences": diffs,
            "transformations": dict(sorted(ctx.notes.items())), "records_only_in_3x": int(only3x or 0)}


def _count(source, t):
    r = source.scalar_row("SELECT COUNT(*) FROM `%s`" % ident(t, M.TABLES))
    return int(r[0]) if r else None


def _short(v):
    s = json.dumps(v, ensure_ascii=False, default=str)
    return v if len(s) <= 200 else s[:200] + "..."


def _natural(s):
    return [int(x) if x.isdigit() else x for x in str(s).replace(":", " ").split()]


def build(run, rec, report, unchanged_proof=None):
    result = {"reconciliation": rec, "skips": {t: {r: e for r, e in sorted(v.items())}
                                                for t, v in sorted(report.skips.items())}}
    result_sha = hashlib.sha256(canon.dumps(result).encode("utf-8")).hexdigest()
    return {"what": "LabLynx.One OCC: 2.x to 3.x migration report",
            "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "run": run, "writes": dict(sorted(report.writes.items())), "total_writes": report.total_writes(),
            "replaced_3x_edits": report.replaced_edits, "kept_in_3x": report.kept_rows[:MAX_LISTED],
            "files": {"carried": report.files_carried, "problems": report.file_problems[:MAX_LISTED]},
            "source_unchanged": unchanged_proof, "result": result, "result_sha256": result_sha}
