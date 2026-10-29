# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The orphaned-file sweep: bytes stored with no record of them are removed after a grace period.

An upload stores its bytes before the transaction that registers them, so a transaction
that fails leaves bytes in the store with no occ.file_blobs row. The sweep removes such a blob when
it is older than the grace period (24 hours by default) and still has no row. Bytes an upload is
about to register are never that old: storing the same bytes again refreshes the blob's time (the
disk store touches the file, the S3 store writes the object again), so the grace period always
counts from the latest upload of those bytes. Half-written temporary files a crashed upload left
on disk go after the same period.

It runs weekly on the worker (files-sweep) and as `occ sweep-files [--dry-run]`. Each removal is
checked against occ.file_blobs inside its own transaction, and the run adds one audit row
(upload.sweep, actor system) listing what went.
"""
import os

from ..audit import writer as audit
from . import store as fstore

SYSTEM = audit.Actor(kind="system")
DEFAULT_GRACE_HOURS = 24.0


def sweep(pool, cfg, grace_hours=DEFAULT_GRACE_HOURS, dry_run=False, store=None):
    st = store or fstore.for_settings(cfg)
    grace = float(grace_hours) * 3600.0
    seen = removed = young = 0
    gone = []
    for sha, age in st.blobs():
        seen += 1
        with pool.tx() as tx:
            if tx.val("SELECT 1 FROM occ.file_blobs WHERE sha256 = :s", s=sha):
                continue
            if age < grace:
                young += 1
                continue
            if not dry_run:
                st.delete(sha)
            removed += 1
            gone.append(sha.hex())
    temps = 0
    if hasattr(st, "stale_temporaries"):
        for path in list(st.stale_temporaries(grace)):
            temps += 1
            if not dry_run:
                try:
                    os.remove(path)
                except OSError:
                    temps -= 1
    if (removed or temps) and not dry_run:
        with pool.tx() as tx:
            audit.write(tx, SYSTEM, "upload.sweep", target="file_blobs",
                        detail={"backend": st.backend, "removed": removed, "temporaries": temps,
                                "sha256": gone[:200], "grace_hours": grace_hours})
    return {"backend": st.backend, "blobs_seen": seen, "removed": removed, "unregistered_but_young": young,
            "temporaries_removed": temps, "dry_run": bool(dry_run)}
