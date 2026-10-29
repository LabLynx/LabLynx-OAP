# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The file store: bytes are kept once per SHA-256.

One interface, so object storage (S3, files/s3.py) can replace disk without changing the API
(OCC_FILES_BACKEND=disk|s3):
    put(chunks) -> (sha256 bytes, size)    hash while writing; the bytes land under their own hash
    open(sha256) -> a binary file object
    exists(sha256) -> bool
    rehash(sha256) -> the SHA-256 of what is stored now (the weekly blob check)
    delete(sha256)                          only through delete_if_unreferenced() or the orphan sweep
    blobs() -> (sha256, age in seconds)     every stored blob, for the orphan sweep (files/sweep.py)

Disk layout: <root>/ab/cd/<64 hex>. A file is written to a temporary name in the same folder tree,
fsynced and renamed, so a reader never sees half a file and two writers of the same bytes agree.
File names a person gave are never used as paths: only the hash is.

register(tx, ...) records the blob in occ.file_blobs (ON CONFLICT DO NOTHING: stored once).
"""
import hashlib
import os
import tempfile

from ..db import ident

CHUNK = 1024 * 1024
_REFERENCING = frozenset(("uploads", "exports", "site_assets"))     # tables whose sha256 column points at a blob


class TooLarge(Exception):
    pass


def location(sha):
    h = sha.hex()
    return "%s/%s/%s" % (h[:2], h[2:4], h)


class DiskStore:
    backend = "disk"

    def __init__(self, root):
        self.root = root

    def _path(self, sha):
        return os.path.join(self.root, location(sha))

    def put(self, chunks, max_size=None):
        os.makedirs(os.path.join(self.root, "tmp"), exist_ok=True)
        h = hashlib.sha256()
        size = 0
        fd, tmp = tempfile.mkstemp(dir=os.path.join(self.root, "tmp"))
        try:
            with os.fdopen(fd, "wb") as fh:
                for chunk in chunks:
                    if not chunk:
                        continue
                    size += len(chunk)
                    if max_size is not None and size > max_size:
                        raise TooLarge()
                    h.update(chunk)
                    fh.write(chunk)
                fh.flush()
                os.fsync(fh.fileno())
            sha = h.digest()
            dest = self._path(sha)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            if os.path.exists(dest):
                os.remove(tmp)
                os.utime(dest)          # fresh again: the orphan sweep's grace period protects it
            else:
                os.replace(tmp, dest)
            return sha, size
        except BaseException:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise

    def put_bytes(self, data):
        return self.put([data])

    def open(self, sha):
        return open(self._path(sha), "rb")

    def exists(self, sha):
        return os.path.exists(self._path(sha))

    def rehash(self, sha):
        h = hashlib.sha256()
        with self.open(sha) as fh:
            for chunk in iter(lambda: fh.read(CHUNK), b""):
                h.update(chunk)
        return h.digest()

    def delete(self, sha):
        try:
            os.remove(self._path(sha))
        except FileNotFoundError:
            pass


    def blobs(self):
        import time
        now = time.time()
        for top in sorted(os.listdir(self.root)) if os.path.isdir(self.root) else ():
            if len(top) != 2:
                continue
            for root, _dirs, names in os.walk(os.path.join(self.root, top)):
                for n in names:
                    if len(n) != 64:
                        continue
                    try:
                        sha = bytes.fromhex(n)
                        age = now - os.stat(os.path.join(root, n)).st_mtime
                    except (ValueError, OSError):
                        continue
                    yield sha, age

    def stale_temporaries(self, older_than):
        """Half-written files a crashed upload left in tmp/, older than the given seconds."""
        import time
        d = os.path.join(self.root, "tmp")
        now = time.time()
        for n in sorted(os.listdir(d)) if os.path.isdir(d) else ():
            p = os.path.join(d, n)
            try:
                if now - os.stat(p).st_mtime > older_than:
                    yield p
            except OSError:
                continue


def for_settings(cfg):
    backend = ((getattr(cfg, "extra", None) or {}).get("OCC_FILES_BACKEND") or "disk").strip().lower()
    if backend == "s3":
        from . import s3
        return s3.from_settings(cfg)
    if backend != "disk":
        raise ValueError("OCC_FILES_BACKEND is disk or s3")
    return DiskStore(cfg.files_root)


def register(tx, store, sha, size):
    tx.run("INSERT INTO occ.file_blobs (sha256, size, backend, location) VALUES (:s, :n, :b, :l) "
           "ON CONFLICT (sha256) DO NOTHING", s=sha, n=size, b=store.backend, l=location(sha))


def delete_if_unreferenced(tx, store, sha):
    """Removes a blob nobody points at any more; returns True when it went."""
    for table in _REFERENCING:
        if tx.val("SELECT 1 FROM occ.%s WHERE sha256 = :s LIMIT 1" % ident(table, _REFERENCING), s=sha):
            return False
    tx.run("DELETE FROM occ.file_blobs WHERE sha256 = :s", s=sha)
    store.delete(sha)
    return True


def iter_file(fh, close=True):
    try:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            yield chunk
    finally:
        if close:
            fh.close()
