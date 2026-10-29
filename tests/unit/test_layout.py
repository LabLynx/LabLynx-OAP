# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Layout, license marking and the clean-room rule, checked on the files themselves."""
import hashlib
import os
import re
import subprocess
import sys

OCC = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
AGPL_SHA256 = "0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0"   # gnu.org/licenses/agpl-3.0.txt
SPDX = "SPDX-License-Identifier: AGPL-3.0-only"
SOURCE_EXT = (".py", ".sql", ".toml", ".service", ".slice", ".conf", ".example", ".md", ".txt", ".sh")


def occ_files():
    for root, dirs, names in os.walk(OCC):
        dirs[:] = [d for d in dirs if d not in ("__pycache__", ".pytest_cache", ".venv")]
        for n in names:
            yield os.path.join(root, n)


def test_license_text_is_agpl_3():
    with open(os.path.join(OCC, "LICENSE"), "rb") as fh:
        assert hashlib.sha256(fh.read()).hexdigest() == AGPL_SHA256


def test_every_source_file_carries_the_agpl_header():
    missing = []
    for path in occ_files():
        rel = os.path.relpath(path, OCC)
        if rel == "LICENSE" or not (path.endswith(SOURCE_EXT) or os.path.basename(path) == ".gitignore"):
            continue
        with open(path, encoding="utf-8") as fh:
            head = fh.read(400)
        if SPDX not in head or "Copyright (c) 2026 LabLynx, Inc." not in head:
            missing.append(rel)
    assert not missing, missing


def test_no_proprietary_header_and_no_core_source_reference():
    bad = []
    for path in occ_files():
        if path.endswith(("LICENSE", ".json")):
            continue
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        if "All rights " + "reserved" in text:
            bad.append(("proprietary header", os.path.relpath(path, OCC)))
        if "core" + "-source" in text:               # clean room: the captured upstream folder is never an input
            bad.append(("names the captured upstream source", os.path.relpath(path, OCC)))
    assert not bad, bad


def test_migration_0001_is_the_design_schema():
    """Migration 0001 is the designed schema (docs/design/schema.sql), byte for byte."""
    a = open(os.path.join(OCC, "occ", "migrations", "0001_schema_v1.sql"), "rb").read()
    b = open(os.path.join(OCC, "docs", "design", "schema.sql"), "rb").read()
    assert a == b
    assert len(re.findall(rb"^CREATE TABLE occ\.", a, re.M)) == 55


# The schema and the 2.x table mapping are public and always present. The other design records are
# the development specification's own (its endpoint catalog, divergences and traceability), which a
# published copy does not carry; where any of them is present, all of them must be.
PUBLIC_DESIGN = ("schema.sql", "mapping.json")
DEVELOPMENT_DESIGN = ("endpoints.json", "divergences.json", "traceability.json", "decisions.json")


def test_design_files_are_present():
    d = os.path.join(OCC, "docs", "design")
    for n in PUBLIC_DESIGN:
        assert os.path.exists(os.path.join(d, n)), n
    present = [n for n in DEVELOPMENT_DESIGN if os.path.exists(os.path.join(d, n))]
    if not present:
        import pytest
        pytest.skip("a published copy: the development design records are not part of it")
    assert present == list(DEVELOPMENT_DESIGN), sorted(set(DEVELOPMENT_DESIGN) - set(present))


def test_runtime_dependencies_are_recorded_and_permissive():
    r = subprocess.run([sys.executable, os.path.join(OCC, "tests", "deps_record.py")], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout[-2000:]


def test_no_database_credential_in_occ():
    """No password, key or connection credential anywhere in the tree."""
    pat = re.compile(r"(password\s*=\s*['\"][^'\"]+['\"]|postgres(ql)?://[^/\s'\"]*:[^@\s'\"]+@|occ_\d+_[A-Za-z0-9_-]{43})")
    hits = []
    for path in occ_files():
        if path.endswith("LICENSE"):
            continue
        with open(path, encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh, 1):
                if pat.search(line):
                    hits.append("%s:%d" % (os.path.relpath(path, OCC), i))
    assert not hits, hits
