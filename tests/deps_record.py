# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Write or check occ/docs/dependencies.json: every package the OCC needs, with its version and
license, split into runtime (installed on the server) and test-only.

    ~/.local/venvs/occ/bin/python tests/deps_record.py          # check (exit 1 on any difference)
    ~/.local/venvs/occ/bin/python tests/deps_record.py --write  # record what the venv holds

Runtime packages must be under a permissive license (the same allow-list as
the workspace's license check, plus PSF-2.0 and MIT-0). Run with the OCC's virtual environment.
"""
import importlib.metadata as md
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(os.path.dirname(HERE), "docs", "dependencies.json")
RUNTIME_ROOTS = ["fastapi", "uvicorn", "pydantic", "pg8000", "nh3", "python-multipart", "cryptography", "pymysql"]
TEST_ROOTS = ["pytest", "httpx"]
PERMISSIVE = {"MIT", "MIT-0", "BSD-2-Clause", "BSD-3-Clause", "0BSD", "Apache-2.0", "ISC", "Zlib", "Unlicense",
              "CC0-1.0", "BlueOak-1.0.0", "Python-2.0", "PSF-2.0"}
# Packages whose metadata does not carry an SPDX expression: the license read from the project.
KNOWN = {"pg8000": "BSD-3-Clause", "python-dateutil": "Apache-2.0 OR BSD-3-Clause", "asn1crypto": "MIT",
         "six": "MIT", "tzdata": "Apache-2.0"}


def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def license_of(dist):
    name = norm(dist.metadata["Name"])
    if name in KNOWN:
        return KNOWN[name]
    m = dist.metadata
    return (m.get("License-Expression") or m.get("License") or "").strip().splitlines()[0] if (
        m.get("License-Expression") or m.get("License")) else ""


def closure(roots):
    seen, todo = {}, list(roots)
    while todo:
        n = norm(todo.pop())
        if n in seen:
            continue
        try:
            d = md.distribution(n)
        except md.PackageNotFoundError:
            continue
        seen[n] = d
        for req in d.requires or []:
            if "extra ==" in req:
                continue
            todo.append(re.split(r"[ ;<>=!~\[(]", req, maxsplit=1)[0])
    return seen


def permissive(expr):
    expr = expr.strip()
    if " OR " in expr:
        return any(permissive(x.strip("() ")) for x in expr.split(" OR "))
    if " AND " in expr:
        return all(permissive(x.strip("() ")) for x in expr.split(" AND "))
    return expr in PERMISSIVE


def build():
    rt = closure(RUNTIME_ROOTS)
    te = {k: v for k, v in closure(TEST_ROOTS).items() if k not in rt}
    row = lambda d: {"name": norm(d.metadata["Name"]), "version": d.version, "license": license_of(d)}
    return {"_what": "Every package the OCC needs. Runtime ones are installed on the server and must be under a "
                     "permissive license; test-only ones never are. Checked by tests/unit/test_layout.py. "
                     "bundled_assets (files shipped inside the OCC, each with its license) and "
                     "tools_run_not_shipped (programs the checks run when installed) are kept by hand.",
            "runtime": sorted((row(d) for d in rt.values()), key=lambda r: r["name"]),
            "test_only": sorted((row(d) for d in te.values()), key=lambda r: r["name"])}


# Kept by hand, carried over by --write and not compared with the environment: files shipped inside the
# OCC that are not packages (fonts), and programs the checks run when installed but never ship.
HAND_KEPT = ("bundled_assets", "tools_run_not_shipped")


if __name__ == "__main__":
    data = build()
    recorded = json.load(open(OUT)) if os.path.exists(OUT) else {}
    for k in HAND_KEPT:
        if k in recorded:
            data[k] = recorded[k]
    if "--write" in sys.argv:
        with open(OUT, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1)
            fh.write("\n")
    bad = [r for r in data["runtime"] if not permissive(r["license"])]
    for r in data["runtime"]:
        print("runtime  %-20s %-12s %s%s" % (r["name"], r["version"], r["license"], "" if permissive(r["license"]) else "   NOT PERMISSIVE"))
    for r in data["test_only"]:
        print("test     %-20s %-12s %s" % (r["name"], r["version"], r["license"]))
    recorded = json.load(open(OUT)) if os.path.exists(OUT) else None
    if {k: v for k, v in (recorded or {}).items() if k != "_what"} != {k: v for k, v in data.items() if k != "_what"}:
        print("docs/dependencies.json differs from the environment")
        sys.exit(1)
    sys.exit(1 if bad else 0)
