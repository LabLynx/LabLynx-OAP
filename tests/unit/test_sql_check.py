# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""No SQL built from text. The package passes the check,
and the check bites: each way of building SQL from outside text is caught, and each allowed
form passes."""
import os
import re
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import sqlcheck  # noqa: E402
from occ import db  # noqa: E402


def test_the_occ_package_builds_no_sql_from_text():
    findings = sqlcheck.check()
    assert findings == [], "\n".join(findings)
    assert len(sqlcheck.EXCEPTIONS) <= 3            # the list stays short; growing it is a decision


BAD = {
    "a request value in an f-string": '''
def f(tx, q):
    tx.all(f"SELECT * FROM occ.records WHERE title = '{q}'")
''',
    "a parameter through %": '''
def f(tx, col):
    tx.run("UPDATE occ.records SET %s = 1" % col)
''',
    "a closed list that is not a constant": '''
def f(tx, col, allowed):
    tx.run("UPDATE occ.records SET %s = 1" % ident(col, allowed))
''',
    "a local that is once safe, once not": '''
def f(tx, q):
    where = "TRUE"
    if q:
        where = q
    tx.all("SELECT 1 WHERE " + where)
''',
    "a list that collects outside text": '''
def f(tx, q):
    parts = ["a = 1"]
    parts.append(q["x"])
    tx.all("SELECT 1 WHERE " + " AND ".join(parts))
''',
    "a fragment function that returns outside text": '''
@sql_fragment
def frag(q):
    return q
''',
    "a pass-through called with outside text": '''
def run_it(tx, where_sql):
    tx.all("SELECT 1 WHERE " + where_sql)

def g(tx, q):
    run_it(tx, q)
''',
    "an unmarked helper's result": '''
def helper(x):
    return "SELECT 1"

def g(tx):
    tx.all(helper(1))
''',
    "a .format with outside text": '''
def g(tx, q):
    tx.all("SELECT {c} FROM t".format(c=q))
''',
}

GOOD = '''
COLS = frozenset(("title", "date"))
SQL = "SELECT 1"
MAP = {"a": "r.id", "b": "r.title"}

@sql_fragment
def frag(full):
    return "SELECT r.id" + (", r.body" if full else ""), {}

def run_it(tx, where_sql):
    tx.all("SELECT 1 WHERE " + where_sql)

def f(tx, col, q, order):
    tx.run("UPDATE occ.records SET %s = :v" % ident(col, COLS), v=q)
    where = ["r.state = 1"]
    for i, tag in enumerate(q["tags"]):
        where.append("tg.tag = :t%d" % i)
    for name, c in (("cat", "r.category_id"), ("status", "r.status_id")):
        where.append("%s = :%s" % (c, name))
    sql, params = frag(True)
    tx.all(sql + " WHERE " + " AND ".join(where) + " ORDER BY " + MAP[order], **params)
    tx.all(SQL)
    tx.all("SELECT {c} FROM t".format(c="x"))
    run_it(tx, "a = 1")
'''


@pytest.mark.parametrize("name", sorted(BAD))
def test_the_check_catches(name):
    assert sqlcheck.check_source(BAD[name]), name


def test_the_allowed_forms_pass():
    assert sqlcheck.check_source(GOOD) == []


def test_ident_refuses_names_outside_the_closed_list():
    assert db.ident("title", frozenset(("title",))) == "title"
    assert db.ident("occ_scratch_ab12", re.compile(r"occ_scratch_\w+")) == "occ_scratch_ab12"
    for bad in ("title; --", "Title", 'a"b', 5, None):
        with pytest.raises(ValueError):
            db.ident(bad, frozenset(("title",)))
    with pytest.raises(ValueError):
        db.ident("occ_scratch_x; --", re.compile(r"occ_scratch_\w+"))
