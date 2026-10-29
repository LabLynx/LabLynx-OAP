# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The `extended` search grammar, compiled to a parameterized SQL condition.

    expr    := term { (AND | OR) term }          AND binds tighter than OR; juxtaposition means AND
    term    := NOT term | '(' expr ')' | filter | word | "quoted phrase"
    filter  := field ':' value
    value   := word | "quoted" | op value (op in > >= < <= =) | a..b (range; dates YYYY-MM-DD)
    word    := substring match on search_text, case-insensitive (so extended=1 finds records containing "1")

The compiled condition refers to the record as alias r and to its status and category as s and c.
Values never enter the SQL text: each becomes a :sN parameter.
"""
import re

from .. import timefmt
from ..db import sql_fragment


class SearchError(ValueError):
    pass


FIELDS = {"author", "body", "category", "custom_id", "date", "elabid", "extrafield", "group", "id", "locked",
          "rating", "status", "tag", "timestamped", "title", "visibility", "attachment"}

_TOKEN = re.compile(r'\s*(?:(?P<lp>\()|(?P<rp>\))|(?P<q>"(?:[^"\\]|\\.)*")|(?P<w>[^\s()"]+(?:"(?:[^"\\]|\\.)*")?[^\s()]*))')


def tokenize(text):
    out, pos = [], 0
    text = text or ""
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m or m.end() == pos:
            if text[pos:].strip() == "":
                break
            raise SearchError("cannot read the search near: %s" % text[pos:pos + 20])
        pos = m.end()
        if m.group("lp"):
            out.append(("(", "("))
        elif m.group("rp"):
            out.append((")", ")"))
        elif m.group("q"):
            out.append(("phrase", _unquote(m.group("q"))))
        elif m.group("w"):
            w = m.group("w")
            if w in ("AND", "OR", "NOT"):
                out.append((w, w))
            else:
                out.append(("word", w))
    return out


def _unquote(s):
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    return re.sub(r'\\(.)', r'\1', s)


def like_escape(text):
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class Compiler:
    def __init__(self):
        self.params = {}

    def p(self, value):
        name = "s%d" % len(self.params)
        self.params[name] = value
        return ":" + name

    def contains(self, col, text):
        return "%s ILIKE %s" % (col, self.p("%" + like_escape(text) + "%"))

    # -- parser ------------------------------------------------------------------------------
    def parse(self, text):
        self.toks = tokenize(text)
        self.i = 0
        if not self.toks:
            return "TRUE"
        sql = self.expr()
        if self.i != len(self.toks):
            raise SearchError("unexpected %s in the search" % self.toks[self.i][1])
        return sql

    def peek(self):
        return self.toks[self.i][0] if self.i < len(self.toks) else None

    def expr(self):
        parts = [self.and_expr()]
        while self.peek() == "OR":
            self.i += 1
            parts.append(self.and_expr())
        return parts[0] if len(parts) == 1 else "(" + " OR ".join(parts) + ")"

    def and_expr(self):
        parts = [self.term()]
        while self.peek() in ("AND", "NOT", "(", "word", "phrase"):
            if self.peek() == "AND":
                self.i += 1
            parts.append(self.term())
        return parts[0] if len(parts) == 1 else "(" + " AND ".join(parts) + ")"

    def term(self):
        kind = self.peek()
        if kind is None:
            raise SearchError("the search ends too early")
        if kind == "NOT":
            self.i += 1
            return "NOT (%s)" % self.term()
        if kind == "(":
            self.i += 1
            inner = self.expr()
            if self.peek() != ")":
                raise SearchError("a parenthesis is not closed")
            self.i += 1
            return inner
        if kind == ")":
            raise SearchError("a parenthesis closes without opening")
        tok = self.toks[self.i][1]
        self.i += 1
        if kind == "phrase":
            return self.contains("r.search_text", tok)
        m = re.match(r'^([a-z_]+)(?:\."((?:[^"\\]|\\.)*)")?:(.*)$', tok)
        if m and m.group(1) in FIELDS:
            field, sub, value = m.group(1), m.group(2), m.group(3)
            if value == "" and self.peek() == "phrase":
                value = '"%s"' % self.toks[self.i][1].replace('"', '\\"')
                self.i += 1
            return self.filter(field, _unquote(sub) if sub is not None else None, value)
        return self.contains("r.search_text", tok)

    # -- filters -----------------------------------------------------------------------------
    def filter(self, field, sub, raw):
        op, value = "=", raw
        rng = None
        mo = re.match(r"^(>=|<=|>|<|=)(.*)$", raw)
        if mo:
            op, value = mo.group(1), mo.group(2)
        value = _unquote(value)
        if ".." in value and not mo:
            a, b = value.split("..", 1)
            rng = (a, b)

        if field == "title":
            return self.contains("r.title", value)
        if field == "body":
            return self.contains("r.body_text", value)
        if field == "elabid":
            return self.contains("r.elabid", value)
        if field == "status":
            return "lower(s.title) = lower(%s)" % self.p(value)
        if field == "category":
            return "lower(c.title) = lower(%s)" % self.p(value)
        if field == "author":
            return ("EXISTS (SELECT 1 FROM occ.users au WHERE au.id = r.owner_id AND "
                    "(au.firstname || ' ' || au.lastname) ILIKE %s)" % self.p("%" + like_escape(value) + "%"))
        if field == "tag":
            return ("EXISTS (SELECT 1 FROM occ.record_tags rt JOIN occ.tags tg ON tg.id = rt.tag_id "
                    "WHERE rt.rid = r.rid AND tg.tag ILIKE %s)" % self.p(like_escape(value)))
        if field == "group":
            return ("EXISTS (SELECT 1 FROM occ.team_group_members gm JOIN occ.team_groups g ON g.id = gm.group_id "
                    "WHERE gm.user_id = r.owner_id AND lower(g.name) = lower(%s))" % self.p(value))
        if field == "attachment":
            if value.lower() in ("yes", "1", "true", "none", "no", "0", "false"):
                has = value.lower() in ("yes", "1", "true")
                return "%sEXISTS (SELECT 1 FROM occ.uploads up WHERE up.rid = r.rid AND up.state = 1)" % ("" if has else "NOT ")
            return ("EXISTS (SELECT 1 FROM occ.uploads up WHERE up.rid = r.rid AND up.state = 1 AND up.real_name ILIKE %s)"
                    % self.p("%" + like_escape(value) + "%"))
        if field in ("locked", "timestamped"):
            truthy = value.lower() in ("1", "yes", "true")
            if value.lower() not in ("1", "yes", "true", "0", "no", "false"):
                raise SearchError("%s: takes yes or no" % field)
            return "r.%s = %s" % (field, "TRUE" if truthy else "FALSE")
        if field in ("id", "rating", "custom_id", "visibility"):
            col = {"id": "r.id", "rating": "r.rating", "custom_id": "r.custom_id", "visibility": "r.canread_base"}[field]
            if rng:
                return "%s BETWEEN %s AND %s" % (col, self.p(_int(field, rng[0])), self.p(_int(field, rng[1])))
            return "%s %s %s" % (col, op, self.p(_int(field, value)))
        if field == "date":
            if rng:
                return "r.date BETWEEN %s AND %s" % (self.p(_date(rng[0])), self.p(_date(rng[1])))
            return "r.date %s %s" % (op, self.p(_date(value)))
        if field == "extrafield":
            if not sub:
                raise SearchError('extrafield needs a name: extrafield."Name":value')
            col = "(r.metadata->'extra_fields'->%s->>'value')" % self.p(sub)
            if op == "=" and not mo:
                return "%s ILIKE %s" % (col, self.p("%" + like_escape(value) + "%"))
            return "%s %s %s" % (col, op, self.p(value))
        raise SearchError("unknown search field %s" % field)


def _int(field, v):
    try:
        return int(v)
    except (TypeError, ValueError):
        raise SearchError("%s: takes a number" % field)


def _date(v):
    try:
        return timefmt.parse_date(v)
    except ValueError:
        raise SearchError("date: takes YYYY-MM-DD")


@sql_fragment
def compile_extended(text):
    """(SQL condition, params) for an `extended` expression."""
    c = Compiler()
    return c.parse(text), c.params
