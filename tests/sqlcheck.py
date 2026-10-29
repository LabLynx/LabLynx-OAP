# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""No SQL built from text: every statement is parameterized, and a name enters SQL only through db.ident().

    ~/.local/venvs/occ/bin/python tests/sqlcheck.py [paths...]     exit 1 and list every finding

Every statement the OCC package (occ/occ) hands to the database must be SQL text written in the
code. Values travel as parameters; the only text allowed into a statement besides literals is an
identifier from a closed list. The check reads the source (Python's own parser) and follows, inside
each function, where the text handed to the database came from. A piece of SQL text is SAFE when it is:

  * a string literal, or literals joined by +, %, f-strings, "sep".join(...) or a conditional;
  * db.ident(name, ALLOWED) with ALLOWED a constant (a module-level name, or NAME.UPPER_CASE);
  * a lookup in a constant: CONSTANT[key] (the result is one of the constant's own values);
  * a module-level name bound once to safe text, or a local whose every binding in the function
    (assignment, +=, .append/.extend/.insert, a for loop over safe items) is safe;
  * a parameter named sql or ending in _sql: the function is a pass-through, and every call to it
    is checked the same way at the caller;
  * the result of a function marked @sql_fragment, whose every return is checked here (for a
    tuple, its first item).

Anything else is a finding: a parameter, an attribute, a call to an unmarked function, a value
read from a request or the database. EXCEPTIONS below name the few places that compose checked
fragments in a way this reader cannot follow, each with its reason; one that no longer exists
fails the check, so the list cannot go stale.
"""
import ast
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OCC = os.path.dirname(HERE)
PACKAGE = os.path.join(OCC, "occ")

SINK_METHODS = {"all", "one", "val", "run", "script", "execute_simple"}
SINK_RECEIVERS = {"tx", "con", "self", "self.con"}

# (relative file, function): reason. Kept short on purpose.
EXCEPTIONS = {
    ("occ/perms/engine.py", "list_filter"):
        "ORs the renderings of the RULES table (one per rule, each literal text around the alias and "
        "the right, both passed through db.ident at the top of list_filter); "
        "tests/unit/test_permissions.py proves the SQL and the Python forms agree",
    ("occ/db/migrate.py", "migrate"):
        "applies the migration files, which are SQL text written in the repository and checksummed",
    ("occ/search/grammar.py", "compile_extended"):
        "the search grammar compiles a parsed expression into SQL from a fixed table of field "
        "renderings; every value the person typed becomes a parameter",
}


def _name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name(node.value)
        return base + "." + node.attr if base else node.attr
    return None


class Module:
    def __init__(self, path):
        self.path = path
        self.rel = os.path.relpath(path, OCC)
        with open(path, encoding="utf-8") as fh:
            self.tree = ast.parse(fh.read(), path)
        self.consts = {}          # module-level names bound exactly once
        counts = {}
        for node in self.tree.body:
            targets = []
            if isinstance(node, ast.Assign):
                targets = [t for t in node.targets if isinstance(t, ast.Name)]
                value = node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                targets, value = [node.target], node.value
            for t in targets:
                counts[t.id] = counts.get(t.id, 0) + 1
                self.consts[t.id] = value
        self.consts = {k: v for k, v in self.consts.items() if counts.get(k) == 1}
        self.functions = [n for n in ast.walk(self.tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _decorated_fragment(fn):
    return any(_name(d) in ("sql_fragment", "db.sql_fragment") for d in fn.decorator_list)


def _sql_params(fn):
    a = fn.args
    names = [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs]
    return [n for n in names if n == "sql" or n.endswith("_sql")]


class Checker:
    def __init__(self, modules):
        self.modules = modules
        self.fragments = set()
        self.passthrough = {}        # function name -> [(index, param name)]
        for m in modules:
            for fn in m.functions:
                if _decorated_fragment(fn):
                    self.fragments.add(fn.name)
                ps = _sql_params(fn)
                if ps:
                    allp = [x.arg for x in fn.args.posonlyargs + fn.args.args]
                    offset = 1 if allp and allp[0] == "self" else 0
                    self.passthrough[fn.name] = [(allp.index(p) - offset if p in allp else None, p) for p in ps]
        self.findings = []
        self.exceptions_seen = set()

    # -- is this expression safe SQL text? ------------------------------------------------------
    def safe(self, node, ctx, depth=0):
        if depth > 40:
            return False
        s = lambda n: self.safe(n, ctx, depth + 1)  # noqa: E731
        if isinstance(node, ast.Constant):
            return isinstance(node.value, (str, int, float, bool)) or node.value is None
        if isinstance(node, ast.JoinedStr):
            return all(s(v.value) if isinstance(v, ast.FormattedValue) else True for v in node.values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return s(node.left) and s(node.right)
        if isinstance(node, (ast.Tuple, ast.List)):
            return all(s(e) for e in node.elts)
        if isinstance(node, ast.IfExp):
            return s(node.body) and s(node.orelse)
        if isinstance(node, (ast.GeneratorExp, ast.ListComp)):
            inner = dict(ctx["locals_safe"])
            for g in node.generators:
                ok = s(g.iter)
                for t in ast.walk(g.target):
                    if isinstance(t, ast.Name):
                        inner[t.id] = ok
            return self.safe(node.elt, dict(ctx, locals_safe=inner), depth + 1)
        if isinstance(node, ast.Subscript):
            return self._is_constant_ref(node.value, ctx) or s(node.value)
        if isinstance(node, ast.Call):
            fname = _name(node.func) or ""
            short = fname.rsplit(".", 1)[-1]
            if short == "join" and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Constant):
                return all(s(a) for a in node.args)
            if short == "ident":
                return len(node.args) >= 2 and self._is_constant_ref(node.args[1], ctx)
            if short in self.fragments:
                return True
            if short == "format" and isinstance(node.func, ast.Attribute):
                return s(node.func.value) and all(s(a) for a in node.args) and all(s(k.value) for k in node.keywords)
            return False
        if isinstance(node, ast.Name):
            if node.id in ctx["sql_params"]:
                return True
            if node.id in ctx["locals_safe"]:
                return ctx["locals_safe"][node.id]
            if node.id in ctx["params"]:
                return False
            v = ctx["module"].consts.get(node.id)
            return v is not None and s(v)
        if isinstance(node, ast.Attribute):
            return node.attr.isupper()        # NAME.UPPER_CASE: a constant of another module
        return False

    def _why(self, node, ctx):
        bad = sorted({x.id for x in ast.walk(node) if isinstance(x, ast.Name) and
                      (ctx["locals_safe"].get(x.id) is False or (x.id in ctx["params"] and
                                                               x.id not in ctx["sql_params"]))})
        return (" [unsafe: %s]" % ", ".join(bad)) if bad else ""

    def _is_constant_ref(self, node, ctx):
        if isinstance(node, ast.Name):
            return node.id in ctx["module"].consts and node.id not in ctx["params"] \
                and node.id not in ctx["locals_safe"]
        if isinstance(node, ast.Attribute):
            return node.attr.isupper()
        return False

    # -- one function ---------------------------------------------------------------------------
    def check_function(self, m, fn):
        a = fn.args
        params = {x.arg for x in a.posonlyargs + a.args + a.kwonlyargs}
        if a.vararg:
            params.add(a.vararg.arg)
        if a.kwarg:
            params.add(a.kwarg.arg)
        ctx = {"module": m, "params": params, "sql_params": set(_sql_params(fn)), "locals_safe": {}}
        bindings = {}
        tuple_from_fragment = {}

        def bind(name, value_node):
            bindings.setdefault(name, []).append(value_node)

        body_nodes = [n for n in ast.walk(fn) if n is not fn]
        nested = set()
        for n in body_nodes:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                nested.update(id(x) for x in ast.walk(n) if x is not n)
        own = [n for n in body_nodes if id(n) not in nested]
        for n in own:
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        bind(t.id, n.value)
                    elif isinstance(t, (ast.Tuple, ast.List)):
                        names = [e.id if isinstance(e, ast.Name) else None for e in t.elts]
                        if isinstance(n.value, (ast.Tuple, ast.List)) and len(n.value.elts) == len(names):
                            for nm, v in zip(names, n.value.elts):
                                if nm:
                                    bind(nm, v)
                        elif isinstance(n.value, ast.Call) and (_name(n.value.func) or "").rsplit(".", 1)[-1] \
                                in self.fragments:
                            for i, nm in enumerate(names):
                                if nm:
                                    tuple_from_fragment[nm] = i == 0
                                    bind(nm, None)
                        else:
                            for nm in names:
                                if nm:
                                    bind(nm, n.value)
            elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name):
                bind(n.target.id, n.value)
            elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.value is not None:
                bind(n.target.id, n.value)
            elif isinstance(n, ast.For):
                tgt, it = n.target, n.iter
                if isinstance(it, ast.Call) and _name(it.func) == "enumerate" and isinstance(tgt, ast.Tuple) \
                        and len(tgt.elts) == 2 and isinstance(tgt.elts[0], ast.Name):
                    bind(tgt.elts[0].id, ast.Constant(0))          # the counter enumerate() gives is an int
                    tgt = tgt.elts[1]
                    it = it.args[0] if it.args else ast.Constant(None)
                for t in ast.walk(tgt):
                    if isinstance(t, ast.Name):
                        bind(t.id, ("iter", it))
            elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                    and n.func.attr in ("append", "extend", "insert") and isinstance(n.func.value, ast.Name):
                for arg in n.args[-1:]:
                    bind(n.func.value.id, ("item", arg) if n.func.attr != "extend" else arg)

        # fixed point: a local is safe when every binding is safe
        names = set(bindings)
        for nm in names:
            ctx["locals_safe"][nm] = True
        changed = True
        while changed:
            changed = False
            for nm in names:
                if not ctx["locals_safe"][nm]:
                    continue
                ok = True
                for v in bindings[nm]:
                    if v is None:
                        ok = tuple_from_fragment.get(nm, False)
                    elif isinstance(v, tuple):
                        ok = self.safe(v[1], ctx)
                    else:
                        ok = self.safe(v, ctx)
                    if not ok:
                        break
                if nm in params and nm not in ctx["sql_params"]:
                    ok = False
                if not ok:
                    ctx["locals_safe"][nm] = False
                    changed = True

        key = (m.rel, fn.name)
        excepted = key in EXCEPTIONS

        # sinks and pass-through calls
        for n in own:
            if not isinstance(n, ast.Call):
                continue
            args = []
            if isinstance(n.func, ast.Attribute) and n.func.attr in SINK_METHODS \
                    and _name(n.func.value) in SINK_RECEIVERS:
                if n.args:
                    args.append(n.args[0])
                args += [k.value for k in n.keywords if k.arg == "sql"]
            short = (_name(n.func) or "").rsplit(".", 1)[-1]
            if short in self.passthrough and short not in SINK_METHODS:
                for idx, pname in self.passthrough[short]:
                    if idx is not None and idx < len(n.args):
                        args.append(n.args[idx])
                    args += [k.value for k in n.keywords if k.arg == pname]
            for arg in args:
                if not self.safe(arg, ctx):
                    if excepted:
                        self.exceptions_seen.add(key)
                    else:
                        self.findings.append("%s:%d in %s(): SQL text that is not from the code: %s%s"
                                             % (m.rel, n.lineno, fn.name, ast.unparse(arg)[:120],
                                                self._why(arg, ctx)))

        if _decorated_fragment(fn):
            for n in own:
                if isinstance(n, ast.Return) and n.value is not None:
                    v = n.value.elts[0] if isinstance(n.value, ast.Tuple) and n.value.elts else n.value
                    if not self.safe(v, ctx):
                        if excepted:
                            self.exceptions_seen.add(key)
                        else:
                            self.findings.append("%s:%d in @sql_fragment %s(): returns text that is not from "
                                                 "the code: %s" % (m.rel, n.lineno, fn.name, ast.unparse(v)[:120]))

    def run(self):
        for m in self.modules:
            for fn in m.functions:
                self.check_function(m, fn)
        for key in EXCEPTIONS:
            if key not in self.exceptions_seen:
                self.findings.append("%s %s(): listed in EXCEPTIONS but nothing there needs it any more; remove "
                                     "it" % key)
        return self.findings


def modules(root=PACKAGE):
    out = []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for f in sorted(files):
            if f.endswith(".py"):
                out.append(Module(os.path.join(dirpath, f)))
    return out


def check(root=PACKAGE):
    return Checker(modules(root)).run()


def check_source(text, rel="occ/sample.py"):
    """Check one piece of source (the negative tests use this); EXCEPTIONS do not apply."""
    m = Module.__new__(Module)
    m.path, m.rel = rel, rel
    m.tree = ast.parse(text)
    counts, consts = {}, {}
    for node in m.tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    counts[t.id] = counts.get(t.id, 0) + 1
                    consts[t.id] = node.value
    m.consts = {k: v for k, v in consts.items() if counts[k] == 1}
    m.functions = [n for n in ast.walk(m.tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    c = Checker([m])
    for fn in m.functions:
        c.check_function(m, fn)
    return c.findings


def main():
    findings = check()
    for f in findings:
        print(f)
    print("%d finding(s)" % len(findings))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
