# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The structured read-only query: fields, conditions, grouping, paging, the
permission filter applied first, refusal of anything outside the closed tables, the READ ONLY
transaction, and 413 for a plan over the cost limit or a run over the time limit."""
import json

import pytest

from occ.query import structured

Q = "/api/v2/occ/query"


@pytest.fixture(scope="module")
def recs(client, world):
    out = {}
    for title, rating, batch, tags in (("Q alpha", 1, "B-1", ["red"]), ("Q beta", 3, "B-2", ["red", "blue"]),
                                       ("Q gamma", 5, "B-2", [])):
        meta = json.dumps({"extra_fields": {"Batch": {"type": "text", "value": batch},
                                            "Yield": {"type": "number", "value": str(rating * 10)}}})
        r = client.post("/api/v2/experiments", json={"title": title, "rating": rating, "metadata": meta,
                                                      "date": "2026-0%d-15" % rating}, headers=world.h("alice"))
        assert r.status_code == 201, r.text
        eid = int(r.headers["location"].rsplit("/", 1)[-1])
        for t in tags:
            assert client.post("/api/v2/experiments/%d/tags" % eid, json={"tag": t},
                               headers=world.h("alice")).status_code in (200, 201)
        out[title] = eid
    # one record in team B that team A must never see
    r = client.post("/api/v2/experiments", json={"title": "Q hidden", "rating": 5}, headers=world.h("bea"))
    out["Q hidden"] = int(r.headers["location"].rsplit("/", 1)[-1])
    return out


def _q(client, world, who="alice", **body):
    body.setdefault("from", "experiments")
    return client.post(Q, json=body, headers=world.h(who))


def test_select_where_and_the_permission_filter(client, world, recs):
    r = _q(client, world, select=["id", "title", "rating", "meta:Batch", "tags", "owner.fullname"],
           where=[{"field": "title", "op": "like", "value": "Q %"}], order_by=["title"])
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["columns"] == ["id", "title", "rating", "meta:Batch", "tags", "owner.fullname"]
    titles = [row[1] for row in d["rows"]]
    assert titles == ["Q alpha", "Q beta", "Q gamma"]                       # not "Q hidden" (team B)
    beta = d["rows"][1]
    assert beta[2] == 3 and beta[3] == "B-2" and beta[4] == "blue|red" and beta[5] == "Alice Test"
    hidden = _q(client, world, who="bea", select=["title"], where=[{"field": "title", "op": "like", "value": "Q %"}])
    assert [row[0] for row in hidden.json()["rows"]] == ["Q hidden"]
    site = _q(client, world, who="sys_site", select=["title"],
              where=[{"field": "title", "op": "like", "value": "Q %"}], order_by=["title"])
    assert [row[0] for row in site.json()["rows"]] == ["Q alpha", "Q beta", "Q gamma", "Q hidden"]


def test_operators(client, world, recs):
    def titles(*where, **kw):
        r = _q(client, world, select=["title"], where=list(where), order_by=["title"], **kw)
        assert r.status_code == 200, r.text
        return [row[0] for row in r.json()["rows"] if row[0].startswith("Q ")]
    assert titles({"field": "rating", "op": ">=", "value": 3}) == ["Q beta", "Q gamma"]
    assert titles({"field": "rating", "op": "!=", "value": 3}) == ["Q alpha", "Q gamma"]
    assert titles({"field": "meta:Batch", "op": "=", "value": "B-2"}) == ["Q beta", "Q gamma"]
    assert titles({"field": "tags", "op": "=", "value": "red"}) == ["Q alpha", "Q beta"]
    assert titles({"field": "id", "op": "in", "value": [recs["Q alpha"], recs["Q gamma"], recs["Q hidden"]]}) == \
        ["Q alpha", "Q gamma"]
    assert titles({"field": "date", "op": "between", "value": ["2026-02-01", "2026-04-30"]}) == ["Q beta"]
    assert titles({"field": "category", "op": "is_null", "value": True},
                  {"field": "title", "op": "like", "value": "q g%"}) == ["Q gamma"]
    assert titles({"field": "id", "op": "=", "value": recs["Q beta"]}, team=world.teams["A"]) == ["Q beta"]


def test_group_by_and_aggregates(client, world, recs):
    r = _q(client, world, group_by=["meta:Batch"], aggregates=["count", "avg:rating", "max:rating", "sum:meta:Yield"],
           where=[{"field": "title", "op": "like", "value": "Q %"}], order_by=[{"field": "meta:Batch", "dir": "asc"}])
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["columns"] == ["meta:Batch", "count", "avg(rating)", "max(rating)", "sum(meta:Yield)"]
    assert d["rows"] == [["B-1", 1, 1, 1, 10], ["B-2", 2, 4, 5, 80]]


def test_paging(client, world, recs):
    body = dict(select=["title"], where=[{"field": "title", "op": "like", "value": "Q %"}], order_by=["title"], limit=2)
    a = _q(client, world, **body).json()
    assert [r[0] for r in a["rows"]] == ["Q alpha", "Q beta"] and a["next"] == "2"
    b = _q(client, world, cursor=a["next"], **body).json()
    assert [r[0] for r in b["rows"]] == ["Q gamma"] and b["next"] is None


@pytest.mark.parametrize("body", [
    {"select": ["id; DELETE FROM occ.records"]},
    {"select": ["title"], "where": [{"field": "title) OR (1=1", "op": "=", "value": "x"}]},
    {"select": ["title"], "where": [{"field": "title", "op": "; DROP", "value": "x"}]},
    {"select": ["title"], "order_by": ["rating"]},                  # not a returned column
    {"select": ["title"], "aggregates": ["sum:title"]},              # not numeric
    {"select": ["title"], "limit": 10001},
    {"from": "audit_events", "select": ["id"]},
    {"select": ["title"], "aggregates": ["drop"]},
])
def test_anything_outside_the_closed_tables_is_refused(client, world, recs, body):
    r = _q(client, world, **body)
    assert r.status_code == 400, r.text


def test_a_value_is_only_ever_a_value(client, world, recs, pool):
    with pool.tx() as tx:
        before = tx.val("SELECT count(*) FROM occ.records")
    r = _q(client, world, select=["title"], where=[{"field": "title", "op": "=", "value": "x'; DELETE FROM occ.records; --"},
                                                   {"field": "meta:Batch'); DELETE FROM occ.records; --", "op": "=",
                                                    "value": "1"}])
    assert r.status_code == 200 and r.json()["rows"] == []
    with pool.tx() as tx:
        assert tx.val("SELECT count(*) FROM occ.records") == before


def test_the_transaction_is_read_only(client, world, recs, pool, monkeypatch):
    """Even a write composed by mistake is refused by the database: the query runs READ ONLY."""
    def evil(p, body):
        return "UPDATE occ.records SET title = 'pwned' RETURNING id", {}, ["id"], 10, 0
    monkeypatch.setattr(structured, "compile_query", evil)
    with pool.tx() as tx:
        before = tx.val("SELECT count(*) FROM occ.records WHERE title = 'pwned'")
    with pytest.raises(Exception) as ex:
        structured.run(pool, client.app.state.settings, None, {})
    assert "read-only transaction" in str(ex.value)
    with pool.tx() as tx:
        assert tx.val("SELECT count(*) FROM occ.records WHERE title = 'pwned'") == before == 0


def test_over_the_cost_limit_answers_413(client, world, recs, cfg):
    cfg.extra["OCC_QUERY_COST_LIMIT"] = "1"
    try:
        r = _q(client, world, select=["title", "tags"])
        assert r.status_code == 413 and "cost limit" in r.json()["message"]
    finally:
        cfg.extra.pop("OCC_QUERY_COST_LIMIT", None)
    assert _q(client, world, select=["title"]).status_code == 200


def test_a_runaway_query_is_stopped_at_the_time_limit(client, world, recs, cfg, pool):
    """20,000 synthetic records and a 1 ms limit: the statement is stopped and answers 413."""
    with pool.tx() as tx:
        team, owner = world.teams["A"], world.users["alice"]
        tx.run("INSERT INTO occ.records (kind_id, id, elabid, team_id, owner_id, created_by, title, metadata) "
               "SELECT 1, 900000 + g, 'runaway-' || g, :t, :u, :u, 'runaway ' || g, "
               "jsonb_build_object('extra_fields', jsonb_build_object('Batch', jsonb_build_object('value', g::text))) "
               "FROM generate_series(1, 20000) g", t=team, u=owner)
    cfg.extra["OCC_QUERY_TIMEOUT_MS"] = "1"
    try:
        r = _q(client, world, group_by=["meta:Batch"], aggregates=["count", "max:rating"], limit=10000,
               where=[{"field": "title", "op": "like", "value": "%runaway%"}])
        assert r.status_code == 413 and "time limit" in r.json()["message"], r.text
    finally:
        cfg.extra.pop("OCC_QUERY_TIMEOUT_MS", None)
        with pool.tx() as tx:
            tx.run("DELETE FROM occ.records WHERE elabid LIKE 'runaway-%'")
    # the connection is healthy afterwards
    assert _q(client, world, select=["title"], limit=1).status_code == 200
