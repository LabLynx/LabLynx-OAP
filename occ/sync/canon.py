# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Canonical form and content hash of a carried row.

A row is hashed in OCC terms: the values the mapping writes into the OCC (ids resolved, times in
UTC). The same function is applied to the row read back from the OCC, so the reconciliation can
compare the 2.x row's hash with its OCC projection's hash. Values are normalized so that a value
that survives the round trip unchanged hashes the same on both sides:

  * times: UTC, ISO 8601, to the microsecond, 'Z';  dates: ISO;
  * decimals and floats: shortest decimal text with trailing zeros removed;
  * booleans: true/false (tinyint 0/1 from 2.x is turned into bool by the mapping);
  * JSON objects: parsed, keys sorted;  bytes: hex;  None stays null.
"""
import datetime as dt
import decimal
import hashlib
import json

UTC = dt.timezone.utc


def norm(v):
    if v is None or isinstance(v, (bool, str)):
        return v
    if isinstance(v, int):
        return v
    if isinstance(v, dt.datetime):
        if v.tzinfo is None:
            v = v.replace(tzinfo=UTC)
        return v.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if isinstance(v, dt.date):
        return v.isoformat()
    if isinstance(v, (decimal.Decimal, float)):
        d = decimal.Decimal(str(v))
        if d == d.to_integral_value():
            return int(d)
        return format(d.normalize(), "f")
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v).hex()
    if isinstance(v, dict):
        return {str(k): norm(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [norm(x) for x in v]
    return str(v)


def dumps(obj):
    return json.dumps(norm(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(obj):
    return hashlib.sha256(dumps(obj).encode("utf-8")).digest()


def json_value(v):
    """A JSON column's value as a Python object (MySQL and pg8000 may hand text or parsed)."""
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray)):
        v = v.decode("utf-8")
    if isinstance(v, str):
        if v.strip() == "":
            return None
        try:
            return json.loads(v)
        except ValueError:
            return v
    return v


def diff(a, b):
    """Field names whose canonical values differ between two canonical dicts."""
    a, b = norm(a or {}), norm(b or {})
    return sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
