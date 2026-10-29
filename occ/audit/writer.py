# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The audit writer: every accepted write leaves a hash-chained audit row.

Every accepted write calls write() inside the same transaction as the change, so the change and
its audit rows commit or roll back together. Rows enter occ.audit_events only through
occ.audit_append, which hash-chains them; triggers refuse UPDATE, DELETE and TRUNCATE.
A value written here is a field's content, never a passphrase, key or cookie: secrets are never logged.
"""
from dataclasses import dataclass

from ..db import jsonb


@dataclass
class Actor:
    kind: str                 # user | apikey | system | sync | migration
    user_id: int = None
    api_key_id: int = None
    team_id: int = None
    request_id: str = None


def actor_for(principal, request_id=None):
    return Actor(kind="apikey" if principal.api_key_id else "user", user_id=principal.user_id,
                 api_key_id=principal.api_key_id, team_id=principal.team_id, request_id=request_id)


def _text(v):
    if v is None:
        return None
    if isinstance(v, bool):
        return "1" if v else "0"
    return str(v)


def write(tx, actor, category, *, kind_id=None, record_id=None, rid=None, team_id=None, target=None,
          old=None, new=None, detail=None):
    payload = {
        "actor_kind": actor.kind, "actor_user_id": actor.user_id, "api_key_id": actor.api_key_id,
        "team_id": team_id if team_id is not None else actor.team_id, "category": category,
        "kind_id": kind_id, "record_id": record_id, "rid": rid, "target": target,
        "old_value": _text(old), "new_value": _text(new), "detail": detail, "request_id": actor.request_id,
    }
    payload = {k: v for k, v in payload.items() if v is not None}
    return tx.val("SELECT occ.audit_append(CAST(:p AS jsonb))", p=jsonb(payload))
