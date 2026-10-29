# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Strict path segments for {kind}, {links} and {lookup}, so /api/v2/teams never reaches a
{kind} route and the reverse: a path matches one route or none."""
from starlette.convertors import Convertor, register_url_convertor

from ..records import kinds as K


class _Choice(Convertor):
    def __init__(self, names):
        self.regex = "|".join(sorted(names, key=len, reverse=True))

    def convert(self, value):
        return value

    def to_string(self, value):
        return str(value)


register_url_convertor("kind", _Choice(K.KINDS))
register_url_convertor("links", _Choice(["experiments_links", "items_links"]))
register_url_convertor("lookup", _Choice(K.LOOKUPS))
