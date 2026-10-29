# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Record kinds: one generic records table; occ.record_kinds says what each kind is.
The four kinds of schema v1 are fixed rows of migration 0001; this mirrors them for the code."""
from dataclasses import dataclass

from .. import errors


@dataclass(frozen=True)
class Kind:
    id: int
    code: str
    lookup_group: int
    is_template: bool
    template_kind: str      # the kind whose records are templates for this one
    bookable: bool
    sequence: str
    singular: str
    page: str


KINDS = {
    "experiments": Kind(1, "experiments", 1, False, "experiments_templates", False, "occ.record_id_experiments",
                        "Experiment", "experiments"),
    "items": Kind(2, "items", 2, False, "items_types", True, "occ.record_id_items", "Resource", "database"),
    "experiments_templates": Kind(3, "experiments_templates", 1, True, None, False,
                                  "occ.record_id_experiments_templates", "Experiment template", "templates"),
    "items_types": Kind(4, "items_types", 2, True, None, False, "occ.record_id_items_types", "Resource template",
                        "resources-templates"),
}
BY_ID = {k.id: k for k in KINDS.values()}


def get(code):
    k = KINDS.get(code)
    if k is None:
        raise errors.bad("Invalid endpoint: %s" % code)
    return k


# The team setting that lets a non-admin member create a record of a kind.
CREATE_SETTING = {"experiments": "users_canwrite_experiments", "items": "users_canwrite_resources",
                  "experiments_templates": "users_canwrite_experiments_templates",
                  "items_types": "users_canwrite_resources_templates"}

# Lookups (statuses and categories) as the API names them: (table, lookup_group, team setting).
LOOKUPS = {
    "experiments_status": ("statuses", 1, "users_canwrite_experiments_status"),
    "items_status": ("statuses", 2, "users_canwrite_resources_status"),
    "experiments_categories": ("categories", 1, "users_canwrite_experiments_categories"),
    "resources_categories": ("categories", 2, "users_canwrite_resources_categories"),
    "items_categories": ("categories", 2, "users_canwrite_resources_categories"),
}
