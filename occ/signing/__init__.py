# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Signatures, signature keys and trusted timestamps (a record's sign and timestamp actions).

minisign.py   the published minisign file formats: keys, signatures, verification
tsa.py        an RFC 3161 time-stamp client (request, response, checks)
service.py    what the API does with them: make a key, sign a record, timestamp a record or a checkpoint
"""
