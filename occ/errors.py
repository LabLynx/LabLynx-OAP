# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Errors in the mirror API's envelope: {code, message, description} with the HTTP status in code,
as eLabFTW answers."""


class OCCError(Exception):
    def __init__(self, status, message, description="", headers=None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.description = description
        self.headers = headers or {}

    def body(self):
        return {"code": self.status, "message": self.message, "description": self.description}


def bad(message, description=""):
    return OCCError(400, message, description)


def forbidden(message="You do not have permission to do that.", description=""):
    return OCCError(403, message, description)


def not_found(message="Nothing to show with this id", description=""):
    return OCCError(404, message, description)


def locked(message="This entry is locked.", description=""):
    return OCCError(423, message, description)


def not_yet(what):
    """A catalog entry this build does not serve yet (it is later work, not a refusal)."""
    return OCCError(501, "Not yet on 3.x: %s is not built in this OCC version." % what)


READ_ONLY_MESSAGE = "This is a read-only preview of LabLynx.One 3.x."
