<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (c) 2026 LabLynx, Inc. -->

# Contributing to the OCC

Thank you for your interest. The OCC is in early development, and this repository is published
from LabLynx's own development. Read this before you open an issue or a pull request.

## Issues

Bug reports and questions are welcome as GitHub issues. A good report says what you ran, what
you expected and what happened instead, with the OCC version (or commit) and your Python and
PostgreSQL versions. Never put a password, an API key or personal data in an issue.

Security problems are not issues: see [SECURITY.md](SECURITY.md).

## Pull requests

Pull requests are read, but at this stage LabLynx may carry a change into its own development
rather than merge it here as it stands. Before you start anything large, open an issue so we can
agree the approach.

By opening a pull request you agree that your contribution is licensed under the
AGPL-3.0-only license of this repository.

A pull request is ready when:

- the unit tests pass (`python -m pytest -q tests/unit`), including the static SQL check;
- every new source file starts with these two lines, in the file's comment syntax:

  ```
  SPDX-License-Identifier: AGPL-3.0-only
  Copyright (c) 2026 LabLynx, Inc.
  ```

  (Add your own copyright line under it if you wish.)
- a schema change is a new numbered migration, never an edit to an applied one;
- every SQL statement is parameterized, and table or column names go through `db.ident()`;
- a new runtime dependency is under a permissive license and recorded in `docs/dependencies.json`.

## Clean room

The OCC contains no eLabFTW code. It is written from its own specification and the API contract.
Do not contribute code copied or adapted from eLabFTW, or from any source whose license does not
allow it.
