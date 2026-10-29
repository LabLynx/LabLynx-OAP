<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (c) 2026 LabLynx, Inc. -->

# LabLynx.One OCC (Open Core CMS)

The OCC is LabLynx's own headless, generic content management system: a PostgreSQL database, an
HTTP API, and the Python backend behind them. It stores records, people, teams, permissions, files
and a tamper-evident audit log, and serves all of it through one API. It has no screens of its own.

The OCC is licensed under the **GNU Affero General Public License, version 3** (`AGPL-3.0-only`).
See [LICENSE](LICENSE).

## What it is for

The OCC is a black box that applications build on. LabLynx.One, LabLynx's laboratory informatics
product, runs on top of it and reaches it only through its API. You can do the same:

- **Build on it through the API, under any license you choose.** An application that talks to the
  OCC over its API is your own work.
- **Change the OCC itself, and the AGPL applies to your changes.** If you modify the OCC and let
  people use your modified version over a network, you must offer them its source code under the
  AGPL-3.0.

Direct database access is possible, but the goal is an API complete enough that nobody needs it.
Please build on the API.

The API mirrors the eLabFTW API v2 and adds to it under `/api/v2/occ/`. The OCC contains no
eLabFTW code: it is written from its own specification and the API contract.

## Status

Early development, not yet released. The schema, the API and the backend are being built and
tested; single sign-on, signatures, trusted timestamps, PDF/A export and an S3 file store are not
built yet. Expect changes.

## Requirements

- Linux
- Python 3.12 or later
- PostgreSQL 18, reached over its local socket with peer authentication (no database password is
  stored anywhere; a database URL with a password or a TCP host is refused)

## Install

```
git clone https://github.com/LabLynx/LabLynx-One-Open-Core-CMS.git occ
cd occ
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Create a database owned by the operating-system user that will run the OCC:

```
createdb lablynx_one
```

## Configure

Settings are read from an env file (`/etc/occ/occ.env`, or the file `OCC_ENV_FILE` names), then
from the environment. The main ones:

| Setting | What it is |
|---|---|
| `OCC_DATABASE_URL` | The PostgreSQL database, e.g. `postgresql:///lablynx_one` |
| `OCC_BASE_URL` | The address people reach the site at, e.g. `https://lab.example.org` |
| `OCC_ROOT_PATH` | The path the API is served under behind the web server, if not `/` |
| `OCC_TIMEZONE` | The site's time zone, e.g. `America/Chicago` (times are stored in UTC) |
| `OCC_FILES_BACKEND` | Where uploaded files go: `disk` (the default) or `s3` |
| `OCC_FILES_ROOT` | The folder for files on disk, e.g. `/var/lib/occ/files` |
| `OCC_S3_ENDPOINT`, `OCC_S3_BUCKET`, `OCC_S3_REGION`, `OCC_S3_CREDENTIALS_FILE` | S3-compatible storage, when `OCC_FILES_BACKEND=s3` |
| `OCC_API_KEY_PEPPER_FILE` | The pepper file API keys are hashed with (made by `init-pepper`) |
| `OCC_SECRET_KEY_FILE` | The key stored secrets are sealed with (made by `init-secret-key`) |
| `OCC_LOG_LEVEL` | `INFO` by default |

Create the pepper API keys are hashed with:

```
.venv/bin/python -m occ.cli init-pepper
```

## Run

```
.venv/bin/python -m occ.cli migrate          # build or update the schema
.venv/bin/python -m occ.cli status           # which migrations are applied
.venv/bin/python -m occ.cli bootstrap --email admin@example.com --firstname Ada --lastname Admin \
    --team "First team" --key-file ./admin.key  # the first administrator and an API key (file mode 0600)
.venv/bin/uvicorn occ.main:app --host 127.0.0.1 --port 8710
```

The API listens on 127.0.0.1 only. Run it, and the background worker (`.venv/bin/python -m occ.cli worker`), under your system's service manager,
and put a web server in front of it for anything else. Other commands:

```
.venv/bin/python -m occ.cli fresh-compare    # does a fresh build of every migration match this database?
.venv/bin/python -m occ.cli audit-verify     # walk the audit chain (--checkpoint records it)
.venv/bin/python -m occ.cli worker           # the background worker (--once for one pass)
```

## Test

```
.venv/bin/pip install pytest==9.2.0 httpx==0.28.1
.venv/bin/python -m pytest -q tests/unit
```

The unit tests need the local PostgreSQL socket and the right to create databases: each run makes
its own scratch database, named `occ_scratch_` and a suffix, and drops it at the end.
`tests/sqlcheck.py` is the static check that no SQL is built from text.

## Layout

```
occ/              the Python package: api/ (routers), auth/, perms/ (the permission engine),
                  records/, people/, files/, exports/, audit/, search/, worker/, db/ and migrations/
tests/unit/       the unit tests
docs/design/      the database schema and the table mapping
```

## Rules the code keeps

- The schema changes only by adding a numbered migration; an applied migration is never edited.
- Every SQL statement is parameterized. A table or column name enters SQL text only through
  `db.ident()`.
- Logs never carry a request body, a query string, a header, a key or a cookie.
- Runtime dependencies are under permissive licenses only (`docs/dependencies.json`).
- Every source file starts with the SPDX line and the copyright line.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

Copyright (c) 2026 LabLynx, Inc.
