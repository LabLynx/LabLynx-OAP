<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (c) 2026 LabLynx, Inc. -->

# Security

## Reporting a vulnerability

Please do not report a security problem in a public issue.

Report it privately through GitHub: on this repository's **Security** tab, choose **Report a
vulnerability**. Include what you found, how to reproduce it, and which version or commit you
tested. We will acknowledge the report, keep you informed while we work on it, and credit you
when the fix is published, unless you ask us not to.

## Supported versions

The OCC has not had a release yet. Fixes go to the `main` branch. Once releases begin, this file
will say which versions receive security fixes.

## What the OCC does to stay safe

- API keys are stored as HMAC-SHA256 hashes with a server-side pepper, never as the key itself.
- Site secrets are sealed with AES-256-GCM.
- The database is reached over its local socket with peer authentication; no database password
  exists to leak.
- The audit log is hash-chained, and `occ audit-verify` recomputes the chain.
- Every SQL statement is parameterized.
- Requests are rate-limited per key or session.
- Logs never carry a request body, a query string, a header, a key or a cookie.
