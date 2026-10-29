# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The 2.x source: eLabFTW 5.6.12's MySQL database, read only.

The migration and the sync read 2.x through this module and nothing else. It never writes:

  * the credentials are the read-only ones (OCC_SOURCE_DB_ENV, a read-only env file the operator
    installs and names in the settings, or the ELN_DB_* variables); a file that is the read/write env
    file (ELN_DB_RW_ENV) is refused;
  * on connecting it reads the account's grants and refuses to go on if they allow anything but
    SELECT (so a wrongly configured account stops the run instead of being trusted);
  * every session is SET SESSION TRANSACTION READ ONLY, so the server refuses a write even if one
    were ever sent;
  * no trigger, table, column or replication privilege is needed or used.

Times: the session time zone is set to UTC, so TIMESTAMP columns come back in UTC. DATETIME
columns carry the 2.x database clock's wall time (US Central, America/Chicago) with no zone; they
are converted to UTC here, using the column types read from information_schema.

Table and column names put into the SQL text come only from the closed lists in mapping.py
(TABLES, and the columns information_schema reports for those tables).
"""
import datetime as dt
import os
import re
import ssl
import zoneinfo

SOURCE_TZ = zoneinfo.ZoneInfo("America/Chicago")
UTC = dt.timezone.utc
_NAME = re.compile(r"^[a-z0-9_]{1,64}$")
_WRITE_GRANTS = re.compile(r"\b(INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|INDEX|TRIGGER|ALL PRIVILEGES|GRANT OPTION|"
                           r"REPLICATION|SUPER|FILE|EXECUTE|EVENT|LOCK TABLES|REFERENCES|CREATE VIEW)\b")


# Columns eLabFTW stamps when an account or key is merely used (a read through the API, a sign-in).
# The before/after proof reports a table whose only change is in these as such.
VOLATILE = {"api_keys": ("last_used_at",), "users": ("last_login", "last_seen_version"),
            "sig_keys": ("last_used_at",)}


class SourceError(Exception):
    pass


def _read_env(path):
    out = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.replace("export ", "").strip()
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                v = v[1:-1]
            out[k] = v
    return out


def credentials(env_file=None):
    """The read-only connection settings. Never the read/write env file: the migration reads 2.x
    read-only, so it must not even hold credentials that could write."""
    path = env_file or os.environ.get("OCC_SOURCE_DB_ENV") or ""
    rw = os.environ.get("ELN_DB_RW_ENV")
    if rw and os.path.exists(path) and os.path.exists(rw) and os.path.samefile(path, rw):
        raise SourceError("refused: the source env file is the read/write one; the migration reads 2.x read-only")
    if os.path.exists(path):
        env = _read_env(path)
    else:
        env = {k: v for k, v in os.environ.items() if k.startswith("ELN_DB_")}
    need = ("ELN_DB_HOST", "ELN_DB_USER", "ELN_DB_PASS", "ELN_DB_NAME")
    if not all(env.get(k) for k in need):
        raise SourceError("no read-only source credentials (OCC_SOURCE_DB_ENV or ELN_DB_*)")
    return {"host": env["ELN_DB_HOST"], "port": int(env.get("ELN_DB_PORT") or 3306), "user": env["ELN_DB_USER"],
            "password": env["ELN_DB_PASS"], "database": env["ELN_DB_NAME"]}


class Source:
    """One read-only connection to 2.x."""

    def __init__(self, creds=None, connect=None):
        self.creds = creds
        self._connect = connect
        self.con = None
        self.datetime_cols = {}      # table -> set of DATETIME column names (Central wall time)
        self.columns = {}            # table -> [column, ...] in table order
        self.grants = []

    # -- connection ------------------------------------------------------------------------------
    def open(self):
        if self._connect is not None:            # tests hand in a fake
            self.con = self._connect()
        else:
            import pymysql
            c = self.creds or credentials()
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.con = pymysql.connect(host=c["host"], port=c["port"], user=c["user"], password=c["password"],
                                       database=c["database"], ssl=ctx, charset="utf8mb4", autocommit=True,
                                       connect_timeout=15, read_timeout=300)
            self.database = c["database"]
        self._session()
        return self

    def _session(self):
        cur = self.con.cursor()
        cur.execute("SET SESSION time_zone = '+00:00'")
        cur.execute("SET SESSION TRANSACTION READ ONLY")
        cur.execute("SHOW GRANTS FOR CURRENT_USER()")
        self.grants = [r[0] for r in cur.fetchall()]
        for g in self.grants:
            if _WRITE_GRANTS.search(g.upper()):
                self.close()
                raise SourceError("refused: the 2.x account can do more than SELECT (%s)" % g.split(" TO ")[0])
        cur.execute("SELECT table_name, column_name, data_type FROM information_schema.columns "
                    "WHERE table_schema = DATABASE() ORDER BY table_name, ordinal_position")
        self.columns, self.datetime_cols = {}, {}
        for t, c, typ in cur.fetchall():
            self.columns.setdefault(t, []).append(c)
            if typ == "datetime":
                self.datetime_cols.setdefault(t, set()).add(c)
        cur.close()

    def close(self):
        if self.con is not None:
            try:
                self.con.close()
            except Exception:
                pass
            self.con = None

    def ping(self):
        try:
            self.con.ping(reconnect=False)
        except Exception:
            self.close()
            self.open()

    # -- reading ---------------------------------------------------------------------------------
    def now_utc(self):
        cur = self.con.cursor()
        cur.execute("SELECT UTC_TIMESTAMP(6)")
        v = cur.fetchone()[0]
        cur.close()
        return v.replace(tzinfo=UTC)

    def has(self, table):
        return table in self.columns

    def query(self, table, sql, args=None):
        """Rows as dicts, with times made timezone-aware UTC. `table` names whose DATETIME columns
        to convert; `sql` is text from mapping.py's closed lists."""
        cur = self.con.cursor()
        cur.execute(sql, args or ())
        names = [d[0] for d in cur.description]
        dtc = self.datetime_cols.get(table, set())
        out = []
        for r in cur.fetchall():
            row = {}
            for n, v in zip(names, r):
                if isinstance(v, dt.datetime):
                    if n in dtc:
                        v = v.replace(tzinfo=SOURCE_TZ).astimezone(UTC)
                    else:
                        v = v.replace(tzinfo=UTC)
                row[n] = v
            out.append(row)
        cur.close()
        return out

    def scalar_row(self, sql, args=None):
        cur = self.con.cursor()
        cur.execute(sql, args or ())
        r = cur.fetchone()
        cur.close()
        return r

    def column_list(self, table):
        cols = self.columns.get(table) or []
        for c in cols:
            if not _NAME.match(c):
                raise SourceError("unexpected column name in %s" % table)
        return cols

    # -- evidence that 2.x is unchanged -----------------------------------------------------------
    def checksums(self, tables):
        """CHECKSUM TABLE and COUNT(*) per table: read-only, used before and after a run."""
        out = {}
        cur = self.con.cursor()
        for t in tables:
            if not _NAME.match(t) or t not in self.columns:
                continue
            cur.execute("CHECKSUM TABLE `%s`" % t)
            ck = cur.fetchone()[1]
            cur.execute("SELECT COUNT(*) FROM `%s`" % t)
            out[t] = {"checksum": int(ck) if ck is not None else None, "rows": int(cur.fetchone()[0])}
            vol = [c for c in VOLATILE.get(t, ()) if c in self.columns[t]]
            if vol:
                rest = [c for c in self.column_list(t) if c not in vol]
                cur.execute("SELECT COALESCE(BIT_XOR(CRC32(CONCAT_WS('|', %s))), 0) FROM `%s`" % (
                    ", ".join("`%s`, ISNULL(`%s`)" % (c, c) for c in rest), t))
                out[t]["stable"] = int(cur.fetchone()[0])
                out[t]["volatile"] = vol
        cur.close()
        return out
