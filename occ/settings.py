# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Process settings: read from an env file, then the process environment.

The env file is /etc/occ/occ.env on an installed server (_MAP below lists its keys), or
whatever OCC_ENV_FILE names. It holds paths, the base URL and the time zone. It never holds a
database password: the database is reached over the local socket with peer authentication, so there is
no password to leak.
"""
import os
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs

DEFAULT_ENV_FILE = "/etc/occ/occ.env"


def read_env_file(path):
    """KEY=VALUE lines; blank lines and # comments ignored; optional surrounding quotes removed."""
    out = {}
    if not path or not os.path.exists(path):
        return out
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                v = v[1:-1]
            out[k.strip()] = v
    return out


@dataclass
class Settings:
    database_url: str = "postgresql:///lablynx_one"
    db_schema: str = "occ"
    base_url: str = "http://127.0.0.1:8710"
    root_path: str = ""
    timezone: str = "America/Chicago"
    files_root: str = "/var/lib/occ/files"
    api_key_pepper_file: str = "/etc/occ/apikey.pepper"
    secret_key_file: str = "/etc/occ/secret.key"
    saml_sp_key: str = "/etc/occ/saml/sp.key"
    saml_sp_crt: str = "/etc/occ/saml/sp.crt"
    pool_size: int = 10
    log_level: str = "INFO"
    rate_burst: int = 60            # requests in any one second, per key or session
    rate_sustained: int = 20        # refill per second; 0 in either turns the limits off (tests only)
    rate_downloads: int = 200       # file downloads per second
    extra: dict = field(default_factory=dict)

    # -- database connection parameters, from a postgresql:// URL with no password --------------
    def db_params(self):
        u = urlparse(self.database_url)
        if u.scheme not in ("postgresql", "postgres"):
            raise ValueError("OCC_DATABASE_URL must be a postgresql:// URL")
        if u.password:
            # There is no database password. Refuse rather than use one.
            raise ValueError("OCC_DATABASE_URL must not carry a password (peer authentication only)")
        q = parse_qs(u.query)
        host = (q.get("host") or [None])[0] or u.hostname
        params = {"database": (u.path or "/").lstrip("/") or "lablynx_one",
                  "user": u.username or _os_user()}
        if host and not host.startswith("/"):
            # TCP would ask for a password (the server's PostgreSQL setup); the OCC uses the socket.
            raise ValueError("OCC_DATABASE_URL must use the local socket, not a TCP host")
        sock_dir = host or "/var/run/postgresql"
        params["unix_sock"] = os.path.join(sock_dir, ".s.PGSQL.%s" % (u.port or 5432))
        return params

    @property
    def database_name(self):
        return self.db_params()["database"]


def _os_user():
    import pwd
    return pwd.getpwuid(os.getuid()).pw_name


_MAP = {
    "OCC_DATABASE_URL": "database_url",
    "OCC_BASE_URL": "base_url",
    "OCC_ROOT_PATH": "root_path",
    "OCC_TIMEZONE": "timezone",
    "OCC_FILES_ROOT": "files_root",
    "OCC_API_KEY_PEPPER_FILE": "api_key_pepper_file",
    "OCC_SECRET_KEY_FILE": "secret_key_file",
    "OCC_SAML_SP_KEY": "saml_sp_key",
    "OCC_SAML_SP_CRT": "saml_sp_crt",
    "OCC_POOL_SIZE": "pool_size",
    "OCC_LOG_LEVEL": "log_level",
    "OCC_RATE_BURST": "rate_burst",
    "OCC_RATE_SUSTAINED": "rate_sustained",
    "OCC_RATE_DOWNLOADS": "rate_downloads",
}
_INTS = {"pool_size", "rate_burst", "rate_sustained", "rate_downloads"}


def load(env_file=None, overrides=None):
    env_file = env_file or os.environ.get("OCC_ENV_FILE") or DEFAULT_ENV_FILE
    values = read_env_file(env_file)
    for k in _MAP:
        if k in os.environ:
            values[k] = os.environ[k]
    s = Settings()
    for k, v in values.items():
        attr = _MAP.get(k)
        if attr is None:
            s.extra[k] = v
            continue
        setattr(s, attr, int(v) if attr in _INTS else v)
    for k, v in (overrides or {}).items():
        setattr(s, k, v)
    s.root_path = (s.root_path or "").rstrip("/")
    s.base_url = s.base_url.rstrip("/")
    s.db_params()  # validates: no password, socket only
    return s
