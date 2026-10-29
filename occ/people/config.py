# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Site configuration (read and change; secret values never answered) and identity-provider writes
(add, change and delete providers and their metadata sources).

Settings live in occ.site_config. A secret (an SMTP, LDAP, DSpace or timestamp-authority password,
the SAML private key, S3 keys) is sealed with AES-256-GCM under the key file named by
OCC_SECRET_KEY_FILE (32 random bytes, readable only by the service user) and is never answered:
GET /config gives '' and <name>_is_set (2.x answers stored secrets; the OCC never does). Names are the 2.x setting names (observed at the API,
GET /api/v2/config, 2026-10-28) plus the OCC's own; anything else answers 400 naming it, so a
mistyped setting is never stored silently. Settings that only applied to password sign-in are stored and have no effect (SSO only).
"""
import os
import re

from .. import errors, timefmt
from ..audit import writer as audit

# 2.x site settings by name (148, read from the answer of GET /api/v2/config on 2026-10-28).
ELAB_NAMES = frozenset((
    "a11y_statement", "a11y_statement_name", "admin_panel_custom_msg", "admin_validate", "admins_archive_users",
    "admins_create_users", "admins_create_users_remote_dir", "admins_import_users", "allow_permission_full",
    "allow_permission_organization", "allow_permission_team", "allow_permission_user", "allow_permission_useronly",
    "allow_users_change_identity", "announcement", "anon_users", "autologout_time", "blox_anon", "blox_enabled",
    "chat_url", "compounds_require_edit_rights", "cookie_validity_time", "dspace_host", "dspace_password",
    "dspace_user", "email_domain", "email_send_grouped", "emit_audit_logs", "enforce_mfa", "extauth_email",
    "extauth_firstname", "extauth_lastname", "extauth_remote_user", "extauth_teams", "inventory_require_edit_rights",
    "keeex_enabled", "keeex_host", "keeex_port", "lang", "ldap_base_dn", "ldap_email", "ldap_firstname", "ldap_host",
    "ldap_lastname", "ldap_password", "ldap_port", "ldap_scheme", "ldap_search_attr", "ldap_sync_teams", "ldap_team",
    "ldap_team_create", "ldap_toggle", "ldap_use_tls", "ldap_username", "legal_notice", "legal_notice_name",
    "local_auth_enabled", "local_login", "local_login_hidden_only_sysadmin", "local_login_only_sysadmin",
    "local_register", "login_announcement", "login_tries", "logout_url", "mail_from", "max_password_age_days",
    "max_revisions", "min_days_revisions", "min_delta_revisions", "min_password_length", "onboarding_email_active",
    "onboarding_email_admins_body", "onboarding_email_admins_subject", "onboarding_email_body",
    "onboarding_email_different_for_admins", "onboarding_email_subject", "password_complexity_requirement",
    "privacy_policy", "privacy_policy_name", "proxy", "remember_me_allowed", "remember_me_checked",
    "remote_dir_config", "remote_dir_service", "s3_bucket_name", "s3_endpoint", "s3_exports_bucket_name",
    "s3_exports_endpoint", "s3_exports_path_prefix", "s3_exports_region", "s3_exports_toggle",
    "s3_exports_use_dedicated_bucket", "s3_exports_use_path_style_endpoint", "s3_exports_verify_cert",
    "s3_path_prefix", "s3_region", "s3_use_path_style_endpoint", "s3_verify_cert", "saml_allowrepeatattributename",
    "saml_authnrequestssigned", "saml_baseurl", "saml_debug", "saml_entityid", "saml_fallback_orgid",
    "saml_logoutrequestsigned", "saml_logoutresponsesigned", "saml_lowercaseurlencoding", "saml_nameidencrypted",
    "saml_nameidformat", "saml_privatekey", "saml_relaxdestinationvalidation", "saml_signmetadata", "saml_strict",
    "saml_sync_email_idp", "saml_sync_teams", "saml_team_create", "saml_team_default", "saml_toggle",
    "saml_user_default", "saml_wantassertionsencrypted", "saml_wantassertionssigned", "saml_wantmessagessigned",
    "saml_wantnameid", "saml_wantnameidencrypted", "saml_wantxmlvalidation", "saml_x509", "saml_x509_new", "schema",
    "smtp_address", "smtp_encryption", "smtp_password", "smtp_port", "smtp_username", "smtp_verify_cert",
    "support_url", "terms_of_service", "terms_of_service_name", "ts_authority", "ts_balance", "ts_cert", "ts_hash",
    "ts_limit", "ts_login", "ts_password", "ts_url", "uploads_storage", "user_msg_need_local_account_created",
    "users_validity_is_externally_managed"))
# The OCC's own settings: read-only mode and its note, whether a team's records may be purged, and
# the S3 file store's credentials.
OCC_NAMES = frozenset(("read_only", "allow_purge", "write_policy_note", "s3_access_key", "s3_secret_key",
                       "upload_max_size"))
NAMES = ELAB_NAMES | OCC_NAMES
SECRETS = frozenset(("smtp_password", "ldap_password", "dspace_password", "ts_password", "saml_privatekey",
                     "s3_access_key", "s3_secret_key"))
# Not settable through the API: the schema version is the OCC's own (only migrations change it).
READ_ONLY_NAMES = frozenset(("schema",))
DEFAULTS = {"read_only": "0", "allow_purge": "0", "min_delta_revisions": "100", "max_revisions": "10",
            "min_days_revisions": "23", "upload_max_size": str(100 * 1024 * 1024),
            "inventory_require_edit_rights": "0", "compounds_require_edit_rights": "0", "ts_hash": "sha256",
            "smtp_port": "25", "min_password_length": "12", "admins_create_users_remote_dir": "0",
            "saml_debug": "0", "uploads_storage": "1", "admin_panel_custom_msg": ""}
MAX_VALUE = 100000


class SealKeyMissing(Exception):
    pass


def _sysadmin(p):
    if not p.is_sysadmin:
        raise errors.forbidden("Only a sysadmin can do that.")


def _writer(p):
    if not p.can_write:
        raise errors.forbidden("This API key is read-only.")


# ------------------------------------------------------------------------------------ sealing
def make_secret_key(path):
    """Create the 32-byte sealing key (mode 0600) if it is missing."""
    if os.path.exists(path):
        return False
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(os.urandom(32))
    return True


def _key(cfg):
    try:
        with open(cfg.secret_key_file, "rb") as fh:
            k = fh.read()
    except OSError:
        raise SealKeyMissing()
    if len(k) != 32:
        raise SealKeyMissing()
    return k


def seal(cfg, name, text):
    """nonce (12 bytes) || AES-256-GCM(text), the setting's name bound in as associated data."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    return nonce + AESGCM(_key(cfg)).encrypt(nonce, text.encode("utf-8"), name.encode("utf-8"))


def unseal(cfg, name, blob):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    blob = bytes(blob)
    return AESGCM(_key(cfg)).decrypt(blob[:12], blob[12:], name.encode("utf-8")).decode("utf-8")


def secret(tx, cfg, name):
    """A secret setting's clear value for the OCC's own use (mail, timestamps), or None."""
    row = tx.one("SELECT value_enc FROM occ.site_config WHERE name = :n AND is_secret", n=name)
    if row is None or row["value_enc"] is None:
        return None
    return unseal(cfg, name, row["value_enc"])


def value(tx, name, default=None):
    v = tx.val("SELECT value FROM occ.site_config WHERE name = :n AND NOT is_secret", n=name)
    if v is None:
        v = DEFAULTS.get(name, default)
    return v


def flag(tx, name):
    return str(value(tx, name, "0") or "0").strip().lower() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------- read and change
def read_config(tx, p):
    _sysadmin(p)
    stored = {r["name"]: r for r in tx.all("SELECT name, value, is_secret, value_enc FROM occ.site_config")}
    out = {}
    for name in sorted(NAMES | set(stored)):
        r = stored.get(name)
        if name in SECRETS or (r is not None and r["is_secret"]):
            out[name] = ""
            out[name + "_is_set"] = bool(r is not None and r["value_enc"] is not None)
        else:
            out[name] = r["value"] if r is not None else DEFAULTS.get(name)
    return out


def _text(name, v):
    if v is None:
        return None
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, str):
        if len(v) > MAX_VALUE:
            raise errors.bad("Incorrect value for %s: too long" % name)
        return v
    raise errors.bad("Incorrect value for %s" % name)


def patch_config(tx, p, actor, cfg, body):
    _sysadmin(p)
    _writer(p)
    if not isinstance(body, dict) or not body:
        raise errors.bad("Send the settings to change as {name: value}")
    unknown = sorted(k for k in body if k not in NAMES)
    if unknown:
        raise errors.bad("Unknown setting: %s" % ", ".join(unknown[:20]))
    fixed = sorted(k for k in body if k in READ_ONLY_NAMES)
    if fixed:
        raise errors.bad("This setting cannot be changed: %s" % ", ".join(fixed))
    values = {k: _text(k, v) for k, v in body.items()}          # validate everything first
    sealed = {}
    for k, v in values.items():
        if k in SECRETS and v not in (None, ""):
            try:
                sealed[k] = seal(cfg, k, v)
            except SealKeyMissing:
                raise errors.OCCError(503, "Secret settings cannot be stored: the server's sealing key is missing.")
    for k, v in values.items():
        if k in SECRETS:
            old_set = tx.val("SELECT value_enc IS NOT NULL FROM occ.site_config WHERE name = :n", n=k)
            if v in (None, ""):
                tx.run("INSERT INTO occ.site_config (name, value, is_secret, value_enc, updated_by) "
                       "VALUES (:n, NULL, true, NULL, :u) ON CONFLICT (name) DO UPDATE SET value = NULL, "
                       "is_secret = true, value_enc = NULL, updated_at = now(), updated_by = EXCLUDED.updated_by",
                       n=k, u=p.user_id)
                if old_set:
                    audit.write(tx, actor, "config.update", target=k, detail={"secret": "cleared"})
            else:
                tx.run("INSERT INTO occ.site_config (name, value, is_secret, value_enc, updated_by) "
                       "VALUES (:n, NULL, true, :e, :u) ON CONFLICT (name) DO UPDATE SET value = NULL, "
                       "is_secret = true, value_enc = EXCLUDED.value_enc, updated_at = now(), "
                       "updated_by = EXCLUDED.updated_by", n=k, e=sealed[k], u=p.user_id)
                audit.write(tx, actor, "config.update", target=k, detail={"secret": "set"})   # never the value
            continue
        old = tx.one("SELECT value FROM occ.site_config WHERE name = :n", n=k)
        if old is not None and old["value"] == v:
            continue
        tx.run("INSERT INTO occ.site_config (name, value, updated_by) VALUES (:n, :v, :u) ON CONFLICT (name) "
               "DO UPDATE SET value = EXCLUDED.value, is_secret = false, value_enc = NULL, updated_at = now(), "
               "updated_by = EXCLUDED.updated_by", n=k, v=v, u=p.user_id)
        audit.write(tx, actor, "config.update", target=k, old=old["value"] if old else DEFAULTS.get(k), new=v)
    return read_config(tx, p)


# ------------------------------------------------------------------------- identity providers
_IDP_TEXT = ("name", "entityid", "email_attr", "team_attr", "fname_attr", "lname_attr", "orgid_attr", "orcid_attr")
IDP_COLUMNS = frozenset(_IDP_TEXT + ("enabled",))
_CERT_PEM = re.compile(r"^[A-Za-z0-9+/=\s-]+$")


def _idp_values(body, creating):
    vals = {}
    for k, v in body.items():
        if k in ("id", "certs", "endpoints", "source", "created_at", "modified_at"):
            continue
        if k not in IDP_COLUMNS:
            raise errors.bad("Unknown identity provider field: %s" % k)
        if k == "enabled":
            vals[k] = str(v).strip().lower() in ("1", "true", "on", "yes")
        else:
            t = "" if v is None else str(v).strip()
            if k in ("name", "entityid", "email_attr") and not t:
                raise errors.bad("Incorrect value for %s: it is empty" % k)
            vals[k] = t
    if creating:
        for k in ("name", "entityid"):
            if not vals.get(k):
                raise errors.bad("Incorrect value for %s: it is required" % k)
    return vals


def _certs(body):
    out = []
    for c in body.get("certs") or []:
        if isinstance(c, str):
            c = {"x509": c, "purpose": 0}
        x = str((c or {}).get("x509") or "").strip()
        if not x or not _CERT_PEM.match(x):
            raise errors.bad("Incorrect value for certs: an x509 certificate in PEM or base64")
        purpose = int((c or {}).get("purpose") or 0)
        if purpose not in (0, 1):
            raise errors.bad("Incorrect value for certs: purpose 0 (signing) or 1 (encryption)")
        out.append((purpose, x))
    return out


def _endpoints(body):
    out = []
    for e in body.get("endpoints") or []:
        loc = str((e or {}).get("location") or "").strip()
        if not loc.startswith("https://"):
            raise errors.bad("Incorrect value for endpoints: location must be an https address")
        binding = (e or {}).get("binding", 0)
        binding = {"HTTP-Redirect": 0, "HTTP-POST": 1}.get(binding, binding)
        if binding not in (0, 1):
            raise errors.bad("Incorrect value for endpoints: binding HTTP-Redirect or HTTP-POST")
        out.append((bool((e or {}).get("is_slo")), binding, loc))
    return out


def _put_children(tx, idp_id, certs, endpoints, body):
    import hashlib
    if "certs" in body:
        tx.run("DELETE FROM occ.idp_certs WHERE idp_id = :i", i=idp_id)
        for purpose, x in certs:
            tx.run("INSERT INTO occ.idp_certs (idp_id, purpose, x509, sha256) VALUES (:i, :p, :x, :h) "
                   "ON CONFLICT DO NOTHING", i=idp_id, p=purpose, x=x,
                   h=hashlib.sha256("".join(x.split()).encode()).hexdigest())
    if "endpoints" in body:
        tx.run("DELETE FROM occ.idp_endpoints WHERE idp_id = :i", i=idp_id)
        for is_slo, binding, loc in endpoints:
            tx.run("INSERT INTO occ.idp_endpoints (idp_id, is_slo, binding, location) VALUES (:i, :s, :b, :l)",
                   i=idp_id, s=is_slo, b=binding, l=loc)


def create_idp(tx, p, actor, body):
    _sysadmin(p)
    _writer(p)
    body = body or {}
    vals = _idp_values(body, True)
    certs, endpoints = _certs(body), _endpoints(body)
    if tx.val("SELECT 1 FROM occ.idps WHERE entityid = :e", e=vals["entityid"]):
        raise errors.bad("An identity provider with that entityid exists already")
    idp_id = tx.val("INSERT INTO occ.idps (name, entityid) VALUES (:n, :e) RETURNING id",
                    n=vals["name"], e=vals["entityid"])
    _apply_idp(tx, idp_id, vals)
    _put_children(tx, idp_id, certs, endpoints, body)
    audit.write(tx, actor, "config.update", target="idp", new=vals["name"], detail={"idp_id": idp_id, "op": "create"})
    return idp_id


def _apply_idp(tx, idp_id, vals):
    from ..db import ident
    for k, v in vals.items():
        tx.run("UPDATE occ.idps SET %s = :v, modified_at = now() WHERE id = :i" % ident(k, IDP_COLUMNS), v=v, i=idp_id)


def patch_idp(tx, p, actor, idp_id, body):
    from . import site
    _sysadmin(p)
    _writer(p)
    body = body or {}
    row = tx.one("SELECT * FROM occ.idps WHERE id = :i FOR UPDATE", i=idp_id)
    if row is None:
        raise errors.not_found()
    vals = _idp_values(body, False)
    certs, endpoints = _certs(body), _endpoints(body)
    if vals.get("enabled") is False and row["enabled"] and \
            not tx.val("SELECT 1 FROM occ.idps WHERE enabled AND id <> :i", i=idp_id):
        raise errors.bad("This is the only enabled identity provider: enable another one first.")
    changed = {k: v for k, v in vals.items() if row[k] != v}
    _apply_idp(tx, idp_id, changed)
    _put_children(tx, idp_id, certs, endpoints, body)
    for k, v in changed.items():
        audit.write(tx, actor, "config.update", target="idp.%s" % k, old=row[k], new=v, detail={"idp_id": idp_id})
    return site.get_idp(tx, p, idp_id)


def delete_idp(tx, p, actor, idp_id):
    _sysadmin(p)
    _writer(p)
    row = tx.one("SELECT * FROM occ.idps WHERE id = :i FOR UPDATE", i=idp_id)
    if row is None:
        raise errors.not_found()
    if row["enabled"] and not tx.val("SELECT 1 FROM occ.idps WHERE enabled AND id <> :i", i=idp_id):
        raise errors.bad("This is the only enabled identity provider: it cannot be removed.")
    if tx.val("SELECT 1 FROM occ.user_identities WHERE idp_id = :i LIMIT 1", i=idp_id):
        raise errors.bad("People sign in through this identity provider: disable it instead.")
    tx.run("DELETE FROM occ.idps WHERE id = :i", i=idp_id)
    audit.write(tx, actor, "config.update", target="idp", old=row["name"], detail={"idp_id": idp_id, "op": "delete"})


def create_idp_source(tx, p, actor, body):
    _sysadmin(p)
    _writer(p)
    body = body or {}
    url = str(body.get("url") or "").strip()
    if not url.startswith("https://"):
        raise errors.bad("Incorrect value for url: an https address")
    auto = str(body.get("auto_refresh", 0)).strip().lower() in ("1", "true", "on", "yes")
    sid = tx.val("INSERT INTO occ.idp_sources (url, auto_refresh) VALUES (:u, :a) RETURNING id", u=url, a=auto)
    audit.write(tx, actor, "config.update", target="idp_source", new=url, detail={"source_id": sid, "op": "create"})
    return sid


def may_refresh(p):
    _sysadmin(p)
    _writer(p)


def patch_idp_source(tx, p, actor, source_id, body):
    """Change a metadata source: enabled and auto_refresh. action=refresh fetches the metadata now; the router sends it to
    people/idp_refresh.py, which fetches outside the transaction (the daily idp-refresh job does the same)."""
    _sysadmin(p)
    _writer(p)
    body = body or {}
    row = tx.one("SELECT * FROM occ.idp_sources WHERE id = :i FOR UPDATE", i=source_id)
    if row is None:
        raise errors.not_found()
    action = body.get("action")
    for name in ("enabled", "auto_refresh"):
        if action == name or name in body:
            raw = body.get(name, body.get("value"))
            if raw is None:
                raise errors.bad("Incorrect value for %s" % name)
            new = str(raw).strip().lower() in ("1", "true", "on", "yes")
            if new != row[name]:
                if name == "enabled":
                    tx.run("UPDATE occ.idp_sources SET enabled = :v WHERE id = :i", v=new, i=source_id)
                else:
                    tx.run("UPDATE occ.idp_sources SET auto_refresh = :v WHERE id = :i", v=new, i=source_id)
                audit.write(tx, actor, "config.update", target="idp_source.%s" % name, old=row[name], new=new,
                            detail={"source_id": source_id})
    r = tx.one("SELECT * FROM occ.idp_sources WHERE id = :i", i=source_id)
    return {"id": r["id"], "url": r["url"], "auto_refresh": 1 if r["auto_refresh"] else 0,
            "enabled": 1 if r["enabled"] else 0, "last_fetched_at": timefmt.out(r["last_fetched_at"])}


def delete_idp_source(tx, p, actor, source_id):
    _sysadmin(p)
    _writer(p)
    row = tx.one("SELECT * FROM occ.idp_sources WHERE id = :i", i=source_id)
    if row is None:
        raise errors.not_found()
    tx.run("DELETE FROM occ.idp_sources WHERE id = :i", i=source_id)
    audit.write(tx, actor, "config.update", target="idp_source", old=row["url"],
                detail={"source_id": source_id, "op": "delete"})
