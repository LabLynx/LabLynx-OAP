# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Email: SMTP settings from occ.site_config, the outbox, and sending.

Settings carry the names the mirror's configuration uses: smtp_address, smtp_port,
smtp_encryption ('ssl' implicit TLS, 'tls' STARTTLS, '' or 'none' plain), smtp_username,
smtp_password (a SECRET: sealed, never returned), smtp_verify_cert, mail_from.

The password is read only as the sealed secret (occ/people/config.py: AES-256-GCM under the
key file) and only for the OCC's own sending. A password stored in clear text, or one that cannot
be unsealed, makes settings() refuse with MailNotConfigured rather than read it from anywhere else:
a secret is never taken from a place it was not sealed into.
Nothing here logs an address list, a body or a password; a failure is logged by its type only.
"""
import email.message
import email.utils
import smtplib
import ssl

NAMES = ("smtp_address", "smtp_port", "smtp_encryption", "smtp_username", "smtp_verify_cert", "mail_from",
         "email_send_grouped", "mail_subject_prefix")
SECRET_NAMES = ("smtp_password",)
TIMEOUT_S = 20
TEST_FAILED = "Could not send email! Full error message has been logged."


class MailNotConfigured(Exception):
    pass


def _rows(tx):
    return {r["name"]: r for r in tx.all("SELECT name, value, is_secret FROM occ.site_config "
                                         "WHERE name = ANY(CAST(:n AS text[]))", n=list(NAMES + SECRET_NAMES))}


def settings(tx, cfg=None):
    """The SMTP settings; cfg (the process settings) is needed to unseal a password."""
    rows = _rows(tx)
    v = {n: (rows[n]["value"] if n in rows and not rows[n]["is_secret"] else None) for n in NAMES}
    if not (v["smtp_address"] or "").strip():
        raise MailNotConfigured("no mail server is configured (smtp_address)")
    pw = rows.get("smtp_password")
    password = None
    if pw is not None and pw["value"]:
        raise MailNotConfigured("the mail server's password is stored unsealed; set it again through the API")
    if pw is not None and pw["is_secret"]:
        if cfg is None:
            raise MailNotConfigured("the mail server's password is sealed and no key file was given")
        try:
            from .people import config as config_mod
            password = config_mod.secret(tx, cfg, "smtp_password")
        except Exception as e:  # noqa: BLE001 - only the type is kept, never the value
            raise MailNotConfigured("the mail server's sealed password cannot be unsealed (%s)" % type(e).__name__)
    try:
        port = int(v["smtp_port"] or 25)
    except ValueError:
        raise MailNotConfigured("smtp_port is not a number")
    return {"host": v["smtp_address"].strip(), "port": port,
            "encryption": (v["smtp_encryption"] or "").strip().lower(),
            "username": (v["smtp_username"] or "").strip(),
            "verify": str(v["smtp_verify_cert"] if v["smtp_verify_cert"] is not None else "1") not in ("0", "false"),
            "mail_from": (v["mail_from"] or "").strip() or "notifications@localhost",
            "grouped": str(v["email_send_grouped"] or "0") in ("1", "true"),
            "prefix": (v["mail_subject_prefix"] or "").strip(), "password": password or None}


def valid_address(addr):
    a = str(addr or "").strip()
    if not a or len(a) > 254 or any(ch in a for ch in "\r\n<>,; ") or a.count("@") != 1:
        return False
    local, domain = a.split("@")
    return bool(local) and "." in domain and not domain.startswith(".") and not domain.endswith(".")


def build(cfg, to, subject, text, html=None):
    m = email.message.EmailMessage()
    m["From"] = cfg["mail_from"]
    m["To"] = to
    m["Subject"] = subject
    m["Date"] = email.utils.formatdate(localtime=False)
    m["Message-ID"] = email.utils.make_msgid(domain=cfg["mail_from"].split("@")[-1] or "localhost")
    m.set_content(text or "")
    if html:
        m.add_alternative(html, subtype="html")
    return m


def send(cfg, msg):
    """Deliver one message; raises on any failure (smtplib's and ssl's own exceptions)."""
    ctx = ssl.create_default_context()
    if not cfg["verify"]:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if cfg["encryption"] == "ssl":
        s = smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=TIMEOUT_S, context=ctx)
    else:
        s = smtplib.SMTP(cfg["host"], cfg["port"], timeout=TIMEOUT_S)
    try:
        if cfg["encryption"] == "tls":
            s.starttls(context=ctx)
        if cfg["username"] and cfg.get("password"):
            s.login(cfg["username"], cfg["password"])
        s.send_message(msg)
    finally:
        try:
            s.quit()
        except Exception:  # noqa: BLE001 - the connection may already be gone
            pass


def queue(tx, to, subject, text, html=None, notification_id=None):
    return tx.val("INSERT INTO occ.email_outbox (to_address, subject, body_text, body_html, notification_id) "
                  "VALUES (:t, :s, :b, :h, :n) RETURNING id", t=to, s=subject, b=text, h=html, n=notification_id)
