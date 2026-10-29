# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Identity-provider metadata refresh (a metadata source's action=refresh, and the daily idp-refresh
job).

A source (occ.idp_sources) is the https address of SAML 2.0 metadata: one EntityDescriptor or an
EntitiesDescriptor holding many. Refreshing fetches it (outside any transaction), reads every
identity provider in it (IDPSSODescriptor: the signing and encryption certificates, the single
sign-on and single logout endpoints for the HTTP-Redirect and HTTP-POST bindings), and then, in one
transaction:
  * a provider the OCC knows by entityID gets the certificates and endpoints the metadata names now
    (its name, attributes and enabled switch are the sysadmin's and stay as they are);
  * a provider the OCC does not know is added DISABLED, tied to the source, named from the
    metadata: a sysadmin turns it on, so a federation's metadata never opens sign-in by
    itself;
  * last_fetched_at moves on and one audit row records the counts.
A document type declaration is refused (no entity tricks), a document over 10 MB is refused, and
only https endpoints are kept. The metadata's own XML signature is not checked: the source's https
address authenticates it.
"""
import hashlib
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

from .. import errors, timefmt
from ..audit import writer as audit

MD = "{urn:oasis:names:tc:SAML:2.0:metadata}"
DS = "{http://www.w3.org/2000/09/xmldsig#}"
MDUI = "{urn:oasis:names:tc:SAML:metadata:ui}"
BINDINGS = {"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect": 0, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST": 1}
MAX_BYTES = 10 * 1024 * 1024
TIMEOUT = 30


class RefreshError(Exception):
    pass


def fetch(url, allow_http=False, timeout=TIMEOUT):
    if not (url.startswith("https://") or (allow_http and url.startswith("http://"))):
        raise RefreshError("A metadata source is an https address.")
    req = urllib.request.Request(url, headers={"Accept": "application/samlmetadata+xml, application/xml",
                                               "User-Agent": "LabLynx.One-OCC"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:        # noqa: S310 (a sysadmin's https source)
            data = r.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as ex:
        raise RefreshError("The metadata source answered %d." % ex.code)
    except (urllib.error.URLError, OSError) as ex:
        raise RefreshError("The metadata source could not be reached (%s)." % type(ex).__name__)
    if len(data) > MAX_BYTES:
        raise RefreshError("The metadata is larger than 10 MB.")
    return data


def _pem_body(text):
    return "".join((text or "").split())


def parse(data):
    """[{entityid, name, certs: [(purpose, base64)], endpoints: [(is_slo, binding, location)]}]"""
    if b"<!DOCTYPE" in data[:4096] or b"<!ENTITY" in data:
        raise RefreshError("The metadata carries a document type declaration: refused.")
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        raise RefreshError("The metadata is not well-formed XML.")
    if root.tag == MD + "EntityDescriptor":
        entities = [root]
    elif root.tag == MD + "EntitiesDescriptor":
        entities = list(root.iter(MD + "EntityDescriptor"))
    else:
        raise RefreshError("The document is not SAML 2.0 metadata.")
    out = []
    for e in entities:
        idp = e.find(MD + "IDPSSODescriptor")
        eid = (e.get("entityID") or "").strip()
        if idp is None or not eid:
            continue
        certs = []
        for kd in idp.findall(MD + "KeyDescriptor"):
            use = kd.get("use")
            for x in kd.iter(DS + "X509Certificate"):
                body = _pem_body(x.text)
                if body:
                    purposes = (0, 1) if use is None else ((1,) if use == "encryption" else (0,))
                    certs += [(p, body) for p in purposes]
        endpoints = []
        for tag, slo in (("SingleSignOnService", False), ("SingleLogoutService", True)):
            for s in idp.findall(MD + tag):
                b, loc = BINDINGS.get(s.get("Binding") or ""), (s.get("Location") or "").strip()
                if b is not None and loc.startswith("https://"):
                    endpoints.append((slo, b, loc))
        name = None
        for dn in idp.iter(MDUI + "DisplayName"):
            name = (dn.text or "").strip() or name
            if dn.get("{http://www.w3.org/XML/1998/namespace}lang") == "en":
                break
        if not name:
            org = e.find(MD + "Organization/" + MD + "OrganizationDisplayName")
            name = (org.text or "").strip() if org is not None else None
        out.append({"entityid": eid, "name": (name or eid)[:255], "certs": sorted(set(certs)), "endpoints": endpoints})
    if not out:
        raise RefreshError("The metadata names no identity provider.")
    return out


def apply(tx, actor, source_id, providers):
    """Writes what parse() read; returns the counts. Runs in the caller's transaction."""
    added = updated = 0
    for pv in providers:
        row = tx.one("SELECT id FROM occ.idps WHERE entityid = :e FOR UPDATE", e=pv["entityid"])
        if row is None:
            idp_id = tx.val("INSERT INTO occ.idps (name, entityid, enabled, source_id) VALUES (:n, :e, false, :s) "
                            "RETURNING id", n=pv["name"], e=pv["entityid"], s=source_id)
            added += 1
        else:
            idp_id = row["id"]
            tx.run("UPDATE occ.idps SET source_id = coalesce(source_id, :s), modified_at = now() WHERE id = :i",
                   s=source_id, i=idp_id)
            updated += 1
        tx.run("DELETE FROM occ.idp_certs WHERE idp_id = :i", i=idp_id)
        for purpose, body in pv["certs"]:
            tx.run("INSERT INTO occ.idp_certs (idp_id, purpose, x509, sha256) VALUES (:i, :p, :x, :h) "
                   "ON CONFLICT DO NOTHING", i=idp_id, p=purpose, x=body, h=hashlib.sha256(body.encode()).hexdigest())
        tx.run("DELETE FROM occ.idp_endpoints WHERE idp_id = :i", i=idp_id)
        for is_slo, binding, loc in pv["endpoints"]:
            tx.run("INSERT INTO occ.idp_endpoints (idp_id, is_slo, binding, location) VALUES (:i, :s, :b, :l)",
                   i=idp_id, s=is_slo, b=binding, l=loc)
    tx.run("UPDATE occ.idp_sources SET last_fetched_at = now() WHERE id = :i", i=source_id)
    counts = {"providers": len(providers), "added_disabled": added, "updated": updated}
    audit.write(tx, actor, "config.update", target="idp_source.refresh", detail=dict(counts, source_id=source_id))
    return counts


def refresh(pool, actor, source_id, allow_http=False, fetcher=None):
    """Fetch outside a transaction, then apply in one. Returns (source shape, counts)."""
    with pool.tx(readonly=True) as tx:
        src = tx.one("SELECT * FROM occ.idp_sources WHERE id = :i", i=source_id)
    if src is None:
        raise errors.not_found()
    try:
        providers = parse((fetcher or fetch)(src["url"], allow_http=allow_http))
    except RefreshError as ex:
        raise errors.OCCError(502, str(ex))
    with pool.tx() as tx:
        counts = apply(tx, actor, source_id, providers)
        r = tx.one("SELECT * FROM occ.idp_sources WHERE id = :i", i=source_id)
    return ({"id": r["id"], "url": r["url"], "auto_refresh": 1 if r["auto_refresh"] else 0,
             "enabled": 1 if r["enabled"] else 0, "last_fetched_at": timefmt.out(r["last_fetched_at"])}, counts)
