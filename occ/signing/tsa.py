# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""An RFC 3161 time-stamp client.

request(digest) builds a TimeStampReq over a SHA-256 digest with a random nonce and certReq set;
fetch() posts it to the configured authority (application/timestamp-query) and check() accepts the
TimeStampResp only when the status is granted, the token's message imprint is the digest sent, the
nonce is the one sent, and the token's CMS signature verifies under the signer certificate it
carries. When the site names the authority's certificate (ts_cert, PEM), the signer certificate
must be that certificate or be signed by it. What is stored is the whole DER TimeStampResp, which
'openssl ts -verify -in <file> -data <file> -CAfile <ca>' reads as it is.

asn1crypto (MIT) parses and builds the structures; cryptography (Apache-2.0 / BSD) checks the
signatures. No public authority is ever contacted by the OCC's tests: they run their own.
"""
import base64
import datetime as dt
import hashlib
import os
import urllib.error
import urllib.request

from asn1crypto import cms, core, pem, tsp, x509 as ax509
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

TIMEOUT = 30
_HASHES = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512, "sha1": hashes.SHA1}


class TSAError(Exception):
    pass


class _Resp(core.Sequence):
    """TimeStampResp with the token optional, as RFC 3161 has it (a refusal carries none)."""
    _fields = [("status", tsp.PKIStatusInfo), ("time_stamp_token", cms.ContentInfo, {"optional": True})]


class Stamp:
    def __init__(self, response_der, gen_time, serial, authority):
        self.response_der, self.gen_time, self.serial, self.authority = response_der, gen_time, serial, authority

    @property
    def token_der(self):
        return tsp.TimeStampResp.load(self.response_der)["time_stamp_token"].dump()


def request(digest, nonce=None):
    nonce = nonce if nonce is not None else int.from_bytes(os.urandom(8), "big")
    req = tsp.TimeStampReq({"version": "v1",
                            "message_imprint": {"hash_algorithm": {"algorithm": "sha256"}, "hashed_message": digest},
                            "nonce": nonce, "cert_req": True})
    return req.dump(), nonce


def fetch(url, digest, login=None, password=None, ca_pem=None, timeout=TIMEOUT):
    if not url or not url.lower().startswith(("http://", "https://")):
        raise TSAError("No timestamping authority is configured (ts_url).")
    body, nonce = request(digest)
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/timestamp-query", "Accept": "application/timestamp-reply",
        "User-Agent": "LabLynx.One-OCC"})
    if login:
        token = base64.b64encode(("%s:%s" % (login, password or "")).encode("utf-8")).decode()
        req.add_header("Authorization", "Basic " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:     # noqa: S310 (the site's own authority)
            der = r.read(1024 * 1024)
    except urllib.error.HTTPError as ex:
        raise TSAError("The timestamping authority answered %d." % ex.code)
    except (urllib.error.URLError, OSError) as ex:
        raise TSAError("The timestamping authority could not be reached (%s)." % type(ex).__name__)
    return check(der, digest, nonce, ca_pem)


def _cert_from(ca_pem):
    data = ca_pem.encode() if isinstance(ca_pem, str) else ca_pem
    if pem.detect(data):
        _t, _h, data = pem.unarmor(data)
    return x509.load_der_x509_certificate(data)


def _verify_with(pub, sig, data, hash_name, sig_algo):
    h = _HASHES.get(hash_name)
    if h is None:
        raise TSAError("unsupported digest %s" % hash_name)
    if isinstance(pub, rsa.RSAPublicKey):
        if sig_algo == "rsassa_pss":
            pub.verify(sig, data, padding.PSS(mgf=padding.MGF1(h()), salt_length=padding.PSS.AUTO), h())
        else:
            pub.verify(sig, data, padding.PKCS1v15(), h())
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(sig, data, ec.ECDSA(h()))
    else:
        pub.verify(sig, data)                     # Ed25519 / Ed448


def check(der, digest, nonce=None, ca_pem=None, authority=""):
    try:
        resp = _Resp.load(der)
        status = resp["status"]["status"].native
    except Exception:                                                    # noqa: BLE001
        raise TSAError("The timestamping authority's answer is not an RFC 3161 response.")
    if status not in ("granted", "granted_with_mods"):
        raise TSAError("The timestamping authority refused the request (%s)." % status)
    token = resp["time_stamp_token"]
    if not token or token["content_type"].native != "signed_data":
        raise TSAError("The time-stamp token is not CMS signed data.")
    sd = token["content"]
    econtent = sd["encap_content_info"]
    if econtent["content_type"].native != "tst_info":
        raise TSAError("The time-stamp token carries no TSTInfo.")
    raw_tst = econtent["content"].contents
    tst = tsp.TSTInfo.load(raw_tst)
    imprint = tst["message_imprint"]
    if imprint["hash_algorithm"]["algorithm"].native != "sha256" or imprint["hashed_message"].native != digest:
        raise TSAError("The time-stamp token is over different data.")
    if nonce is not None and tst["nonce"].native != nonce:
        raise TSAError("The time-stamp token's nonce is not the one sent.")
    _verify_token_signature(sd, raw_tst, ca_pem)
    gen = tst["gen_time"].native
    if gen.tzinfo is None:
        gen = gen.replace(tzinfo=dt.timezone.utc)
    return Stamp(der, gen, str(tst["serial_number"].native), authority)


def _verify_token_signature(sd, raw_tst, ca_pem):
    signers = sd["signer_infos"]
    if len(signers) != 1:
        raise TSAError("The time-stamp token must have exactly one signer.")
    si = signers[0]
    certs = [c.chosen for c in (sd["certificates"] or []) if isinstance(c.chosen, ax509.Certificate)]
    sid = si["sid"]
    signer = None
    for c in certs:
        if sid.name == "issuer_and_serial_number":
            if (c.issuer == sid.chosen["issuer"] and c.serial_number == sid.chosen["serial_number"].native):
                signer = c
        elif c.key_identifier == sid.chosen.native:
            signer = c
    ca = _cert_from(ca_pem) if ca_pem else None
    if signer is None:
        if ca is None:
            raise TSAError("The time-stamp token carries no signer certificate and no ts_cert is set.")
        cert = ca
    else:
        cert = x509.load_der_x509_certificate(signer.dump())
    hash_name = si["digest_algorithm"]["algorithm"].native
    attrs = si["signed_attrs"]
    if not attrs:
        raise TSAError("The time-stamp token has no signed attributes.")
    md = None
    for a in attrs:
        if a["type"].native == "message_digest":
            md = a["values"][0].native
    if md != hashlib.new(hash_name, raw_tst).digest():
        raise TSAError("The time-stamp token's message digest does not match its content.")
    signed = attrs.dump()
    signed = b"\x31" + signed[1:]                 # the signature covers the SET OF form
    try:
        _verify_with(cert.public_key(), si["signature"].native, signed, hash_name,
                     si["signature_algorithm"]["algorithm"].native)
    except InvalidSignature:
        raise TSAError("The time-stamp token's signature does not verify.")
    if ca is not None and cert.fingerprint(hashes.SHA256()) != ca.fingerprint(hashes.SHA256()):
        try:
            cert.verify_directly_issued_by(ca)
        except (InvalidSignature, ValueError, TypeError):
            raise TSAError("The time-stamp token is not signed by the configured authority (ts_cert).")
