# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""A local RFC 3161 timestamping authority for the OCC's tests. Never a public one.

    with LocalTSA(folder) as tsa:      # tsa.url, tsa.ca_pem_path, tsa.tsa_pem_path, tsa.ca_pem
        ...

It makes its own throwaway CA and a TSA certificate (EC P-256, extended key usage timeStamping,
critical), listens on 127.0.0.1 on a free port, and answers each TimeStampReq with a granted
TimeStampResp whose token is CMS signed data carrying the content type, the message digest, the
signing time and the ESS signing-certificate-v2 attribute (RFC 5816), so 'openssl ts -verify'
accepts it. refuse=True makes it answer 'rejection' instead, to test that path. Test tooling only:
it is never shipped and never part of the OCC.
"""
import datetime as dt
import hashlib
import http.server
import os
import threading

from asn1crypto import algos, cms, core, tsp, x509 as ax509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OCC test only")])


def _cert(subject, issuer, pub, signer_key, ca=False, tsa=False):
    now = dt.datetime.now(dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(pub)
         .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
         .not_valid_after(now + dt.timedelta(days=30))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False))
    if ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    if tsa:
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
        b = b.add_extension(x509.KeyUsage(True, True, False, False, False, False, False, False, False), critical=True)
    return b.sign(signer_key, hashes.SHA256())


class LocalTSA:
    def __init__(self, folder, refuse=False):
        self.folder = folder
        self.refuse = refuse
        self.served = 0
        os.makedirs(folder, exist_ok=True)
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.ca = _cert(_name("OCC Test TSA Root"), _name("OCC Test TSA Root"), self.ca_key.public_key(), self.ca_key,
                        ca=True)
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cert = _cert(_name("OCC Test TSA"), self.ca.subject, self.key.public_key(), self.ca_key, tsa=True)
        self.ca_pem = self.ca.public_bytes(serialization.Encoding.PEM).decode()
        self.ca_pem_path = os.path.join(folder, "tsa-ca.pem")
        self.tsa_pem_path = os.path.join(folder, "tsa.pem")
        with open(self.ca_pem_path, "w") as fh:
            fh.write(self.ca_pem)
        with open(self.tsa_pem_path, "wb") as fh:
            fh.write(self.cert.public_bytes(serialization.Encoding.PEM))
        self._serial = 1000
        self._srv = None

    # ------------------------------------------------------------------ the response
    def respond(self, req_der):
        req = tsp.TimeStampReq.load(req_der)
        if self.refuse:
            return bytes.fromhex("3005300302010" + "2")       # PKIStatusInfo {rejection}, no token
        self._serial += 1
        tst = tsp.TSTInfo({
            "version": "v1", "policy": "1.3.6.1.4.1.99999.1.1",
            "message_imprint": req["message_imprint"], "serial_number": self._serial,
            "gen_time": dt.datetime.now(dt.timezone.utc).replace(microsecond=0),
            "accuracy": {"seconds": 1}, "nonce": req["nonce"].native,
        })
        tst_der = tst.dump()
        cert_der = self.cert.public_bytes(serialization.Encoding.DER)
        acert = ax509.Certificate.load(cert_der)
        ess = tsp.SigningCertificateV2({"certs": [{"hash_algorithm": {"algorithm": "sha256"},
                                                   "cert_hash": hashlib.sha256(cert_der).digest()}]})
        attrs = cms.CMSAttributes([
            cms.CMSAttribute({"type": "content_type", "values": ["tst_info"]}),
            cms.CMSAttribute({"type": "signing_time", "values": [cms.Time({"utc_time": dt.datetime.now(
                dt.timezone.utc).replace(microsecond=0)})]}),
            cms.CMSAttribute({"type": "message_digest", "values": [hashlib.sha256(tst_der).digest()]}),
            cms.CMSAttribute({"type": "signing_certificate_v2", "values": [ess]}),
        ])
        signed = b"\x31" + attrs.dump()[1:]
        sig = self.key.sign(signed, ec.ECDSA(hashes.SHA256()))
        si = cms.SignerInfo({
            "version": "v1",
            "sid": cms.SignerIdentifier({"issuer_and_serial_number": cms.IssuerAndSerialNumber(
                {"issuer": acert.issuer, "serial_number": acert.serial_number})}),
            "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
            "signed_attrs": attrs,
            "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "sha256_ecdsa"}),
            "signature": sig,
        })
        sd = cms.SignedData({
            "version": "v3",
            "digest_algorithms": [algos.DigestAlgorithm({"algorithm": "sha256"})],
            "encap_content_info": {"content_type": "tst_info", "content": core.ParsableOctetString(tst_der)},
            "certificates": [acert] if req["cert_req"].native else [],
            "signer_infos": [si],
        })
        token = cms.ContentInfo({"content_type": "signed_data", "content": sd})
        return tsp.TimeStampResp({"status": {"status": "granted"}, "time_stamp_token": token}).dump()

    # ------------------------------------------------------------------ the server
    def __enter__(self):
        tsa = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):                                       # noqa: N802
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n)
                try:
                    out = tsa.respond(body)
                    code = 200
                except Exception:                                    # noqa: BLE001
                    out, code = b"bad request", 400
                tsa.served += 1
                self.send_response(code)
                self.send_header("Content-Type", "application/timestamp-reply")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass

        self._srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d/tsa" % self._srv.server_address[1]
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *a):
        if self._srv:
            self._srv.shutdown()
            self._srv.server_close()
            self._srv = None
