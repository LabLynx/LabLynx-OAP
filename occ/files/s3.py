# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The S3 file store: the same interface as the disk store, so the API
does not change when a site keeps its files in object storage.

It speaks the S3 REST API itself, signed with AWS Signature Version 4, over the standard library's
HTTP client, so it brings no package (one less dependency to license and keep up to date). Objects are named <prefix><ab>/<cd>/<64 hex>, the same
location the disk store uses. Settings (process settings, read at start):

    OCC_FILES_BACKEND=s3               disk (the default) or s3
    OCC_S3_ENDPOINT=https://s3.example.org     path-style addressing: <endpoint>/<bucket>/<key>
    OCC_S3_BUCKET=occ-files
    OCC_S3_REGION=us-east-1
    OCC_S3_PREFIX=                     optional, e.g. "lablynx-one/"
    OCC_S3_CREDENTIALS_FILE=/etc/occ/s3.credentials    two lines: access key id, secret (mode 0600)
    OCC_S3_VERIFY_TLS=1

put() hashes while it spools the bytes to a temporary file, then sends them in one PUT whose
x-amz-content-sha256 is that hash, so the store itself checks the bytes it received. An object is
always written again, even when it exists, so its LastModified moves on and the orphan sweep's grace
period protects bytes an upload is about to register. The keys are never logged.
"""
import datetime as dt
import hashlib
import hmac
import http.client
import os
import ssl
import tempfile
import xml.etree.ElementTree as ET
from urllib.parse import quote, urlparse

from .store import CHUNK, TooLarge, location

_NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
EMPTY_SHA = hashlib.sha256(b"").hexdigest()


class S3Error(Exception):
    def __init__(self, status, what):
        super().__init__("S3 %s answered %d" % (what, status))
        self.status = status


def read_credentials(path):
    with open(path, encoding="utf-8") as fh:
        lines = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    if len(lines) < 2:
        raise ValueError("the S3 credentials file holds two lines: access key id, secret")
    return lines[0], lines[1]


class _Body:
    """A GET's body as a binary file object; closes its connection when closed."""

    def __init__(self, conn, resp):
        self._conn, self._resp = conn, resp

    def read(self, n=-1):
        return self._resp.read() if n is None or n < 0 else self._resp.read(n)

    def close(self):
        try:
            self._resp.close()
        finally:
            self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class S3Store:
    backend = "s3"

    def __init__(self, endpoint, bucket, region, access_key, secret_key, prefix="", verify_tls=True,
                 spool_dir=None, timeout=60):
        u = urlparse(endpoint)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError("OCC_S3_ENDPOINT must be an http(s) address")
        self.scheme, self.host, self.port = u.scheme, u.hostname, u.port
        self.base_path = (u.path or "").rstrip("/")
        self.bucket, self.region, self.prefix = bucket, region, prefix or ""
        self._ak, self._sk = access_key, secret_key
        self.verify_tls = verify_tls
        self.spool_dir = spool_dir
        self.timeout = timeout

    # ------------------------------------------------------------------ HTTP and signing
    def _hostheader(self):
        default = 443 if self.scheme == "https" else 80
        return self.host if not self.port or self.port == default else "%s:%d" % (self.host, self.port)

    def _conn(self):
        if self.scheme == "https":
            ctx = ssl.create_default_context()
            if not self.verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            return http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=ctx)
        return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

    def _path(self, key=None):
        p = "%s/%s" % (self.base_path, quote(self.bucket, safe=""))
        if key is not None:
            p += "/" + quote(key, safe="/-_.~")
        return p

    def _sign(self, method, path, query, headers, payload_sha):
        now = dt.datetime.now(dt.timezone.utc)
        amz, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
        headers = dict(headers)
        headers.update({"host": self._hostheader(), "x-amz-date": amz, "x-amz-content-sha256": payload_sha})
        names = sorted(k.lower() for k in headers)
        lower = {k.lower(): str(v).strip() for k, v in headers.items()}
        cq = "&".join("%s=%s" % (quote(k, safe="-_.~"), quote(v, safe="-_.~")) for k, v in sorted(query.items()))
        creq = "\n".join([method, path, cq, "".join("%s:%s\n" % (n, lower[n]) for n in names), ";".join(names),
                          payload_sha])
        scope = "%s/%s/s3/aws4_request" % (day, self.region)
        sts = "\n".join(["AWS4-HMAC-SHA256", amz, scope, hashlib.sha256(creq.encode()).hexdigest()])
        k = hmac.new(("AWS4" + self._sk).encode(), day.encode(), hashlib.sha256).digest()
        for part in (self.region, "s3", "aws4_request"):
            k = hmac.new(k, part.encode(), hashlib.sha256).digest()
        sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
        headers["Authorization"] = ("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s"
                                    % (self._ak, scope, ";".join(names), sig))
        return headers

    def _request(self, method, key=None, query=None, body=None, payload_sha=EMPTY_SHA, headers=None, stream=False):
        query = query or {}
        path = self._path(key)
        hdrs = self._sign(method, path, query, headers or {}, payload_sha)
        url = path + ("?" + "&".join("%s=%s" % (quote(k, safe="-_.~"), quote(v, safe="-_.~"))
                                     for k, v in sorted(query.items())) if query else "")
        conn = self._conn()
        try:
            conn.request(method, url, body=body, headers=hdrs)
            resp = conn.getresponse()
            if stream and resp.status == 200:
                return resp.status, _Body(conn, resp)
            data = resp.read()
            conn.close()
            return resp.status, data
        except BaseException:
            conn.close()
            raise

    def key(self, sha):
        return self.prefix + location(sha)

    # ------------------------------------------------------------------ the store interface
    def ensure_bucket(self):
        status, _ = self._request("HEAD")
        if status == 404:
            status, _ = self._request("PUT")
            if status not in (200, 204):
                raise S3Error(status, "making the bucket")
        elif status not in (200, 204):
            raise S3Error(status, "reading the bucket")

    def put(self, chunks, max_size=None):
        h = hashlib.sha256()
        size = 0
        with tempfile.TemporaryFile(dir=self.spool_dir) as tmp:
            for chunk in chunks:
                if not chunk:
                    continue
                size += len(chunk)
                if max_size is not None and size > max_size:
                    raise TooLarge()
                h.update(chunk)
                tmp.write(chunk)
            tmp.flush()
            tmp.seek(0)
            sha = h.digest()
            status, _ = self._request("PUT", self.key(sha), body=tmp, payload_sha=sha.hex(),
                                      headers={"Content-Length": str(size),
                                               "Content-Type": "application/octet-stream"})
        if status not in (200, 201, 204):
            raise S3Error(status, "storing a file")
        return sha, size

    def put_bytes(self, data):
        return self.put([data])

    def open(self, sha):
        status, body = self._request("GET", self.key(sha), stream=True)
        if status == 404:
            raise FileNotFoundError(sha.hex())
        if status != 200:
            raise S3Error(status, "reading a file")
        return body

    def exists(self, sha):
        status, _ = self._request("HEAD", self.key(sha))
        if status in (200, 204):
            return True
        if status == 404:
            return False
        raise S3Error(status, "looking for a file")

    def rehash(self, sha):
        h = hashlib.sha256()
        with self.open(sha) as fh:
            for chunk in iter(lambda: fh.read(CHUNK), b""):
                h.update(chunk)
        return h.digest()

    def delete(self, sha):
        status, _ = self._request("DELETE", self.key(sha))
        if status not in (200, 204, 404):
            raise S3Error(status, "removing a file")

    def blobs(self):
        """(sha256 bytes, age in seconds) for every stored blob (ListObjectsV2, page by page)."""
        token = None
        now = dt.datetime.now(dt.timezone.utc)
        while True:
            q = {"list-type": "2", "prefix": self.prefix}
            if token:
                q["continuation-token"] = token
            status, data = self._request("GET", query=q)
            if status != 200:
                raise S3Error(status, "listing files")
            if b"<!DOCTYPE" in data[:512]:
                raise S3Error(status, "listing files (a document type declaration is refused)")
            root = ET.fromstring(data)
            for c in root.iter(_NS + "Contents"):
                k = c.findtext(_NS + "Key") or ""
                name = k[len(self.prefix):].rsplit("/", 1)[-1]
                if len(name) != 64:
                    continue
                try:
                    sha = bytes.fromhex(name)
                except ValueError:
                    continue
                lm = c.findtext(_NS + "LastModified") or ""
                try:
                    t = dt.datetime.fromisoformat(lm.replace("Z", "+00:00"))
                    age = (now - t).total_seconds()
                except ValueError:
                    age = 0
                yield sha, age
            if (root.findtext(_NS + "IsTruncated") or "").lower() == "true":
                token = root.findtext(_NS + "NextContinuationToken")
                if not token:
                    return
            else:
                return


def from_settings(cfg):
    e = cfg.extra or {}
    need = ("OCC_S3_ENDPOINT", "OCC_S3_BUCKET", "OCC_S3_CREDENTIALS_FILE")
    missing = [k for k in need if not e.get(k)]
    if missing:
        raise ValueError("OCC_FILES_BACKEND=s3 needs %s" % ", ".join(missing))
    ak, sk = read_credentials(e["OCC_S3_CREDENTIALS_FILE"])
    spool = os.path.join(cfg.files_root, "tmp")
    os.makedirs(spool, exist_ok=True)
    return S3Store(e["OCC_S3_ENDPOINT"], e["OCC_S3_BUCKET"], e.get("OCC_S3_REGION") or "us-east-1", ak, sk,
                   prefix=e.get("OCC_S3_PREFIX") or "", verify_tls=str(e.get("OCC_S3_VERIFY_TLS", "1")) != "0",
                   spool_dir=spool)
