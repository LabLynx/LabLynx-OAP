# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""The minisign file formats, written from the format's published description, so the stock
minisign tool reads what the OCC writes and the OCC reads what the tool writes.

Public key file:   "untrusted comment: ..." then base64("Ed" | key id (8) | Ed25519 public key (32))
Secret key file:   "untrusted comment: ..." then base64("Ed" | "Sc" | "B2" | salt (32) | opslimit (8, LE) |
                   memlimit (8, LE) | sealed (104)); sealed = (key id | secret key (64) | checksum (32))
                   XOR scrypt(passphrase, salt), checksum = BLAKE2b-256("Ed" | key id | secret key),
                   the secret key being the 32-byte seed followed by the public key.
Signature file:    "untrusted comment: ..." / base64("ED" | key id | Ed25519(BLAKE2b-512(data))) /
                   "trusted comment: <text>" / base64(Ed25519(signature (64) | trusted comment text)).

scrypt's cost comes from opslimit and memlimit the way libsodium's scryptsalsa208sha256 derives it
(r = 8; N and p from the two limits). The OCC writes opslimit 2^20 and memlimit 2^25 (N = 2^15,
r = 8, p = 1: 32 MB, about a tenth of a second here), not the tool's own 1 GB default, which this
shared server cannot spend on every signature. Any minisign reads the limits from
the file, so the tool still opens an OCC key.
"""
import base64
import hashlib
import os
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

OPSLIMIT = 1 << 20
MEMLIMIT = 1 << 25
MIN_PASSPHRASE = 12


class BadPassphrase(Exception):
    pass


class FormatError(ValueError):
    pass


def _scrypt_params(opslimit, memlimit):
    """N (as log2), r, p from libsodium's opslimit/memlimit (crypto_pwhash_scryptsalsa208sha256)."""
    opslimit = max(opslimit, 32768)
    r = 8
    if opslimit < memlimit // 32:
        p = 1
        max_n = opslimit // (r * 4)
    else:
        max_n = memlimit // (r * 128)
    n_log2 = 1
    while n_log2 < 63 and not ((1 << n_log2) > max_n // 2):
        n_log2 += 1
    if not (opslimit < memlimit // 32):
        maxrp = min((opslimit // 4) // (1 << n_log2), 0x3FFFFFFF)
        p = maxrp // r
    return n_log2, r, max(p, 1)


def _kdf(passphrase, salt, opslimit, memlimit, length):
    n_log2, r, p = _scrypt_params(opslimit, memlimit)
    need = 128 * r * ((1 << n_log2) + p + 2) + (1 << 20)
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=1 << n_log2, r=r, p=p, maxmem=need, dklen=length)


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def key_id_hex(key_id):
    """How minisign prints a key id: the 8 bytes as a little-endian number, in upper-case hex."""
    return "%016X" % struct.unpack("<Q", key_id)[0]


def _b64line(text, index):
    lines = [ln for ln in text.strip().splitlines() if ln.strip()]
    try:
        return base64.b64decode(lines[index].strip(), validate=True), lines
    except (IndexError, ValueError):
        raise FormatError("not a minisign file")


class KeyPair:
    def __init__(self, key_id, seed, public):
        self.key_id, self.seed, self.public = key_id, seed, public

    @property
    def key_id_hex(self):
        return key_id_hex(self.key_id)

    def public_file(self):
        return ("untrusted comment: minisign public key %s\n%s\n"
                % (self.key_id_hex, base64.b64encode(b"Ed" + self.key_id + self.public).decode()))

    def secret_file(self, passphrase, opslimit=OPSLIMIT, memlimit=MEMLIMIT):
        if len(passphrase or "") < MIN_PASSPHRASE:
            raise BadPassphrase("The passphrase needs at least %d characters." % MIN_PASSPHRASE)
        salt = os.urandom(32)
        sk = self.seed + self.public
        checksum = hashlib.blake2b(b"Ed" + self.key_id + sk, digest_size=32).digest()
        plain = self.key_id + sk + checksum
        sealed = _xor(plain, _kdf(passphrase, salt, opslimit, memlimit, len(plain)))
        blob = b"Ed" + b"Sc" + b"B2" + salt + struct.pack("<QQ", opslimit, memlimit) + sealed
        return "untrusted comment: minisign encrypted secret key\n%s\n" % base64.b64encode(blob).decode()

    def sign(self, data, trusted_comment, untrusted_comment="signature from the LabLynx.One OCC"):
        key = Ed25519PrivateKey.from_private_bytes(self.seed)
        if "\n" in trusted_comment or "\r" in trusted_comment:
            raise ValueError("a trusted comment is one line")
        sig = key.sign(hashlib.blake2b(data, digest_size=64).digest())
        glob = key.sign(sig + trusted_comment.encode("utf-8"))
        return ("untrusted comment: %s\n%s\ntrusted comment: %s\n%s\n"
                % (untrusted_comment, base64.b64encode(b"ED" + self.key_id + sig).decode(), trusted_comment,
                   base64.b64encode(glob).decode()))


def generate():
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return KeyPair(os.urandom(8), seed, public)


def open_secret(text, passphrase):
    """The key pair inside a secret key file; BadPassphrase when the checksum does not match."""
    blob, _ = _b64line(text, 1)
    if len(blob) != 2 + 2 + 2 + 32 + 16 + 104 or blob[:2] != b"Ed" or blob[2:4] != b"Sc" or blob[4:6] != b"B2":
        raise FormatError("not a minisign Ed25519 secret key sealed with scrypt")
    salt = blob[6:38]
    opslimit, memlimit = struct.unpack("<QQ", blob[38:54])
    plain = _xor(blob[54:], _kdf(passphrase or "", salt, opslimit, memlimit, 104))
    key_id, sk, checksum = plain[:8], plain[8:72], plain[72:]
    if hashlib.blake2b(b"Ed" + key_id + sk, digest_size=32).digest() != checksum:
        raise BadPassphrase("Wrong passphrase.")
    return KeyPair(key_id, sk[:32], sk[32:])


def read_public(text):
    blob, _ = _b64line(text, 1)
    if len(blob) != 42 or blob[:2] != b"Ed":
        raise FormatError("not a minisign Ed25519 public key")
    return blob[2:10], blob[10:]


def trusted_comment(sig_text):
    for line in sig_text.splitlines():
        if line.startswith("trusted comment: "):
            return line[len("trusted comment: "):]
    raise FormatError("no trusted comment")


def verify(data, sig_text, pub_text):
    """True when the signature file verifies the data and its trusted comment under the public key
    (both the prehashed 'ED' form the OCC writes and the legacy 'Ed' form)."""
    try:
        key_id, pk = read_public(pub_text)
        sblob, lines = _b64line(sig_text, 1)
        if len(sblob) != 74 or sblob[2:10] != key_id or sblob[:2] not in (b"ED", b"Ed"):
            return False
        tc = lines[2]
        if not tc.startswith("trusted comment: "):
            return False
        glob = base64.b64decode(lines[3].strip(), validate=True)
        key = Ed25519PublicKey.from_public_bytes(pk)
        sig = sblob[10:]
        key.verify(sig, hashlib.blake2b(data, digest_size=64).digest() if sblob[:2] == b"ED" else data)
        key.verify(glob, sig + tc[len("trusted comment: "):].encode("utf-8"))
        return True
    except (InvalidSignature, FormatError, ValueError, IndexError):
        return False
