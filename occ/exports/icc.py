# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""An sRGB ICC profile (version 2.1, display class), built here from the published sRGB values
(IEC 61966-2-1: the primaries adapted to the D50 profile connection space, and the sRGB tone curve
as a 1024-entry table), so the OCC's PDF/A output intent carries no third-party file
(nothing with a license of its own to ship). Layout from the ICC.1:2001-04 specification."""
import struct

_D50 = (0.9642, 1.0, 0.8249)
_RED = (0.4360747, 0.2225045, 0.0139322)
_GREEN = (0.3850649, 0.7168786, 0.0971045)
_BLUE = (0.1430804, 0.0606169, 0.7141733)


def _s15(v):
    return struct.pack(">i", int(round(v * 65536)))


def _xyz(x, y, z):
    return b"XYZ " + b"\0" * 4 + _s15(x) + _s15(y) + _s15(z)


def _curve():
    vals = []
    for i in range(1024):
        c = i / 1023.0
        lin = c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
        vals.append(int(round(lin * 65535)))
    return b"curv" + b"\0" * 4 + struct.pack(">I", len(vals)) + struct.pack(">%dH" % len(vals), *vals)


def _desc(text):
    a = text.encode("ascii") + b"\0"
    return (b"desc" + b"\0" * 4 + struct.pack(">I", len(a)) + a + struct.pack(">II", 0, 0)
            + struct.pack(">HB", 0, 0) + b"\0" * 67)


def _text(text):
    return b"text" + b"\0" * 4 + text.encode("ascii") + b"\0"


def srgb():
    tags = [(b"desc", _desc("sRGB (LabLynx.One OCC)")), (b"cprt", _text("No copyright, use freely")),
            (b"wtpt", _xyz(*_D50)), (b"rXYZ", _xyz(*_RED)), (b"gXYZ", _xyz(*_GREEN)), (b"bXYZ", _xyz(*_BLUE))]
    curve = _curve()
    table = bytearray()
    data = bytearray()
    base = 128 + 4 + 12 * (len(tags) + 3)
    entries = []
    for sig, body in tags:
        entries.append((sig, base + len(data), len(body)))
        data += body + b"\0" * (-len(body) % 4)
    curve_off = base + len(data)
    data += curve + b"\0" * (-len(curve) % 4)
    for sig in (b"rTRC", b"gTRC", b"bTRC"):
        entries.append((sig, curve_off, len(curve)))           # the three channels share one curve
    table += struct.pack(">I", len(entries))
    for sig, off, ln in entries:
        table += sig + struct.pack(">II", off, ln)
    size = 128 + len(table) + len(data)
    header = (struct.pack(">I", size) + b"\0\0\0\0" + struct.pack(">I", 0x02100000) + b"mntr" + b"RGB " + b"XYZ "
              + struct.pack(">6H", 2026, 1, 1, 0, 0, 0) + b"acsp" + b"\0" * 4 + b"\0" * 4 + b"\0" * 4 + b"\0" * 4
              + b"\0" * 8 + struct.pack(">I", 0) + _s15(_D50[0]) + _s15(_D50[1]) + _s15(_D50[2]) + b"\0" * 4
              + b"\0" * 16 + b"\0" * 28)
    assert len(header) == 128
    return header + bytes(table) + bytes(data)
