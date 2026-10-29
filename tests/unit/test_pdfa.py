# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""PDF/A-2b and its parts: embedded and subset fonts whose license allows
it, widths that match the font program, a ToUnicode map, an sRGB output intent, XMP metadata that
agrees with the document information, and a file identifier. When OCC_VERAPDF names an installed
veraPDF (the PDF Association's validator, GPL/MPL: run here, never shipped), the file must pass its
PDF/A-2B profile as well."""
import os
import re
import struct
import subprocess
import zlib

import pytest

from occ.exports import icc, pdf, ttf

VERAPDF = os.environ.get("OCC_VERAPDF")


def _doc():
    d = pdf.Document(title="Résumé — αβγ Ж", author="Alice Test", subject="test", archival=True)
    d.heading("Heading with ü, €, ✓ and 漢")          # 漢 is not in DejaVu Sans: it prints as '?'
    d.field("Date", "2026-10-28")
    d.paragraph("Plain paragraph. " * 60)
    return d, d.bytes()


def _streams(data):
    for m in re.finditer(rb"<<([^>]*?/Filter /FlateDecode[^>]*?)>>\nstream\n", data):
        n = int(re.search(rb"/Length (\d+)", m.group(1)).group(1))
        yield m.group(1), zlib.decompress(data[m.end():m.end() + n])


def test_the_font_files_and_their_license_are_there():
    for name in pdf.FONT_FILES.values():
        f = ttf.Font(os.path.join(pdf.FONT_DIR, name))
        assert f.embeddable and f.cmap.get(ord("A")) and f.units == 2048
    lic = open(os.path.join(pdf.FONT_DIR, "LICENSE-DejaVu"), encoding="utf-8").read()
    assert "bitstream-vera" in lic and "Permission is hereby granted" in lic


def test_pdfa_structure():
    d, data = _doc()
    assert data.startswith(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3")
    assert b"/OutputIntents [" in data and b"/S /GTS_PDFA1" in data
    assert b"<pdfaid:part>2</pdfaid:part><pdfaid:conformance>B</pdfaid:conformance>" in data
    assert re.search(rb"/ID \[<[0-9A-F]{32}> <[0-9A-F]{32}>\]", data)
    assert b"/Type1" not in data and b"/Helvetica" not in data                # nothing left unembedded
    assert data.count(b"/Subtype /CIDFontType2") == 2 and data.count(b"/FontFile2") == 2
    assert data.count(b"/ToUnicode") == 2
    # subset: the embedded programs are much smaller than the whole fonts
    programs = [zlib.decompress(data[m.end():m.end() + int(m.group(1))])
                for m in re.finditer(rb"/Length (\d+) /Length1 \d+ /Filter /FlateDecode >>\nstream\n", data)]
    assert len(programs) == 2 and all(len(p) < 200000 for p in programs)
    # the widths written agree with the font program
    f = d.fonts.fonts[False]
    w = re.search(rb"/BaseFont /[A-Z]{6}\+DejaVuSans /CIDSystemInfo .*?/W \[([^\]]*(?:\][^\]]*)*?)\] /CIDToGIDMap", data)
    pairs = re.findall(rb"(\d+) \[(\d+)\]", w.group(1))
    assert pairs and all(int(wd) == int(round(f.width(int(g)))) for g, wd in pairs)
    # the character the font lacks became '?', never the .notdef glyph
    q = f.cmap[ord("?")]
    for _head, body in _streams(data):
        for hexstr in re.findall(rb"<([0-9A-F]+)> Tj", body):
            gids = [int(hexstr[i:i + 4], 16) for i in range(0, len(hexstr), 4)]
            assert 0 not in gids
    assert q in d.fonts.used[True]
    # the ICC profile is well formed: its size field, class, colour space and signature
    prof = icc.srgb()
    assert struct.unpack(">I", prof[:4])[0] == len(prof) and prof[12:20] == b"mntrRGB " and prof[36:40] == b"acsp"


def test_plain_pdf_is_unchanged_in_kind():
    d = pdf.Document(title="plain")
    d.paragraph("hello")
    data = d.bytes()
    assert data.startswith(b"%PDF-1.4") and b"/Helvetica" in data and b"/OutputIntents" not in data


@pytest.mark.skipif(not VERAPDF, reason="OCC_VERAPDF does not name an installed veraPDF")
def test_verapdf_passes_the_pdfa_2b_profile(tmp_path):
    from occ.exports import render
    _d, data = _doc()
    rec = {"title": "Batch 7 — Ölprobe", "type": "experiments", "date": "2026-10-28", "fullname": "Alice Test",
           "tags": "a|b", "body": "<p>Body with <b>bold</b> and ✓</p>", "steps": [{"body": "step", "finished": 1}],
           "comments": [{"fullname": "Bob", "created_at": "2026-10-28 10:00:00", "comment": "Looks good"}],
           "uploads": [{"real_name": "x.csv", "filesize": 3, "hash": "ab" * 32}],
           "changelog": [{"created_at": "2026-10-28", "fullname": "Alice", "target": "title", "content": "x"}],
           "metadata": '{"extra_fields": {"Yield": {"value": "42", "unit": "%"}}}'}
    for name, blob in (("a.pdf", data), ("record.pdf", render.to_pdf([rec, rec], "Two records", True))):
        f = tmp_path / name
        f.write_bytes(blob)
        r = subprocess.run([VERAPDF, "--format", "text", "--flavour", "2b", str(f)], capture_output=True, text=True,
                           timeout=300)
        assert r.stdout.startswith("PASS"), r.stdout + r.stderr
