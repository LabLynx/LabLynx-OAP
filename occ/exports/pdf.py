# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""A small PDF writer for record exports (the OCC's own layout, the same content as 2.x).

Two forms, one layout:
  * PDF (archival=False): PDF 1.4 with the standard Helvetica fonts every PDF reader carries, so it
    needs no runtime package (WeasyPrint was the obvious choice, but its hyphenation
    dependency is not under a permissive license). Text is set in WinAnsi (Latin-1); a character
    outside it is written as '?'.
  * PDF/A-2b (archival=True): the fonts are embedded (DejaVu Sans and DejaVu Sans
    Bold, Bitstream Vera license, kept in exports/fonts with their license) as CIDFontType2 with
    Identity-H, subset to the glyphs used, with widths and a ToUnicode map; an sRGB output intent
    (exports/icc.py); XMP metadata naming PDF/A-2 conformance B and matching the document
    information; a file identifier in the trailer. Any character the font has prints; one it
    lacks prints as '?'.

    doc = Document(title="...", archival=True)
    doc.heading("Title"); doc.field("Date", "2026-10-28"); doc.paragraph("text ..."); data = doc.bytes()
"""
import datetime as dt
import hashlib
import os
import zlib

from . import icc, ttf

PAGE_W, PAGE_H = 595.28, 841.89        # A4 in points
MARGIN = 50
BODY = 10
LINE = 13
FONT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts")
FONT_FILES = {"F1": "DejaVuSans.ttf", "F2": "DejaVuSans-Bold.ttf"}

# Helvetica advance widths (per 1000 em) for printable ASCII 32..126; others use 556.
_W = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556,
      556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667,
      556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556,
      556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722,
      500, 500, 500, 334, 260, 334, 584]


def text_width(s, size, bold=False):
    w = sum(_W[ord(ch) - 32] if 32 <= ord(ch) <= 126 else 556 for ch in s)
    return w * size / 1000.0 * (1.06 if bold else 1.0)


def _latin1(s):
    return "".join(ch if ord(ch) < 256 and (ch >= " " or ch == "\t") else "?" for ch in str(s).replace("\t", "    "))


def _esc(s):
    return _latin1(s).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _clean(s):
    return "".join(ch for ch in str(s).replace("\t", "    ") if ch >= " " and ch != "\x7f")


class StandardFonts:
    """Helvetica and Helvetica-Bold, WinAnsi."""

    def width(self, s, size, bold=False):
        return text_width(s, size, bold)

    def show(self, s, bold=False):
        return "(%s)" % _esc(s)


_FONT_CACHE = {}


def _font(name):
    if name not in _FONT_CACHE:
        _FONT_CACHE[name] = ttf.Font(os.path.join(FONT_DIR, name))
    return _FONT_CACHE[name]


class EmbeddedFonts:
    """DejaVu Sans (F1) and Bold (F2); glyph ids are written as 2-byte CIDs (Identity-H)."""

    def __init__(self):
        self.fonts = {False: _font(FONT_FILES["F1"]), True: _font(FONT_FILES["F2"])}
        self.used = {False: {}, True: {}}            # gid -> the text it stands for (ToUnicode)

    def _gid(self, font, ch):
        g = font.cmap.get(ord(ch))
        return g if g else font.cmap.get(ord("?"), 0)

    def width(self, s, size, bold=False):
        f = self.fonts[bold]
        return sum(f.width(self._gid(f, ch)) for ch in _clean(s)) * size / 1000.0

    def show(self, s, bold=False):
        f = self.fonts[bold]
        out = []
        for ch in _clean(s):
            g = self._gid(f, ch)
            self.used[bold].setdefault(g, ch if f.cmap.get(ord(ch)) else "?")
            out.append("%04X" % g)
        return "<%s>" % "".join(out)


def wrap(text, width, size, bold=False, fonts=None):
    measure = (fonts.width if fonts else text_width)
    out = []
    for para in str(text or "").split("\n"):
        words = para.split(" ")
        line = ""
        for w in words:
            cand = (line + " " + w) if line else w
            if measure(cand, size, bold) <= width:
                line = cand
                continue
            if line:
                out.append(line)
            while measure(w, size, bold) > width:          # a single word longer than the line
                cut = len(w)
                while cut > 1 and measure(w[:cut], size, bold) > width:
                    cut -= 1
                out.append(w[:cut])
                w = w[cut:]
            line = w
        out.append(line)
    return out


class Document:
    def __init__(self, title="", author="", subject="", archival=False):
        self.info = {"Title": title, "Author": author, "Subject": subject, "Producer": "LabLynx.One OCC"}
        self.archival = archival
        self.fonts = EmbeddedFonts() if archival else StandardFonts()
        self.pages = []
        self._ops = None
        self._y = 0
        self._new_page()

    def _new_page(self):
        self._ops = []
        self.pages.append(self._ops)
        self._y = PAGE_H - MARGIN

    def _need(self, h):
        if self._y - h < MARGIN:
            self._new_page()

    def _text(self, font, size, gray, x, y, text):
        return "BT /%s %g Tf %g g %.2f %.2f Td %s Tj ET" % (font, size, gray, x, y, self.fonts.show(text, font == "F2"))

    def _line(self, text, size=BODY, bold=False, x=MARGIN, gray=0):
        self._need(size + 3)
        self._y -= size + 3
        self._ops.append(self._text("F2" if bold else "F1", size, gray, x, self._y, text))

    def heading(self, text, size=16):
        for ln in wrap(text, PAGE_W - 2 * MARGIN, size, True, self.fonts):
            self._line(ln, size, True)
        self.space(4)

    def subheading(self, text):
        self.space(6)
        self._line(text, 12, True)
        self._need(4)
        self._ops.append("0.6 G 0.5 w %.2f %.2f m %.2f %.2f l S" % (MARGIN, self._y - 2, PAGE_W - MARGIN, self._y - 2))
        self._y -= 6

    def field(self, label, value):
        label = "%s: " % label
        lw = self.fonts.width(label, BODY, True)
        lines = wrap(value if value not in (None, "") else "-", PAGE_W - 2 * MARGIN - lw, BODY, fonts=self.fonts)
        self._need(LINE)
        self._y -= LINE
        self._ops.append(self._text("F2", BODY, 0, MARGIN, self._y, label))
        self._ops.append(self._text("F1", BODY, 0, MARGIN + lw, self._y, lines[0]))
        for ln in lines[1:]:
            self._line(ln, BODY, x=MARGIN + lw)

    def paragraph(self, text, size=BODY, gray=0):
        for ln in wrap(text, PAGE_W - 2 * MARGIN, size, fonts=self.fonts):
            self._line(ln, size, gray=gray)

    def space(self, h=LINE / 2):
        self._y -= h

    # ------------------------------------------------------------------ writing
    def bytes(self):
        objs = []                                         # object n is objs[n - 1]

        def add(body):
            objs.append(body)
            return len(objs)

        catalog = add(None)
        pages_id = add(None)
        total = len(self.pages)
        streams = []
        for n, ops in enumerate(self.pages, 1):
            footer = self._text("F1", 8, 0.4, MARGIN, MARGIN / 2, "%s - page %d of %d" % (self.info["Title"][:80], n, total))
            streams.append(("\n".join(ops + [footer])).encode("latin-1"))
        if self.archival:
            f1 = self._type0(add, False)
            f2 = self._type0(add, True)
        else:
            f1 = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
            f2 = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
        kids = []
        for raw in streams:
            data = zlib.compress(raw)
            cid = add(b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(data) + data + b"\nendstream")
            kids.append(add(("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %.2f %.2f] /Resources << /Font << /F1 %d 0 R "
                             "/F2 %d 0 R >> >> /Contents %d 0 R >>" % (pages_id, PAGE_W, PAGE_H, f1, f2, cid)).encode()))
        objs[pages_id - 1] = ("<< /Type /Pages /Kids [%s] /Count %d >>"
                              % (" ".join("%d 0 R" % k for k in kids), len(kids))).encode()
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        pdf_date = now.strftime("D:%Y%m%d%H%M%S+00'00'")
        info_items = [(k, v) for k, v in self.info.items() if v]
        if self.archival:
            meta = add(self._xmp_stream(info_items, now))
            profile = icc.srgb()
            prof = add(b"<< /N 3 /Length %d >>\nstream\n" % len(profile) + profile + b"\nendstream")
            intent = add(("<< /Type /OutputIntent /S /GTS_PDFA1 /OutputConditionIdentifier (sRGB IEC61966-2.1) "
                          "/Info (sRGB IEC61966-2.1) /DestOutputProfile %d 0 R >>" % prof).encode())
            objs[catalog - 1] = ("<< /Type /Catalog /Pages %d 0 R /Metadata %d 0 R /OutputIntents [%d 0 R] >>"
                                 % (pages_id, meta, intent)).encode()
            info = add(("<< %s /CreationDate (%s) /ModDate (%s) >>" % (
                " ".join("/%s %s" % (k, _utf16(v)) for k, v in info_items), pdf_date, pdf_date)).encode("latin-1"))
            header = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
        else:
            objs[catalog - 1] = ("<< /Type /Catalog /Pages %d 0 R >>" % pages_id).encode()
            info = add(("<< %s /CreationDate (%s) >>" % (" ".join("/%s (%s)" % (k, _esc(v)) for k, v in info_items),
                                                         now.strftime("D:%Y%m%d%H%M%SZ"))).encode("latin-1"))
            header = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
        out = bytearray(header)
        offsets = []
        for i, body in enumerate(objs, 1):
            offsets.append(len(out))
            out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
        xref = len(out)
        out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
        for off in offsets:
            out += b"%010d 00000 n \n" % off
        fid = hashlib.md5(bytes(out[:xref]) + pdf_date.encode()).hexdigest().upper().encode()   # noqa: S324 (an id)
        out += b"trailer\n<< /Size %d /Root %d 0 R /Info %d 0 R /ID [<%s> <%s>] >>\nstartxref\n%d\n%%%%EOF\n" % (
            len(objs) + 1, catalog, info, fid, fid, xref)
        return bytes(out)

    def _type0(self, add, bold):
        f = self.fonts.fonts[bold]
        used = self.fonts.used[bold]
        if not f.embeddable:
            raise ValueError("the font does not allow embedding")
        gids = sorted(set(used) | {0})
        program = f.subset(gids)
        data = zlib.compress(program)
        tag = "".join(chr(65 + (b % 26)) for b in hashlib.sha256(program).digest()[:6])
        name = "%s+%s" % (tag, f.ps_name)
        ff = add(b"<< /Length %d /Length1 %d /Filter /FlateDecode >>\nstream\n" % (len(data), len(program)) + data
                 + b"\nendstream")
        bbox = " ".join(str(f.scale(v)) for v in f.bbox)
        desc = add(("<< /Type /FontDescriptor /FontName /%s /Flags 32 /FontBBox [%s] /ItalicAngle %g /Ascent %d "
                    "/Descent %d /CapHeight %d /StemV %d /FontFile2 %d 0 R >>"
                    % (name, bbox, f.italic_angle, f.scale(f.ascent), f.scale(f.descent), f.scale(f.cap_height),
                       120 if bold else 80, ff)).encode())
        widths = " ".join("%d [%d]" % (g, int(round(f.width(g)))) for g in gids)
        cid = add(("<< /Type /Font /Subtype /CIDFontType2 /BaseFont /%s /CIDSystemInfo << /Registry (Adobe) "
                   "/Ordering (Identity) /Supplement 0 >> /FontDescriptor %d 0 R /DW %d /W [%s] /CIDToGIDMap /Identity >>"
                   % (name, desc, int(round(f.width(0))), widths)).encode())
        cmap = _to_unicode({g: used[g] for g in gids if g in used})
        cm = add(b"<< /Length %d >>\nstream\n" % len(cmap) + cmap + b"\nendstream")
        return add(("<< /Type /Font /Subtype /Type0 /BaseFont /%s /Encoding /Identity-H /DescendantFonts [%d 0 R] "
                    "/ToUnicode %d 0 R >>" % (name, cid, cm)).encode())

    def _xmp_stream(self, info_items, now):
        iso = now.strftime("%Y-%m-%dT%H:%M:%S+00:00")
        info = dict(info_items)
        x = ('<?xpacket begin="﻿" id="W5M0MpCehiHzreSzNTczkc9d"?>\n'
             '<x:xmpmeta xmlns:x="adobe:ns:meta/">\n'
             '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">\n'
             '<rdf:Description rdf:about="" xmlns:pdfaid="http://www.aiim.org/pdfa/ns/id/" '
             'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xmp="http://ns.adobe.com/xap/1.0/" '
             'xmlns:pdf="http://ns.adobe.com/pdf/1.3/">\n'
             '<pdfaid:part>2</pdfaid:part><pdfaid:conformance>B</pdfaid:conformance>\n'
             '<pdf:Producer>%s</pdf:Producer>\n'
             '<xmp:CreateDate>%s</xmp:CreateDate><xmp:ModifyDate>%s</xmp:ModifyDate>\n'
             % (_xml(info.get("Producer", "")), iso, iso))
        if info.get("Title"):
            x += '<dc:title><rdf:Alt><rdf:li xml:lang="x-default">%s</rdf:li></rdf:Alt></dc:title>\n' % _xml(info["Title"])
        if info.get("Author"):
            x += '<dc:creator><rdf:Seq><rdf:li>%s</rdf:li></rdf:Seq></dc:creator>\n' % _xml(info["Author"])
        if info.get("Subject"):
            x += ('<dc:description><rdf:Alt><rdf:li xml:lang="x-default">%s</rdf:li></rdf:Alt></dc:description>\n'
                  % _xml(info["Subject"]))
        x += '</rdf:Description>\n</rdf:RDF>\n</x:xmpmeta>\n<?xpacket end="w"?>'
        data = x.encode("utf-8")
        return b"<< /Type /Metadata /Subtype /XML /Length %d >>\nstream\n" % len(data) + data + b"\nendstream"


def _xml(s):
    s = _clean(s)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _utf16(s):
    """A PDF text string in UTF-16BE with its byte-order mark, as hex."""
    return "<FEFF%s>" % _clean(s).encode("utf-16-be").hex().upper()


def _to_unicode(mapping):
    lines = ["/CIDInit /ProcSet findresource begin", "12 dict begin", "begincmap",
             "/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def",
             "/CMapName /Adobe-Identity-UCS def", "/CMapType 2 def", "1 begincodespacerange", "<0000> <FFFF>",
             "endcodespacerange"]
    items = sorted(mapping.items())
    for i in range(0, len(items), 100):
        chunk = items[i:i + 100]
        lines.append("%d beginbfchar" % len(chunk))
        for g, ch in chunk:
            lines.append("<%04X> <%s>" % (g, ch.encode("utf-16-be").hex().upper()))
        lines.append("endbfchar")
    lines += ["endcmap", "CMapName currentdict /CMap defineresource pop", "end", "end"]
    return "\n".join(lines).encode("ascii")
