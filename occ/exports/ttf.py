# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 LabLynx, Inc.
"""Just enough TrueType for embedding a font in an archival PDF (PDF/A).

Font(path) reads the tables a PDF needs: units per em, the bounding box, ascent and descent, cap
height, the italic angle, the advance widths (hmtx), the Unicode-to-glyph map (cmap formats 4 and
12) and whether the font may be embedded (OS/2 fsType). subset(glyphs) writes a smaller font
program that keeps every glyph id where it was (so a PDF's CIDToGIDMap stays Identity) but empties
every glyph not used, after following composite glyphs to their parts, and drops the layout
tables a PDF does not read. Written from the OpenType specification's table layouts.
"""
import struct

KEEP = ("cmap", "cvt ", "fpgm", "glyf", "head", "hhea", "hmtx", "loca", "maxp", "name", "OS/2", "post", "prep")


class Font:
    def __init__(self, path):
        with open(path, "rb") as fh:
            self.data = fh.read()
        d = self.data
        n = struct.unpack(">H", d[4:6])[0]
        self.tables = {}
        for i in range(n):
            tag, _cs, off, ln = struct.unpack(">4sIII", d[12 + 16 * i: 28 + 16 * i])
            self.tables[tag.decode("latin-1")] = (off, ln)
        head = self._t("head")
        self.units = struct.unpack(">H", head[18:20])[0]
        self.bbox = struct.unpack(">hhhh", head[36:44])
        self.loca_long = struct.unpack(">h", head[50:52])[0] == 1
        hhea = self._t("hhea")
        self.ascent, self.descent = struct.unpack(">hh", hhea[4:8])
        n_hm = struct.unpack(">H", hhea[34:36])[0]
        self.num_glyphs = struct.unpack(">H", self._t("maxp")[4:6])[0]
        hmtx = self._t("hmtx")
        adv = [struct.unpack(">H", hmtx[4 * i: 4 * i + 2])[0] for i in range(n_hm)]
        self.advances = adv + [adv[-1]] * (self.num_glyphs - n_hm)
        os2 = self._t("OS/2")
        self.fs_type = struct.unpack(">H", os2[8:10])[0]
        ver = struct.unpack(">H", os2[0:2])[0]
        self.cap_height = struct.unpack(">h", os2[88:90])[0] if ver >= 2 and len(os2) >= 90 else self.ascent
        post = self._t("post")
        ia = struct.unpack(">i", post[4:8])[0]
        self.italic_angle = ia / 65536.0
        self.cmap = self._cmap()
        self.ps_name = self._name(6) or "Font"

    def _t(self, tag):
        off, ln = self.tables[tag]
        return self.data[off:off + ln]

    def _name(self, name_id):
        t = self._t("name")
        count, str_off = struct.unpack(">HH", t[2:6])
        for i in range(count):
            pid, eid, _lid, nid, ln, off = struct.unpack(">HHHHHH", t[6 + 12 * i: 18 + 12 * i])
            if nid != name_id:
                continue
            raw = t[str_off + off: str_off + off + ln]
            return raw.decode("utf-16-be") if pid in (0, 3) else raw.decode("latin-1")
        return None

    def _cmap(self):
        t = self._t("cmap")
        n = struct.unpack(">H", t[2:4])[0]
        best = None
        for i in range(n):
            pid, eid, off = struct.unpack(">HHI", t[4 + 8 * i: 12 + 8 * i])
            fmt = struct.unpack(">H", t[off:off + 2])[0]
            if (pid, eid, fmt) in ((3, 10, 12), (0, 4, 12)):
                best = (off, 12)
                break
            if fmt == 4 and (pid, eid) in ((3, 1), (0, 3)) and best is None:
                best = (off, 4)
        out = {}
        if best is None:
            return out
        off, fmt = best
        if fmt == 12:
            ngroups = struct.unpack(">I", t[off + 12: off + 16])[0]
            for g in range(ngroups):
                start, end, gid = struct.unpack(">III", t[off + 16 + 12 * g: off + 28 + 12 * g])
                for cp in range(start, end + 1):
                    out[cp] = gid + (cp - start)
            return out
        segx2 = struct.unpack(">H", t[off + 6: off + 8])[0]
        seg = segx2 // 2
        ends = struct.unpack(">%dH" % seg, t[off + 14: off + 14 + segx2])
        starts = struct.unpack(">%dH" % seg, t[off + 16 + segx2: off + 16 + 2 * segx2])
        deltas = struct.unpack(">%dh" % seg, t[off + 16 + 2 * segx2: off + 16 + 3 * segx2])
        ro_pos = off + 16 + 3 * segx2
        ranges = struct.unpack(">%dH" % seg, t[ro_pos: ro_pos + segx2])
        for i in range(seg):
            for cp in range(starts[i], ends[i] + 1):
                if cp == 0xFFFF:
                    continue
                if ranges[i] == 0:
                    gid = (cp + deltas[i]) & 0xFFFF
                else:
                    pos = ro_pos + 2 * i + ranges[i] + 2 * (cp - starts[i])
                    gid = struct.unpack(">H", t[pos:pos + 2])[0]
                    if gid:
                        gid = (gid + deltas[i]) & 0xFFFF
                if gid:
                    out[cp] = gid
        return out

    @property
    def embeddable(self):
        """OS/2 fsType: 0 installable, 4 preview and print, 8 editable; 2 forbids embedding."""
        return not (self.fs_type & 0x0002) or bool(self.fs_type & 0x000C)

    def width(self, gid):
        return self.advances[gid] * 1000.0 / self.units

    def scale(self, v):
        return int(round(v * 1000.0 / self.units))

    # ------------------------------------------------------------------ subsetting
    def _glyph_ranges(self):
        loca = self._t("loca")
        if self.loca_long:
            offs = struct.unpack(">%dI" % (self.num_glyphs + 1), loca[:4 * (self.num_glyphs + 1)])
        else:
            offs = [2 * x for x in struct.unpack(">%dH" % (self.num_glyphs + 1), loca[:2 * (self.num_glyphs + 1)])]
        return offs

    def _components(self, glyph):
        if len(glyph) < 10 or struct.unpack(">h", glyph[:2])[0] >= 0:
            return []
        out, pos = [], 10
        while True:
            flags, gid = struct.unpack(">HH", glyph[pos:pos + 4])
            out.append(gid)
            pos += 4 + (4 if flags & 0x0001 else 2)
            if flags & 0x0008:
                pos += 2
            elif flags & 0x0040:
                pos += 4
            elif flags & 0x0080:
                pos += 8
            if not flags & 0x0020:
                return out

    def subset(self, glyphs):
        glyf = self._t("glyf")
        offs = self._glyph_ranges()
        keep = set(glyphs) | {0}
        todo = list(keep)
        while todo:
            g = todo.pop()
            for c in self._components(glyf[offs[g]:offs[g + 1]]):
                if c not in keep and c < self.num_glyphs:
                    keep.add(c)
                    todo.append(c)
        new_glyf = bytearray()
        new_loca = []
        for g in range(self.num_glyphs):
            new_loca.append(len(new_glyf))
            if g in keep:
                new_glyf += glyf[offs[g]:offs[g + 1]]
                while len(new_glyf) % 4:
                    new_glyf += b"\0"
        new_loca.append(len(new_glyf))
        tables = {}
        for tag in KEEP:
            if tag in self.tables:
                tables[tag] = self._t(tag)
        tables["glyf"] = bytes(new_glyf)
        tables["loca"] = struct.pack(">%dI" % len(new_loca), *new_loca)
        head = bytearray(tables["head"])
        head[8:12] = b"\0\0\0\0"                    # checkSumAdjustment, recomputed below
        head[50:52] = struct.pack(">h", 1)          # long loca offsets
        tables["head"] = bytes(head)
        return _write_sfnt(tables)


def _checksum(b):
    b = b + b"\0" * (-len(b) % 4)
    return sum(struct.unpack(">%dI" % (len(b) // 4), b)) & 0xFFFFFFFF


def _write_sfnt(tables):
    tags = sorted(tables)
    n = len(tags)
    es = max(i for i in range(16) if (1 << i) <= n)
    sr = (1 << es) * 16
    out = bytearray(struct.pack(">IHHHH", 0x00010000, n, sr, es, n * 16 - sr))
    offset = 12 + 16 * n
    body = bytearray()
    dirs = []
    for t in tags:
        data = tables[t]
        dirs.append(struct.pack(">4sIII", t.encode("latin-1"), _checksum(data), offset + len(body), len(data)))
        body += data + b"\0" * (-len(data) % 4)
    out += b"".join(dirs) + body
    adj = (0xB1B0AFBA - _checksum(bytes(out))) & 0xFFFFFFFF
    hpos = offset + sum(len(tables[t]) + (-len(tables[t]) % 4) for t in tags[:tags.index("head")])
    out[hpos + 8: hpos + 12] = struct.pack(">I", adj)
    return bytes(out)
