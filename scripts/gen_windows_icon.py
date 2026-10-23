#!/usr/bin/env python3
"""Regenerate the sec-portable Windows icon (cmd/portable/icon.ico) and the
linker resource cmd/portable/rsrc_windows_amd64.syso. Pure standard library;
Go picks the .syso up automatically for windows/amd64 builds."""
import os
import struct
import zlib

SIZES = (256, 48, 32, 16)
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "cmd", "portable")


def inside_round_rect(x, y, size, radius):
    cx = min(max(x, radius), size - radius)
    cy = min(max(y, radius), size - radius)
    return (x - cx) ** 2 + (y - cy) ** 2 <= radius * radius


def sample(u, v):
    """Colour at unit-square point (u, v) as (r, g, b, a) or None."""
    if not inside_round_rect(u, v, 1.0, 0.22):
        return None
    top, bottom = (37, 99, 235), (29, 58, 138)
    r, g, b = (int(top[i] + (bottom[i] - top[i]) * v) for i in range(3))
    # white play triangle: the "click to start" cue
    x0, x1, y0, y1 = 0.36, 0.72, 0.26, 0.74
    if x0 <= u <= x1:
        half = (y1 - y0) / 2 * (1 - (u - x0) / (x1 - x0))
        if abs(v - 0.5) <= half:
            return (255, 255, 255, 255)
    return (r, g, b, 255)


def render(size, ss=4):
    rows = []
    for py in range(size):
        row = bytearray([0])
        for px in range(size):
            acc = [0, 0, 0, 0]
            for sy in range(ss):
                for sx in range(ss):
                    c = sample((px + (sx + .5) / ss) / size, (py + (sy + .5) / ss) / size)
                    if c:
                        a = c[3]
                        acc[0] += c[0] * a; acc[1] += c[1] * a; acc[2] += c[2] * a; acc[3] += a
            n = ss * ss
            if acc[3]:
                row += bytes((acc[0] // acc[3], acc[1] // acc[3], acc[2] // acc[3], acc[3] // n))
            else:
                row += bytes(4)
        rows.append(bytes(row))
    raw = b"".join(rows)

    def chunk(tag, data):
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def ico(images):
    head = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, blobs = b"", b""
    for size, png in images:
        entries += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(png), offset + len(blobs))
        blobs += png
    return head + entries + blobs


def group_icon(images):
    data = struct.pack("<HHH", 0, 1, len(images))
    for i, (size, png) in enumerate(images, 1):
        data += struct.pack("<BBBBHHIH", size % 256, size % 256, 0, 0, 1, 32, len(png), i)
    return data


def syso(images):
    """COFF object holding RT_ICON entries and one RT_GROUP_ICON (id 1)."""
    resources = [(3, i, png) for i, (_, png) in enumerate(images, 1)] + [(14, 1, group_icon(images))]
    types = {}
    for rtype, rid, data in resources:
        types.setdefault(rtype, []).append((rid, data))

    def directory(entries):  # entries: [(id, offset_or_subdir_flagged)]
        out = struct.pack("<IIHHHH", 0, 0, 0, 0, 0, len(entries))
        for ident, target in entries:
            out += struct.pack("<II", ident, target)
        return out

    # layout: root | per-type dirs | per-name dirs | per-lang dirs | data entries | data
    root_size = 16 + 8 * len(types)
    type_dir_sizes = {t: 16 + 8 * len(v) for t, v in types.items()}
    cursor = root_size
    type_offsets = {}
    for t in types:
        type_offsets[t] = cursor
        cursor += type_dir_sizes[t]
    name_offsets = {}
    for t, items in types.items():
        for rid, _ in items:
            name_offsets[(t, rid)] = cursor
            cursor += 16 + 8
    entry_offsets = {}
    for t, items in types.items():
        for rid, _ in items:
            entry_offsets[(t, rid)] = cursor
            cursor += 16
    data_offsets = {}
    for t, items in types.items():
        for rid, data in items:
            data_offsets[(t, rid)] = cursor
            cursor += (len(data) + 3) & ~3
    total = cursor

    buf = bytearray(total)
    buf[0:root_size] = directory([(t, 0x80000000 | type_offsets[t]) for t in types])
    for t, items in types.items():
        o = type_offsets[t]
        buf[o:o + type_dir_sizes[t]] = directory([(rid, 0x80000000 | name_offsets[(t, rid)]) for rid, _ in items])
        for rid, data in items:
            buf[name_offsets[(t, rid)]:name_offsets[(t, rid)] + 24] = directory([(0x0409, entry_offsets[(t, rid)])])
            buf[entry_offsets[(t, rid)]:entry_offsets[(t, rid)] + 16] = struct.pack(
                "<IIII", data_offsets[(t, rid)], len(data), 0, 0)
            buf[data_offsets[(t, rid)]:data_offsets[(t, rid)] + len(data)] = data

    relocs = b"".join(struct.pack("<IIH", entry_offsets[k], 0, 3) for k in entry_offsets)  # IMAGE_REL_AMD64_ADDR32NB
    raw_ptr = 20 + 40
    reloc_ptr = raw_ptr + total
    sym_ptr = reloc_ptr + len(relocs)
    header = struct.pack("<HHIIIHH", 0x8664, 1, 0, sym_ptr, 1, 0, 0)
    section = struct.pack("<8sIIIIIIHHI", b".rsrc", 0, 0, total, raw_ptr, reloc_ptr, 0,
                          len(entry_offsets), 0, 0xC0300040)
    symbol = struct.pack("<8sIhHBB", b".rsrc", 0, 1, 0, 3, 0)
    return header + section + bytes(buf) + relocs + symbol + struct.pack("<I", 4)


def main():
    images = [(s, render(s)) for s in SIZES]
    with open(os.path.join(OUT, "icon.ico"), "wb") as f:
        f.write(ico(images))
    with open(os.path.join(OUT, "rsrc_windows_amd64.syso"), "wb") as f:
        f.write(syso(images))


if __name__ == "__main__":
    main()
