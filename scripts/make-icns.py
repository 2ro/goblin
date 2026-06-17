#!/usr/bin/env python3
"""Build a macOS .icns from a square PNG, dependency-free.

macOS has `iconutil` and Linux distros have `png2icns`, but neither is reliably
present, and ImageMagick's own .icns writer only emits a single size. So we
assemble the multi-resolution PNG-payload .icns container by hand (the format
macOS 10.7+ accepts): the `icns` magic + big-endian length, then one entry per
OSType, each carrying an 8-bit PNG. ImageMagick (`magick`) does the resizing.

Usage: make-icns.py <source.png> <out.icns>
"""

import struct
import subprocess
import sys

# OSType -> pixel size. PNG-payload entries. Sizes above the source are
# Lanczos-upscaled (soft but acceptable for the few large Dock/Finder slots).
SLOTS = [
    (b"icp4", 16),
    (b"icp5", 32),
    (b"icp6", 64),
    (b"ic07", 128),
    (b"ic08", 256),
    (b"ic11", 32),   # 16@2x
    (b"ic12", 64),   # 32@2x
    (b"ic13", 256),  # 128@2x
    (b"ic09", 512),  # 512
    (b"ic14", 512),  # 256@2x
]


def render(src, size):
    out = "/tmp/_icns_%d.png" % size
    subprocess.run(
        ["magick", src, "-resize", "%dx%d" % (size, size),
         "-filter", "Lanczos", "-depth", "8", "PNG32:%s" % out],
        check=True,
    )
    return open(out, "rb").read()


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: make-icns.py <source.png> <out.icns>")
    src, out = sys.argv[1], sys.argv[2]
    cache, entries = {}, []
    for ostype, size in SLOTS:
        if size not in cache:
            cache[size] = render(src, size)
        data = cache[size]
        entries.append(ostype + struct.pack(">I", 8 + len(data)) + data)
    body = b"".join(entries)
    with open(out, "wb") as f:
        f.write(b"icns" + struct.pack(">I", 8 + len(body)) + body)
    print("wrote %s (%d entries)" % (out, len(entries)))


if __name__ == "__main__":
    main()
