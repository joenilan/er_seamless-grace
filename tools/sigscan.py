#!/usr/bin/env python3
"""Grace sigscan — fuzz-scan an IDA-style AOB pattern against a PE (default: eldenring.exe).

Usage:
  python sigscan.py "E8 ? ?? ?? ?? 48 8B 15 ? ?? ?? ?? 48 8D 4B 20" [--exe PATH]

Reports match counts for the exact pattern plus progressively loosened
variants, with file offsets. Use tools/peaddr.py to convert offsets to VAs.
"""
import argparse, mmap, re, sys

def aob_to_regex(pat: str):
    rx = b""
    for t in pat.split(" "):
        rx += b"." if "?" in t else re.escape(bytes([int(t, 16)]))
    return re.compile(rx)

LOOSENings = [
    lambda p: p,                                   # exact
    lambda p: p.replace("48 8D 4B 20", "48 8D 4? 20"),   # lea reg nibble
    lambda p: p.replace("48 8D 4B 20", "48 8D 4B ??"),   # lea disp
    lambda p: p.replace("48 8B 15", "48 8B ??"),         # mov reg
    lambda p: p.replace("48 8B 15", "48 8B ??").replace("48 8D 4B 20", "48 8D 4? ??"),
]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pattern")
    ap.add_argument("--exe", default=r"E:\SteamLibrary\steamapps\common\ELDEN RING\Game\eldenring.exe")
    args = ap.parse_args()

    with open(args.exe, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    print(f"scanning {args.exe} ({len(mm)/1e6:.1f} MB)")

    for i, loos in enumerate(LOOSENings):
        pat = loos(args.pattern)
        if "?" not in pat.split(" ")[0] and "?" not in pat:
            pass
        rx = aob_to_regex(pat)
        hits = [m.start() for m in rx.finditer(mm)]
        label = "exact" if i == 0 else f"loose-{i}"
        print(f"{label:8} {len(hits):6d} matches  {pat[:80]}"
              + (f"  first: {[hex(h) for h in hits[:6]]}" if hits else ""))
        if i > 0 and len(hits) == 1:
            print(f"         ^ unique candidate — likely the moved site (file offset {hex(hits[0])})")

if __name__ == "__main__":
    main()
