#!/usr/bin/env python3
"""diffsite — given OLD and NEW eldenring.exe plus a failing AOB pattern,
find the old site, fingerprint it with surrounding unique code, and locate
the same function in the new exe. Reports the new pattern bytes.

Usage:
  python diffsite.py "80 B9 B5 0A 00 00 00" \
      --old <path-to-old-eldenring.exe> [--new <path-to-new-exe>]
"""
import argparse, re, sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

def aob_rx(pat):
    rx = b""
    for t in pat.split(" "):
        rx += b"." if "?" in t else __import__("re").escape(bytes([int(t, 16)]))
    return __import__("re").compile(rx, __import__("re").S)

def load(p):
    import mmap
    f = open(p, "rb")
    return mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ), pefile.PE(p)

def secmap(pe, base):
    out = []
    for s in pe.sections:
        out.append((s.PointerToRawData, s.PointerToRawData + s.SizeOfRawData,
                    base + s.VirtualAddress, s.Name.decode().rstrip("\x00")))
    return out

def off2va(secs, off):
    for lo, hi, va, nm in secs:
        if lo <= off < hi:
            return va + (off - lo), nm
    return None, None

def va2off(secs, va):
    for lo, hi, sva, nm in secs:
        if sva <= va < sva + (hi - lo):
            return lo + (va - sva), nm
    return None, None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pattern")
    ap.add_argument("--old", required=True)
    ap.add_argument("--new", default=r"E:\SteamLibrary\steamapps\common\ELDEN RING\Game\eldenring.exe")
    ap.add_argument("--before", type=int, default=96, help="context bytes before site for fingerprint")
    ap.add_argument("--after", type=int, default=96)
    args = ap.parse_args()

    mold, pold = load(args.old)
    mnew, pnew = load(args.new)
    bold = pold.OPTIONAL_HEADER.ImageBase
    bnew = pnew.OPTIONAL_HEADER.ImageBase
    sold = secmap(pold, bold)
    snew = secmap(pnew, bnew)
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    rx = aob_rx(args.pattern)
    olds = [m.start() for m in rx.finditer(mold)]
    print(f"old exe: pattern matches: {[hex(o) for o in olds]}")
    if not olds:
        sys.exit("pattern not found in old exe?!")

    news = [m.start() for m in rx.finditer(mnew)]
    print(f"new exe: exact pattern matches: {[hex(o) for o in news]}")

    for off in olds:
        va, nm = off2va(sold, off)
        if not va or nm != ".text":
            print(f"skip {hex(off)} ({nm}) — not .text")
            continue
        print(f"\n=== OLD site {hex(off)} (VA {hex(va)} in {nm}) ===")
        for i in md.disasm(mold[off:off+48], va):
            print(f"  {hex(i.address)}: {i.mnemonic} {i.op_str}")

        # fingerprint: take fixed byte windows before the site that are unique in old exe
        anchor = None
        for back in range(args.before, 16, -8):
            w = mold[off-back:off]
            if len(w) < 16 or b"\x00\x00\x00\x00\x00" in w:
                continue
            if len(re.findall(re.escape(w), mold)) == 1:
                anchor = (off-back, w)
                break
        if not anchor:
            print("  no unique before-context found — trying after-context")
            for fwd in range(32, args.after, 8):
                w = mold[off+8:off+8+fwd]
                if len(w) < 16 or b"\x00\x00\x00\x00\x00" in w:
                    continue
                if len(re.findall(re.escape(w), mold)) == 1:
                    anchor = (off+8, w)
                    break
        if not anchor:
            print("  no unique context window found; giving up on this site")
            continue
        apos, w = anchor
        delta = off - apos  # where the pattern sits relative to the window
        print(f"  fingerprint window @ {hex(apos)} len {len(w)} (pattern at +{delta})")

        nhits = [m.start() for m in __import__("re").finditer(__import__("re").escape(w), mnew)]
        print(f"  new exe: fingerprint matches: {[hex(h) for h in nhits]}")
        for nh in nhits:
            nsite = nh + delta
            nva, nnm = off2va(snew, nsite)
            print(f"  --- NEW candidate site {hex(nsite)} (VA {hex(nva) if nva else '?'}) ---")
            print(f"      new bytes: {mnew[nsite:nsite+len(args.pattern.split())].hex()}")
            for i in md.disasm(mnew[nsite:nsite+48], nva):
                print(f"      {hex(i.address)}: {i.mnemonic} {i.op_str}")
            return_bytes = mnew[nsite:nsite+len(args.pattern.split(" "))].hex(" ")
            print(f"      => NEW PATTERN BYTES: {return_bytes}")

if __name__ == "__main__":
    main()
