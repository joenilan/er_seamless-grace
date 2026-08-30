#!/usr/bin/env python3
"""peaddr — convert eldenring.exe file offsets <-> VAs, and disassemble around a site.

Usage:
  python peaddr.py 0x1181f23            # offset -> VA + disasm context
  python peaddr.py --va 0x141182923     # VA -> offset
"""
import argparse, sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE = r"E:\SteamLibrary\steamapps\common\ELDEN RING\Game\eldenring.exe"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("addr")
    ap.add_argument("--va", action="store_true", help="input is a VA, not a file offset")
    ap.add_argument("--exe", default=EXE)
    ap.add_argument("--context", type=int, default=48)
    args = ap.parse_args()

    pe = pefile.PE(args.exe)
    base = pe.OPTIONAL_HEADER.ImageBase
    data = open(args.exe, "rb").read()

    secs = [(s.PointerToRawData, s.PointerToRawData + s.SizeOfRawData,
             base + s.VirtualAddress, s.Name.decode().rstrip("\x00")) for s in pe.sections]

    if args.va:
        va = int(args.addr, 0)
        for lo, hi, sva, nm in secs:
            if sva <= va < sva + (hi - lo):
                off = lo + (va - sva)
                break
        else:
            sys.exit(f"VA {hex(va)} not in any section")
    else:
        off = int(args.addr, 0)
        for lo, hi, sva, nm in secs:
            if lo <= off < hi:
                va = sva + (off - lo)
                nm_ = nm
                break
        else:
            sys.exit(f"offset {hex(off)} not in any section")

    print(f"file offset {hex(off)}  <->  VA {hex(va)}")

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    start = max(0, off - args.context)
    print(f"--- disasm ({hex(start)} .. {hex(off + args.context)}) ---")
    # disasm forward from the target address for reliable output
    for i in md.disasm(data[off:off + args.context], va):
        print(f"  {hex(i.address)}: {i.mnemonic} {i.op_str}")

if __name__ == "__main__":
    main()
