#!/usr/bin/env python3
"""Grace patcher v6 — SIGFIX #1 + #2. Both patterns via [rdx] heap indirection."""
import pefile, struct, os

SRC = r"E:\git\ersc-re\dist\SeamlessCoop\ersc.dll"
OUT = r"E:\git\er-seamless-grace\build\ersc.dll"
SCAN_RVA = 0xd4d80
TEXT_RVA, TEXT_RAW, TEXT_VSIZE, TEXT_RAWSIZE = 0x1000, 0x400, 0x18c626, 0x18c800
BASE = 0x180000000

DEAD1 = bytes.fromhex("e8" + "00000000" + "488b15" + "00000000" + "488d4b20")
Q1A = struct.unpack("<Q", DEAD1[0:8])[0]
Q1B = struct.unpack("<Q", DEAD1[8:16])[0]
DEAD2 = bytes.fromhex("80b9b54a00000000")
Q2A = struct.unpack("<Q", DEAD2)[0]

raw = bytearray(open(SRC, "rb").read())
def rva2raw(rva):
    return TEXT_RAW + (rva - TEXT_RVA)
cave_rva = TEXT_RVA + TEXT_VSIZE + 0x10
cave_raw = rva2raw(cave_rva)
CAVE_CAP = TEXT_RAWSIZE - (TEXT_VSIZE + 0x10)
assert all(b in (0xCC, 0x00) for b in raw[cave_raw:cave_raw+CAVE_CAP])

e = bytes
s = bytearray()
s += e([0x48, 0x85, 0xD2])                    # test rdx, rdx
j = len(s); s += e([0x74, 0x00]); j0 = j
s += e([0x48, 0x8B, 0x02])                    # rax = [rdx] (heap data ptr)
s += e([0x48, 0x85, 0xC0])
j = len(s); s += e([0x74, 0x00]); j1 = j
# branch A: E8 16-byte binary pattern
s += e([0x49, 0xBA]) + struct.pack("<Q", Q1A)
s += e([0x4C, 0x39, 0x10])                    # cmp [rax], r10
j = len(s); s += e([0x75, 0x00]); jA = j
s += e([0x49, 0xBA]) + struct.pack("<Q", Q1B)
s += e([0x4C, 0x39, 0x50, 0x08])              # cmp [rax+8], r10
j = len(s); s += e([0x75, 0x00]); jA1 = j
s += e([0xC6, 0x80]) + struct.pack("<I", 14) + e([0x4F])   # mov byte [rax+14], 0x4F
s += e([0xEB]) + b"\x00"; jADONE = len(s) - 1
# branch B: 8-byte cmp pattern (same heap indirection)
s += e([0x49, 0xBA]) + struct.pack("<Q", Q2A)
s += e([0x4C, 0x39, 0x10])                    # cmp [rax], r10
j = len(s); s += e([0x75, 0x00]); jB = j
s += e([0x66, 0xC7, 0x40, 0x02, 0x77, 0x4A])  # mov word [rax+2], 0x4A77
done = len(s)
for jx in (j0, j1, jA, jA1, jB):
    s[jx+1] = done - (jx + 2)
s[jADONE] = done - (jADONE + 1)
s += bytes.fromhex("415741564155")
s += e([0xFF, 0x25, 0, 0, 0, 0]) + struct.pack("<Q", BASE + SCAN_RVA + 6)
print(f"stub {len(s)} bytes (cap {CAVE_CAP})")
assert len(s) <= CAVE_CAP

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md = Cs(CS_ARCH_X86, CS_MODE_64)
n = sum(1 for _ in md.disasm(bytes(s), BASE + cave_rva))
print(f"disassembles: {n} instructions")

entry_raw = rva2raw(SCAN_RVA)
assert raw[entry_raw:entry_raw+6].hex() == "415741564155"
rel = cave_rva - (SCAN_RVA + 5)
raw[entry_raw:entry_raw+6] = e([0xE9]) + struct.pack("<i", rel) + e([0x90])
raw[cave_raw:cave_raw+len(s)] = s
os.makedirs(os.path.dirname(OUT), exist_ok=True)
open(OUT, "wb").write(raw)
print(f"wrote {OUT}")
