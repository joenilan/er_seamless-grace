#!/usr/bin/env python3
"""Grace patcher — SIGFIX #1 (build 2, raw-file offsets).

Installs an entry detour on the signature-scan function (RVA 0xd4d80) inside
ersc.dll. The detour jumps to a code cave in .text tail padding which rewrites
the dead pattern text 'E8 ? ?? ?? ?? 48 8B 15 ? ?? ?? ?? 48 8D 4B 20'
(45 bytes, std::string_view {data@0, size@8}) to '... 48 8D 47 20' before the
scan parses it. Everything else untouched.
"""
import pefile, struct, sys, os

SRC = r"E:\git\ersc-re\dist\SeamlessCoop\ersc.dll"
OUT = r"E:\git\er-seamless-grace\build\ersc.dll"

SCAN_RVA = 0xd4d80
TEXT_RVA, TEXT_RAW, TEXT_VSIZE, TEXT_RAWSIZE = 0x1000, 0x400, 0x18c626, 0x18c800
BASE = 0x180000000

PAT = "E8 ? ?? ?? ?? 48 8B 15 ? ?? ?? ?? 48 8D 4B 20"
SIZE = len(PAT)          # 45
B_IDX = PAT.rfind("4B") + 1   # index of 'B' (41)
assert SIZE == 45 and PAT[B_IDX] == "B", (SIZE, B_IDX)

raw = bytearray(open(SRC, "rb").read())

def rva2raw(rva):
    assert TEXT_RVA <= rva < TEXT_RVA + TEXT_RAWSIZE
    return TEXT_RAW + (rva - TEXT_RVA)

# ---- cave: CC tail padding after VSize (RVA 0x18c626..0x18c800) ----
cave_rva = TEXT_RVA + TEXT_VSIZE + 0x10      # 0x18c636, margin after last fn
cave_raw = rva2raw(cave_rva)
CAVE_CAP = TEXT_RAWSIZE - (TEXT_VSIZE + 0x10)
print(f"cave RVA {hex(cave_rva)} VA {hex(BASE+cave_rva)} raw {hex(cave_raw)} cap {CAVE_CAP}")
assert all(b == 0xCC or b == 0x00 for b in raw[cave_raw:cave_raw+CAVE_CAP]), "cave not clean"

# ---- stub ----
e = bytes
s = bytearray()
s += e([0x48, 0x83, 0x7A, 0x08, SIZE])            # cmp qword [rdx+8], 45
j1 = len(s); s += e([0x75, 0x00])                 # jne done
s += e([0x48, 0x8B, 0x02])                        # mov rax, [rdx]
s += e([0x48, 0x85, 0xC0])                        # test rax, rax
j2 = len(s); s += e([0x74, 0x00])                 # je done
s += e([0x81, 0x38]) + b"E8 ?"                    # cmp dword [rax], 'E8 ?'
j3 = len(s); s += e([0x75, 0x00])                 # jne done
s += e([0x80, 0xB8]) + struct.pack("<I", B_IDX) + e([0x42])   # cmp byte [rax+41], 'B'
j4 = len(s); s += e([0x75, 0x00])                 # jne done
s += e([0xC6, 0x80]) + struct.pack("<I", B_IDX) + e([0x37])   # mov byte [rax+41], '7'
done = len(s)
for j in (j1, j2, j3, j4):
    s[j+1] = done - (j + 2)
s += bytes.fromhex("415741564155")                # push r15; push r14; push r13 (displaced)
s += e([0xFF, 0x25, 0, 0, 0, 0]) + struct.pack("<Q", BASE + SCAN_RVA + 6)  # jmp back
print(f"stub {len(s)} bytes (cap {CAVE_CAP})")
assert len(s) <= CAVE_CAP

# verify stub decodes cleanly
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md = Cs(CS_ARCH_X86, CS_MODE_64)
n = sum(1 for _ in md.disasm(bytes(s), BASE + cave_rva))
print(f"stub disassembles to {n} instructions")

# ---- entry detour (6 bytes over the 3 pushes) ----
entry_raw = rva2raw(SCAN_RVA)
orig = raw[entry_raw:entry_raw+6]
assert orig.hex() == "415741564155", f"unexpected prologue {orig.hex()}"
rel = cave_rva - (SCAN_RVA + 5)
detour = e([0xE9]) + struct.pack("<i", rel) + e([0x90])
raw[entry_raw:entry_raw+6] = detour
raw[cave_raw:cave_raw+len(s)] = s

os.makedirs(os.path.dirname(OUT), exist_ok=True)
open(OUT, "wb").write(raw)
print(f"\nwrote {OUT} ({len(raw)} bytes)")
print("detour:", detour.hex(), "@ raw", hex(entry_raw))
print("install: backup Game\\SeamlessCoop\\ersc.dll -> ersc.dll.vanilla.bak, copy this file in.")
