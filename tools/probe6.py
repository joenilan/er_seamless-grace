"""Grace probe 6 — locate the 80 B9 B5 4A 00 00 00 00 buffer in live memory."""
import ctypes, ctypes.wintypes as wt, sys, subprocess

psapi = ctypes.WinDLL("Psapi.dll")
k32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq eldenring.exe", "/FO", "CSV", "/NH"],
                     capture_output=True, text=True).stdout
pids = []
for line in out.strip().splitlines():
    parts = [p.strip('"') for p in line.split('","')]
    if len(parts) >= 2 and "eldenring" in parts[0].lower():
        pids.append(int(parts[1]))
if not pids:
    sys.exit("no process")
h = k32.OpenProcess(0x0410, False, pids[0])
if not h:
    sys.exit("OpenProcess failed")

def read(addr, n):
    data = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    if k32.ReadProcessMemory(h, ctypes.c_void_p(addr), data, n, ctypes.byref(got)):
        return data.raw[:got.value]
    return b""

class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD), ("__a", wt.DWORD),
                ("RegionSize", ctypes.c_size_t), ("State", wt.DWORD),
                ("Protect", wt.DWORD), ("Type", wt.DWORD), ("__b", wt.DWORD)]

needles = {
    "80b9(8B)": bytes.fromhex("80b9b54a00000000"),
    "80b9(4B)": bytes.fromhex("80b9b54a"),
    "utf16":    "80 B9 B5 4A 00 00 00 00".encode("utf-16-le"),
    "ascii":    b"80 B9 B5 4A 00 00 00 00",
}
addr = 0
MEM_COMMIT = 0x1000
readable = {0x02, 0x04, 0x06, 0x20, 0x40}
counts = {k: 0 for k in needles}
samples = {k: [] for k in needles}
while addr < 0x7FFFFFFEFFFF:
    mbi = MBI()
    r = k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
    if not r:
        addr += 0x1000
        continue
    size = mbi.RegionSize
    if mbi.State == MEM_COMMIT and (mbi.Protect & 0xFF) in readable:
        data = read(mbi.BaseAddress, min(size, 0x4000000))
        if data:
            for k, pat in needles.items():
                start = 0
                while True:
                    i = data.find(pat, start)
                    if i < 0:
                        break
                    counts[k] += 1
                    if len(samples[k]) < 5:
                        samples[k].append((hex(mbi.BaseAddress + i),
                                           data[max(0, i-24):i+len(pat)+24]))
                    start = i + 1
    addr += size if size else 0x1000

for k in needles:
    print(f"{k:10} hits: {counts[k]}")
    for a, c in samples[k]:
        print(f"    {a}: {c!r}")
k32.CloseHandle(h)
