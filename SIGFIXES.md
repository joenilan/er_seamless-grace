# SIGFIXES — signature & offset repairs

Most recent first. Every entry: what broke, the diagnosis, the applied fix,
and its status. "Applied" fixes live where AGENTS.md's design decision says;
until the patch mechanism ships, entries hold at `diagnosed`.

---

## SIGFIX #1 — signatures.cpp:1399 — spawn-init helper anchor (2026-08-30)

**Status: diagnosed, patch pending (mechanism not built yet)**

- Failing pattern (from fatal dialog):
  `E8 ? ?? ?? ?? 48 8B 15 ? ?? ?? ?? 48 8D 4B 20`
- Error: `No such pattern` → process abort at startup.

**Diagnosis**

| | old exe (pre 23850278) | new exe (build 23850278, FV 2.7.0.0) |
|---|---|---|
| exact pattern | 1 match | **0 matches** |
| `48 8D 4? 20` loosened | — | **exactly 1: file off `0x1181f23`, VA `0x141182923`** |

New code at the site (.text):

```
call 0x1411452d0
mov rdx, [rip+0x34149a1]
lea rcx, [rdi+0x20]     ; was: lea rcx, [rbx+0x20]  (modrm 4B -> 47)
test rbx, rbx
cmovne rdx, rbx
call 0x1411452d0
```

Compiler register-allocation swap: object ptr moved rbx→rdi. One nibble.

- Rejected candidate: file off `0x2223838` (`lea rcx,[rbx+0x58]`) — lea
  displacement moved 0x20→0x58 AND surrounding context differs (misaligned
  prologue, different call target shape). Not the same source line.

**Fix (pending mechanism)**: the scan-time pattern for this signature must
accept `48 8D 47 20` where it expected `48 8D 4B 20` — i.e. pattern becomes
`E8 ? ?? ?? ?? 48 8B 15 ? ?? ?? ?? 48 8D 47 20` (or generalized `48 8D 4? 20`).
See AGENTS.md for why we do NOT byte-patch eldenring.exe itself.

**After this fix**: relaunch; expect the next failing signature in the dialog
(abort stops at first failure). Repeat loop documented in AGENTS.md.
