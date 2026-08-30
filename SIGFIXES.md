# SIGFIXES — signature & offset repairs

Most recent first. Every entry: what broke, the diagnosis, the applied fix,
and its status. "Applied" fixes live where AGENTS.md's design decision says;
until the patch mechanism ships, entries hold at `diagnosed`.

---

## SIGFIX #1 — signatures.cpp:1399 — spawn-init helper anchor (2026-08-30)

**Status: patch built & installed — awaiting user launch test**

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

**Fix — code-cave detour in ersc.dll (see `tools/patch_sigfix1.py`)**

RE established: `F_scan = 0x1800d4d80` (286 call sites) receives the pattern
as a decrypted **std::string_view** (`rdx` = {data@0, size@8}) — the scan
parses the pattern TEXT in-place. So the fix is an entry detour:

- `0x1800d4d80`: `jmp 0x18018d636` + `nop` (6 bytes over the 3 prologue pushes)
- cave at RVA `0x18d636` (CC tail padding past .text VSize — executable):
  if size==45 && data starts `"E8 ? "` && data[41]=='B' → data[41]='7';
  then executes the displaced pushes and jumps back to `0x1800d4d86`.
- Total file diff: 65 bytes, all inside `.text`.

Installed to `Game\SeamlessCoop\ersc.dll`; original preserved as
`ersc.dll.vanilla.bak` (2026-07-28 stock v1.9.9).

**Test outcome**: (pending — launch via ersc_launcher.exe)
- in-game → pass; look for runtime oddities near spawn/init code
- NEW dialog with a different pattern → progress; loop per AGENTS.md
- silent crash / no dialog → suspect Themida .text CRC; fall back to
  companion-DLL mechanism (AGENTS.md design decision #2)
