# AGENTS.md — ER Seamless - Grace

Read this fully before working. It encodes everything discovered so far so you
don't have to re-derive it.

## Mission

Keep Seamless Co-op v1.9.9 working on patched Elden Ring executables, as a
personal-use harness. Diagnose each break, patch minimally, document in
`SIGFIXES.md`. The long-term option is replacing parts of the mod with our own
code loaded alongside, but the immediate job is signature/offset repair.

## Hard rules

- **NEVER commit `dist/`** — it contains LukeYui's copyrighted `ersc.dll` and
  related files. `.gitignore` covers it; keep it that way. Same for any game
  files or dumps of game memory.
- **Never launch the user's game yourself.** The user runs test launches and
  reports/screenshots the results. You prepare builds and analyze outcomes.
- Patches must be **minimal, documented, and reversible**. Every modified byte
  gets a line in `SIGFIXES.md` (file, offset/VA, old bytes, new bytes, reason).
- No distribution of patched game or mod files. Personal use only.
- The original mod author (LukeYui / yuiamoroll on GitHub) gets credit; this
  repo is a compatibility harness, not a fork of his work.

## Environment

- Windows PC, PowerShell 7 (`pwsh`). Repo local path: `E:\git\ersc-re`
  (matches GitHub repo `joenilan/er_seamless-grace`).
- Game install: `E:\SteamLibrary\steamapps\common\ELDEN RING\Game`
  - `eldenring.exe` — current exe (patched 2026-08-27, build 23850278,
    PE FileVersion 2.7.0.0)
  - `Game\SeamlessCoop\` — installed mod (v1.9.9)
  - `Game\SeamlessCoop\crashdumps\` — crash dumps (check for new ones after runs)
  - `Game\mod_loader_log.txt` — EldenModLoader log
- Tooling: Python 3.12 with `pefile` + `capstone` installed (pip).
  mingw gcc at `C:\Qt\Tools\mingw810_64\bin\`. WSL Ubuntu available.
  No Ghidra/IDA installed yet.

## Findings so far (2026-08-30)

### The failure
Launching via `ersc_launcher.exe` on game build 23850278:
```
Seamless Coop 1.9.9 - Fatal Error
A fatal error has occurred and the process has been aborted:
No such pattern
'E8 ? ?? ?? ?? 48 8B 15 ? ?? ?? ?? 48 8D 4B 20'
The mod may not be compatible with the installed game version
ersc\signatures\signatures.cpp:1399
```

### The break (SIGFIX #1)
- Old pattern: `E8 ? ?? ?? ?? 48 8B 15 ? ?? ?? ?? 48 8D 4B 20`
- Fuzz-scan of new exe: original = 0 matches;
  `E8 ? ?? ?? ?? 48 8B 15 ? ?? ?? ?? 48 8D 4? 20` = exactly 1 match at
  **file offset 0x1181f23, VA 0x141182923**.
- The site: `call 0x1411452d0; mov rdx,[rip+0x34149a1]; lea rcx,[rdi+0x20]`
  — the compiler swapped rbx→rdi in the `lea` (modrm 4B→47). One nibble.
- Alternate fuzzy candidate at file offset 0x2223838 (`lea rcx,[rbx+0x58]`) —
  judged NOT the target (struct offset moved 0x20→0x58, context differs).
- NOTE: these are FILE offsets; convert via PE sections (text file↔VA delta).

### ersc.dll structure (v1.9.9, sha256 in dist/, built 2026-04-21)
- Packed with **Themida**: 5.5MB `.themida` section. Some functions are
  virtualized (e.g. the fatal-error handler at `0x180028800` = `jmp` into
  the VM). Most of `.text` (1.6MB) is PLAIN, patchable code.
- Strings (patterns, messages) are **encrypted at rest** — decrypted at
  runtime into memory. The movabs constant streams in .text are the
  decrypt-staging code.
- Single export: `modengine_ext_init` (loaded via ModEngine-compatible path).
- Static imports minimal (Themida IAT obfuscation); libcurl statically
  linked inside.
- Key .text locations (RVA):
  - `0x2aa23`: builds the string "1.99" (version-related gate logic; NOT the
    current blocker — the signature failure kills first)
  - `0xd5446`-`0xd547b`: fatal-error setup — `lea rdx,"No such pattern"`,
    `lea rdx,"signatures.cpp"` path, `mov r8d,0x577` (line 1399),
    `call 0x180028800` (virtualized fatal handler)
- .rdata strings of interest (RVA): `0x1dbbe6` "No such pattern",
  `0x1dbc05` "The mod may not be compatible...",
  `0x1db755` "signatures.cpp", `0x1dbb6c`-ish RTTI names:
  CSMenuMan, CSLockTgtMan, CSMapItemMan, CSEventFlagMan, YKEventFlagMan,
  CSGameMan, CSFeMan, GameDataMan.
- Beware: RVA vs blob-offset off-by-0x1000 when reading sections with
  pefile `get_data(0x1000, ...)` — always convert.

### Tool flow that works
1. `tools/sigscan.py` — fuzz-scan a pattern against eldenring.exe, reports
   exact + loosened-variant match counts/addresses.
2. Disassemble candidates with capstone (see `tools/disasm_sites.py` pattern).
3. Iterate: fix → user launches → next dialog names next pattern.

## Open design decision: how fixes get applied

On-disk patching of `eldenring.exe` is UNSAFE for semantic instructions
(changing `47`→`4B` would make the game execute `lea rcx,[rbx+0x20]` with the
wrong object in rbx — real gameplay corruption). Preferred options, in order:

1. **Code-cave stub inside ersc.dll** (no extra files): patch the scan
   function's entry (plain .text) to jump to a cave that corrects the
   (bytes,mask) in-place before comparison, then falls through. Needs the
   scan function's entry + arg layout (next RE step).
2. **Companion DLL** (proxy dinput8/winmm, mingw-built) polling the heap for
   decrypted pattern tables and patching them. Race vs ersc init timing;
   acceptable fallback.

## Workflow for a new game patch

1. User updates game; launch via ersc_launcher; screenshot the fatal dialog
   (it names the failing pattern + signatures.cpp line).
2. Fuzz-scan pattern against new exe (`tools/sigscan.py`).
3. Disassemble candidate site(s); confirm semantic match (compare against
   prior SIGFIXES entries — patterns recur).
4. Decide patch per "Open design decision" above; implement; log in
   SIGFIXES.md; hand to user for launch test.
5. Repeat until in-game. Watch `crashdumps\` for runtime breaks after load.
