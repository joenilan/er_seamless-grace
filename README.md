# ER Seamless - Grace
A harness that keeps Elden Ring Seamless Co-op alive across game patches.
"Grace" because it isn't a full mod — it patches, adapts, and (eventually) extends.

## What this is

FromSoftware patches break Seamless Co-op by shifting the bytes its hooks
rely on. Grace is a personal-use project that:

1. **Diagnoses** each break (extract failed signatures, fuzz-scan the new exe,
   locate the moved code)
2. **Fixes** it at runtime or on disk — minimal, documented, reversible patches
3. **Documents** every fix in `SIGFIXES.md` so the next patch is faster

Personal project for me and friends. Not distributed. Not a takeover of
LukeYui's Seamless Co-op — all credit for the original mod is theirs.

## Layout

| Path | What |
|---|---|
| `dist/` | Stock Seamless Co-op files (GITIGNORED — author's copyrighted work, never commit) |
| `tools/` | Python RE/analysis scripts (signature fuzz-scanner, disasm helpers) |
| `SIGFIXES.md` | Every signature/offset break + fix, most recent first |
| `AGENTS.md` | Operating manual for AI agents working on this repo |

## Status

- Game: eldenring.exe build 23850278 (2026-08-27 patch), FileVersion 2.7.0.0
- Mod: Seamless Co-op v1.9.9 (2026-04-21)
- Known broken: 1st signature at signatures.cpp:1399 — see SIGFIXES.md
