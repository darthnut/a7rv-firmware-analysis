# Plugin verbs — the complete `command NNNN` inventory

**Summary.** Across the entire extracted a15 filesystem (188 `.so`), exactly **two** genuine service
verb handlers exist, both in `libpro00.so`: `command001F` (HASP read/reset) and `command00F1` (an
always-success stub). No `open`/`close`/`memory NNNN` export exists anywhere.

**Where.** `fs/a15/lib/libpro00.so` (6,032 bytes; project `ghidra_plugins`, load base `0x100000`).
`command001F` @ `0x001009a4`, `command00F1` @ `0x00100a64`. Verbs resolve via the SENSER dispatcher's
`snprintf("command%04X") + dlsym` path ([senser-verb-dispatch](senser-verb-dispatch.md)).

**Mechanism.**
- **Inventory (byte-anchored).** `nm -A -D --defined-only fs/a15/lib/*.so | grep ' (command|open|close|
  memory)[0-9A-Fa-f]{4}$'` returns exactly two lines — both from `libpro00.so`. The same anchored scan
  over every partition's `lib/` returns the identical two. (The earlier "six plugins" claim was loose
  substring matching on mangled C++ names like `RingBuffer<Command>`.)
- **`command001F` — HASP read/reset.** One pointer arg; `*param_1` is the operation selector. `0x00` →
  allocate an 88-byte buffer, call `Read_Hasp()`, hand the buffer back (ptr/size/deleter in slots 3/4/5),
  return `1` (or `0x82` on failure). `0x80` → `Reset_Hasp()`, return `1`/`0x82`. Any other selector →
  `0x81`. `Read_Hasp`/`Reset_Hasp` are *imports*, defined in both `libObj.so` and `libsencore.so`.
- **`command00F1` — a 2-instruction stub** (`mov w0,#1; ret`): takes no args, calls nothing, always
  returns `1` — a registered no-op that acks the verb.

**Verification.** *deep (bytes + decompile).* The anchored `nm` inventory is exhaustive for this
extraction; both handler bodies are decompiled in full (and `command00F1` disassembled to its two
instructions); the measured load base confirmed (`0x1009a4 − 0x9a4 = 0x100000`).

**Boundary / open.** Verb handlers can live in modules **not in this image** — e.g. `libSnr.so` (plugin
module id `0xff02`) is absent from `fs/a15/lib/`, so the inventory is exhaustive *for this extraction*,
not for every shipping unit. Which library provides `Read_Hasp`/`Reset_Hasp` at runtime (both define
them) depends on link/load order — unresolved. *Why* Sony ships an always-succeeding handler for
`0x00F1` (placeholder? disabled feature?) cannot be determined from this binary.

**Source.** [framework-runs/plugin-verb-map.md](../../framework-runs/plugin-verb-map.md)
