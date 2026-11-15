# SENSER verb dispatch — the post-auth command dispatcher

**Summary.** The real post-auth service verb dispatcher lives in `libsencore.so` (not `sen.elf`): a
receive loop → verb-table walk → auth-gated polymorphic execute → `command%04X`/`dlsym` plugin
resolution, with three verb tables swapped in by authentication level.

**Where.** `fs/a15/lib/libsencore.so` (project `ghidra_svc`, module base 0, so VA == `nm` offset).
`SenserThread` `0x10b7ac`, `Parse` `0x10e9f4`, `ParseCheck` `0x10ea84`, `Command::Execute` `0x10db08`,
`PluginCommand::DoExecute` `0x10d908`, `ProductInfoFunc` `0x10eabc`, `GetPluginModule` `0x10db68`,
`CreatePluginCommand` `0x10e254`, `onComplete(int)` `0x10c108`, `start_authentication` `0x10c328`. Verb
tables `pFunc_level_A/B/C` at `0x16c848`/`0x16c8b8`/`0x16c8f8`.

**Mechanism.**
- **Chain:** `SenserThread` reads a 12-byte header (length u32 at `buf[0..3]`, **verb = u16 at
  `buf+4`**, status returned at `buf[0xb]`) → `Parse` walks the active verb table and calls the matching
  factory → `Command::Execute` checks an **auth gate** (vtable+0x28 → status `0x82` if unauthenticated)
  then dispatches `DoExecute` (vtable+0x10) → the handler's return becomes the status byte, output
  streams back via `MemoryData(SenserIfSend, …)`.
- **Auth-level tables.** `onComplete(level)` swaps the `pFunc` pointer: level 3 → table A (most
  privileged, the only level that clears `terminal_change_function_is_disabled`), level 2 → B, level 1 →
  C. `start_authentication` first sets `pFunc = 0`, so **pre-auth there are zero authorized verbs** —
  every verb hits the `0x80` fall-through.
- **Plugin bridge.** `ProductInfoFunc` (verb `0x0010`) loads `libpro(verb>>8).so` and resolves
  `command/open/close/memory%04X` by `snprintf` + `dlsym` — reaching the two real plugin verbs in
  `libpro00.so` ([plugin-verbs](plugin-verbs.md)).
- **Named level-A verbs:** `MiconAccessFunc` (`0x0003`), `AdjustControlFunc` (`0x0004`, logs `ADJ_CTRL`,
  returns `0xa0` on resource-lock).

**Verification.** *light.* The whole dispatch chain decompiled by address; the three verb tables
byte-read (stride 16, fn-slot at +8, Thumb LSB → kind tag) and validated against three low verbs whose
handlers were separately decompiled. The high-verb (`0xFF00`/`0xFF02`/`0x00FF`) exact handler identities
and the auth-level-integer ↔ table mapping are **HYPOTHESIS**.

**Boundary / open.** `0xff03` memory-dump: **no handler exists** — not a verb-table entry and not a
`memory FF03` symbol anywhere in the image. The live `0x80` is the missing-handler fallback firing
(manufactured at three sites: `Parse` `0x10ea30`, `CreatePluginCommand` `0x10e2b8`, `DoExecute`
`0x10d908`), not a locked routine executing. Whether a `0xff03` handler is materialised on demand (e.g.
a HASP-entitlement-gated `libproFF.so`) is unprovable statically. See
[Investigation 2](../../investigations/02-service-mode-and-auth.md) and
[OPEN-QUESTIONS.md](../../OPEN-QUESTIONS.md) item 9.

**Source.** [framework-runs/sencatalog-map.md](../../framework-runs/sencatalog-map.md)
