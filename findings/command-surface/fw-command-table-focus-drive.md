# FW command table — the focus / drive family

**Summary.** The internal FW `SET_` command table in `cpapp` is 20-byte entries in registration order
with the Thumb LSB set on pointers; the focus/drive handlers are almost all **state latches** that park
arguments in a RAM settings block for another task to consume — only `SET_DRIVE_MODE` forwards over OSAL.

**Where.** `cpapp-b.bin` (project `ghidra_cpapp`; VA = file offset + `0x108000`). Table geometry
byte-verified around file `0x10ff7d4`–`0x10ff850`. Entry: `{u16 id @+0x00, handler|1 @+0x04, flags
@+0x08, 0 @+0x0c, checker|1 @+0x10}`, stride `0x14`. Family handlers: `0x4008 SET_DRIVE_MODE`
`0x33dbc4`, `0x4015 SET_BRACKET_MODE` `0x33e9b0`, `0x401B SET_P_SHIFT_DRIVE` `0x33e0d0`, `0x4152
SET_FOCUS_BRK_EXEC_STATE` `0x3453bc`, `0x4165 SET_FOLLOW_FOCUS` `0x345158`, `0x4166
SET_PRESET_FOCUS_ZOOM_COMMAND` `0x3451c0`.

**Mechanism.**
- **Entry geometry** re-derived by `read_bytes` (ten of ten pointer words = catalog value + `0x108000`),
  which fixes the field order and confirms the catalog is a dump in **registration order, not sorted**.
  The `+0x08` flag is per-entry (0 or 1); pointers carry the Thumb LSB, which is why `list_xrefs` on the
  even handler addresses returns zero.
- **Handler shape:** each latches payload bytes into the shared settings block (`0x0157aa10`-based) under
  a trace-enable mask, then `return 1` — **none validates or calls its checker**.
- **`SET_DRIVE_MODE` is the one that leaves cpapp:** on a drive-mode transition it builds an OSAL message
  and sends via `osal_snd_msg` to **queue/msg-id `0x90040193`, dest `0x90030001`, opcode `0xd006`/`0xd003`
  (assert/clear bit `0x4000000`)** — a cross-processor forward.
- **`0x4152` (the Investigation 1 anchor)** latches the exec state and, via a one-deep pending-request
  slot (`hint_2355e8`), logs "receive … before complete" if a second request arrives first. The exec-state
  global `0x0157b418` has **one write and no reader** in `cpapp`.
- **The checker column:** real checkers are phase-gated *consistency assertions* (compare incoming payload
  vs. live latch, log `LiroSeq_ParamCheckErr` on drift) that return void — **not permission gates**. The
  shared value `0x790e2e` (59 catalog lines) is not a checker at all but a settings-block initializer.

**Verification.** *light (ids vs catalog).* Six of eight family handlers plus the checker and supporting
IPC builders decompiled by address; entry geometry and five-entry cross-check byte-verified against
`reference/command-table.txt`. Statements about *why* a value exists, and the "parked for another task"
model, are flagged HYPOTHESIS (inferred from missing readers + change counters).

**Boundary / open.** The **consumers of the latched globals are on the other processor / in images not
in hand**; no handler touches a peripheral register directly. Whether the dispatcher calls the checker at
all, and what the `param_2` phase argument means, is not reachable by xref. The `0x4000000` bit's effect
downstream of OSAL queue `0x90040193` is out of scope. See
[OPEN-QUESTIONS.md](../../OPEN-QUESTIONS.md) item 6.

**Source.** [framework-runs/cpappcmd-map.md](../../framework-runs/cpappcmd-map.md)
