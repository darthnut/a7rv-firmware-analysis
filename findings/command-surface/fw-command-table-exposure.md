# FW command table — the exposure / metering / WB family

**Summary.** The exposure-triangle, metering and white-balance setters in `cpapp`, mostly local latches
into the same settings block; two forward work (one to an RTOS queue, one replays ~170 commands), and
`SET_WB_MODE` exists twice — `0x4006` sets, `0x4063` re-applies.

**Where.** `cpapp-b.bin` (project `ghidra_cpapp`; VA = file offset + `0x108000`). Handlers: `0x4006
SET_WB_MODE` `0x33da5c`, `0x4028 SET_IRIS_DRIVE` `0x33ec00`, `0x4029 SET_ISO_SPEED_RATE` `0x33ed58`,
`0x402C SET_CUSTOM_WB_SAVE` `0x33f0f0`, `0x4045 SET_REQ_CUSTOM_WB_DATA` `0x33f934`, `0x4046
SET_SPOT_METER_FOCUS` `0x33d728`, `0x4054 SET_TOUCH_SPOT_METER` `0x33e448`, `0x40DB
SET_STANDARD_EXPOSURE_STEP` `0x342b34`, `0x4063 SET_WB_MODE (re-apply)` `0x345a48`, `0x415A
SET_EXPOSURE_CANCEL` `0x3458e0`. Latch block base `0x0157aa10`; header accessor `FUN_00baaaa6`.

**Mechanism.**
- **Common shape:** read the message (`[p+8]` payload; header at negative offsets via `FUN_00baaaa6`),
  latch into the `0x0157aa10` block, `return 1` under a trace-enable guard.
- **Local latches:** `0x4006` (WB), `0x4029` (ISO + multi-shot NR), `0x4054` (touch spot), `0x40DB`
  (6 exposure-step bytes). `0x4028 SET_IRIS_DRIVE` is the one that does arithmetic (mode-gated,
  delta-accumulating, writes a bounded ring).
- **Hand-off via a one-deep pending slot:** `0x4046`/`0x402C`/`0x4045` call `hint_2355e8` (logs
  "receive … before complete" and drops a second request before the first completes); `0x4046` also marks
  property `0x2001` dirty for the emitter ([property-emitter](property-emitter.md)).
- **`0x415A SET_EXPOSURE_CANCEL`** is the only real queue forward here: it posts a 5-word callback
  descriptor into an **RTOS message queue** via `FUN_004e8a90` → `FUN_005c353c` — but the queue id is from
  a runtime handle, so there is **no static port to cite**.
- **`0x4063 SET_WB_MODE` is a bulk re-apply, not a setter:** `FUN_00897918` replays ~170 commands through
  a 333-entry, stride-`0x14` dispatch table at VA `0x010ff600`, where the "checker" column is the *second
  callback* — the same function object `reference/command-table.txt` lists as the checker.

**Verification.** *light (ids vs catalog).* Ten of twelve family handlers plus two checkers and the
replay/RTOS helpers decompiled by address; ids re-verified byte-for-byte against the catalog; the
333-entry replay table layout pinned by `read_bytes`. The checker's role ("state-drift assertion", not a
gate), the `SET_DRIVE_MODE` contrast, and the replay-slot semantics are flagged.

**Boundary / open.** The **cross-processor consumer side is out of scope** — handlers latch and forward;
the sensor/imaging processor's handling was not followed. The trace-enable flag `0x01915dc6` has ~90
READs and no WRITE in `cpapp` (initialised elsewhere). On the replay path the checker is invoked as
`checker(settings_ptr, slot)` with every `slot` zero, so a `param_2==1`-gated checker would do nothing —
unresolved whether something writes those slots at runtime. See
[OPEN-QUESTIONS.md](../../OPEN-QUESTIONS.md) item 6.

**Source.** [framework-runs/cmdexposure-map.md](../../framework-runs/cmdexposure-map.md)
