# `sen.elf` — the SENSER power/lifecycle daemon

**Summary.** `sen.elf` is a thin supervisor shell, not the service brain: it reads a mode word,
registers one power-control queue, `dlopen`s `libsencore.so` and hands it a `poll()` reactor, and runs
a log/time loop. It holds **no verb dispatch, no auth, no crypto, and no `0xff03` reference.**

**Where.** `fs/a15/bin/sen.elf` (project `ghidra_svc`, image base `0x400000`, stripped). `main` =
`FUN_00401cb0` (recovered from `entry` `0x401e08`); startup `FUN_00401f80`; mode resolve `FUN_00402a60`;
power callback `FUN_00402020`; the `poll()` reactor `FUN_00402e58`; log sink `FUN_004021a4`. Version
banner `" 1.3.4 / 2012.8.23"`, build option `PRINT_METHOD : OSAL`.

**Mechanism.**
- **Mode.** Reads a persisted integer from `/setting/sen/smode` (else `/boot/sen/smode`), mirrors to
  `/var/.sen/.smode`, logs `SENSER_MODE = %d`. **If mode == 0, it never `dlopen`s anything** — the
  reactor just spins at 1 Hz.
- **The one registration:** `osal_reg_sync_msg_queue_cb(0x3d032e, …, FUN_00402020)` — a **power** queue,
  payload one byte: `0` = resume (full re-init), `1` = suspend (stop/deinit the core), else `abort()`.
- **Core handoff:** `dlopen("libsencore.so")` → `senser_usb_mode_start(&reactor)` + `sens_adjCmd_init()`
  (+ `NinThread` via `pthread_create`). The channel is **USB**; the verb logic and any gate live in
  `libsencore.so` ([senser-verb-dispatch](senser-verb-dispatch.md)).
- **The reactor dispatches file descriptors, not verbs:** `handler->vtable[2](handler, reactor)` per
  ready pollfd; the handler objects are constructed inside `libsencore.so`.
- **QIDs used:** `0x3d032e` (power, registered), `0x8f013a` (log sink — the same cross-processor queue
  as Investigation 1's STP pool), `0x8f0313` (log-error), `0x910042` (time-of-day). The log header stamps
  module id `0x3d`.

**Verification.** *light (negative / redirect).* Every control-flow claim decompiled by address;
negatives established by search (`search_code "0xff03"` → 0, `"0x25906be"` → 0, no `/dev/` string, no
socket/crypto imports). `sen.elf` carries a dead inlined copy of the HASP history appender
([hasp-store](hasp-store.md)) with no in-image caller.

**Boundary / open.** The verb table, the auth, and the `0xff03` gate are all in `libsencore.so`, not
here. The `0x3d` module-id reading and the "libsencore owns the auth" claim are **HYPOTHESIS** (negative
evidence: those symbols/strings/constants are absent from `sen.elf` while the module that owns the
channel is loaded by it).

**Source.** [framework-runs/sendaemon-map.md](../../framework-runs/sendaemon-map.md)
