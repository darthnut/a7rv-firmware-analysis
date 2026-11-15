# a7R V firmware: av-cam.bin develop-resource acquire path (`ExecRcAcquire`)

Static reverse-engineering of the user's own Sony a7R V firmware (`av-cam.bin`, Ghidra project
`ghidra_avcam`). Companion to Investigation 1 (focus-bracket write-cliff cadence measurements).
All addresses are Ghidra virtual addresses. No firmware bytes reproduced.

## A. The acquire path — `ModuleRcBase::ExecRcAcquire`

### A.1 Locating it (binary is function-stripped)

`search_symbols_by_name("ExecRcAcquire")` → no symbols; `search_strings("ExecRcAcquire")` → the
function-ident string `"ExecRcAcquire"` @ `0x013f1e64`, source-file string `"ModuleRcBase.cpp"` @
`0x013f1e72`, and log strings `[SDF] ModuleRcBase::ExecRcAcquire retry rcct_acquire START/END` @
`0x013f1e83` / `0x013f1ebf`. All five string xrefs land inside one function,
**`FUN_01058430` = `ModuleRcBase::ExecRcAcquire`** (`list_xrefs` on the three string addresses;
decompiled via `decompile_function("01058430")`). INT_ERROR log sites carry source line numbers
`0x40`(64), `0x4c`(76), `0x57`(87), `0x5e`(94) — the retry loop occupies lines ~64–94 of
`ModuleRcBase.cpp`.

### A.2 Call chain (each hop decompiled by address)

```
SDF module exec  FUN_010592f4  ("ModuleRcResizeSetAicParam.cpp::Exec", call @0x01059350)
 └─ FUN_01058430  ModuleRcBase::ExecRcAcquire           (ModuleRcBase.cpp:64–94)
     └─ FUN_01063f98  WrapRcctAcquire::Api_Exec         (WrapRcctAcquire.cpp:49)
         ├─ FUN_01064010  encode request descriptor (6×u32) into 4-byte request word
         └─ FUN_01064070  WrapRcctAcquire::MainProcess  (WrapRcctAcquire.cpp:122)
             └─ FUN_012d66f0  rcct_Acquire              (api_rc.cpp:434)
                 ├─ FUN_012caf58  get RC-driver instance/handle
                 └─ FUN_012caf64  driver call → returns acquire_id
```

The resource acquired is an **RC (reduce/convert) hardware-engine context handle** — an
`acquire_id` token from the `rcct` (RC-contrOol) driver. Evidence: `rcct_Acquire` logs
`[RC] ERROR ... acquireId=...` (`0x0144f74f`); the SDF wrapper logs `[SDF WrapRcctAcquire] id:0x%x`
(`0x013f2598`); consumer strings name the unit classes `rcct_Acquire(RC_FUNC_COPY)` /
`rcct_Acquire(RC_FUNC_RESIZE)` (§B). The handle is stored in the caller's module context at
`ctx+0xc` (output `param_8` = `param_1+0xc` in `FUN_010592f4`) and released by `ExecRcRelease`
(§B.1).

### A.3 The retry loop (from `decompile_function("01058430")`)

Ghidra pseudo-C, condensed (branches/labels as emitted):

```c
FUN_01058430(ctx, p2..p7, u32 *out_id /*param_8*/) {
  FUN_01063f58(stack_ctx);                       // init per-call context
  local_88..local_74 = *p2..*p7;                 // copy 6×u32 request descriptor
  iVar1 = FUN_01063f98(stack_ctx, &desc, local_90);   // attempt #1 → local_90[0] = acquire_id
  if (iVar1 != 0) {
    if (iVar1 == 0x80) {                         // 0x80 = retryable ("busy")
      log("[SDF] ModuleRcBase::ExecRcAcquire retry rcct_acquire START");
      for (iVar3 = 0; ; ) {                      // ≤ 100 retries
        block = {0x28, 0, 0 /*status out @+0x14*/, 20000 /*timeout @+0x18*/, 0};
        e = FUN_0102efc4(0x910041, &block);      // OS service: timed wait/delay
        if (block.status_or_e != 0) { log_int_error(line 76); iVar1 = 0x100; goto out; }
        iVar1 = FUN_01063f98(stack_ctx, &desc, local_90);   // retry acquire
        if (iVar1 == 0)   goto log_end;          // success
        if (iVar1 != 0x80){ log_int_error(line 87); goto log_end; }
        if (++iVar3 >= 100) break;               // exhaustion
      }
      log_int_error(0x80, line 94);              // "gave up"
      iVar1 = 0x80;                              // ← returned upward on exhaustion
  log_end:
      log("[SDF] ... retry rcct_acquire END");
    } else { log_int_error(line 64); }           // non-retryable error, no retry
  }
 out:
  if (iVar1 != 0) local_90[0] = 0;               // failure ⇒ zero the id
  *out_id = local_90[0];
  thunk_FUN_01062df8(stack_ctx);                 // context dtor
  return iVar1;
}
```

- **Retry condition:** acquire status `0x80`.
- **Backoff:** per iteration, OS service `0x910041` (see below) with a 40-byte param block:
  `+0x00=0x28` (block size), `+0x14` = status out (read back via `local_58._4_4_`),
  `+0x18 = 20000` (timeout/interval). `FUN_0102efc4` is a generic **OS service dispatch**:
  tail-call to `(**(code**)(DAT_01000020 + 0x3b8))` — a system-call table slot — with ~200 call
  sites across the module, first arg = service ID. *HYPOTHESIS:* 20000 is in µs (≈20 ms fixed
  wait per retry); the unit is not resolvable statically from av-cam.bin alone.
- **Bound & exhaustion:** hard cap `iVar3 < 100` → up to 100 retries; on exhaustion returns
  **`0x80`** with `*out_id = 0`. A wait-service failure returns **`0x100`**. Worst-case stall:
  100 × wait(20000 units) — ≈2 s if µs (*HYPOTHESIS*, same unit caveat).
- **Caller behavior** (`FUN_010592f4`): nonzero acquire status logs INT_ERROR
  `ModuleRcResizeSetAicParam.cpp:65` and the module exec returns the error — the frame's RC job is
  abandoned, and `ExecRcRelease` is **skipped** (nothing was acquired).

### A.4 What status `0x80` means — error-mapping table

`WrapRcctAcquire::MainProcess` maps driver errors through `FUN_01063eac`, which indexes an
11-entry table at `0x01305fc0` for driver codes `0..0xA` (`param_2 < 0xb`, else `0x80000000`).
Bytes read with `read_bytes("0x01305fc0", 48)`; driver enum names are the contiguous string run at
`0x01424089–0x01424129` (*HYPOTHESIS:* declaration order = enum order — supported by the mapping
being semantically coherent):

| driver code | name | SDF status |
|---|---|---|
| 0 | `RC_ERR_OK` | `0x000000` |
| 1 | `RC_ERR_NG` | `0x000100` |
| 2 | `RC_ERR_BUSY` | **`0x000080`** |
| 3 | `RC_ERR_IMAGE_PARAM` | `0x100000` |
| 4 | `RC_ERR_PARAM` | `0x100000` |
| 5 | `RC_ERR_NOT_SUPPORTED` | `0x000002` |
| 6 | `RC_ERR_ACQUIRED` | **`0x000080`** |
| 7 | `RC_ERR_REQ_OVERFLOW` | `0x000100` |
| 8 | `RC_ERR_HW` | `0x000100` |
| 9 | `RC_ERR_TIMEOUT` | `0x000400` |
| 10 | `RC_ERR_SYSTEM` | `0x000100` |

So the retry loop fires **iff the RC unit is `BUSY` or already `ACQUIRED` by another flow** — a
pool/unit-contention condition, not a parameter or HW fault. Every other error returns immediately.

### A.5 Fast path that skips the acquire

Before acquiring, `FUN_010592f4` calls `FUN_01059548` (`ModuleRcResizeSetAicParam` "is RC needed?"
gate): it returns "skip" **only if** src/dst format fields (`+0xa8`, forced-acquire if either is
`3`), geometry fields (`+0xb0..0xbc`, `+0x88`, and `+0x94+0x9c` / `+0x96+0x9e` width+offset sums
match), and all extra-parameter u16s (`+0x12..+0x26`) are identical/zero. I.e., an identity
resize with no AIC extras never touches the RC pool.

## B. What releases it / the stall

### B.1 The release chain — the lease is held across the whole HW job

`list_xrefs("012d67d8")` (driver `rcct_Release`, named by string `"rcct_Release"` @ `0x0144f76d`,
xref from inside itself @ `0x012d68a0`) closes the SDF release chain:

```
ModuleRcResizeSetAicParam::Exec  FUN_010592f4   (call @0x010594d0, end of per-frame exec)
 └─ FUN_01058670  ModuleRcBase::ExecRcRelease       (ModuleRcBase.cpp:126; ident string 0x013f1ef9,
 │                                                    xref 0x010586a8; only caller = FUN_010592f4)
     └─ FUN_01064714  WrapRcctRelease::Api_Exec     (WrapRcctRelease.cpp:37)
         └─ FUN_01064764(acquire_id)
             └─ FUN_012d67d8  rcct_Release          (call @0x01064774)
```

Ordering inside the module exec (`FUN_010592f4`, decompiled): acquire (§A) → store id at
`ctx+0xc` → program AIC params `FUN_0105966c` (err line `0x48`) → interrupt-mask op
`FUN_0102e994(*(ctx+8), 0xfffff3ff)` (*HYPOTHESIS:* mask) → submit/enable job `FUN_01064840` →
**`FUN_010598f8` "WaitCallbackRc"** — a blocking wait for RC HW completion (its error path logs
`[SDF] WaitCallbackRc_Err %ld`, string @ `0x013f1f18`, plus event `FUN_01033980(0x40,0,0x6804,
0x803d,4,…)`) → then `ExecRcRelease` **unconditionally** at `0x010594d0`, even if
WaitCallbackRc errored. On acquire failure the release call is skipped (nothing held; id zeroed).

Consequence, established statically: **an RC unit lease is held for the duration of one complete
resize job — submit through HW-completion callback — not just for the submit.** Hold time ≈ full
job runtime, and the waiting thread is the same one that would re-acquire next frame.

### B.2 Who else shares the pool

Every caller of driver `rcct_Acquire` `FUN_012d66f0` (`list_xrefs`), matched to its own
`rcct_Release` callers:

| flow | acquire fn (class string) | release fn |
|---|---|---|
| SDF develop module (§A/§B.1) | `FUN_01064070` (ModuleRcResizeSetAicParam) | `FUN_01064764` |
| VDT **RCOPY** | `FUN_011cc1f0` (`rcct_Acquire(RC_FUNC_COPY)` @ `0x1423c5e`) | `FUN_011cc4e4` @ `0x011cc4f8` |
| VDT **RSIZE** | `FUN_011cd338` (`RC_FUNC_RESIZE` @ `0x1424319`) | `FUN_011cd608` @ `0x011cd61c` |
| VDT **RSIZ_STRM** | `FUN_011cf524` (string @ `0x1424a7b`) | `FUN_011cf814` (two exits: `0x011cf82c`, `0x011cf838`) |
| VDT **RSIZE_YUV** | `FUN_011d1844` (string @ `0x14253d7`) | `FUN_011d1b38` (two exits: `0x011d1b50`, `0x011d1b5c`) |
| decode-side flow (release-side only) | *not via `FUN_012d66f0`* | `FUN_011fbc88` `"ReleaseMain"` @ `0x011fbd00` |

The last row: `FUN_011fbc88` logs under `"ReleaseMain"`, programs `rcct_SetAicVmcParam`
(`FUN_012d7260`) and then releases (`FUN_012d67d8`), with an error string referencing
`SDF_INTRA_ERR_TIMEOUT` — a decoder/VC-side consumer whose acquire entry point is elsewhere
(unmapped; not one of the five `FUN_012d66f0` callers). So at least **six flows** touch the same
RC driver; pool capacity itself lives in the driver instance behind `FUN_012caf58` and was not
resolved statically.

### B.3 Why sustained writes exhaust the pool — what is shown vs. what is hypothesis

Established statically:
1. the develop path holds the RC lease across the whole job incl. completion wait (§B.1);
2. ≥6 flows contend on one RC driver (§B.2);
3. contention (`RC_ERR_BUSY`/`RC_ERR_ACQUIRED` → `0x80`) makes the **requesting thread block in a
   fixed-step loop: up to 100 × wait(20000 units) ≈ ≤2 s** (§A.3, units *HYPOTHESIS*);
4. on exhaustion the frame's develop job is dropped outright (return `0x80`, release skipped).

**HYPOTHESIS (write-pipeline linkage, not statically shown):** that the focus-bracket write
pipeline (cross-chip, ~44-frame buffer measured in Investigation 1) backpressures the SDF graph —
downstream buffers stay pinned until the write drains, develop jobs queue/linger, overlapping RC
demand from develop + preview/streaming flows crosses the pool's service rate, and the §A.3 retry
loop then *paces* the observed cadence degradation. This is not a static call-path result: SDF
module exec is dispatched data-driven by the graph scheduler, and no direct call edge from
`FUN_010592f4`/`FUN_01058430` to any write/recording subsystem function was found in av-cam.bin.
The mechanism *consistent with* Investigation 1's post-≈44-frame cadence cliff is that per-frame
acquire waits (and, past ~2 s of contention, outright develop-job drops) begin once contention
becomes sustained — but tying specific cliff timing to the 20 ms × 100 loop needs dynamic
confirmation.

### B.4 Open items

- Unit of the `20000` timeout (µs assumed); whether OS service `0x910041` is a plain timed sleep
  or a timed event/semaphore wait (40-byte block layout — status-out @`+0x14`, timeout @`+0x18` —
  is consistent with either).
- RC pool size / unit count: driver-internal, behind `FUN_012caf58`; unresolved.
- Which scheduler triggers `ModuleRcResizeSetAicParam::Exec` per frame, and its queue-depth
  behavior under backpressure: unmapped.
- Driver internals of `rcct_Acquire`→`FUN_012caf64` and `rcct_Release` `FUN_012d67d8`: unmapped.
- Acquire entry point of the decode-side `"ReleaseMain"` flow (§B.2, last row): unmapped.

## C. Scope / safety

- **Static analysis only.** Everything here comes from Ghidra decompilation/strings/xrefs of
  `av-cam.bin`; nothing was run on a camera in this job. All addresses are **Ghidra virtual
  addresses** (file at `fs/a3/av-cam.bin`), not load addresses or file offsets.
- **No firmware content reproduced.** The document cites addresses, log-string fragments (short),
  function symbols embedded as strings, and Ghidra pseudo-C paraphrased to mechanism level.
- **Own device / own firmware.** This is the user's legally obtained a7R V firmware, analyzed for
  a personal public write-up; no modification, patching, or exploitation is involved or enabled —
  the map describes resource arbitration that already happens at runtime.
- Cross-chip write-pipeline timing numbers (~44-frame buffer, post-cliff cadence) are **quoted
  from Investigation 1's measurements**, not re-derived here; this job supplies the software-side
  acquire/retry/release mechanism only.
- Ghidra artifacts: the binary is function-stripped (all identities recovered from embedded
  strings, so names like `ExecRcAcquire` are the firmware's own log strings, not linker symbols);
  `FUN_0102efc4`'s decompile carries Ghidra's "could not recover jumptable … treating indirect
  jump as call" warning, which does not affect the tail-call-to-service-table conclusion;
  pseudo-C in §A.3 is condensed, not verbatim. Enum-order inference in §A.4 is flagged
  *HYPOTHESIS* inline, as are the timeout unit and the write-pipeline linkage (§B.3).

## How this was checked

All via read-only Ghidra MCP tools against project `ghidra_avcam`, binary `av-cam.bin` (analysis
already complete at start). Symbol search returns nothing (stripped), so every function was found
**by embedded string → xref**, then **decompiled by address** (never by name, to avoid PLT-style
thunks):

1. `list_project_binaries` — confirmed `av-cam.bin` loaded/analyzed.
2. `search_strings` — anchors: `ExecRcAcquire`, `ExecRcRelease`, `MainProcess`,
   `ModuleRcBase.cpp`, `WrapRcctAcquire.cpp`, `WrapRcctRelease.cpp`, `ModuleRcResizeSetAicParam.cpp`,
   `rcct_Acquire`, `rcct_Release`, `api_rc.cpp`, `RC_ERR_`, `rcct_Acquire(`, `WaitCallbackRc`.
3. `list_xrefs` — on those string addresses to pin containing functions; on `012d66f0`
   (`rcct_Acquire`) and `012d67d8` (`rcct_Release`) to enumerate all pool consumers/releasers; on
   `01058430`/`01058670` to confirm single-caller status.
4. `decompile_function` (by address) — `01058430`, `01058670`, `010592f4`, `01059548`,
   `01063eac`, `01063f98`, `01064070`, `01064714`, `0102efc4`, `012d66f0`, `011fbc88`.
5. `read_bytes("0x01305fc0", 48)` — the raw 11-entry error→status table of §A.4.

No AArch64 binutils available on this host; disassembly cross-checks were not needed — every
mechanism claim rests on the decompiled pseudo-C plus string/xref anchors listed inline above.
Questions or corrections welcome — §B.4 lists what remains unproven.
