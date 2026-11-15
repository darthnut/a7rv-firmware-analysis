# Develop-resource acquire — the write-cliff mechanism (`av-cam.bin`)

**Summary.** The focus-bracket post-~44-frame write cliff is an SDF develop-resource acquire/retry loop in
`av-cam.bin`: the camera holds an RC hardware-engine lease across a whole resize job, and under pool
contention the requesting thread blocks in a fixed-step retry loop (≤100 × a 20000-unit wait) and
eventually drops the frame's develop job.

**Where.** `av-cam.bin` (project `ghidra_avcam`, function-stripped — names from embedded log strings,
Ghidra VAs). `ModuleRcBase::ExecRcAcquire` `FUN_01058430`; caller `ModuleRcResizeSetAicParam::Exec`
`FUN_010592f4`; `WrapRcctAcquire::Api_Exec` `FUN_01063f98` → `rcct_Acquire` `FUN_012d66f0`; release chain
`ExecRcRelease` `FUN_01058670` → `rcct_Release` `FUN_012d67d8`; error table at `0x01305fc0`.

**Mechanism.**
- **The resource** is an RC (reduce/convert) hardware-engine context handle (`acquire_id`) from the
  `rcct` driver, stored at `ctx+0xc` and released by `ExecRcRelease`.
- **The retry loop:** attempt acquire; on status **`0x80`** (retryable), log "retry rcct_acquire START",
  then up to **100** iterations of `{wait via OS service 0x910041, 40-byte block, timeout 20000}` + retry;
  on exhaustion return `0x80` with id zeroed; a wait failure returns `0x100`.
- **`0x80` = BUSY or ACQUIRED** (the 11-entry error table at `0x01305fc0`, byte-read: `RC_ERR_BUSY` and
  `RC_ERR_ACQUIRED` both map to `0x80`) — a **pool/unit-contention** condition, not a parameter or HW
  fault; every other error returns immediately.
- **The lease is held across the whole HW job:** acquire → program AIC params → submit → **`WaitCallbackRc`
  blocking wait for HW completion** → release *unconditionally*. So hold time ≈ full job runtime, and the
  waiting thread is the one that would re-acquire next frame.
- **≥6 flows share the pool** (SDF develop + VDT RCOPY/RSIZE/RSIZ_STRM/RSIZE_YUV + a decode-side
  "ReleaseMain"). An identity resize with no AIC extras skips the acquire entirely.

**Verification.** *light.* The acquire path, caller, wrapper, release chain, and the error table are
decompiled/byte-read; the retry bound (100) and the `0x80` retry condition read directly from the loop;
the "lease held across the completion wait" established from `FUN_010592f4`'s ordering. The whole binary
was function-stripped, so every identity comes from embedded strings → xref.

**Boundary / open.** The **unit of the `20000` timeout is HYPOTHESIS** (µs → ~2 s worst case; the write-
pipeline-linkage math in Investigation 1 depends on this). The **RC pool size / unit count is
driver-internal** (behind `FUN_012caf58`), unresolved. The tie to the cross-chip write pipeline is
**HYPOTHESIS, not a static call-path result**: SDF module exec is dispatched data-driven by the graph
scheduler, and no direct call edge from the acquire path to any write/recording subsystem was found. The
cadence measurements are quoted from [Investigation 1](../../investigations/01-focus-bracket-cadence.md),
not re-derived here. See [OPEN-QUESTIONS.md](../../OPEN-QUESTIONS.md) item 7.

**Source.** [framework-runs/develop-map.md](../../framework-runs/develop-map.md)
