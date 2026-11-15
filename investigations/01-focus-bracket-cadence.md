# Investigation 1 — focus-bracket cadence

**The question:** why do some in-camera focus-bracket stacks run slow while others run fast? Is the
slowdown a settings/flash effect fixable today, something physical, or a firmware lever worth
pursuing?

> **Status — settled.** Two independent lines of evidence converge: a controlled bench test (cadence
> measured from EXIF capture timestamps, [RESULTS.md](../RESULTS.md)) and a complete static
> reverse-engineering sweep of `cpapp-b.bin` — extended with a follow-on decode that traced the frame
> trigger's dispatch sites and located the one camera-side settle constant, and with a full trace of
> the write-cliff into `av-cam.bin`. **Neither the fast-zone cadence nor the slowdown is meaningfully
> tunable in camera firmware** (the one located constant buys ≤2–3 fields at real risk; the write
> cliff has no patchable depth). The honest answer is below.

Related reference pages: the develop-resource arbitration behind the write cliff is
[findings/behavior/develop-resource-acquire.md](../findings/behavior/develop-resource-acquire.md); the
cross-processor log queue noted below is on the OSAL fabric
([findings/transport/osal-uipc.md](../findings/transport/osal-uipc.md)); machine-readable timeline at
[reference/frame-cycle-data.json](../reference/frame-cycle-data.json).

## TL;DR

Focus-bracket cadence has **two regimes, two different limiters — neither one a camera-firmware
timer:**

- **Short stacks (≤ ~44 frames): paced by focus-step overhead.** A fastest-burst reference (no focus
  stepping) runs ~**9 VD fields** (0.151 s ≈ 6.6 fps) — the capture+write ceiling. Focus Bracket's
  fast zone runs ~**20 fields** (0.34 s). The gap, **~11 fields (~0.19 s) per frame, is one serial
  lens-move cycle the bracket FSM inserts between exposures** — identical tethered vs untethered,
  flash on vs off. The follow-up decode settles the mechanism precisely (see
  [*The frame cycle, end to end*](#the-frame-cycle-end-to-end)): 1 field to compute+send the move,
  ~6 fields of physical lens travel (polled), a hard-coded **4-field settle** (file `0x27D4B4`), then
  the unchanged 9-field imaging segment. The bulk is lens physics; the settle is the one camera-side
  constant.
- **Long stacks (> ~44 frames): paced by the write-pipeline cliff.** The buffer absorbs ~44 frames at
  full speed, then cadence collapses to the sustained write/transfer rate. The stall is an SDF
  develop-resource acquire retry loop whose server **traces fully into `av-cam.bin`** (the develop
  subsystem — the acquire chain, resource server, and memory manager all live there). The key result:
  the pool's size is **runtime-configured** (`CdMemMgr` / `SetMemArea`), so the ~44-frame depth is
  emergent from boot-time byte-capacity vs frame size — there is **no patchable depth constant
  anywhere**, in `cpapp` or `av-cam`.

The original fast/slow memory maps onto **pre-cliff vs post-cliff** (and onto the save path: card-only
post-cliff ≈ 36 fields, tethered-to-both ≈ 95–116 fields).

**The one firmware lever found — a 2-byte relaxation of an STP buffer-full gate — is real and verified
in the binary, but touches neither the 11-field focus overhead nor the write cliff.** It is documented
below for completeness, not recommended.

## Background: the VD field quantization

The capture pipeline is clocked by a "VD" scheduler.

- 1 VD field = **500 ticks = 16.6833 ms**.
- Cadence is quantized to whole fields. Measured points: **9 fields** (burst ceiling), **~20 fields**
  (focus-bracket fast zone, tethered), **~36 fields** (card-only slow stacks, post-cliff), **~95–116
  fields** (tethered-to-both, post-cliff).

Because cadence is quantized, the differences are discrete field counts, not smeared timing — which is
what let the bench test and the disassembly line up frame-for-frame.

## What paces it — the decomposition

Measured on the bench (see [RESULTS.md](../RESULTS.md)), then cross-checked against the binary:

| regime | cadence | what limits it | firmware lever? |
|---|---|---|---|
| burst, no focus step | **9 fields** (0.151 s) | capture + write ceiling | n/a (this is the floor) |
| focus-bracket, fast zone (≤~44 frames) | **20 fields** (0.34 s) | **serial lens-move cycle** (~11 fields: 1 send + ~6 travel + 4 settle) on top of capture | settle constant exists (`0x27D4B4`) but buys ≤2–3 fields at real risk; travel is lens physics |
| focus-bracket, past the cliff | 36–116 fields | **write pipeline** at buffer-full | in `av-cam.bin` (develop subsystem) — runtime-configured, **no static constant** |

The ~11-field focus-step overhead decomposes as: **1 field** to compute+send the move, **~6 fields** of
lens physical travel (lens- and width-dependent), and **4 fields of hard-coded camera-side settle** —
event hops contribute ~0 (GetSendTiming's window is µs-scale, not field-scale). The only camera-side
time constants in the path: that settle and the 60-field abort cap.

## Static analysis — what is, and isn't, in `cpapp`

A full sweep of the focus-bracket and capture paths in `cpapp-b.bin` (Ghidra, ~1,300 decompiled
sequencer functions) established these, each grounded in the binary with offsets and decompiled
evidence (VA = file offset + `0x108000`):

- **The focus-step calculator** is at file `0x27D2F0` / VA `0x3852F0`. Per-frame lens target =
  start/last position ± step, where `step = TABLE[idx] × (lens_ctx[0xE] >> 1) × dir`, clamped to the
  lens near/far limits. The **step table** is at file `0x27D384` / VA `0x385384`: 10 × u16,
  `{32, 42, 53, 64, 74, 85, 96, 106, 117, 128}` (verified byte-for-byte). The menu "Focus Step Width"
  selects where on this ramp a run operates — so a larger width is a **larger physical move per frame,
  not a longer delay.**
- **Zero kernel-sleep calls** (the `FUN_005CAAFC` sleep primitive) exist anywhere in the decompiled
  sequencer set — the *bracket* overhead is not a sleep-based delay. But the follow-up decode **did
  locate one hard-coded camera-side wait**: a fixed **4-field settle** in the bracket FSM (state 2),
  byte-verified at file `0x27D4B4` (`cmp r0,#4`, bytes `04 28`). There is no *sleep-based* delay, but
  there *is* a poll-count settle.
- **The write cliff's stall shape** is an SDF develop-resource acquire retry loop —
  `ModuleRcBase::ExecRcAcquire`, file `0x3484F0` / VA `0x4504F0`: the acquire returns `0x80` (busy)
  and the loop retries up to 100 times. That chain **traces fully into `av-cam.bin`** (10,654
  functions, opened and analyzed): the server-side `ExecRcAcquire` (`FUN_01058430`) → `rcct_Acquire` →
  `RcDriver::AcquireSeqCtrl`, which walks four exec-ctrl objects — any busy returns the `0x80` the
  `cpapp` client sees. The memory behind them (`CdMemMgr`) is **configured at runtime**
  (`SetMemArea_ENC/DEC`), so the ~44-frame depth is emergent from boot-time byte-capacity — **not a
  static constant**, in `cpapp` or `av-cam`. Full mechanism:
  [findings/behavior/develop-resource-acquire.md](../findings/behavior/develop-resource-acquire.md).

## The frame cycle, end to end

A follow-on pass resolved the remaining open questions in the lens-timing decode — where the frame
trigger is dispatched from, why nothing overlaps, and the exact camera-side floor. This is the
per-frame timeline the [interactive page](https://darthnut.github.io/a7rv-firmware-analysis/docs/frame-cycle.html)
draws. All offsets are `cpapp-b.bin` file offsets (VA = file + `0x108000`); all constants byte-verified
with capstone.

### One bracket frame ≈ 20 VD fields (0.34 s), fully serial

| # | Stage | Fields (typ.) | Bound | What happens | Code anchor (file) |
|---|---|---|---|---|---|
| 0 | **Frame kick** | (in-stage) | — | After the *previous* frame's readout, the still-execute pipeline enters its capture-init stage (`Stg>CapInit` / `Stg>CapInitLv`), packs the per-frame request, and calls the bracket trigger: request(`0x8594A8`) + kick(`0x859504`) → the FSM's pending-kick flag. The trigger also emits an event whose handler sets flag byte `0x0158829A`. | stage bodies file `0x36EBDC` (call site VA `0x47EED2`) and file `0x363BD8` (call site VA `0x473E52`); trigger `0x85BA62` |
| 1 | **FSM state 0 — compute + send** | 1 | exactly 1 per invocation | Target = `step_table[idx] × lens scaling`, clamped; sent as one `MOVE_FC_A` (cmd `0x43`) lens command, **fixed drive profile 0** | FSM body `0x27D398`, case 0; target calc `0x27D2F0`; send chain `0x91603E` → `0x928A86` → payload builder `0x2CB7E4` (trace `BL:MOVE_FC_A`) |
| 2 | **FSM state 1 — lens travel wait** | ~6 (bench-derived) | 1–60 (abort cap) | Polls the *camera-generic* move-done gate once per field | case 1; poll `0x9160FA`; timeout `cmp r0,#0x3C` @ `0x27D48C` (bytes `3c 28`) |
| 3 | **FSM state 2 — fixed settle** | **4 (exact)** | exactly 4 | A hard-coded poll counter must reach 4 before the focus-window validation runs; the **one camera-side time constant** in the move path | case 2; settle `cmp r0,#4` @ **`0x27D4B4`** (bytes `04 28`); retry cap `cmp r0,#0xB` @ `0x27D55A` |
| 4 | **FSM state 3 — parked / exposure** | ~9 | ≥9 (imaging) | FSM idles; the stage pipeline arms and runs the exposure + readout — the same 9-field segment a plain burst frame costs | case 3 (empty body); exposure arm on the `EC_ExpWait`/`SetupCap` path |

**Why bracket runs at ~20 fields while bursts run at 9:** the move cycle (states 0–2, ~11 fields) is
inserted *between* imaging cycles, and the exposure stage cannot arm until the FSM parks in state 3.
There is no overlap path in the code. The bench's exact 20 (= ~11 move-side + 9 imaging) confirms the
two halves are strictly additive with no hidden idle.

**Camera-side floor:** with an idealized zero-travel lens, states 0+2 cost 1+4 = 5 fields plus at least
one poll-tick for state 1 → ~6 fields of body-fixed overhead, so even a magic lens could not beat ~15
fields (4 fps) for this drive profile. The only camera-side time constants in the whole path: the
**4-field settle** (`0x27D4B4`) and the 60-field abort cap (`0x27D48C`). Travel time (state 1) is lens
physics.

**Drive-profile note:** all five public `MOVE_FC_A` send variants (family `0x928A86`–`0x928CBC`) pass
fixed literals for the drive/flag bytes; the bracket path uses the plain variant (drive 0). No
bracket-specific fast/slow drive selection exists in `cpapp`; whether the lens interprets those bytes
as motor speed is lens-side (OPEN).

## The one lever found: the STP buffer-full gate (real, but low-value)

Function at **file offset `0x4196B4`** (VA `0x5216B4`). The relevant branch:

```c
if (param_2 == 4) {
    if (DAT_019d22c0 != '\0') {            // sticky "already full" flag -> bail
        return;
    }
    if (DAT_0115e994 < iVar1 * 2 + 0x28U) {   // need = 0x28 + 2*r   (THE GATE)
        iVar1 = FUN_005fe578(auStack_114, 0xec, s__STP_ERROR___BUFFER_FULL____00521798);
        DAT_019d22c0 = '\x01';             // latch full
    }
    DAT_0115e994 = DAT_0115e994 + (-0x14 - iVar1);   // consume = 0x14 + r
}
FUN_00b6c2f2(param_2, &uStack_128, iVar1 + 0x14);    // send msg of (r + 0x14) bytes
if (DAT_019d22c0 == '\x01') {
    DAT_0119424a = '\0';                   // disable this whole path once full
}
```

- **Availability check** demands `need = 0x28 + 2·r`; **actual consumption** is `consume = 0x14 + r` —
  roughly **2× headroom**, pure policy slack.
- **Pool counter** `DAT_0115E994` initializes to **16364 (≈16 KB)**; xref analysis (95k resolved
  `movw`/`movt` refs) shows **only this gate** touches it. It is a **~16 KB request-*message* staging
  pool, not image data** — it literally logs `[STP_ERROR]: BUFFER FULL!!!` and latches trace off when
  full.

> **Cross-processor closure (the "missing replenisher").** The gate only ever *decrements* the
> counter; the matching replenish is never visible in `cpapp`. The likely reason: the counter is
> balanced from the **other processor.** The gate sends into a shared UIPC queue (`0x8F013A`); on the
> a15 Linux side, `sen.elf`'s log forwarder posts into that **same** queue — and `0x8F013A` is
> referenced on both sides (see [findings/transport/osal-uipc.md](../findings/transport/osal-uipc.md)
> and [findings/service-mode/senser-power-daemon.md](../findings/service-mode/senser-power-daemon.md)).
> So the STP pool looks like a **cross-processor** structure, which would explain why the balancing
> write is invisible to `cpapp`-only analysis. **The a15-side write to the counter itself was not
> observed** — strong circumstantial evidence, not a located writer.

**The candidate patch** relaxes the 2× headroom to 1×:

| file offset | before | after | instruction change |
|---|---|---|---|
| `0x41973E` | `28` | `14` | `movs r1,#0x28` → `movs r1,#0x14` |
| `0x419746` | `40` | `00` | `add.w r2,r1,r0,lsl#1` → `add.w r2,r1,r0` |

Two bytes, re-disassembled before/after with capstone; original bytes confirmed in the shipping
`cpapp-b.bin`. See [docs/patch.md](../docs/patch.md) for the risk write-up.

> ### ⚠ Why this isn't the answer.
> The bench test and the static sweep agree that this gate guards a trace/request message pool that is
> **distinct from the SDF/develop path governing the ~44-frame write cliff**, and it has nothing to do
> with the physical focus-step overhead that paces the short stacks actually shot. It is a real,
> verified lever that moves neither of the two things that actually pace focus bracketing. Do not treat
> it as a mod to flash.

## Lever table (final)

| candidate lever | where | verdict |
|---|---|---|
| STP message-gate 2×→1× headroom | file `0x41973E`/`0x419746` | **real, verified — but low-value**; touches neither the 11-field overhead nor the write cliff |
| focus-step settle constant | file `0x27D4B4` | **located**: a hard 4-field settle counter in FSM state 2, bytes `04 28`, **one-byte patchable** — but buys ≤2–3 fields (~50 ms/frame) and the settle exists to let the focus-window check see a still image; trimming it risks window-check retries (≤12 budget) and soft-focus frames. High-risk, small reward. |
| bracket move drive profile | family `0x928A86`–`0x928CBC` | bracket uses the plain fixed profile (drive 0); no faster profile is *selected* anywhere in `cpapp`. Whether a faster profile exists is lens-side (OPEN). |
| step-width table shrink | file `0x27D384` | works, but it's the **existing menu setting** by another name (pure geometry) |
| VD comm-window margins | file `0x3B5C26`/`0x9EEA46` | **refuted as a field-scale cost** by the ns-reading of GetSendTiming (2 µs margins) |
| move/exposure overlap | — | **structurally absent**: the kick is issued from the *next* frame's capture-init and the settle gate precedes the FSM park the exposure stage waits on |
| write-cliff buffer depth | — | **in `av-cam.bin`** (develop subsystem, verified) — runtime-configured (`CdMemMgr`/`SetMemArea`), **no patchable constant** |

## Practical takeaways (no firmware needed)

- **Keep stacks ≤ ~44 frames** to stay in the fast zone; deep stacks hit the write wall.
- To go faster in the fast zone, the real levers are physical: a **smaller focus-step width** (shorter
  lens moves) or a **faster-focusing lens** — the camera firmware has no delay to trim there.
- To push the cliff later / raise the post-cliff rate: **compressed / lossless RAW** (smaller files), a
  **faster card**, and a lighter save path (card-only beats tethered-to-both). These are measured next
  steps, not firmware.

## An unreconciled loose end (old 26 vs new 20 fields)

Earlier card-only data put the *fast* zone at **26 fields**; this bench puts it at **20 fields**. The
leading candidate is a **flash-recycle interlock**: a release-lock manager (`cpapp` file `0x2213CC`)
holds an `SB_CHARGE` lock, and the next exposure waits for charge-complete (a 20000-unit charge-wait at
file `0x2214E8`). The decode of that charge-wait is byte-verified, but the wall-clock turns on the
tick-period's unit, which the code does not state (µs → ~20 s; ns → ~20 ms) — so it **sharpens** the
flash-recycle hypothesis without closing it. The decisive test is empirical; see
[RESULTS.md](../RESULTS.md) (*Still to measure*) and [TESTING.md](../TESTING.md).
