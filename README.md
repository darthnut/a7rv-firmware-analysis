# Sony a7R V — firmware analysis

**Purpose.** An analysis of the Sony a7R V's firmware. The goal is to understand how
the camera works and to identify potential areas for improvement through firmware
modification. This is reverse engineering of my own camera, for interoperability and
understanding — **no Sony firmware is redistributed here**, only byte offsets and
derived analysis.

> **Working ethos.** Map first, measure before modifying, and never present an
> untested change as a mod to flash. Where an investigation turns up a candidate
> firmware lever, it's documented as a *hypothesis* with its evidence and its risk,
> not a recipe. Modifying and flashing camera firmware can permanently brick the
> device; anything here is acted on only on a body someone is willing to lose, and
> only once there's a measured reason to.

## How this is organized

- **Investigations** — each one states what we wanted to improve, what the binary
  actually shows, and whether there's a firmware lever worth pursuing. The first is
  below.
- **[docs/method.md](docs/method.md)** — shared tooling, the Ghidra setup, the
  `movw`/`movt` address-resolution trap, and a running address reference.
- **[docs/patch.md](docs/patch.md)** — detailed risk write-up for the one candidate
  patch we found.
- **[TESTING.md](TESTING.md)** / **[RESULTS.md](RESULTS.md)** — empirical protocols
  and their measured results, because the binary only tells half the story.

---

# Investigation 1 — focus-bracket cadence

**The question:** why do some in-camera focus-bracket stacks run slow while others
run fast? Is the slowdown a settings/flash effect fixable today, something physical,
or a firmware lever worth pursuing?

> **Status — settled.** Two independent lines of evidence now converge: a controlled
> bench test (cadence measured from EXIF capture timestamps, [RESULTS.md](RESULTS.md))
> and a complete static reverse-engineering sweep of `cpapp-b.bin`. **Neither the
> fast-zone cadence nor the slowdown is a tunable camera-firmware constant.** The one
> patch we found is real but low-value. The honest answer is below.

## TL;DR

Focus-bracket cadence has **two regimes, two different limiters — neither one a
camera-firmware timer:**

- **Short stacks (≤ ~44 frames): paced by focus-step overhead.** A fastest-burst
  reference (no focus stepping) runs ~**9 VD fields** (0.151 s ≈ 6.6 fps) — the
  capture+write ceiling. Focus Bracket's fast zone runs ~**20 fields** (0.34 s). The
  gap, **~11 fields (~0.19 s) per frame, is the lens physically moving and settling
  between shots** — identical tethered vs untethered, flash on vs off. Static RE
  confirms this is **not a firmware delay**: the "Focus Step Width" menu loads a move
  *distance*, not a timer, and there is **not a single kernel-sleep call in the entire
  ~1,300-function focus-bracket sequencer.** The settle lives in the lens (MCU /
  lens-file data), not in `cpapp`.
- **Long stacks (> ~44 frames): paced by the write-pipeline cliff.** The buffer
  absorbs ~44 frames at full speed, then cadence collapses to the sustained
  write/transfer rate. Static RE locates the *shape* of this stall (an SDF
  develop-resource acquire retry loop) but shows the **buffer pool itself lives in a
  different binary — the develop subsystem (`av-cam.bin`), not `cpapp`.** No
  image-buffer depth constant exists in `cpapp` to tune.

The original fast/slow memory maps onto **pre-cliff vs post-cliff** (and onto the
save path: card-only post-cliff ≈ 36 fields, tethered-to-both ≈ 95–116 fields).

**The one firmware lever we found — a 2-byte relaxation of an STP buffer-full gate —
is real and verified in the binary, but touches neither the 11-field focus overhead
nor the write cliff.** It is documented below for completeness, not recommended.

## Background: the VD field quantization

The capture pipeline is clocked by a "VD" scheduler.

- 1 VD field = **500 ticks = 16.6833 ms**.
- Cadence is quantized to whole fields. Measured points: **9 fields** (burst ceiling),
  **~20 fields** (focus-bracket fast zone, tethered), **~36 fields** (card-only slow
  stacks, post-cliff), **~95–116 fields** (tethered-to-both, post-cliff).

Because cadence is quantized, the differences are discrete field counts, not smeared
timing — which is what let the bench test and the disassembly line up frame-for-frame.

## What paces it — the decomposition

Measured on the bench (see [RESULTS.md](RESULTS.md)), then cross-checked against the
binary:

| regime | cadence | what limits it | firmware lever? |
|---|---|---|---|
| burst, no focus step | **9 fields** (0.151 s) | capture + write ceiling | n/a (this is the floor) |
| focus-bracket, fast zone (≤~44 frames) | **20 fields** (0.34 s) | **lens move + settle** (~11 fields on top of capture) | **no** — physical; no delay constant in `cpapp` |
| focus-bracket, past the cliff | 36–116 fields | **write pipeline** at buffer-full | not in `cpapp` — pool is in `av-cam.bin` |

The ~11-field focus-step overhead decomposes (bench-anchored bounds, static-informed
split) as: lens physical move ~5–8 fields (per-lens, in the lens motor/data), 2–3
VD-quantized comm hops where **the send/reply slots are reported by the lens**, and
≤4 fields of camera-side margin guards. The only part that lives in the camera and is
even arguably tunable is those ≤4 fields of margin — and they're lens-protocol-timing
risky (see the lever table).

## Static analysis — what is, and isn't, in `cpapp`

A full sweep of the focus-bracket and capture paths in `cpapp-b.bin` (Ghidra, ~1,300
decompiled sequencer functions) established these, each grounded in the binary with
offsets and decompiled evidence:

- **The focus-step calculator** is at file `0x27D2F0` / VA `0x3852F0`. Per-frame lens
  target = start/last position ± step, where
  `step = TABLE[idx] × (lens_ctx[0xE] >> 1) × dir`, clamped to the lens near/far
  limits. The **step table** is at file `0x27D384` / VA `0x385384`: 10 × u16,
  `{32, 42, 53, 64, 74, 85, 96, 106, 117, 128}` (verified byte-for-byte). The menu
  "Focus Step Width" selects where on this ramp a run operates — so a larger width is
  a **larger physical move per frame, not a longer delay.**
- **Zero kernel-sleep calls** (the `FUN_005CAAFC` sleep primitive) exist anywhere in
  the decompiled sequencer set. There is **no camera-side settle/delay constant** in
  the focus path to trim. This is the decisive negative for the short-stack regime.
- **The write cliff's stall shape** is an SDF develop-resource acquire retry loop —
  `ModuleRcBase::ExecRcAcquire`, file `0x3484F0` / VA `0x4504F0`: the acquire returns
  `0x80` (busy) and the loop retries up to 100 times, posting a wait message each
  pass. But the **buffer pool behind that acquire chain lives in the cross-processor
  develop manager (`av-cam.bin`), not `cpapp`** — no image-buffer depth constant
  surfaced in any `cpapp` sweep.

## The one lever we found: the STP buffer-full gate (real, but low-value)

Function at **file offset `0x4196B4`** (Ghidra VA `0x5216B4`; load base `0x108000`,
so VA = file offset + `0x108000`). The relevant branch:

```c
if (param_2 == 4) {
    if (DAT_019d22c0 != '\0') {            // sticky "already full" flag -> bail
        return;
    }
    if (DAT_0115e994 < iVar1 * 2 + 0x28U) {   // need = 0x28 + 2*r   (THE GATE)
        iVar1 = FUN_005fe578(auStack_114, 0xec,
                             s__STP_ERROR___BUFFER_FULL____00521798);
        DAT_019d22c0 = '\x01';             // latch full
    }
    DAT_0115e994 = DAT_0115e994 + (-0x14 - iVar1);   // consume = 0x14 + r
}
FUN_00b6c2f2(param_2, &uStack_128, iVar1 + 0x14);    // send msg of (r + 0x14) bytes
if (DAT_019d22c0 == '\x01') {
    DAT_0119424a = '\0';                   // disable this whole path once full
}
```

- **Availability check** demands `need = 0x28 + 2·r`; **actual consumption** is
  `consume = 0x14 + r` — roughly **2× headroom**, pure policy slack.
- **Pool counter** `DAT_0115E994` initializes to **16364 (≈16 KB)**; xref analysis
  (95k resolved `movw`/`movt` refs) shows **only this gate** touches it. It is a
  **~16 KB request-*message* staging pool, not image data** — it literally logs
  `[STP_ERROR]: BUFFER FULL!!!` and latches trace off when full.

**The candidate patch** relaxes the 2× headroom to 1×:

| file offset | before | after | instruction change |
|---|---|---|---|
| `0x41973E` | `28` | `14` | `movs r1,#0x28` → `movs r1,#0x14` |
| `0x419746` | `40` | `00` | `add.w r2,r1,r0,lsl#1` → `add.w r2,r1,r0` |

Two bytes, re-disassembled before/after with capstone; original bytes confirmed in
the shipping `cpapp-b.bin`. See [docs/patch.md](docs/patch.md) for the risk write-up.

> ### ⚠ Why this isn't the answer.
> The bench test and the static sweep agree that this gate guards a trace/request
> message pool that is **distinct from the SDF/develop path governing the ~44-frame
> write cliff**, and it has nothing to do with the physical focus-step overhead that
> paces the short stacks actually shot. It is a real, verified lever that moves
> neither of the two things that actually pace focus bracketing. Do not treat it as a
> mod to flash.

## Lever table (final)

| candidate lever | where | verdict |
|---|---|---|
| STP message-gate 2×→1× headroom | file `0x41973E`/`0x419746` | **real, verified — but low-value**; touches neither the 11-field overhead nor the write cliff |
| focus-step settle constant | — | **does not exist** (zero sleeps in the path) |
| step-width table shrink | file `0x27D384` | works, but it's the **existing menu setting** by another name (pure geometry — smaller moves, but more frames for the same depth) |
| VD comm-window margins | file `0x3B5C26`/`0x9EEA46` | ≤4 fields best case, **lens-protocol-timing risk** (slots are lens-defined) |
| write-cliff buffer depth | — | **not in `cpapp`** — lives in the develop subsystem (`av-cam.bin`), unanalyzed |

## Practical takeaways (no firmware needed)

- **Keep stacks ≤ ~44 frames** to stay in the fast zone; deep stacks hit the write
  wall.
- To go faster in the fast zone, the real levers are physical: a **smaller focus-step
  width** (shorter lens moves) or a **faster-focusing lens** — the camera firmware has
  no delay to trim there.
- To push the cliff later / raise the post-cliff rate: **compressed / lossless RAW**
  (smaller files), a **faster card**, and a lighter save path (card-only beats
  tethered-to-both). These are measured next steps, not firmware.

## Where this could still go (outside `cpapp`)

Two avenues remain, both beyond what the current analysis covers:

1. **`av-cam.bin` (the develop subsystem).** The ~44-frame write-buffer pool lives
   here, not in `cpapp`. If any image-buffer depth is tunable, this is where it would
   be — unanalyzed so far.
2. **Dynamic instrumentation.** Splitting the ~11-field focus overhead empirically
   into lens-move vs comm-hop (e.g. via the firmware's own `ImagerSeqLog`) would
   confirm the static inference and bound exactly how much, if any, is camera-side.

---

# Investigation 2 — other customization surfaces

**The question:** with the cadence question settled, where *else* in the firmware is
there room to customize or improve the camera? This is a breadth-first **map**, not a
set of mods — each surface is recorded with what the binary shows and how hard it
would actually be to do anything with it. Nothing here is pursued to a working change.

## TL;DR

Five surfaces surveyed in `cpapp-b.bin` and the a15 Linux partition. The most
interesting is a **dormant factory service stack**; the rest are reference material or
dead ends.

- **Dormant SSH / service stack (a15).** The camera ships, unused, a full SSH service
  — `sbin/sshd`, a host-key generator, and `libInfraSSHManager.so`
  (`network::InfraSshManager`). The boot chain is mapped: `bin/im.elf` (power/boot
  manager, `C3P_PACKET` inter-process protocol) → `bin/sen.elf` (SENSER core v1.3.4,
  reads a numeric "smode" from a cascade of `/boot`, `/setting`, `/var` paths) →
  service stack. **The gate is a factory service token** (a HASP check at
  `/setting/.hasp`) plus the right smode: SSH is provisioned only when Sony's factory
  tool connects. *Feasibility: medium-hard — it would mean defeating the token check,
  i.e. a focused reverse-engineering project on its own, not a setting or a flag flip.
  Documented as a surface, not attempted.*
- **Command-dispatcher catalog — 288 commands mapped.** Every internal
  `SET_` / `PID_SET_` / `PUSH_` command was paired with its handler offset and log
  string (e.g. imager-mode, power-save, and drive commands). This is a reference for
  any future tether/remote work. Note: the **external** exposure layer (PTP / the
  Creators' App remote API) is **not** in `cpapp` — no PTP strings there; it lives in
  the USB-gadget / network daemons on a15, unanalyzed. The full catalog is kept in the
  working notes rather than committed here.
- **`ImagerSeqLog` — the camera's own timing instrument.** The sequence logger that
  would let us split the ~11-field focus overhead empirically (see Investigation 1's
  open items) was located: log sites call a trace-category gate (`0x278B8C`, channel
  `0x1C`) into an ARM-side category registry, writing `{id, payload, u64 timestamp}`
  on the same kernel timebase. **Enabling a category is a service/debug action — almost
  certainly the same gated service stack above.** So the diagnostic win and the SSH
  surface are the same lock.
- **PowerSave handler** (`0x27C144` / VA `0x384144`). Imager power sequencing mapped —
  sensor-drive register writes and training waits. This is **frame-to-frame imager
  sleep logic, not the thermal-limit table**; the thermal constants remain unfound.
- **Cosmetic / flags — nothing actionable.** `SysSound.bin` is a packed sound bank
  (no plaintext, format RE needed before any replacement). A `debug_mode` string that
  looked promising was run down and **closed**: it's a field name inside a VD-drive
  register-dump format, not a global debug switch.

**Bottom line.** The one surface with real leverage (SSH / service access, which would
also unlock the `ImagerSeqLog` diagnostics) sits behind a factory-tool token, not a
config flag. It's a legitimate future RE target but a substantial one, and it is only
mapped here — not defeated.

---

# Investigation 3 — a7R VI firmware (blocked)

**The question:** can the same approach read the newer a7R VI body firmware?

**Answer: no — blocked at the crypto, and no feature claims are made from it.** The a7R
VI update package (`BODYDATA`, ~338 MB) is the same UFU container family, but the
package-format version has moved on (`DATV = 04` vs the a7R V's `01`) and the payload
is **fully encrypted** — entropy 8.00/8 throughout, no plaintext islands. The a7R V
(Gen5) AES keys were tested against every plausible header / frame / trailer split and
produced **zero valid checksums**: they do not apply. The 338 MB size (vs the a7R V's
751 MB plaintext) suggests a **partial / delta** package rather than a full image.

Reading it would require the a7R VI generation's updater keys (the kind of thing that
historically comes from community RE of the updater), or a flash dump taken off the
body directly. Until then, **nothing about a7R VI features can be asserted from this
file** — anything claimed would be speculation, and is deliberately not recorded here.

---

## Method

- Target: `cpapp-b.bin` (flat ARM/Thumb-2 image, Ghidra load base `0x00108000`).
- Tooling: Ghidra 12.2 headless + Temurin JDK 25; scripts to force Thumb mode, dump
  xrefs/callers, and resolve `movw`/`movt` immediate address pairs (this firmware
  builds RAM addresses with immediate pairs, not literal pools — a naïve literal
  scan finds nothing, which is a trap). Byte-level checks with a standalone Python
  verifier.
- Empirical cadence measured from each frame's EXIF `DateTimeOriginal` +
  `SubSecTimeOriginal`, segmented into stacks by time gap and reported in VD fields.
- See [docs/method.md](docs/method.md) for detail.

## Legal & safety

- This is reverse engineering of **my own camera**, for interoperability and
  understanding. **No Sony firmware is redistributed here** — only byte offsets and
  derived analysis.
- Nothing here is validated on hardware. Modifying and flashing camera firmware can
  **permanently brick** the device and will void any warranty. If you act on this,
  do it only on a body you are prepared to lose, and only after an empirical test
  gives a reason to.
