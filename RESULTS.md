# Empirical cadence results

Measured 2026-10-27, tethered via Imaging Edge Remote, cadence read from each
frame's EXIF capture clock (`DateTimeOriginal` + `SubSecTimeOriginal`, ~0.01 s
resolution — confirmed fine enough to resolve a 0.3–0.6 s cadence). 1 VD field =
16.6833 ms.

## Setup

- Camera: ILCE-7RM5 (a7R V), tethered USB, PC Remote. Firmware **version 4.00** —
  the same firmware version as the `cpapp-b.bin` analyzed in this repo.
- Lens: 100 mm macro, tripod, static subject. Drive: **Focus Bracket**.
- Save destination: **PC + Camera card** (both) for all stacks below.
- RAW-L, ~60 MB/frame.
- Exposure: baseline M 1/200 f/6.3 ISO 100 (flash tests); the long flash-off run
  was M 1/40 f/5.6 ISO 1000 (opened up for no flash). Exposure is timing-neutral
  here — shutter ≪ frame interval, RAW size ~constant — so it does not affect the
  result.

## Measured stacks

| # | condition | frames | pre-cliff cadence | cliff at | post-cliff cadence |
|---|---|---|---|---|---|
| v0 | tethered, flash OFF | 25 | **20 fields** (0.334 s) | — (too short) | — |
| F1 | tethered, flash **ON** | 50 | **20 fields** (0.336 s) | frame ~45 | ~100 fields (1.7 s) |
| F2 | tethered, flash **OFF** | 103 | **~19–20 fields** (0.32 s) | frame ~45 | **~95–116 fields (1.6–1.9 s)** |
| U1 | **untethered** (card only), flash OFF | 20 | **20 fields** (0.340 s) | — (short) | — |
| B1 | **burst** (continuous, fastest, no focus step) | 14 | **9 fields (0.151 s ≈ 6.6 fps)** | — | — |

## What this shows

1. **The flash is not the pacer.** Flash ON and flash OFF produce the *same*
   pre-cliff cadence (20 fields) **and the same cliff location (~frame 45).** The
   single most common suspect for this symptom is ruled out.
2. **The slowdown is write-pipeline saturation.** The buffer absorbs ~44 frames at
   full speed; once full, cadence drops to the sustained write/transfer rate and
   stays there. Static RE locates the stall shape (an SDF develop-resource acquire
   retry loop, `ExecRcAcquire` at VA `0x4504F0`) but shows the buffer pool itself
   lives in the **develop subsystem (`av-cam.bin`), not `cpapp`** — so this is *not*
   the STP message gate, and there is no `cpapp`-side depth constant to tune.
3. **Buffer depth ≈ 44 frames** under these conditions (RAW-L, saving to both).
4. **The exact slow rate depends on the write path.** Tethered-to-both here is
   ~1.7 s/frame (card write **+** USB transfer). The user's historical card-only
   "slow" stacks ran ~0.6 s (36 fields) — same mechanism, faster path (no USB).

## Practical implications (no firmware needed)

- **Stacks ≤ ~44 frames stay in the fast zone.** Deep stacks hit the wall.
- Levers that should push the cliff later or raise the post-cliff rate: **compressed
  / lossless-compressed RAW** (smaller files), a **faster card**, and — for tethered
  work — **PC-only vs card-only** save path. These are the next things to test.

## The decomposition — why the fast zone is ~20 fields

A fastest-**burst** reference (continuous drive, *no* focus stepping) ran at
**9 fields (0.151 s ≈ 6.6 fps)** — the camera's capture + write ceiling for a short
run. Focus Bracket's fast zone is **20 fields (0.34 s)**. The gap —
**~11 fields (≈0.19 s) per frame — is focus-step overhead**: the lens moving and
settling between shots. In the fast zone that overhead, *not* the write path, is the
dominant cost, and it is **identical tethered vs untethered** (both 20 fields).

So "faster when shooting remote" is a **confound, not a real effect** — the tether
doesn't change cadence. The remote stacks just happened to be short (fast zone); the
slow memories were longer stacks that crossed the cliff.

## Firmware relevance (revised — honest)

Two regimes, two different limiters:

- **Short stacks (≤ ~44 frames)** — paced by **focus-step overhead** (~0.19 s/frame).
  That lives in the **AF / lens-drive control**, *not* the STP buffer gate, so the
  2-byte buffer patch does **nothing** here. Real levers for short stacks are
  non-firmware: a **smaller focus-step width**, or a **faster-focusing lens**.
- **Long stacks (> ~44 frames)** — paced by the **write pipeline** at the buffer
  cliff. Static RE places the controlling buffer pool in the **develop subsystem
  (`av-cam.bin`), not `cpapp`** — reached through the SDF acquire retry loop
  (`ExecRcAcquire`, VA `0x4504F0`), *distinct* from the STP message gate at
  `0x4196B4`. So no `cpapp` patch — including the 2-byte STP relaxation — addresses
  this cliff; the pool that governs it isn't in the binary we analyzed.

**Bottom line:** for the short stacks typically shot, cadence is
focus-mechanism-bound (lens move + settle, no camera-firmware timer). For long
stacks it's the write pipeline, governed by a pool outside `cpapp`. The 2-byte STP
patch is real and verified but moves neither regime — it is not the lever.

## Still to measure (optional)

- Compressed vs uncompressed RAW → does smaller data push the cliff later / raise the
  post-cliff rate?
- A long *untethered* stack → the card-only post-cliff rate (expect ~0.6 s / 36
  fields, matching the old slow stacks).
- Firmware version (Menu → Setup → Version).
