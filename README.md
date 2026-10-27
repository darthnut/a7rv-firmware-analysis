# Sony a7R V — focus-bracket cadence investigation

Reverse-engineering my own a7R V's firmware to answer one question: **why do some
in-camera focus-bracket stacks run slow (~0.60 s/frame) while others run fast
(~0.43 s/frame)?** Is the slowdown a settings/flash effect I can fix today, or
something in the firmware?

> **Status — read this first.**
> Static analysis is complete. The candidate firmware patch below is **untested on
> hardware and its benefit is unproven.** We currently *doubt* it's the real
> bottleneck (see [Why we're skeptical](#why-were-skeptical-it-matters)). An
> empirical cadence test settles it — results will land in
> [RESULTS.md](RESULTS.md). **Do not flash anything on the strength of this repo
> alone.**

---

## TL;DR

- The fast/slow split is a clean **+10 VD "fields"** (~166.8 ms) added per frame.
  The 26-field fast cadence is an architectural floor (VD scheduler quantization);
  no firmware lever lowers it.
- Static RE of `cpapp-b.bin` mapped the VD scheduler and surfaced exactly one
  plausible firmware lever: a **buffer-full gate** with a conservative *2× headroom*
  policy and a known **2-byte relaxation**.
- **But that gate guards a ~16 KB STP request-*message* staging pool, not an image
  buffer.** Pixel data never traverses it; it literally logs
  `[STP_ERROR]: BUFFER FULL!!!` and latches trace off when full. Its causal link to
  the +10-field slowdown is **plausible but unproven**, and it reads more like a
  trace/request path than the capture pacer.
- So the honest next step is **measurement, not flashing**: a controlled cadence
  test (flash on/off first) to find what actually paces the slow stacks.

---

## Background: the VD field quantization

The capture pipeline is clocked by a "VD" scheduler.

- 1 VD field = **500 ticks = 16.6833 ms**.
- Fast focus-bracket cadence = **26 fields ≈ 0.434 s/frame**.
- Slow cadence = **36 fields ≈ 0.599 s/frame**.
- Difference = **+10 fields ≈ 166.8 ms**, consistently.

Because cadence is quantized to whole fields, the 26-field case is a hard floor —
whatever causes the slow case adds *ten discrete fields*, it doesn't smear the
timing. That's the shape of the thing we're hunting.

---

## The gate (what we found)

Function at **file offset `0x4196B4`** (Ghidra VA `0x5216B4`; load base `0x108000`,
so VA = file offset + `0x108000`). The relevant branch, from the Ghidra
decompilation:

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

Reading it out:

- **Availability check:** `need = 0x28 + 2·r` where `r` is the request size.
- **Actual consumption:** `consume = 0x14 + r`.
- The check demands roughly **2× what it consumes** — conservative headroom, i.e.
  pure policy slack. On a "full" verdict it logs `[STP_ERROR]: BUFFER FULL!!!`, sets
  a sticky flag, and **latches the whole STP path off** (`DAT_0119424a = 0`).
- **Pool counter:** RAM `DAT_0115E994`, initialized to **16364 (≈16 KB)**.
  `16384 − 16364 = 20 = 0x14` — exactly one message's fixed overhead. Ghidra xref
  analysis (across 95k resolved `movw`/`movt` refs) shows **only this gate** reads or
  writes the counter: it's one-sided, advisory bookkeeping.
- After accounting, it hands the request to the mailbox send function
  (`FUN_00B6C2F2`) as a byte-sized message of `r + 0x14`. **This is a request-message
  staging pool, not image data.**

---

## The candidate patch (a hypothesis — not validated)

Relax the 2× headroom to 1× so the check demands only what it consumes
(`need` becomes `0x14 + r`):

| file offset | before | after | instruction change |
|---|---|---|---|
| `0x41973E` | `28` | `14` | `movs r1,#0x28` → `movs r1,#0x14` |
| `0x419746` | `40` | `00` | `add.w r2,r1,r0,lsl#1` → `add.w r2,r1,r0` |

Two bytes. Re-disassembled before/after with capstone; surrounding instructions are
unchanged. The original bytes (`28 21` at `0x41973E`, `01 eb 40 02` at `0x419744`)
were confirmed present in the shipping `cpapp-b.bin`.

> ### ⚠ Do not treat this as a mod to flash.
> It is an analysis artifact. See [docs/patch.md](docs/patch.md) for the full risk
> write-up. Short version: the benefit is unproven, the target looks like a
> trace/request path rather than the capture pacer, and flashing *any* modified
> firmware can permanently brick the camera.

---

## Why we're skeptical it matters

This is the honest part, and it's why we test before we flash:

1. **It's a message/trace pool, not an image buffer.** Pixel data never passes
   through it. A gate on trace-message staging has no obvious reason to add ten
   whole VD fields to capture cadence.
2. **The 2× headroom is conservative slack** that plausibly guards a
   replenisher-lag accounting race — and we never located the replenisher, so we
   can't prove removing the slack is safe or even relevant.
3. **Worst case of the relaxed gate is handled**, by static reading: a marginal
   request passes the check and then fails downstream, producing a handled
   type-`0xF` fallback message → a dropped/retried STP request. Not corruption, not
   a brick — *per static analysis, which is not a hardware guarantee.*
4. **The +10-field mechanism itself is still unexplained.** Nothing ties it
   specifically to this gate. The link is plausible-unproven.

In other words: static analysis found a lever, but we can't show it's connected to
the thing we want to move.

---

## What actually settles it: the cadence test

Before anyone considers firmware, measure what paces the slow stacks. Prime
suspects, in order: **flash recycle**, pipeline warm-up, shutter mode, write
pressure. The full protocol is in [TESTING.md](TESTING.md); measured results go in
[RESULTS.md](RESULTS.md).

If the test shows the slowdown is flash/shutter/settings, the firmware angle is
moot and this repo stands as a "here's what it *isn't*" write-up. If it points at
write-pipeline backlog, *then* the gate becomes worth a hardware trial — on a body
someone is willing to lose.

---

## Method

- Target: `cpapp-b.bin` (flat ARM/Thumb-2 image, Ghidra load base `0x00108000`).
- Tooling: Ghidra 12.2 headless + Temurin JDK 25; scripts to force Thumb mode, dump
  xrefs/callers, and resolve `movw`/`movt` immediate address pairs (this firmware
  builds RAM addresses with immediate pairs, not literal pools — a naïve literal
  scan finds nothing, which is a trap). Byte-level checks with a standalone Python
  verifier.
- See [docs/method.md](docs/method.md) for detail.

## Legal & safety

- This is reverse engineering of **my own camera**, for interoperability and
  understanding. **No Sony firmware is redistributed here** — only byte offsets and
  derived analysis.
- Nothing here is validated on hardware. Modifying and flashing camera firmware can
  **permanently brick** the device and will void any warranty. If you act on this,
  do it only on a body you are prepared to lose, and only after the empirical test
  gives a reason to.
