# The candidate patch — details & risk

This documents a 2-byte change to `cpapp-b.bin`. **It is an analysis hypothesis, not
a released mod.** It has never been flashed to a camera. Read all of this before you
even think about it.

## What it changes

The gate at file `0x4196B4` (VA `0x5216B4`) decides whether the STP request-message
staging pool has room before accepting a request:

```
need    = 0x28 + 2*r      # availability check (what must be free)
consume = 0x14 + r        # what the request actually takes
```

The check demands ~2× the consumption as headroom. The patch collapses `need` to
`0x14 + r` — i.e. the gate only reports "full" when there isn't room for even this
one message.

| file offset | before | after | instruction |
|---|---|---|---|
| `0x41973E` | `28` | `14` | `movs r1,#0x28` → `movs r1,#0x14` |
| `0x419746` | `40` | `00` | `add.w r2,r1,r0,lsl#1` → `add.w r2,r1,r0` |

- Ghidra load base `0x00108000`; VA = file offset + `0x108000`.
- Byte order is confirmed: the imm8 of `movs` sits in the low byte at `0x41973E`;
  the shift field of the `add.w` sits at `0x419746`.
- Verified original bytes: `28 21` at `0x41973E`, `01 eb 40 02` at `0x419744`.
- Re-disassembled before/after (capstone): `movs r1,#0x28 … add.w r2,r1,r0,lsl#1`
  → `movs r1,#0x14 … add.w r2,r1,r0`. No neighboring instructions move.

> This is a raw image patch only. It does **not** include the vendor's
> envelope/signature handling. Repacking, re-signing, and flashing a modern Sony
> body is a separate, unsolved problem and is out of scope here.

## Why the benefit is unproven

- The pool is **STP request messages** (~16 KB staging), not pixel data. There is no
  demonstrated path from "more trace-message headroom" to "fewer VD fields per
  captured frame."
- The 2× headroom is most likely a guard against a replenisher-lag accounting race.
  The replenisher is now located — it is **on the other processor** (the a15, via the
  shared UIPC queue `0x8F013A`; see Investigation 1's "cross-processor closure"). Since
  the pool is balanced across a processor boundary, the timing of that replenish — and
  therefore whether the 2× slack is actually unnecessary — still can't be shown from
  static `cpapp` analysis alone.
- The +10-field slowdown has not been tied to this gate by any trace or measurement.

## Why the damage risk looks low (but is not zero)

By static reading of the surrounding code:

- The pool counter (`DAT_0115E994`) is **advisory** — only this gate touches it. It
  is not a handle other subsystems dereference.
- The mailbox the request goes to is self-managing (alloc / enqueue / free-back are
  all present and widely referenced).
- The worst case of an over-relaxed gate is a request that passes the check then
  fails allocation downstream, producing a **handled type-`0xF` fallback message** —
  a dropped/retried STP request, not a corrupted frame and not a hang.

**None of that is a hardware guarantee.** Static analysis can miss timing effects,
side channels, and anything the decompiler got subtly wrong. Flashing modified
firmware can permanently brick a camera.

## Bottom line — resolved, and the answer is no

The cadence test has since run ([RESULTS.md](../RESULTS.md)), and a full static sweep
followed. Both point the same way:

- The fast-zone cadence is **physical focus-step overhead** (lens move + settle), with
  **no camera-firmware delay constant** anywhere in the focus path — so this patch
  cannot touch it.
- The long-stack slowdown **is** the write pipeline, but the controlling buffer pool
  lives in the **develop subsystem (`av-cam.bin`), reached via the SDF acquire path
  (`ExecRcAcquire`, VA `0x4504F0`) — a *different* subsystem from this STP message
  gate.** So the one condition under which this patch would have earned a trial turned
  out to point at a different binary.

This patch is a **real, verified** 2-byte change that relaxes a conservative headroom
policy on a trace/request-message pool. It is kept here as an analysis artifact. It is
**not** the lever for focus-bracket cadence, and there is no measured reason to flash
it.
