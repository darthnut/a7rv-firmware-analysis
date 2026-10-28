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
- **[Acknowledgments & prior work](#acknowledgments--prior-work)** — this project did
  **not** crack the firmware encryption; it builds on community work that did, credited
  there.

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

> **Cross-processor closure (the "missing replenisher").** Earlier passes noted that
> this gate only ever *decrements* the counter — the matching replenish was never
> visible in `cpapp`, so the accounting looked one-sided. That is now resolved: the
> counter is balanced from the **other processor.** The gate sends into a shared UIPC
> queue (`0x8F013A`); on the a15 Linux side, `sen.elf`'s log forwarder
> (`FUN_004021A4`) posts `{type 2, id 0x3D}` into that **same** queue — and `0x8F013A`
> is in fact referenced on both the cpapp and the a15 sides. The STP pool is a
> **cross-processor** structure (cpapp ↔ a15), which is exactly why its replenisher is
> invisible to any `cpapp`-only analysis. (The a15 side is mapped in
> [Investigation 2](#investigation-2--other-customization-surfaces).)

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

- **Dormant SSH / service stack (a15) — decoded, then found to be prior art.** The camera
  ships, unused, a full SSH service — `sbin/sshd`, a host-key generator, and
  `libInfraSSHManager.so` (`network::InfraSshManager`). The boot chain is mapped:
  `bin/im.elf` (power/boot manager, `C3P_PACKET` inter-process protocol) →
  `bin/sen.elf` (SENSER core v1.3.4, reads a numeric "smode" from a cascade of
  `/boot`, `/setting`, `/var` paths) → service stack. The factory service-mode gate is
  mapped end to end: a numeric "smode", a USB command channel, and a **three-level
  SHA-256 challenge-response** whose keys are **static 512-byte secrets embedded in a
  shipped library**; completing it lets the connected tool provision the `sshd` login.
  Full chain, offsets, and the security implication are in
  [the subsection below](#the-service-mode-authentication-decoded). *The earlier
  "HASP token" framing was wrong — `/setting/.hasp` is a session audit log, not the
  gate. And the whole mechanism turned out to be `ma1co`'s prior public work — see the
  credit note under the decode; the key bytes are not reproduced here either way.*
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
also unlock the `ImagerSeqLog` diagnostics) is gated by a factory-tool
challenge-response, not a config flag — and that gate is now fully mapped (below). Its
entire strength rests on three static keys baked into a shipped library, so it is "only
as secret as the firmware encryption." No working unlock was performed on hardware;
this is a static map of the mechanism.

## The service-mode authentication, decoded

> **Prior art — credit to `ma1co` / Sony-PMCA-RE.** After mapping this ourselves, we
> found the whole thing had **already been reverse-engineered and published** years ago
> by `ma1co` in [Sony-PMCA-RE](https://github.com/ma1co/Sony-PMCA-RE): the SENSER
> protocol, the challenge-response, and the keys. Cross-checking confirmed the a7R V
> runs the **same system with the same keys, unrotated** — the keys we extracted match
> `senserKeysSha256` in that public repo byte-for-byte, and a working reference client
> already exists there. **So the decode below is a re-derivation of known work, credited
> to `ma1co`,** not an original discovery of this project. The little that does look
> specific to the a7R V is collected under
> [What's actually new for the a7R V](#whats-actually-new-for-the-a7r-v) at the end of
> this investigation.

All offsets in this subsection are in the **a15 Linux ELF libraries**
(`libsencore.so`, `sen.elf`, `libInfraSSHManager.so`), not in `cpapp` — a different
address space from Investigation 1's load base. Everything here is read-only static
analysis (Ghidra, symbols from `.dynsym`). **The actual key bytes are not reproduced**
— only their offsets and the verification mechanism, consistent with this repo's
no-redistribution line.

**1. Service mode (`smode`).** `sen.elf` persists a one-byte mode in a `/boot` →
`/setting` → `/var/.sen/.smode` cascade. `FUN_004028D0` matches it against a
one-entry string table (`key 1 → "UU"`): on a match it writes the literal string
`"UU"` into the smode file (service mode ON); anything else removes the file (OFF).
Startup mirrors the byte to `/var/.sen/.smode` and logs `SENSER_MODE = %d`.

**2. The USB service channel.** `SenserIfStart` → `Usb::open_channel()` →
`InitiationDispatcher::register_handler()` brings up an event-driven USB command
channel (`CORE_START MODE:SENSER`). The protocol worker is `NinThread`
(`libsencore.so` @ `0x10BBFC`), framing fixed `0x204`-byte packets dispatched by
`CmdDecode`.

**3. The three-level challenge-response ladder.** `CmdDecode` command ids:

| cmd | verb | effect |
|---|---|---|
| 1 | `HOP` (`xxhop`) | hello / handshake start |
| 3 | `STEP` (`xxstep`) → `JUMP` | **challenge-response**; on success `level++` (1→2→3, wraps) |
| 5 / 7 | `KICK` (`xxkick`) | authenticated command executor; then `tlog_set_hasp(id)` |
| — | unknown | `NIN_THREAD_ERR_UNKNOWN_CMD` |

`xxstep` (`libsencore.so` @ `0x115C1C`) verifies `SHA256(challenge[512] ‖ key[512])`
by `memcmp` against the tool's response. There is **one 512-byte static key per
level**, embedded in `libsencore.so`:

| level | key offset (`libsencore.so`) |
|---|---|
| 1 | `0x1570D8` |
| 2 | `0x156ED8` |
| 3 | `0x156CD8` |

On reaching **level 3** the service creates `/ramdsk/dev` and writes `"AA\0"` to
`/ramdsk/dev/mode` — a live-session marker other subsystems honour (a candidate
trigger for the `av-cam` `debug=1` paths, and so plausibly for `ImagerSeqLog`). It is
removed on session end. `xxstep2` (`0x116058`) is a parallel re-auth variant for cmd
ids 9/10.

**4. From authenticated session to SSH.** Once the ladder is cleared, the service
command set includes `network::InfraSshManager::PasswordManagerImpl::updatePasswordFile`
(`libInfraSSHManager.so` @ `0x108318`), which writes `name + sep + password` (len
< 0x65) under `flock` to `/tmp_network/ssh/ssh_name_password`. In other words, **the
party that completes the handshake sets the `sshd` login** — this is how the factory
tool enables SSH.

**5. `/setting/.hasp` is an audit log, not a gate** (correcting the Investigation 2
TL;DR's earlier framing). It is an 88-byte, 10-entry ring of
`{u16 tool-id, 6-byte BCD timestamp}`; `Regist_HaspId` appends the current session and
**returns success when the file is absent**. "Hasp last_histroy data error" means a
corrupt log, not an auth failure. It records *who connected*, it does not decide
*whether* they may.

**6. Related service surface.** Beyond USB there is an **adjustment-command channel**
with no USB needed: `sens_adjCmd_init` registers an OSAL UIPC callback on queue
`0x3D025F` → dispatcher `FUN_00112630`. Named verbs there include `cmd 0x14`
(mode-file ops on `/mode` ↔ `/tmode`) and **log extraction** (op 4:
`/log/ulogio_klog.txt`, `/log/ulogio_tlog.txt`, `/log/escapelog.bin`), alongside
factory sensor-adjustment handlers that pair with `a15/bin/adjstctl.elf`. The real
post-auth verb table, however, is **runtime-registered** (a `PacketData` factory
vector at `DAT_0016CA08`), so the individual command ids are **not statically
enumerable** without execution.

**Security finding.** The factory-tool authentication is a set of **hardcoded,
shared, static secrets shipped inside the firmware** — not per-device key material and
not a hardware dongle. Its confidentiality rests entirely on the assumption that "the
firmware is encrypted," which is the very assumption this class of project (community
RE of Sony updater crypto) already defeats. The access vector is **physical USB to the
camera**, and nothing here has been exercised on hardware; it is documented as a
mapped design weakness.

## The command surface, and an open route for others

A later pass mapped the camera's internal command table and assessed what actually
*using* the service channel would take. Both are recorded as findings; the second is
deliberately left as a direction, not a tool.

**Command table (static).** The firmware command-dispatch table was located in `cpapp`
(region `0xFF6E4C`–`0xFF8FE4`), 20-byte entries of
`{u16 id, handler fn, flags, checker fn}`:

- **306 FW commands** (id families `0x40xx` / `0x41xx`, ASCII `@`/`A`) — e.g. `0x4152`
  (`"AR"`) is the verified `SET_FOCUS_BRK_EXEC_STATE`, the focus-bracket trigger from
  Investigation 1.
- **102 property handlers** (`0x78xxxx`) — the GET/query layer.
- As everywhere else in this firmware, **nothing references the table statically**:
  commands are matched by id and dispatched through the runtime-registered path, so the
  individual verb *semantics* are not recoverable without running the code. The full id
  list stays in the working notes, not committed here (same policy as the earlier
  catalog).

**The connection route — not new ground.** Reading *live* internal state means a client
that completes the handshake and reads responses back — and that client already exists:
`ma1co`'s [Sony-PMCA-RE](https://github.com/ma1co/Sony-PMCA-RE) is a public, working
implementation of this exact SENSER system, which (per the credit note above) the a7R V
reuses with the same keys. This repo doesn't duplicate it. Extending it to the a7R V
would be ordinary device-support work plus **verification on real hardware, which has
not been done here** — the local tooling has only passed an offline selftest. (Emulation
was assessed as a safer verifier — `ma1co`'s OpenMemories-QEMU — but it models older
Sony SoCs; bringing up the a7R V's CXD90057 / BIONZ XR would be a substantial project of
its own, so hardware remains the only practical check.)

The real caution is **not** secrecy — the keys and protocol are public — but the
**device**:

- **"Read-only" can't be guaranteed in this mode.** The post-auth verb surface includes
  arbitrary memory write, a terminal shell, and factory **calibration/adjustment**
  control: this is the manufacturing interface, not a developer sandbox. A wrong command
  can alter sensor calibration or brick the body, with no user-level recovery.
- The verb table is registered at runtime, so its full command set isn't recoverable
  from static analysis — all the more reason to **observe-first** (enumerate and read
  before issuing anything that writes), and only ever on **a camera you own and are
  prepared to lose**.

## What's actually new for the a7R V

Setting aside everything `ma1co` already published, the genuinely a7R V-specific
findings here are modest — and **anything touching the live device is unverified** (no
hardware test):

- **The SENSER keys are unrotated into Gen5 / BIONZ XR.** The a7R V (ILCE-7RM5) takes
  the same `senserKeysSha256` values as earlier bodies — a confirmation that Sony never
  rotated them, not a code change.
- **`MSS` start / stop (`0x920202` / `0x920203`) — decoded.** Not in the PMCA-RE map;
  it's a *relay*, posting a 4-word sync message to UIPC queue `0x80924220` for another
  subsystem to consume (not a local service). The consumer isn't in the `cpapp` image.
- **The C3P / UIPC fabric behind the gate** — the shared cross-processor queue, the
  adjustment channel (`0x3D025F`) with its log-pull verbs, and the `UU` / `AA` mode
  files — mapped with offsets (see Investigation 2, and the `cpapp` closure in
  Investigation 1).
- **USB identity isn't statically recoverable.** The a7R V's senser-mode VID/PID is
  provisioned at runtime by a kernel USB gadget (`usbg_sen.ko`), with no static
  descriptor in the image — so static analysis **cannot** supply the camera's device
  identity, and confirming it needs hardware. (The updater-mode PID `0x03E2` is already
  known upstream.)
- **The `PacketData` verb registry is built at runtime**, so its command ids aren't
  recoverable statically — live enumeration only.
- Separately, the focus-bracket cadence work (Investigation 1) is original to this
  project and unrelated to PMCA.

That is the honest scope of what could go upstream: mostly **documentation** of the
Gen5 service stack and the updater container layout (see Investigation 3), plus the
deltas above — with the USB identity and the runtime verb table left for hardware.

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

For reference, the a7R V updater the keys *do* open has this container layout — our
mapping, with **no keys or payload reproduced**: an `89 55 46 55 0d 0a 1a 0a` magic,
then big-endian `{u32 size, u32 tag}` chunks — `DATV` (format version: `1` on the a7R V,
`4` on the a7R VI), `PROV`, `UDID` (92 bytes on the a7R V, 44 on the a7R VI), the `FDAT`
payload, and `DEND` + a CRC-32 over the preceding bytes. `FDAT` is 1024-byte frames
(each a 2-byte word-sum checksum + a flags word, `bit15` = last frame), the first frame's
leading 512 bytes under a header cipher, and a trailer of a 16-byte IV plus a 256-byte
RSA-2048 signature. The AES decryption of that payload is the community's work (credited
below), not ours; the **container framing** is what this project mapped, and it is the
shareable part.

Reading it would require the a7R VI generation's updater keys (the kind of thing that
historically comes from community RE of the updater), or a flash dump taken off the
body directly. Until then, **nothing about a7R VI features can be asserted from this
file** — anything claimed would be speculation, and is deliberately not recorded here.

---

## Acknowledgments & prior work

**This project did not break the firmware encryption.** Being able to read the a7R V
firmware at all rests entirely on earlier community reverse-engineering, which this
project only *applied* — a small script lifts their published keys and container layout
and runs them on a package you supply; it derives nothing cryptographic. Credit for
getting inside Sony's Gen5 (CXD9005x / BIONZ XR) firmware belongs to:

- **[q19032/Sony-firmware-unpacker](https://github.com/q19032/Sony-firmware-unpacker)**
  — firmware **decryption and key derivation** (the update-package crypto: the `FF03`
  memory read on the CXD9005x and the `SHA256(…)` key formula). This is the work that
  makes the package readable.
- **[David Buchanan — `ILCE-7M4-RE`](https://github.com/DavidBuchanan314/ILCE-7M4-RE)**
  (and [`Sony-ILCE-7M4-Linux`](https://github.com/DavidBuchanan314/Sony-ILCE-7M4-Linux))
  — the foundational boot-ROM / serial-boot / eMMC reverse engineering on the CXD90057
  generation: getting code running low enough to pull secrets off the silicon. The hard
  part.
- **[ma1co — `fwtool.py`](https://github.com/ma1co/fwtool.py)** and
  **[`Sony-PMCA-RE`](https://github.com/ma1co/Sony-PMCA-RE)** — the firmware **container
  format / unpacking** and the Sony camera **service protocol** (the SENSER system
  Investigation 2 re-derives and credits in full above).
- **[Erlla — `sony-a7m4-custom-firmware`](https://github.com/Erlla/sony-a7m4-custom-firmware)**
  — brought the above together into working A7 IV custom-firmware tooling.
- **[Hearts-Ace — `sony-a7r5-custom-firmware`](https://github.com/Hearts-Ace/sony-a7r5-custom-firmware)**
  — carried the scheme to the a7R V (ILCE-7RM5) and confirmed the a7 IV keys and
  container apply unchanged — which is why the Ver. 4.00 package here decrypts with the
  a7 IV constants.

One precise point, because it bounds what any of this makes possible: the keys above
decrypt the **update package** (the FDAT layer), which is a *different* key system from
the **eMMC AES-XTS** encryption on the camera itself. "We can read the firmware" and
"we can flash a modified one onto a body" rest on different pieces of the upstream work,
and **only reading is settled** — this project stays on the reading side.

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
