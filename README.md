# Sony a7R V — firmware analysis

Reverse engineering of the Sony a7R V (ILCE-7RM5) firmware, on **my own camera**, for
interoperability and understanding. The goal is to map how the camera works and to find
where — if anywhere — behaviour could be improved through firmware modification.

**No Sony firmware is redistributed here.** Everything in this repo is derived analysis:
byte offsets, virtual addresses, struct layouts, protocol fields and mechanism. No key
material, no license blobs, no credential bytes, and no firmware image or extracted binary
appears anywhere in it.

> **Working ethos.** Map first, measure before modifying, and never present an untested
> change as a mod to flash. Where an investigation turns up a candidate firmware lever it is
> documented as a *hypothesis* with its evidence and its risk, not a recipe. Modifying and
> flashing camera firmware can permanently brick the device; anything here is acted on only on
> a body someone is willing to lose, and only once there is a measured reason to.

---

## What this is

Two threads of work, now written up as one reference:

1. **Behaviour investigations** — question-driven studies that start from something the camera
   does (why focus-bracket stacks slow down; what the dormant service mode is) and chase it into
   the binary until it is settled or the static trail ends.
2. **A subsystem reference** — 21 static-analysis studies of the a7R V's security, service, IPC,
   persistence and command subsystems, each verified against the binaries, each carrying its own
   verification status and static boundary so a reader can tell *solid* from *inferred* from
   *out-of-image* at a glance.

The headline structural finding is a **complete crypto / keystore spine** and a **full service-mode
chain**, traced end to end up to the point where they leave the extracted firmware:

- **At rest:** application data → **SecVault** (AES-256-GCM, per-record random data key) → **Backup
  store** → backup daemon. The data key is wrapped by a key-encryption key held in an **out-of-image
  key service** (OSAL QID `0x25906be`); the master key is provider-side / hardware-rooted and never
  enters any extracted image. Confidentiality of everything at rest reduces to that one key.
- **Service mode:** a 3-level SHA-256 challenge-response (`libsencore.so`) → a runtime verb
  dispatcher → SSH provisioning (`libInfraSSHManager.so` starts `sshd`, sets a `crypt(3)` `$5$`
  login, persists an ECDSA host key through the Backup store). The auth is prior public work
  (`ma1co` / Sony-PMCA-RE); this repo re-derives and credits it and adds the Gen5 deltas.

---

## Architecture at a glance

- **Two processors.** A main **SoC / BIONZ XR** side running the camera application
  (`cpapp-b.bin`) and the develop/imaging pipeline (`av-cam.bin`), and an **a15 AArch64 Linux**
  side (the `fs/a15` userland: ~352 shared objects, ~75 service ELFs) that owns USB, networking,
  SSH, the service channel and the crypto/keystore.
- **One message fabric.** Everything is wired together by **OSAL / UIPC** over `/dev/uipc`, a
  QID-addressed message bus. Key QIDs: `0x25906be` (crypto key service), `0x82cd08e0` (Backup
  domain), `0x3d032e` (SENSER power), `0x8f013a` (log sink).
- **Security spine.** SecVault + key service + Backup store at rest; SENSER auth → verb dispatch →
  SSH for the service channel; HASP as a check-in log, not a feature gate.

Full picture: **[ARCHITECTURE.md](ARCHITECTURE.md)**.

---

## Where to find what

| You want… | Go to |
|---|---|
| The firmware's shape — images, binaries, IPC, boot, security at a glance | **[ARCHITECTURE.md](ARCHITECTURE.md)** |
| The narrative studies (question → binary → answer) | **[investigations/](investigations/)** |
| &nbsp;&nbsp;· Why focus-bracket cadence drops after ~44 frames | [investigations/01-focus-bracket-cadence.md](investigations/01-focus-bracket-cadence.md) |
| &nbsp;&nbsp;· Service mode, the SHA-256 auth decode, the observe-only hardware session | [investigations/02-service-mode-and-auth.md](investigations/02-service-mode-and-auth.md) |
| &nbsp;&nbsp;· Why the a7R VI firmware is blocked | [investigations/03-a7rvi-blocked.md](investigations/03-a7rvi-blocked.md) |
| &nbsp;&nbsp;· The security architecture, synthesised | [investigations/04-security-architecture.md](investigations/04-security-architecture.md) |
| The subsystem reference — one curated page per subsystem | **[findings/](findings/)** |
| &nbsp;&nbsp;· crypto / keystore · service mode · transport · command surface · persistence · behaviour | [findings/README.md](findings/README.md) |
| How any of this was done, and what deep / light / hypothesis mean | **[method/](method/README.md)** |
| The open frontier, prioritised, each with its static boundary | **[OPEN-QUESTIONS.md](OPEN-QUESTIONS.md)** |
| Raw data to reuse — the command catalog, the frame-cycle data | **[reference/](reference/README.md)** |
| The raw run archive (provenance for every finding) | **[framework-runs/](framework-runs/)** |
| Empirical test protocol / measured results | [TESTING.md](TESTING.md) · [RESULTS.md](RESULTS.md) |
| The candidate 2-byte patch's risk write-up | [docs/patch.md](docs/patch.md) |
| Interactive frame-cycle timeline (GitHub Pages) | [the per-frame bracket timing page](https://darthnut.github.io/a7rv-firmware-analysis/docs/frame-cycle.html) |

---

## Status

- **Investigation 1 (focus-bracket cadence): settled.** Two regimes, two limiters, neither a
  camera-firmware timer. No worthwhile firmware lever. Confirmed by bench measurement + full static
  sweep of `cpapp-b.bin` and `av-cam.bin`.
- **Investigation 2 (service mode): mapped end to end, one observe-only hardware session run.** Auth
  decode confirmed live on an owned body; the raw memory-dump verb (`0xff03`) returned locked. No
  writes issued.
- **Investigation 3 (a7R VI): blocked** at the crypto layer; recorded as a boundary.
- **Subsystem reference: 21 studies complete**, each verified against the binaries, each with its
  verification status and static boundary. The crypto/keystore spine and the service-mode chain are
  the two fully-traced structures; both terminate at an out-of-image provider, which is recorded
  rather than guessed past.

Nothing here is validated on hardware beyond the single observe-only service-mode session. This is a
static map; the open items are in [OPEN-QUESTIONS.md](OPEN-QUESTIONS.md).

---

## Acknowledgments & prior work

**This project did not break the firmware encryption.** Being able to read the a7R V firmware at all
rests entirely on earlier community reverse-engineering, which this project only *applied* — a small
script lifts their published keys and container layout and runs them on a package you supply; it
derives nothing cryptographic. Credit for getting inside Sony's Gen5 (CXD9005x / BIONZ XR) firmware
belongs to:

- **[q19032/Sony-firmware-unpacker](https://github.com/q19032/Sony-firmware-unpacker)** — firmware
  **decryption and key derivation** (the update-package crypto: the `FF03` memory read on the
  CXD9005x and the `SHA256(…)` key formula). This is the work that makes the package readable.
- **[David Buchanan — `ILCE-7M4-RE`](https://github.com/DavidBuchanan314/ILCE-7M4-RE)** (and
  [`Sony-ILCE-7M4-Linux`](https://github.com/DavidBuchanan314/Sony-ILCE-7M4-Linux)) — the
  foundational boot-ROM / serial-boot / eMMC reverse engineering on the CXD90057 generation: getting
  code running low enough to pull secrets off the silicon. The hard part.
- **[ma1co — `fwtool.py`](https://github.com/ma1co/fwtool.py)** and
  **[`Sony-PMCA-RE`](https://github.com/ma1co/Sony-PMCA-RE)** — the firmware **container format /
  unpacking** and the Sony camera **service protocol** (the SENSER system Investigation 2
  re-derives and credits in full).
- **[masterflai — `pmca-re-reloaded`](https://github.com/masterflai/pmca-re-reloaded)** — a
  maintained Rust port of `ma1co`'s `Sony-PMCA-RE` (USB transport, Windows drivers, a tested service
  shell). The first observe-only hardware session in Investigation 2 was run with it.
- **[Erlla — `sony-a7m4-custom-firmware`](https://github.com/Erlla/sony-a7m4-custom-firmware)** —
  brought the above together into working A7 IV custom-firmware tooling.
- **[Hearts-Ace — `sony-a7r5-custom-firmware`](https://github.com/Hearts-Ace/sony-a7r5-custom-firmware)**
  — carried the scheme to the a7R V (ILCE-7RM5) and confirmed the a7 IV keys and container apply
  unchanged — which is why the Ver. 4.00 package here decrypts with the a7 IV constants.

One precise point, because it bounds what any of this makes possible: the keys above decrypt the
**update package** (the FDAT layer), which is a *different* key system from the **eMMC AES-XTS**
encryption on the camera itself. "We can read the firmware" and "we can flash a modified one onto a
body" rest on different pieces of the upstream work, and **only reading is settled** — this project
stays on the reading side.

### Related work — parallel efforts

- **[t2r05 — ILME-FX30 service-mode research](https://github.com/t2r05/fx30-senser-map)** — maps the
  FX30's USB service session (Senser / Jiritsu) on fw 6.00/6.01: which channels are reachable, what
  the data looks like, and a reproducible hidden-burst enable via an equal-length firmware patch.
  Same generation and the same offsets-not-binaries ethos as this repo; it parallels Investigation
  2's service-mode work closely.
- **[YuuLuo — A7C II Camera Tools](https://github.com/YuuLuo/a7c2-camera-tools)** — reproducible
  firmware tooling for the ILCE-7CM2: a service-mode (Jiritsu) worker that builds a patched 2.00 DAT
  to enable Creative Look modes and the shutter sound. More applied modding than static write-up, but
  the same modern-body service machinery.
- **[ma1co — OpenMemories-Symbols](https://github.com/ma1co/OpenMemories-Symbols)** — a database of
  reverse-engineered firmware symbols (`bin2elf` for `av.bin`): the symbol-naming side of this kind
  of work, for a few older bodies.
- **[obs1dium — FocusBracket](https://github.com/obs1dium/FocusBracket)** — an early (2016, A5100)
  proof-of-concept that drove focus bracketing from the OpenMemories app layer, before Sony shipped
  the feature natively. Thematically adjacent to Investigation 1, though it uses the public app API
  rather than touching the capture pipeline.

---

## Legal & safety

- This is reverse engineering of **my own camera**, for interoperability and understanding. **No
  Sony firmware is redistributed here** — only byte offsets and derived analysis.
- Apart from the one **observe-only** service-mode session in
  [Investigation 2](investigations/02-service-mode-and-auth.md) (no writes), nothing here is
  validated on hardware. Modifying and flashing camera firmware can **permanently brick** the device
  and will void any warranty. If you act on this, do it only on a body you are prepared to lose, and
  only after an empirical test gives a reason to.
- Much of the firmware digging was done with AI assistance (GLM-5.3, and a local Flash-Next
  model driving Ghidra); **every finding was verified against the binary** — and, where stated,
  against the hardware — before it was recorded. See [method/](method/README.md).
