# Investigation 2 — service mode, the auth decode, and the hardware session

**The question:** with the cadence question settled, where *else* in the firmware is there room to
customize or improve the camera? This started as a breadth-first **map**, not a set of mods — each
surface recorded with what the binary shows and how hard it would be to do anything with it. The one
surface with real leverage turned out to be the **dormant factory service stack**, which this
investigation maps end to end: a numeric service mode, a USB challenge-response, a runtime verb
dispatcher, and SSH provisioning.

The detailed, per-subsystem write-ups of the pieces named here live under
[findings/service-mode/](../findings/service-mode/):
[senser-verb-dispatch](../findings/service-mode/senser-verb-dispatch.md),
[senser-power-daemon](../findings/service-mode/senser-power-daemon.md),
[ssh-provisioning](../findings/service-mode/ssh-provisioning.md),
[plugin-verbs](../findings/service-mode/plugin-verbs.md),
[hasp-store](../findings/service-mode/hasp-store.md),
[hasp-id-gates](../findings/service-mode/hasp-id-gates.md),
[adjustment-command-table](../findings/service-mode/adjustment-command-table.md),
[adjustment-message-framing](../findings/service-mode/adjustment-message-framing.md).

## TL;DR

- **Dormant SSH / service stack (a15) — decoded, then found to be prior art.** The camera ships,
  unused, a full SSH service — `sbin/sshd`, a host-key generator, and `libInfraSSHManager.so`. The
  boot chain is mapped: `bin/im.elf` (power/boot manager, `C3P_PACKET` protocol) → `bin/sen.elf`
  (SENSER core v1.3.4, reads a numeric "smode" from a cascade of `/boot`, `/setting`, `/var` paths) →
  service stack. The factory service-mode gate is mapped end to end: a numeric "smode", a USB command
  channel, and a **three-level SHA-256 challenge-response** whose keys are **static 512-byte secrets
  embedded in a shipped library**; completing it lets the connected tool provision the `sshd` login.
  *The earlier "HASP token" framing was wrong — `/setting/.hasp` is a session audit log, not the gate.
  And the whole mechanism turned out to be `ma1co`'s prior public work — see the credit note; the key
  bytes are not reproduced here either way.*
- **Command-dispatcher catalog — mapped.** Every internal `SET_` / `PID_SET_` / `PUSH_` command was
  paired with its handler offset and log string. The full catalog is committed as
  [`reference/command-table.txt`](../reference/command-table.txt) — 306 FW commands + 150 property
  handlers with handler/checker offsets and names (offsets only, no firmware bytes). The curated
  write-ups of these families are under
  [findings/command-surface/](../findings/command-surface/). Note: the **external** exposure layer
  (PTP / the Creators' App remote API) is **not** in `cpapp` — it lives in the USB-gadget / network
  daemons on a15 ([usb-ptp-surface](../findings/command-surface/usb-ptp-surface.md)).
- **`ImagerSeqLog` — the camera's own timing instrument.** The sequence logger that would let us split
  the ~11-field focus overhead empirically (Investigation 1's open item) was located: log sites call a
  trace-category gate (`0x278B8C`, channel `0x1C`) into an ARM-side category registry. **Enabling a
  category is a service/debug action — almost certainly the same gated service stack.** So the
  diagnostic win and the SSH surface are the same lock.
- **PowerSave handler** (`0x27C144` / VA `0x384144`). Imager power sequencing mapped — sensor-drive
  register writes and training waits. This is **frame-to-frame imager sleep logic, not the thermal-limit
  table**; the thermal constants remain unfound.
- **Cosmetic / flags — nothing actionable.** `SysSound.bin` is a packed sound bank (format RE needed
  before any replacement). A `debug_mode` string that looked promising was run down and closed: it's a
  field name inside a VD-drive register-dump format, not a global debug switch.

**Bottom line.** The one surface with real leverage (SSH / service access, which would also unlock the
`ImagerSeqLog` diagnostics) is gated by a factory-tool challenge-response, not a config flag — and that
gate is now fully mapped. Its entire strength rests on three static keys baked into a shipped library,
so it is "only as secret as the firmware encryption." A first **observe-only** hardware session has
since completed this challenge-response on an owned body — the decode works live, no writes issued —
and found the raw memory-dump verb locked (`0x80`); see
[First hardware session](#first-hardware-session) below.

## The service-mode authentication, decoded

> **Prior art — credit to `ma1co` / Sony-PMCA-RE.** After mapping this ourselves, we found the whole
> thing had **already been reverse-engineered and published** years ago by `ma1co` in
> [Sony-PMCA-RE](https://github.com/ma1co/Sony-PMCA-RE): the SENSER protocol, the challenge-response,
> and the keys. Cross-checking confirmed the a7R V runs the **same system with the same keys,
> unrotated** — the keys we extracted match `senserKeysSha256` in that public repo byte-for-byte, and a
> working reference client already exists there. **So the decode below is a re-derivation of known
> work, credited to `ma1co`,** not an original discovery of this project. The little that does look
> specific to the a7R V is collected under [What's actually new](#whats-actually-new-for-the-a7r-v).

All offsets in this subsection are in the **a15 Linux ELF libraries** (`libsencore.so`, `sen.elf`,
`libInfraSSHManager.so`), not in `cpapp` — a different address space from Investigation 1. Everything
here is read-only static analysis. **The actual key bytes are not reproduced** — only their offsets and
the verification mechanism.

**1. Service mode (`smode`).** `sen.elf` persists a one-byte mode in a `/boot` → `/setting` →
`/var/.sen/.smode` cascade. `FUN_004028D0` matches it against a one-entry string table (`key 1 →
"UU"`): on a match it writes the literal string `"UU"` into the smode file (service mode ON); anything
else removes the file (OFF). Startup mirrors the byte to `/var/.sen/.smode` and logs `SENSER_MODE = %d`.
Full daemon write-up: [senser-power-daemon](../findings/service-mode/senser-power-daemon.md).

**2. The USB service channel.** `SenserIfStart` → `Usb::open_channel()` →
`InitiationDispatcher::register_handler()` brings up an event-driven USB command channel
(`CORE_START MODE:SENSER`). The protocol worker is `NinThread` (`libsencore.so` @ `0x10BBFC`), framing
fixed `0x204`-byte packets dispatched by `CmdDecode`.

**3. The three-level challenge-response ladder.** `CmdDecode` command ids:

| cmd | verb | effect |
|---|---|---|
| 1 | `HOP` (`xxhop`) | hello / handshake start |
| 3 | `STEP` (`xxstep`) → `JUMP` | **challenge-response**; on success `level++` (1→2→3, wraps) |
| 5 / 7 | `KICK` (`xxkick`) | authenticated command executor; then `tlog_set_hasp(id)` |
| — | unknown | `NIN_THREAD_ERR_UNKNOWN_CMD` |

`xxstep` (`libsencore.so` @ `0x115C1C`) verifies `SHA256(challenge[512] ‖ key[512])` by `memcmp`
against the tool's response. There is **one 512-byte static key per level**, embedded in
`libsencore.so`:

| level | key offset (`libsencore.so`) |
|---|---|
| 1 | `0x1570D8` |
| 2 | `0x156ED8` |
| 3 | `0x156CD8` |

On reaching **level 3** the service creates `/ramdsk/dev` and writes `"AA\0"` to `/ramdsk/dev/mode` — a
live-session marker other subsystems honour (a candidate trigger for the `av-cam` `debug=1` paths, and
so plausibly for `ImagerSeqLog`). It is removed on session end. `xxstep2` (`0x116058`) is a parallel
re-auth variant for cmd ids 9/10.

The **real post-auth verb dispatcher** is a layer up from this, in `libsencore.so` (not in `sen.elf`):
`SenserThread` → `Parse` → `Command::Execute` (auth gate) → `PluginCommand::DoExecute`, with three
auth-level verb tables swapped in by level. Full decode:
[senser-verb-dispatch](../findings/service-mode/senser-verb-dispatch.md).

**4. From authenticated session to SSH.** Once the ladder is cleared, the service command set includes
`network::InfraSshManager::PasswordManagerImpl::updatePasswordFile` (`libInfraSSHManager.so` @
`0x108318`), which writes `name + sep + password` (len < 0x65) under `flock` to
`/tmp_network/ssh/ssh_name_password`. In other words, **the party that completes the handshake sets the
`sshd` login** — this is how the factory tool enables SSH. The full provisioning path — host-key
generation, Backup-store persistence, the `crypt(3)` `$5$` hash, PAM tally reset — is in
[ssh-provisioning](../findings/service-mode/ssh-provisioning.md).

**5. `/setting/.hasp` is an audit log, not a gate** (correcting the earlier framing). It is an 88-byte,
10-entry ring of `{u16 tool-id, 6-byte BCD timestamp}`; `Regist_HaspId` appends the current session and
**returns success when the file is absent**. It records *who connected*, it does not decide *whether*
they may. And no firmware module anywhere branches on a HASP id value — an evidenced negative across
~65k functions. See [hasp-store](../findings/service-mode/hasp-store.md) and
[hasp-id-gates](../findings/service-mode/hasp-id-gates.md).

**6. Related service surface.** Beyond USB there is an **adjustment-command channel** with no USB
needed: `sens_adjCmd_init` registers an OSAL UIPC callback on queue `0x3D025F` → dispatcher
`FUN_00112630`. Named verbs there include mode-file ops and **log extraction**, alongside factory
sensor-adjustment handlers that pair with `a15/bin/adjstctl.elf`. The factory adjustment vocabulary —
1,779 commands mapped to block/code opcodes — is in
[adjustment-command-table](../findings/service-mode/adjustment-command-table.md); the argv→wire framing
is in [adjustment-message-framing](../findings/service-mode/adjustment-message-framing.md).

**Security finding.** The factory-tool authentication is a set of **hardcoded, shared, static secrets
shipped inside the firmware** — not per-device key material and not a hardware dongle. Its
confidentiality rests entirely on the assumption that "the firmware is encrypted," which is the very
assumption this class of project already defeats. The access vector is **physical USB to the camera**.

## Cross-validation against Sony-PMCA-RE

The a7R V's SENSER stack was checked directly against `ma1co`'s public reference client
([`Sony-PMCA-RE`](https://github.com/ma1co/Sony-PMCA-RE)), which implements this exact system. Three
results:

- **Keys — byte-identical.** The three 512-byte auth keys extracted from the a7R V's `libsencore.so`
  match `constants.senserKeysSha256` in the public repo byte-for-byte. Sony did **not** rotate the
  SENSER keys into Gen5.
- **Auth wire format — matches their client.** The handshake lines up with `Sony-PMCA-RE`'s
  `SonySenserAuthDevice`: a big-endian `{u16 cmd, u16 salt, 512-B data}` packet with the command sent
  *inverted*; `HOP` (cmd 1) → `STEP` (cmd 3, `SHA256(challenge ‖ key[level])`) → `JUMP`, three levels,
  then `KICK` (cmd 5) executes.
- **USB identity — a split.** The a7R V updater-mode PID (`0x03E2`) is **already** in their `sony.py`.
  The senser-mode PIDs and vendor requests noted earlier are **their generic constants**, *not* values
  from a7R V firmware — and the a7R V's *actual* senser-mode VID/PID is **provisioned at runtime**
  (kernel gadget `usbg_sen.ko`, no static descriptor), so it can't be read from the image and would
  need hardware to confirm.

Net: the a7R V reuses ma1co's SENSER system essentially unchanged; what is genuinely new is narrow.

## The command surface, and an open route for others

A later pass mapped the camera's internal command table and assessed what actually *using* the service
channel would take. The firmware command-dispatch table is in `cpapp` (region `0xFF6E4C`–`0xFF8FE4`),
20-byte entries `{u16 id, handler fn, flags, checker fn}`: 306 FW commands (`0x40xx`/`0x41xx`) + 150
property handlers (`0x78xxxx` → `0x20xx`). As everywhere else in this firmware, **nothing references the
table statically** — commands are matched by id and dispatched through the runtime-registered path. The
full id list is [`reference/command-table.txt`](../reference/command-table.txt); the curated
family write-ups are under [findings/command-surface/](../findings/command-surface/).

**The connection route — not new ground.** Reading live internal state means a client that completes the
handshake, and that client already exists: `ma1co`'s `Sony-PMCA-RE`, and the maintained Rust port
[`masterflai/pmca-re-reloaded`](https://github.com/masterflai/pmca-re-reloaded). This repo doesn't
duplicate it. The real caution is **not** secrecy — the keys and protocol are public — but the
**device**:

- **"Read-only" can't be guaranteed in this mode.** The post-auth verb surface includes arbitrary
  memory write, a terminal shell, and factory **calibration/adjustment** control: this is the
  manufacturing interface, not a developer sandbox. A wrong command can alter sensor calibration or
  brick the body, with no user-level recovery.
- The verb table is registered at runtime, so its full command set isn't recoverable from static
  analysis — all the more reason to **observe-first**, and only ever on **a camera you own and are
  prepared to lose**.

## First hardware session

Everything above was static analysis plus an offline self-test. A first **observe-only** session was
run on an **owned** a7R V (ILCE-7RM5, firmware 4.00) using
[`masterflai/pmca-re-reloaded`](https://github.com/masterflai/pmca-re-reloaded). **No writes were
issued**, and the camera was verified healthy afterward. Two results:

- **The decoded gate completes on real hardware.** The three 512-byte SHA-256 keys lifted from this
  body's own `libsencore.so` authenticate: the handshake runs in **SHA-256 mode** (`HOP` → `STEP`×3 →
  `KICK`) and reaches the service prompt. That promotes the auth decode from a static map to behaviour
  **confirmed on a live body** — observe-only, nothing written. Read-only identity/backup verbs
  (`info`, the 88-byte `HASP` audit block, the settings-backup image) returned valid data. Device-
  specific contents are **not** reproduced here.
- **The raw memory-dump verb is locked on this body.** The SENSER *MemoryDump* verb (`pFunc 0xff03`;
  flat `{u32 base, u32 size}` payload, packet-header selectors `0`) returned camera result code
  **`0x80`** for **every** address tried — `0x0`, and the `cpapp` VAs `0x108000` / `0x385598` /
  `0x115E994` — at sizes `0x10` through `0x200`. It is **not** a size/alignment artifact. As driven
  with the default selectors, the verb exposes **no memory** on a7R V fw 4.00.

  *Why* it refuses isn't settled from this alone. Dispatch is runtime-registered — there's no static
  `0xff03` handler in the a15 exports — so the verb may be **unregistered** on this body, or permission-
  gated. It is also **consistent with** the two-processor split (SENSER on the **a15 / Linux** core,
  `cpapp` on the **separate main core**), under which an a15-side dump verb would have no line of sight
  to `cpapp` addresses at all — but that is a plausible reading, **not proven here**. Either way,
  reading `cpapp` memory live would have to bridge through the a15, and enabling that terminal is itself
  a *write*, so it was out of scope for an observe-only run. See
  [senser-verb-dispatch](../findings/service-mode/senser-verb-dispatch.md) for the three static sites
  where `0x80` is manufactured.

Scope caveat: one body, one firmware, default packet selectors. A non-zero selector, or a different
firmware, could behave differently; this records what fw 4.00 returned, read-only.

## What's actually new for the a7R V

Setting aside everything `ma1co` already published, the genuinely a7R V-specific findings are modest —
and **anything touching the live device is unverified beyond the one observe-only session above**:

- **The SENSER keys are unrotated into Gen5 / BIONZ XR.** A confirmation that Sony never rotated them,
  not a code change.
- **`MSS` start / stop (`0x920202` / `0x920203`) — decoded.** Not in the PMCA-RE map; a *relay* posting
  a 4-word sync message to UIPC queue `0x80924220` for another subsystem to consume. The consumer isn't
  in the `cpapp` image.
- **The C3P / UIPC fabric behind the gate** — the shared cross-processor queue, the adjustment channel
  (`0x3D025F`), and the `UU` / `AA` mode files — mapped with offsets.
- **USB identity isn't statically recoverable.** The a7R V's senser-mode VID/PID is provisioned at
  runtime by a kernel USB gadget (`usbg_sen.ko`), so static analysis **cannot** supply the camera's
  device identity.
- **The `PacketData` verb registry is built at runtime**, so its command ids aren't recoverable
  statically — live enumeration only.
- The focus-bracket cadence work ([Investigation 1](01-focus-bracket-cadence.md)) is original to this
  project and unrelated to PMCA.
