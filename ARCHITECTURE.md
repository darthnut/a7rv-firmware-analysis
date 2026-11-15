# Architecture — what the a7R V firmware looks like

A one-screen model of the camera's software, as far as static analysis of the user's own extracted
firmware reaches. Every subsystem named here has a curated page under [findings/](findings/) and a
raw study under [framework-runs/](framework-runs/); this document is the map that ties them together.
Offsets and mechanism only — no key material, no firmware bytes.

---

## 1. Two processors, two worlds

The a7R V is a dual-processor design, and almost every "where does this live?" question resolves to
one of the two sides:

| | Main SoC (BIONZ XR) | a15 (AArch64 Linux) |
|---|---|---|
| **Images in hand** | `cpapp-b.bin` (17.6 MB, camera application), `av-cam.bin` (13 MB, develop/imaging) | the `fs/a15` filesystem: ~352 shared objects, ~75 service ELFs |
| **ISA / layout** | ARM/Thumb-2, flat image, Ghidra load base `0x108000` (VA = file + `0x108000`) | AArch64 ELFs, per-image load base (noted per finding) |
| **Owns** | the capture pipeline, the FW command table (`0x40xx`/`0x41xx`), the property emitter (`0x78xxxx`/`0x20xx`), focus/drive/exposure handlers, develop-resource arbitration | USB, networking, SSH, the SENSER service channel, the crypto/keystore, Backup persistence, PTP/PC-Remote |
| **Reached from the other side via** | OSAL/UIPC queue messages (runtime-registered dispatch) | OSAL/UIPC queue messages |

The split is load-bearing for security reasoning: the SENSER service channel and the whole
crypto/keystore run on the **a15 Linux** side, while the FW command table runs on the **main SoC**.
An a15-side memory-dump verb has no line of sight to `cpapp` addresses at all
([Investigation 2](investigations/02-service-mode-and-auth.md)), and the PTP responder must bridge
across the processor boundary to reach a FW command
([findings/command-surface/usb-ptp-surface.md](findings/command-surface/usb-ptp-surface.md)).

### The images, and how they are read

The update package (`FDAT` layer) is decrypted with the community's published a7 IV / Gen5 keys and
container layout (see the [acknowledgments](README.md#acknowledgments--prior-work)); this project
only applies them. The container framing this repo mapped — the `89 55 46 55` magic, big-endian
`{u32 size, u32 tag}` chunks (`DATV`/`PROV`/`UDID`/`FDAT`/`DEND` + CRC-32), and the 1024-byte `FDAT`
frames — is detailed in [Investigation 3](investigations/03-a7rvi-blocked.md). The on-camera **eMMC
AES-XTS** encryption is a different key system and is out of scope: this project reads, it does not
flash.

---

## 2. Key binaries and what each does

**Main SoC:**

- **`cpapp-b.bin`** — the camera application. Holds the **FW command table** (409 commands, 20-byte
  entries `{u16 id, handler|1, flags, 0, checker|1}`, stride `0x14`, Thumb LSB set on pointers) and
  the **property emitter** (a 150-entry change-driven table at VA `0x010FEE4C`). See
  [findings/command-surface/](findings/command-surface/).
- **`av-cam.bin`** — the develop / imaging pipeline. Holds the SDF develop-resource arbitration
  (`ExecRcAcquire`) behind the focus-bracket write cliff
  ([findings/behavior/develop-resource-acquire.md](findings/behavior/develop-resource-acquire.md)).

**a15 Linux — the service and security surface:**

- **`libosal_uipc.so`** — the message fabric client (§3).
- **`libsencore.so`** — the SENSER service core: the real post-auth verb dispatcher, the 3-level
  SHA-256 auth, the HASP accessors. Loaded by **`sen.elf`** (a thin power/lifecycle shell that owns
  no verbs).
- **`libInfraSSHManager.so`** — stands up `sshd` in service mode: host-key generation/persistence,
  the `crypt(3)` `$5$` login file, PAM tally reset.
- **`libsecvlt.so`** (SecVault) — the AES-256-GCM secure store (four fixed slots).
- **`libBackupManager.so`** / `libbkdmn.so` / `bk.elf` — the Backup persistence store
  (`/setting/Backup.bin`).
- **`libpro00.so`** — the only plugin that exports real service verbs (`command001F` HASP,
  `command00F1` stub).
- **`adjstctl.elf`** / **`libtestcmd.so`** — the factory adjustment CLI and its framing library
  (1,779-command vocabulary).
- **`crypter.elf`** — a factory crypt-file provisioning tool (removable-media write path).
- **`libInfraRemote.so`** / `libptp.so` / `libInfraPtpControl.so` — the PTP / PC-Remote responder.
- The key-service provider for QID `0x25906be` is **not in any extracted image** (best on-disk
  candidate: `appFw.so`); this is the central static boundary of the crypto spine.

---

## 3. The OSAL / UIPC message fabric

Everything above talks over one bus: **OSAL/UIPC**, a userspace client (`libosal_uipc.so`) of a
kernel driver at **`/dev/uipc`**. It is the single most load-bearing mechanism in the firmware, and
its ABI is decompile-verified
([findings/transport/osal-uipc.md](findings/transport/osal-uipc.md)).

- **Two layers, chosen by QID bit 15.** Bit 15 set → a pure-userspace fast path (callback runs in
  the sender's thread, zero syscalls). Bit 15 clear → exactly one `ioctl` on the `/dev/uipc` fd.
- **QID encoding:** bits 0–14 = 15-bit queue index (0 is illegal), bit 15 = userspace/kernel, bits
  16–27 = 12-bit type/owner, bit 31 must be clear.
- **ioctl ABI (decompile-verified):** `(dir<<31)|nr`, no encoded size — `0x80000004` send,
  `0x80000005` sync-send, `0x80000008` register-callback, `0x8000000a/b` alloc/free.
- **Message buffer:** `0x18`-byte header, payload at `base+0x18`, canaries
  (`0xa5a5a5a5`/`0x55555555`/`0x77777777`), a priority/flags byte.
- **Sync reply is a callback, not a message:** the kernel writes a function pointer + argument back
  into the request struct and userspace calls it. **One callback per QID** (a second registration
  traps under debug builds) — so a QID is a point-to-point endpoint, not a multicast channel.

### The QIDs that recur across this analysis

| QID | Domain | Where documented |
|---|---|---|
| `0x25906be` | **crypto key service** (import/crypt/release; module `0x0259`, slot `0x06be`, kernel-routed) | [key-service](findings/crypto-keystore/key-service.md) |
| `0x82cd08e0` | **Backup domain** (persistence writes) | [backup-store](findings/persistence/backup-store.md) |
| `0x3d032e` | **SENSER power** (resume/suspend to `sen.elf`) | [senser-power-daemon](findings/service-mode/senser-power-daemon.md) |
| `0x8f013a` | **log sink** (a15 log collector; also the STP cross-processor queue in Investigation 1) | [osal-uipc](findings/transport/osal-uipc.md) |
| `0x94020a` | command-executor ("IM system") — how the SSH manager runs `/usr/sbin/sshd` | [ssh-provisioning](findings/service-mode/ssh-provisioning.md) |
| `0x3d025f` | adjustment-command channel into `libsencore` | [senser-verb-dispatch](findings/service-mode/senser-verb-dispatch.md) |

**Constant ≠ owner.** A QID named in a binary is not evidence that binary owns the queue; ownership
is a runtime fact (whoever registered the callback first), and for `0x25906be` that owner is in no
extracted image at all.

---

## 4. Boot & storage

- **Boot / service mode.** `im.elf` (power/boot manager, `C3P_PACKET` protocol) → `sen.elf` (SENSER
  core v1.3.4; reads a numeric "smode" from a `/boot` → `/setting` → `/var/.sen/.smode` cascade) →
  the service stack. `sen.elf` is only the power/lifecycle daemon; it `dlopen`s `libsencore.so` and
  hands it the reactor ([findings/service-mode/senser-power-daemon.md](findings/service-mode/senser-power-daemon.md)).
- **Persistence.** The Backup store (`/setting/Backup.bin`, behind `bk.elf` / `backup.ko`) holds
  camera settings and identity-bearing material: the SSH ECDSA host key (`0x3000000`), the SecVault
  records, Wi-Fi/BT/serial data, GPS/time settings. Addressing is a 32-bit id =
  `(subsystem u16 << 16) | item` ([findings/persistence/](findings/persistence/)).
- **Secure store.** SecVault's four slots sit on Backup subsystems `0x02f9` (slots 0–2) and `0x02ec`
  (slot 3); the SSH host key sits on subsystem `0x300`. Tmpfs copies (`/tmp_network/ssh/…`) are
  rewritten from Backup at init, so identity survives reboot despite living on tmpfs.

---

## 5. Security architecture at a glance

Three structures, each traced to its static boundary:

1. **Data at rest — the crypto/keystore spine.**
   `application data → SecVault (AES-256-GCM, per-record random DEK) → Backup store → backup daemon`.
   The DEK is wrapped by a KEK held in the out-of-image key service (QID `0x25906be`); SecVault and
   the Backup client are both pure *clients* of that service (no server-registration API imported).
   The master key lives provider-side / hardware-rooted and never crosses the queue. **This is the
   definitive boundary:** confidentiality of everything at rest reduces to that one key, which is in
   no extracted image. See [findings/crypto-keystore/](findings/crypto-keystore/) and
   [Investigation 4](investigations/04-security-architecture.md).

2. **The service channel — auth → dispatch → shell.**
   `SHA-256 3-level challenge-response (libsencore) → runtime verb dispatcher → SSH provisioning`.
   Authentication rests on three static 512-byte keys shipped in a library (prior public work,
   `ma1co`), so it is "only as secret as the firmware encryption." Access vector is physical USB.
   See [findings/service-mode/](findings/service-mode/) and
   [Investigation 2](investigations/02-service-mode-and-auth.md).

3. **Entitlements — HASP is a log, not a gate.**
   `/setting/.hasp` is an 88-byte, 10-entry ring of `(u16 id, BCD timestamp)` check-ins. **No
   firmware module branches on a HASP id value** (an evidenced negative across ~65k functions). Any
   feature gating happens off-device in Sony's service/factory tooling. See
   [findings/service-mode/hasp-id-gates.md](findings/service-mode/hasp-id-gates.md).

The command surface sits on top of all this: 409 internal FW commands (focus/drive, exposure/WB, a
change-driven property emitter), the 1,779-command factory adjustment vocabulary, and a separate
runtime PTP opcode map for external PC-Remote — none of which reaches secret material directly. See
[findings/command-surface/](findings/command-surface/).
