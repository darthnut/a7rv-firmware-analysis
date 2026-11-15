# Open questions — the frontier

What is *not* settled, prioritised, each with the static boundary where the trail ends and why. These
are drawn from the per-finding "Boundary / open" sections, the synthesis in
[framework-runs/CONSOLIDATED.md](framework-runs/CONSOLIDATED.md) §8, and the prioritised
[framework-runs/target-list.md](framework-runs/target-list.md). Each item names the image or layer
that would resolve it.

Everything below terminates in an image or hardware root **not in hand**, and is recorded rather than
guessed past. Nothing here is a to-do with a known answer; it is the edge of what static analysis of
the extracted firmware can reach.

---

## Tier 1 — the crypto / security spine

### 1. The master KEK — what the key service's key-encryption key is bound to
**The single most important unresolved secret; everything at rest depends on it.** SecVault stores a
*wrapped* per-record DEK; the KEK that wraps it lives inside the out-of-image key service (QID
`0x25906be`) and never crosses the queue. The decisive unknown is whether that KEK is per-device
(serial/SPACC-derived), model-wide, or hardware-rooted (HSM/OTP).
**Boundary:** the provider process is in no extracted image. String-level machinery one layer over
(`libInfraCryptCore.so`: `ics_getSerialNumber`, `act_get_key_source`, `SerialPublicKey`, `FixKey`,
`backup == abRedKey`) hints at a per-device source; `kmod/elpspacc.ko`'s SPACC HSM mailbox
(`/dev/spaccusr`, `SPACC_REG_HSM_*`) hints at a hardware root. Neither is decided from these images.
**Resolve by:** loading the provider into Ghidra and reading its op-2/op-3 handlers.
→ [key-wrapping-root](findings/crypto-keystore/key-wrapping-root.md) ·
[key-service](findings/crypto-keystore/key-service.md)

### 2. Which binary owns QID `0x25906be` (the key-service server identity)
The service is reached by SecVault *and* the Backup client, both pure clients. The provider is not in
any loaded image, and its best on-disk candidate (`libsecvlt.so`) was **refuted** — libsecvlt is a
second client, not the server.
**Boundary:** the QID exists only as `movz`/`movt` immediates in code (zero raw-byte hits), so only a
code-encoding search finds the server. Of the images that carry both QID halves and the
server-registration API, **`appFw.so`** is the one on-disk candidate (HYPOTHESIS; not decompiled).
**Resolve by:** locating the `osal_reg_sync_msg_queue_cb` call whose immediate materialises
`0x25906be` in `appFw.so`, or reading the kernel subscriber for slot `0x06be` in `osal_uipc.ko`.
→ [key-service](findings/crypto-keystore/key-service.md) · [secvault](findings/crypto-keystore/secvault.md)

### 3. SecVault slot payloads — the "C2PA" attribution is UNconfirmed
Slots 0–2 (subsystem `0x02f9`) are addressed only by `InfraC2PA` in `libmpr.so`, which is why they
are read as C2PA content-credential signing material (slot 1 = cert chain, slot 2 = write-only
private key, slot 0 = companion object). **This identity is HYPOTHESIS** — there are no C2PA strings
in `libsecvlt.so` itself, and no AArch64 disassembler was available to prove which `SECVLT_*` call
each magic-materialising site feeds. Slot 3 (subsystem `0x02ec`, 60000 B) has **no consumer in any
image** — payload entirely unknown.
**Boundary:** the callers are stripped libraries not loaded in Ghidra; attribution rests on nearest-
preceding `.dynsym` symbols and `.rodata` strings in `libmpr.so`.
→ [secvault-slots](findings/crypto-keystore/secvault-slots.md)

---

## Tier 2 — persistence and the external surface

### 4. Backup payload inventory — what each `(subsystem, item)` actually holds
The id *scheme* is solid (proven three ways). The *registry* — which id holds what — is largely
HYPOTHESIS: only the SSH host key (`0x300/0x3000000`), the four SecVault ids, and a GPS clock flag
(`0x2cf0014`) are CONFIRMED; the rest (`0xa1`, `0x7a`, `0x7b`, `0x102`, `0x0f9`, `0xfa` memory
carve-out, `0x91`) are read from caller context only, and the `BKID_*` names are name-derived.
**Boundary:** the payload owners are backup-daemon-side (`libbkdmn.so` / `bk.elf`); `Backup.bin` is
not in the extraction. `Backup_read` has 167 xrefs in `libObj.so` alone — the read side is sampled,
not exhausted.
→ [backup-registry](findings/persistence/backup-registry.md)

### 5. PTP handler bodies and the Sony vendor opcode values
The PC-Remote responder is a runtime `std::map<u16 OperationCode, MrpwOperationsBase*>` in
`libInfraRemote.so`, populated by static `.init_array` registrars. The ~50 operation classes are
known by name; the **numeric vendor opcodes are not resolvable** (baked into constructor bodies), and
the opcode → FW-command (`0x40xx`) translation site was never located.
**Boundary:** `libInfraRemote.so` / `libptp.so` are not imported into any Ghidra project; `ptpExt.map`
(the likely extension map) is absent from the extraction.
**Resolve by:** disassembling the `.init_array` constructors; finding the a15→cpapp queue id.
→ [usb-ptp-surface](findings/command-surface/usb-ptp-surface.md)

### 6. Main-SoC-side consumers of the latched command state
Nearly every `cpapp` FW handler is a *latch*: it parks arguments plus a change counter in a settings
block and returns 1, with no reader in `cpapp` itself (e.g. the focus-bracket exec-state global has
one write and no read). The consumers live on the other processor / in images not in hand. The one
exception is `SET_DRIVE_MODE`, which forwards over OSAL to a statically visible port.
**Boundary:** the cross-processor queue consumers and the write-cliff *release* side are in the main-
SoC image not extracted.
→ [fw-command-table-focus-drive](findings/command-surface/fw-command-table-focus-drive.md) ·
[fw-command-table-exposure](findings/command-surface/fw-command-table-exposure.md)

### 7. The focus-bracket write-cliff release side
Investigation 1 traced the acquire path (`ExecRcAcquire` retry loop in `av-cam.bin`) that paces the
post-~44-frame cliff. The *release* side and the tie to the cross-chip write pipeline remain
HYPOTHESIS — the cross-chip timing is the measured part, the backpressure linkage is not a static
call-path result.
**Boundary:** SDF module exec is dispatched data-driven by the graph scheduler; no direct call edge
from the acquire path to any write/recording subsystem was found in `av-cam.bin`. Also open: the unit
of the `20000` retry timeout (µs → ~20 s worst case; ns → below the measurement floor).
→ [develop-resource-acquire](findings/behavior/develop-resource-acquire.md) ·
[Investigation 1](investigations/01-focus-bracket-cadence.md)

---

## Tier 3 — blocked or low-value

### 8. a7R VI firmware — blocked at the crypto layer
The a7R VI update package (`BODYDATA`, ~338 MB) is the same UFU container family but fully encrypted
(entropy 8.00/8 throughout), format version moved on (`DATV = 04` vs `01`), and the a7R V Gen5 keys
produce zero valid checksums against it.
**Boundary:** reading it needs the a7R VI generation's updater keys (community RE of the updater) or a
flash dump off the body. No static path without new key material. Nothing about a7R VI features can be
asserted from this file.
→ [Investigation 3](investigations/03-a7rvi-blocked.md)

### 9. The service-mode `0xff03` memory-dump verb — why it is locked
On a live owned body the raw memory-dump verb returned `0x80` for every address. Statically, `0xff03`
is in no SENSER verb table and no `memory FF03` symbol exists, so the live result is the missing-
handler fallback firing — but *why* (unregistered on this body vs. permission-gated vs. the a15/cpapp
processor split meaning an a15 dump verb has no line of sight to `cpapp` addresses) is not settled.
**Boundary:** SENSER dispatch is runtime-registered in `libsencore.so`; whether a `0xff03` handler is
materialised on demand (e.g. by a HASP entitlement) is not provable from the static image. Settling it
would need the a15 debug terminal — and enabling that terminal is itself a *write*, out of scope for an
observe-only run.
→ [senser-verb-dispatch](findings/service-mode/senser-verb-dispatch.md) ·
[Investigation 2](investigations/02-service-mode-and-auth.md)

### 10. HASP id → feature meaning
The firmware is a recorder/transport of HASP ids; it never branches on an id value. What a specific id
*means* is assigned by external Sony service/factory tooling.
**Boundary:** not in the firmware at all — the factory harness is not part of any image.
→ [hasp-id-gates](findings/service-mode/hasp-id-gates.md)

---

## Non-goals (not statically resolvable from these images)

The hardware/fused KEK · runtime-provisioned values (HASP ids, the senser-mode VID/PID, which is set
by the `usbg_sen.ko` kernel gadget) · main-SoC-side queue consumers · thermal constants · lens-firmware
semantics · the on-media `Backup.bin` record format (daemon/kernel-side) · the `/dev/uipc` kernel
driver internals. These are listed so a reader does not mistake their absence for an oversight.
