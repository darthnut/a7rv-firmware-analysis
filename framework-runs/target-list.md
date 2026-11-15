# a7R V firmware — prioritized analysis target list

Scope: the **interesting surface** (security, crypto, customization, service-mode, documented
behavior), not literal full coverage of ~65k functions / 352 libs / two 17 MB blobs. Priorities
reflect value × static tractability. Each entry: why, tractability, rough cost (Flash-Next jobs
at ~1.5–2 h each, one at a time), and setup (Ghidra import?).

Legend: ✅ done · 🔄 running/queued · ⬜ not started · ⛔ likely blocked statically

## Done this session (baseline)
plugin-verb (HASP verbs) · service-adjust (adjstctl 1779-cmd vocab) · service-framing ·
ssh-provisioning · osal-uipc · backup-store · crypter · hasp-store · cpapp focus/drive cmds (8) ·
keyservice (QID 0x25906be) · haspgates (negative) · develop (ExecRcAcquire) · secvault
(AES-256-GCM). 🔄 sen.elf (SENSER daemon). imdb abandoned.

---

## Tier 1 — High value, tractable, do next (the crypto/security spine)

1. **Key-wrapping root / master key source** ⬜ ~1–2 jobs. *Why:* SecVault stores a **wrapped
   DEK**; the key-encryption key (KEK) lives outside libsecvlt — in the key service (QID
   0x25906be) or hardware. Pin where the KEK comes from (derived? fused/OTP? a provisioning
   blob?) and exactly where the static trail ends. Closes the single most important crypto
   question. *May hit a hardware/fused-key wall — then the deliverable is the boundary.*
   Depends on: keyservice + secvault (done). Import: maybe the key-service provider lib if found.

2. **SENSER service verb catalog + MemoryDump 0xff03** ⬜ ~1–2 jobs (sen.elf run may seed it).
   *Why:* complete the post-auth service command set and settle *why* the 0xff03 memory-dump verb
   returned 0x80 on live hardware (unregistered vs permission-gated). Ties Investigation 2 →
   daemon → verbs. Import: none (ghidra_svc).

3. **SecVault slot contents map** ⬜ ~1 job. *Why:* the 4 SecVault slots and the Backup-store
   item ids (0x3000000 = SSH key, etc.) — map subsystem/item → what each actually holds (keys,
   WiFi creds, licenses, calibration). Makes the persistence story concrete. Import: none.

4. **Factory adjustment handler semantics** ⬜ ~2–3 jobs. *Why:* service-adjust mapped the 1779
   host-side command *names→opcodes*; the **camera-side handlers** (what an ADJ_/DIAG_ actually
   does to sensor/AF/gyro) are unmapped. Pick high-value families (sensor cal, AF adjust,
   ADJSTART/ADJEND session). *This is the "manufacturing can alter calibration" surface.* Import:
   find the handler binary (cpapp or an a15 svc lib).

## Tier 2 — Valuable, more work

5. **Remaining FW command families** ⬜ ~6–10 jobs. *Why:* 401 of 409 commands unmapped. Group
   by family and do the behavior-relevant ones: exposure/metering, white balance, the 0x78xxxx
   **property GET layer** (102 handlers), I/O & storage, custom-button/menu. Skip pure
   image-pipeline params. Import: none (ghidra_cpapp).

6. **Boot & provisioning chain** ⬜ ~1–2 jobs. *Why:* bootin.elf + a15 init — how the service
   account, sshd, host key and SecVault get set up at boot vs factory; first-boot provisioning.
   Connects SSH + SecVault + service mode. Import: bootin.elf.

7. **USB / PC-Remote (PTP) command surface** ⬜ ~1–2 jobs. *Why:* how tethering (Imaging Edge)
   commands map onto the FW command table — the externally reachable attack/automation surface.
   Import: likely the USB/PTP handler lib.

8. **Where calibration/settings persist** ⬜ ~1 job. *Why:* do adjustment values land in
   SecVault, the Backup store, or a raw partition? Closes the data-at-rest picture. Import: none.

## Tier 3 — Lower value or partly blocked

9. **Investigation-1 remnants** ⛔ *Why:* the write-cliff *release* side and the cross-processor
   queue consumers (0x8f013a / 0x80924220) almost certainly live in the **main-SoC image not in
   hand** — record the boundary, don't chase. ~1 job to close out, then stop.

10. **Imaging / develop pipeline internals (av-cam)** ⬜ huge, low customization value. Only if a
    specific behavior question demands it.

11. **a7R VI firmware** ⛔ blocked at the crypto layer (Gen5 keys rejected). No static path
    without new key material.

12. **libIMDB** ⛔ deprioritized — stuck-loop dud, low value.

---

## Cross-cutting

- **Deep re-verifications** (post-noon, quiet window): OSAL ioctl numbers in the real u_osal
  bodies; backup key-service protocol (FUN_001010e4); confirm SecVault owns QID 0x25906be;
  AES-256-GCM key-source claims. ~0.5 day.
- **Explicit non-goals (not statically resolvable):** the hardware/fused KEK, runtime-provisioned
  values (HASP ids, VID/PID), main-SoC-side queue consumers, thermal constants, lens-firmware
  semantics.

## Rough totals
- **Tier 1:** ~5–8 jobs → ~1.5–2 days continuous. Highest value; finishes the crypto/security spine.
- **Tier 1+2:** ~16–26 jobs → ~4–6 days continuous.
- **Everything tractable (1–3 closeouts):** ~20–30 jobs → ~5–7 days continuous, single Flash-Next
  stream. A parallel cloud/GLM lane roughly halves wall-clock.

Beyond this is literal full coverage (weeks–months, never truly 100%, mostly low-value silicon
glue) — out of scope for "map the interesting subsystems."
