# Investigation 4 — the security architecture, synthesised

Where Investigations 1–3 each chased one question, this one steps back and assembles the security
picture that the 21 subsystem studies, taken together, draw: a **crypto/keystore spine** that protects
everything at rest, and a **service-mode chain** that is the camera's privileged side door. Both are
traced end to end — up to the exact point where they leave the extracted firmware, which is recorded as
the boundary rather than guessed past.

This is a synthesis; each claim is backed by a curated finding and its raw study. The two structures
are the headline result of the whole project.

---

## 1. The crypto / keystore spine

The camera's data-at-rest protection is a four-layer stack, traced end to end up to the point where it
leaves the extracted firmware.

### SecVault — the secure store
`libsecvlt.so` is a secure store of **four fixed slots** selected by a 32-bit item magic (descriptor
table at VA `0x101c30`, byte-verified). Each record is a `0x58`-byte header plus ciphertext: magic
`SECVAULT` (`DEADDEAD` after delete), a **wrapped data-encryption key (DEK)** at `+0x08`, a cleartext
12-byte IV, the GCM tag, size, and attributes. Encryption is **AES-256-GCM** via OpenSSL EVP. Slot 2 is
**unreadable by design** (an attribute bit makes `SECVLT_load` refuse it forever, and the bit can
neither be added nor cleared through the API). Slots 0–2 are read as C2PA content-credential signing
material (HYPOTHESIS); slot 3 has no consumer in any image.
→ [secvault](../findings/crypto-keystore/secvault.md) · [secvault-slots](../findings/crypto-keystore/secvault-slots.md)

### Key handling — the DEK is per-record random, the KEK is out of image
On store, the DEK is **per-record random** (`RAND_bytes`, 32 bytes). On load, the DEK is filled entirely
by an RPC **response payload** — it is unwrapped by an out-of-process key service. The **key-encryption
key (KEK) never enters `libsecvlt.so`**. This is the definitive static boundary: the master key lives
provider-side (the key service or hardware), not in any extracted a15 image.
→ [key-wrapping-root](../findings/crypto-keystore/key-wrapping-root.md)

### The key service — QID `0x25906be`
SecVault and the Backup store both reach the crypto service at **OSAL QID `0x25906be`** (module
`0x0259`, slot `0x06be`, kernel-routed). The command protocol is `2 = import-key → opaque handle`,
`3 = crypt`, `5 = release`; `0x428`-byte messages, `0x400`-byte chunks. The provider is **not in any
loaded image** (the QID is built in code, found by zero raw-byte sweeps). The best on-disk candidate is
`appFw.so` (the only image carrying both QID halves and the server-registration API) —  **HYPOTHESIS**;
the earlier guess that `libsecvlt.so` hosts the service was **refuted** (it is a second client).
→ [key-service](../findings/crypto-keystore/key-service.md)

### Persistence — the Backup store
SecVault records persist through the Backup store, keyed by `(subsystem, item)`, over OSAL port
`0x82cd08e0`. Its own encryption is **not local** — it is the same RPC-to-key-service.
→ [backup-store](../findings/persistence/backup-store.md) · [backup-registry](../findings/persistence/backup-registry.md)

### Net picture
```
application data → SecVault (AES-256-GCM, random per-record DEK) → Backup store → backup daemon
                         │
                         └─ DEK wrapped by a KEK held in an out-of-image key service (QID 0x25906be)
```
**Confidentiality of everything at rest reduces to that one provider-side key.** Whether it is per-device
(serial/SPACC-derived), model-wide, or hardware-rooted (the `elpspacc.ko` HSM mailbox) cannot be decided
from these images — the decisive code is behind the QID. This is the single most important unresolved
secret in the whole project; see [OPEN-QUESTIONS.md](../OPEN-QUESTIONS.md) item 1.

---

## 2. Service mode — authentication → dispatcher → verbs → shell

A privileged factory/maintenance channel, now mapped as a chain.

### Authentication
A 3-level SHA-256 challenge-response in `libsencore.so` (`SHA256(challenge[512] ‖ key[512])`, one static
512-byte key per level), decoded in [Investigation 2](02-service-mode-and-auth.md). This is prior public
work (`ma1co` / Sony-PMCA-RE), confirmed byte-identical on the a7R V.

### Dispatcher
The real post-auth verb dispatcher is in **`libsencore.so`**, not the `sen.elf` daemon. Chain:
`SenserThread` (reads a 12-byte header; verb = u16 at `buf+4`) → `Parse` (walks the active verb table) →
`Command::Execute` (**auth gate** at vtable+0x28 → status `0x82` if unauthenticated) →
`PluginCommand::DoExecute` (calls the handler). Three auth-level verb tables are swapped in by level, so
**pre-auth there are zero authorized verbs**. This sits one layer above the `command%04X`/`dlsym`
plugin-verb resolution.
→ [senser-verb-dispatch](../findings/service-mode/senser-verb-dispatch.md) · [plugin-verbs](../findings/service-mode/plugin-verbs.md)

### `sen.elf` is only the power daemon
`sen.elf` is the power/lifecycle daemon (RESUME/SUSPEND on QID `0x3d032e`); it registers no verb table
and contains no crypto. The memory-dump verb `0xff03` is reachable through the dispatch but returned
`0x80` (locked) on live hardware, consistent with a missing `command NNNN` symbol.
→ [senser-power-daemon](../findings/service-mode/senser-power-daemon.md)

### SSH provisioning
`libInfraSSHManager.so` starts `/usr/sbin/sshd` by posting the literal command string to an **OSAL
command-executor** (QID `0x94020a`; the module imports no libc `exec`/`system`/`popen`). The login
credential is a **crypt(3) `$5$` (SHA-256) password file** on the PAM path, not a Unix user or
`authorized_keys`. The **ECDSA host key** is generated by `create_host_key.sh` and persisted via the
Backup store (subsystem `0x300`, item `0x3000000`), so it survives reboot despite living on tmpfs.
→ [ssh-provisioning](../findings/service-mode/ssh-provisioning.md)

### Security posture
The whole chain's confidentiality rests on three static keys baked into a shipped library, so it is
"only as secret as the firmware encryption" — which this class of project already defeats. The access
vector is **physical USB**. HASP is not part of the gate: it is a check-in log, and no firmware module
branches on a HASP id value.
→ [hasp-store](../findings/service-mode/hasp-store.md) · [hasp-id-gates](../findings/service-mode/hasp-id-gates.md)

---

## 3. How the two structures relate

They meet at two points:

1. **The Backup store is shared.** The SSH host key, the SecVault records, and camera settings all
   persist through the same Backup domain (`0x82cd08e0`), and SecVault + Backup both wrap their secrets
   through the same out-of-image key service (`0x25906be`). So the service-mode SSH identity and the
   at-rest crypto spine are anchored to the same persistence and the same KEK.
2. **The OSAL/UIPC fabric carries both.** Every link above is an OSAL queue message
   ([osal-uipc](../findings/transport/osal-uipc.md)); the processor split (a15 service/crypto vs. main-SoC
   command table) is why the service-mode memory-dump verb has no line of sight to `cpapp` addresses.

The practical upshot: an attacker (or a researcher) with physical USB can complete the public SENSER
auth and reach the service shell, but **reading or forging data at rest still requires the out-of-image
KEK**, and that key is the one thing the extracted firmware does not contain. The two structures are
fully mapped; both terminate at the same provider-side boundary, recorded in
[OPEN-QUESTIONS.md](../OPEN-QUESTIONS.md).
