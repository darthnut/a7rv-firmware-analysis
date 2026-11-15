# Key-wrapping root — where the KEK comes from

**Summary.** The payload key (DEK) is per-record random; the key-encryption key (KEK) that wraps it lives
inside the out-of-image key service and never crosses the queue — so the master key's binding
(per-device vs model-wide vs hardware) cannot be decided from any extracted image.

**Where.** `libsecvlt.so` (`ghidra_secvlt`): `SECVLT_store` `0x101544` (the `RAND_bytes` DEK +
import/wrap sequence), `SECVLT_load` `0x101768` (unwrap), RPC primitive `FUN_0010117c` `0x10117c`, sync
send `FUN_001010e8` `0x1010e8`. Cross-check `libBackupManager.so` `writeBackupEncryption` `0x101454`.
String-level only (never decompiled): `libInfraSKD.so`, `libInfraCryptCore.so`, `appFw.so`.

**Mechanism.**
- **Payload key (DEK): per-record, random (confirmed).** `SECVLT_store` calls `RAND_bytes(stack, 0x20)`
  fresh for every store; the 32-byte DEK exists only on the client stack, is handed to the service to be
  wrapped (op 3, direction 1), and only its wrapped form persists (`rec+0x08`). No two records share a
  DEK.
- **KEK: lives inside the service; not obtainable through this protocol (confirmed client-side).** The
  AES key buffer in `SECVLT_load` is filled **entirely by the RPC response payload** — the unwrapped DEK
  arrives in the client's output buffer. No observed op returns KEK material.
- **The one non-code inference:** the only key material SecVault *gives* the service is a value already
  stored in plaintext in the record it protects (the GCM tag). So the service must mix in its own secret
  (a KEK, or a KDF over a device secret) that never crosses the queue — **confirmed that the KEK is
  provider-side; HYPOTHESIS on the exact mechanism.**

**Verification.** *light (boundary pinned).* The DEK generation, the import/wrap/unwrap op sequence, and
the EVP key-argument back-trace are decompiled by address in both clients. The provider-side KEK is a
client-side-absence result (the trio `osal_valloc_msg_wait` / `osal_snd_sync_msg` / `osal_free_msg` is
present, the server-registration API is not) plus one labelled inference.

**Boundary / open.** The trail ends at `osal_snd_sync_msg(0x25906be, …)`. Per-device vs model-wide is
**UNRESOLVED**: Backup's import blob is a model-wide static placeholder (but B.2 shows import material
need not be secret); `libInfraCryptCore.so` carries per-device machinery (`ics_getSerialNumber`,
`act_get_key_source`, `SerialPublicKey`, `FixKey`, `backup == abRedKey`) → if the provider sources keys
there, the KEK is per-device; `kmod/elpspacc.ko`'s SPACC HSM mailbox → if it bottoms out there, the KEK
is hardware-rooted and non-exportable. **Do not conclude device-specific security from this image set.**
Resolve by loading `appFw.so` and reading the `0x25906be` callback's op-2/op-3 handlers. See
[OPEN-QUESTIONS.md](../../OPEN-QUESTIONS.md) item 1.

**Source.** [framework-runs/keywrap-map.md](../../framework-runs/keywrap-map.md)
