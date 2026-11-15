# a7R V crypto/key service behind the Backup store

Static RE of the user's own Sony a7R V firmware (image at `/srv/a7rv/a7rv-fw`). Mechanism,
offsets, ports only — **no key material is reproduced anywhere in this document.**

Status: COMPLETE — QID identified; provider out of the loaded images, best candidate SECVAULT (HYPOTHESIS)

## A. The key-service port

**QID: `0x25906be`** — the crypt/import RPC in libBackupManager.so is a synchronous OSAL
message queue to this single queue ID. (All offsets = Ghidra virtual addresses.)

### The send path (libBackupManager.so)

`FUN_001010e4` @0x1010e4 is the RPC wrapper. It allocates the message **on that QID**, fills
it, and calls the send helper; `FUN_00101050` @0x101050 does the actual synchronous send.
Quoted send (Ghidra `decompile_function` @0x101050):

```c
int FUN_00101050(ulong param_1, long param_2, int *param_3, long param_4, long *param_5)
{
  iVar1 = osal_snd_sync_msg(0x25906be, param_5);   // <-- the RPC
  if (iVar1 == 0) {
    if (*param_5 == 0) { iVar1 = -0x3fa; }         // status word == 0 → error
    else if (((param_2 != 0) && ((param_1 & 1) != 0)) &&
            (memcpy((void *)(param_2 + param_4), param_5 + 5, param_5[4]), ...
```

And the allocation (Ghidra decompile @0x1010e4):

```c
iVar2 = osal_valloc_msg_wait(0x25906be, &local_8, 0x428, 1);  // 0x428-byte message
...
osal_free_msg(0x25906be);
```

Callers (xrefs from Ghidra `list_xrefs` @0x1010e4):
`BackupManager::cipherUpdate` @0x1013b4, `BackupManager::writeBackupEncryption` @0x101454,
`BackupManager::readBackupDecryption` @0x101594, and `FUN_00101238` @0x101238 (handle release).

### Message struct (0x428 bytes, u64-indexed, same buffer reused for request → response)

| Field | Content | Evidence |
|---|---|---|
| `msg[0]` | command number | `*local_8 = param_1` @0x1010e4 |
| `msg[1]` | key handle (0 on import) | `local_8[1] = param_3`; cipherUpdate passes handle |
| `msg[2]` | constant `1` on import, `0` on crypt — meaning unclear (key slot / algorithm selector — HYPOTHESIS) | `local_8[2] = param_4` |
| `msg[3]` | direction on import: `1` = encrypt (write path), `0` = decrypt (read path) | `local_8[3] = param_5` |
| `msg[4]` | payload length (in / out) | set from memcpy size; read back as `param_5[4]` |
| `msg[5]…` | 0x400-byte data buffer (chunked) | `memcpy(local_8+5, param_8+uVar3, ≤0x400)` |
| response `msg[0]` | status word | `*param_5 == 0 → -0x3fa` @0x101050 |

### Commands (confirmed)

- **2 = import-key → opaque handle.** `writeBackupEncryption`: `FUN_001010e4(2, 3, 0, 1, 1,
  &local_8, 0, &DAT_001120a8, 0x10)` — 16-byte input from a static blob; the returned handle
  lands in `&local_8` because flags bit0 makes `FUN_00101050` copy the response payload back.
  `readBackupDecryption` does the same with direction `0`. **Confirmed: 2 = import.**
- **3 = crypt.** `cipherUpdate` @0x1013b4: `FUN_001010e4(3, 3, handle, 0, 0, out, &bytes, in,
  len)` — 0x400-byte chunks, direction baked into the handle at import. **Confirmed: 3 = crypt.**
- **5 = release handle.** `FUN_00101238` @0x101238: `FUN_001010e4(5, 2, handle, 0,0,0,0, buf, 1)`.
- Flags word (`param_2`): bit1 = copy input buffer into message, bit0 = copy response payload
  to caller buffer.

### Key input: a static placeholder blob

Import key material is `&DAT_001120a8` (libBackupManager.so, .rodata/.data region), length
0x10. `list_xrefs` 0x1120a8 → **only** the two import PARAM sites; nothing ever writes it.
Characterization only (bytes deliberately not quoted): 16 fully-printable-ASCII bytes forming
the well-known sequential hex-digit placeholder pattern (`0`–`9` then `a`–`f`) — textbook
placeholder default, not high-entropy random material. See C.

### QID semantics (libosal_uipc.so, ghidra_svctools)

Ghidra decompile `osal_valloc_msg_wait` @0x1067b0 and `osal_reg_sync_msg_queue_cb` @0x105b88:
- bit 15 of the QID selects the transport: `(qid >> 15) & 1` — **0 → `u_osal_*` kernel path**
  (`u_osal_valloc_msg_wait` @0x103e98 etc., backed by `kmod/osal_uipc.ko`). 0x25906be has
  bit15 = 0, so backup RPCs are **kernel-routed uIPC message queues**, not userland sockets.
- queue slot = `qid & 0x7fff` = **0x06be**; module/task field = `(qid >> 16) & 0xfff` = **0x0259**.
- Server-side registration is `osal_reg_sync_msg_queue_cb(qid, &handle, cb, arg)` @0x105b88,
  which keys the local table on `qid & 0x7fff`. So the provider is the process (or kernel
  subscriber) owning module **0x0259**, queue **0x06be**.
- Max message 0x1000 (`osal_valloc_msg_wait`: `0x1000 < param_3 → error`), so 0x400 chunks
  with a 0x28-byte header fit one page.

## B. Who serves it

**Not found in the loaded Ghidra images.** A literal-code search for `0x25906be` in every
binary loaded across the three Ghidra projects — ghidra_extra (`crypter.elf`,
`libBackupManager.so`, `libObj.so`), ghidra_svc (`sen.elf`, `libsencore.so`, `libIMDB.so`,
`libInfraSSHManager.so`), ghidra_svctools (`libosal_uipc.so`, `adjstctl.elf`,
`libtestcmd.so`) — returns hits **only** in `libBackupManager.so`, i.e. only the client.
A full-image raw-byte sweep for the little-endian dword `BE 06 59 02` over `bin/`, `lib/`,
`kmod/` (read-only `grep -Pa`) finds **zero** files — the QID is never stored as data, only
materialized in code (movz/movk), so a data-table search alone cannot resolve the provider.
Other queue owners found, none ours: `sen.elf` registers **0x3d032e** ("SENSER CORE module"
— `FUN_00401f80` → `osal_reg_sync_msg_queue_cb(0x3d032e, &DAT_00416288, FUN_00402020)`);
`libObj.so` registers 0x4b0231 ("SENSER"), 0x4b0376 ("LSI_TRANSFER"), 0x807b018d, 0x80924126,
0x910040. `crypter.elf` is unrelated (Memory Stick crypt-file updater: `mcmn_init`,
`GetCryptFileInputModeUpdater` imports).

**Recorded for future images:** QID **`0x25906be`** = module field **0x0259**, queue slot
**0x06be** (`qid & 0x7fff`), bit15 = 0 → kernel uIPC routing (`kmod/osal_uipc.ko`).
A future image can grep for the `movz #0x6be` + `movk #0x259,lsl 16` pair (AArch64 encodings
`[C0-DE] D7 80 [52|D2]` and `[20-3E] 4B A0 [72|F2]`).

**Strongest out-of-image candidate: `lib/libsecvlt.so` — "SECVAULT"** (HYPOTHESIS; not loaded
in Ghidra, so this is string/encoding evidence, not decompilation):
- It contains the literal tag `SECVAULT` and source name `sec_vault_internal.c`.
- It imports exactly the client-side OSAL queue trio `osal_valloc_msg_wait` /
  `osal_snd_sync_msg` / `osal_free_msg` — the same synchronous request/response idiom as
  libBackupManager (Ghidra-verified on the client side).
- It uses `EVP_aes_256_gcm` / `EVP_CIPHER_CTX_set_key_length` (OpenSSL) — i.e. it performs
  the bulk crypto itself rather than delegating further.
- It imports `Backup_nread`, `Backup_write`, `Backup_get_datasize`, `Backup_sync_subsystem`
  — the vault persists through the same Backup subsystem `writeBackupEncryption` writes into.
- It is the only library besides `libBackupManager.so`, `appFw.so`, `libmpr.so` and
  `libAiDictionary.so` that contains **both** halves of the QID's movz/movk encodings (pair
  co-occurrence is suggestive, not proof — the two instructions need not be adjacent).
- Its consumers are `libInfraCryptCore.so` and `libmpr.so`, so the SECVAULT service thread
  most likely runs inside one of those host processes (HYPOTHESIS).

Kernel/hardware substrate (context, out of scope): `bin/load_crypto_ko.sh` loads
`elpmem.ko`, `elppdu.ko`, `elpspacc.ko`, `elpspaccusr.ko`, `crypto_kapi.ko`. String analysis
of these shows Sony's **SPACC** security engine: `/dev/spaccusr` device, AES-GCM backend,
and an HSM mailbox (`SPACC_REG_HSM_CMD_REQ/GNT/CTX_CMD`). If SECVAULT bottoms out in
SPACC/HSM, key operations are hardware-accelerated (HYPOTHESIS; kmods not decompiled).

## C. Key provenance

**Confirmed (client side):** the key that the Backup store *imports* into the crypt service
(`&DAT_001120a8`, 16 bytes, `list_xrefs` shows no writer) is a **static constant baked into
libBackupManager.so** — a printable-ASCII sequential hex-digit placeholder pattern
(characterized, not quoted). It is therefore **model-wide / per-firmware-build, identical on
every a7R V running this firmware, and not derived from the device**. This is a textbook
placeholder default, which strongly suggests the *real* protection does not come from this
blob at import time (HYPOTHESIS).

**HYPOTHESIS (out of image):** the effective data-encryption key is likely established
*inside* the service. Supporting string-level evidence, no decompilation:
- SECVAULT (`libsecvlt.so`) holds AES-256-GCM internally and persists via `Backup_nread` /
  `Backup_write` — the client-visible blob can be an index/wrapper rather than the real key.
- `libInfraCryptCore.so` (a SECVAULT consumer) carries per-device machinery:
  `ics_getSerialNumber`, `ics_getModelName`, `ics_generateMui`, `iCryptManager_createPrivateKey`,
  `act_get_key_source`, `SerialPublicKey`, `FixKey`, and a debug string `backup == abRedKey`
  hinting backup key material is compared against or fed from an iCrypt key source.
- SPACC's HSM mailbox (`kmod/elpspacc.ko`) gives a plausible hardware root of trust: if used,
  keys become per-device and non-exportable (HYPOTHESIS; kmods not analyzed).

**Judgement:** the key the Backup client supplies is model-wide (VERIFIED client-side);
whether the service mixes it with per-device (serial/SPACC/HSM) material cannot be determined
from these images — the decisive code is in `libsecvlt.so` / `libInfraCryptCore.so` /
`kmod/*`, none of which is decompiled here. Do **not** conclude device-specific security
from this image set alone.

## D. Scope / safety

- Mechanism, offsets, ports and protocol only. **No key bytes are reproduced in this
  document**; the 16-byte import blob is characterized (ASCII pattern class, length, xrefs)
  but never dumped.
- All analysis is static, read-only, on the owner's own extracted firmware at
  `/srv/a7rv/a7rv-fw`. No device interaction, no runtime exploitation, no dumping of
  live key material.
- Ghidra analysis was restricted to read-only tools (project listing, decompilation by
  address, xrefs, code/symbol search). Binary import/analysis and all mutation tools were
  not used, so `libsecvlt.so` and `libInfraCryptCore.so` are characterized from ELF
  strings/`readelf` only and are marked HYPOTHESIS wherever behavior is inferred.
- Out of scope: kernel module internals (`osal_uipc.ko` queue routing, `backup.ko`,
  `elpspacc*.ko`), unextracted images (e.g. main-SoC / other-core side), and anything
  requiring running the device.

## How this was checked

1. `list_project_binaries` on ghidra_extra / ghidra_svc / ghidra_svctools — inventory.
2. Ghidra `decompile_function` **by address**: `FUN_001010e4` @0x1010e4 (RPC wrapper,
   valloc + fill + chunking), `FUN_00101050` @0x101050 (send: `osal_snd_sync_msg(0x25906be,…)`),
   `FUN_00101238` @0x101238, `cipherUpdate` @0x1013b4, `writeBackupEncryption` @0x101454,
   `readBackupDecryption` @0x101594, `isReadDataEncrypt` @0x101414 (libBackupManager.so);
   `osal_valloc_msg_wait` @0x1067b0, `osal_snd_sync_msg` @0x106458,
   `osal_reg_sync_msg_queue_cb` @0x105b88 (libosal_uipc.so — QID decode, 0x1000 cap, reg
   keyed on `qid & 0x7fff`); `FUN_00401f80` (sen.elf — shows its QID is 0x3d032e, not ours).
3. `list_xrefs` @0x1010e4 (caller set) and @0x1120a8 (blob: import PARAM sites only → blob
   never written); `read_bytes` 0x1120a8,16 → blob characterized as printable-ASCII
   placeholder pattern (value withheld).
4. `search_code` (literal mode) for `0x25906be` and for the queue-reg APIs in every loaded
   binary → client-only hits; `search_symbols_by_name` for `osal_`, reg callbacks.
5. Read-only filesystem sweeps (grep): queue-reg API importers across `bin/`+`lib/`+`kmod/`;
   raw little-endian dword `BE 06 59 02` (0 hits anywhere); AArch64 `movz #0x6be` /
   `movk #0x259,lsl16` encodings (5 co-occurring files incl. `libsecvlt.so`); `strings` +
   `readelf -d` on `libsecvlt.so`, `libInfraCryptCore.so`, `kmod/{crypto_kapi,elpspacc,
   elpspaccusr,backup}.ko`, `bin/load_crypto_ko.sh`.
6. Open items: `libsecvlt.so` / `libInfraCryptCore.so` not decompiled (import out of scope);
   movz+movk co-occurrence not adjacency-verified; kernel-side uIPC subscriber for slot 0x06be
   unexamined; a future image with SECVAULT loaded should re-run the literal search for
   `0x25906be` to convert B's HYPOTHESIS into a finding.
