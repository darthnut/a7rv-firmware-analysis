# Backup store — model and cipher (`libBackupManager.so`)

**Summary.** The persistence layer addresses items by a 32-bit id `= (type<<16)|item`, sends
fire-and-forget writes to a backup daemon over OSAL port `0x82cd08e0`, and encrypts not locally but by
the same RPC to the key service — the userland library never holds the real key.

**Where.** `fs/a15/lib/libBackupManager.so` (project `ghidra_extra`, base `0x100000`). `writeBackup`
`0x10135c`, `writeBackupEncryption` `0x101454`, `readBackupDecryption` `0x101594`, `cipherUpdate`
`0x1013b4`, `isReadDataEncrypt` `0x101414`, `isNeedPadding` `0x101440`, the async sender `BkDmn_write`
`0x10128c`, the key-service RPC core `FUN_001010e4` `0x1010e4`. Backing store `/setting/Backup.bin`
(behind `bk.elf` / `backup.ko`).

**Mechanism.**
- **Addressing:** `id = (type u16 << 16) | item` (proven by `BkDmn_write` splitting the id back apart on
  the wire). Writes are **asynchronous fire-and-forget** to OSAL port `0x82cd08e0` (cmd 2, type, id, len,
  payload) — the client cannot confirm persistence; only `Backup_sync_subsystem(type)` forces a flush.
- **Cipher:** 16-byte block, **no padding** (`isNeedPadding` rejects non-multiples of 16). Encryption is
  **not a library** — `cipherUpdate` and the key helpers funnel into one synchronous RPC to the key
  service on **port `0x25906be`** ([key-service](../crypto-keystore/key-service.md)): cmd 2 import
  (16-byte input from a static `.rodata` placeholder), cmd 3 crypt, cmd 5 release.
- **`isReadDataEncrypt`** is a heuristic, not metadata: an all-zero item is returned as plaintext (that is
  how deletion — zero-fill — reads back harmlessly), anything else is decrypted.
- **Two client paths:** the `BackupManager` encrypted/plaintext wrapper, and the raw `libbkdmn.so` API
  (`Backup_read`/`Backup_write`/`Backup_nread`/`Backup_sync_subsystem`) that most consumers actually use.

**Verification.** *light.* Every cited function decompiled by address; the id split and the async write
message read directly; the 16-byte import constant byte-read and confirmed never-written; the
`/setting/Backup.bin` backing identified from `bk.elf` strings. The AES family / mode is **HYPOTHESIS**
(from `libInfraSKD.so` leaked symbols `Aes::Encrypt{ECB,CBC}` + `AES/CBC/CTR/ECB/GCM` strings; the handle
is opaque).

**Boundary / open.** The **daemon and kernel side are out of scope** — `bk.elf`, `backup.ko`, any
daemon-side encryption, and the on-media `Backup.bin` record format are owned there; no `Backup.bin`
image exists in the extraction. **Policy finding:** the `BackupManager` encrypted wrapper has **no
shipped consumer** — real consumers (SSH manager, `libObj`, `NsBkSet.elf`) use the raw `libbkdmn` API, so
the SSH host key is persisted via raw `Backup_write` (plaintext client-side, unless the daemon encrypts
internally — OPEN). The id registry is [backup-registry](backup-registry.md).

**Source.** [framework-runs/backup-map.md](../../framework-runs/backup-map.md)
