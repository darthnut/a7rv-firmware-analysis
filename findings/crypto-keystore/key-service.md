# Key service — the crypto RPC behind QID `0x25906be`

**Summary.** SecVault and the Backup store both wrap their secrets by RPC to a crypto/key service on
OSAL QID `0x25906be`; the service's provider is in no extracted image, and the client never sees the KEK.

**Where.** Client side in `libBackupManager.so` (project `ghidra_extra`): RPC wrapper `FUN_001010e4`
`0x1010e4`, sync send `FUN_00101050` `0x101050`, callers `cipherUpdate` `0x1013b4`,
`writeBackupEncryption` `0x101454`, `readBackupDecryption` `0x101594`. QID decode in `libosal_uipc.so`
(project `ghidra_svctools`): `osal_valloc_msg_wait` `0x1067b0`, `osal_reg_sync_msg_queue_cb` `0x105b88`.

**Mechanism.**
- **One queue.** `0x25906be` → module field `0x0259`, queue slot `0x06be` (`qid & 0x7fff`), bit 15 = 0 →
  **kernel-routed uIPC** (`kmod/osal_uipc.ko`), not a userland socket. Max message `0x1000`.
- **Message** (`0x428` bytes, u64-indexed, reused for the reply): `msg[0]` command, `msg[1]` key handle,
  `msg[2]` a client selector (`1` for Backup imports, `0x10`/`0` for SecVault — meaning unresolved),
  `msg[3]` direction (1 = encrypt, 0 = decrypt), `msg[4]` payload length, `msg[5…]` 0x400-byte chunks.
- **Commands (confirmed by decompile):** `2 = import-key → opaque handle`, `3 = crypt` (direction baked
  into the handle at import), `5 = release`. Flags word: bit 1 copy input into the message, bit 0 copy
  response payload back out.
- **Client key input.** The Backup client imports a **static 16-byte placeholder** from `.rodata`
  (`0x1120a8`) — a printable-ASCII sequential hex-digit pattern (characterised, not quoted), identical on
  every unit, therefore *not* device-unique material. SecVault instead imports each record's own GCM tag.
  In both clients **the KEK is never transmitted** — only import material, handles, and wrapped/cleartext
  DEKs cross the queue.

**Verification.** *light.* The RPC wrapper, sync send, and all three caller commands decompiled by
address; the QID semantics (bit-15 transport select, slot/module decode, `0x1000` cap) decompiled from
`libosal_uipc.so`; the 16-byte import blob confirmed never-written (`list_xrefs` shows import-param sites
only). Provider identity and the KEK's binding are inference beyond the client.

**Boundary / open.** The provider is **not in any loaded image**: a literal `0x25906be` search hits only
clients, and a raw-byte dword sweep finds **zero** files (the QID exists only as `movz`/`movt`
immediates). The strongest on-disk candidate is `appFw.so` (the only image carrying both QID halves and
the `osal_reg_sync_msg_queue_cb` server API) — **HYPOTHESIS**; `libsecvlt.so` was **refuted** as the
provider. A future image can grep for the `movz #0x6be` + `movk #0x259,lsl 16` encoding pair. See
[key-wrapping-root](key-wrapping-root.md) and [OPEN-QUESTIONS.md](../../OPEN-QUESTIONS.md) items 1–2.

**Source.** [framework-runs/keyservice-map.md](../../framework-runs/keyservice-map.md)
