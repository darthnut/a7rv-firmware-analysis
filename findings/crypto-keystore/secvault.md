# SecVault — the AES-256-GCM secure store

**Summary.** `libsecvlt.so` is a four-slot secure store with AES-256-GCM over a per-record random data
key, wrapped by an out-of-process key service; it is a *client* of that service, not the provider.

**Where.** `fs/a15/lib/libsecvlt.so` (Ghidra project `ghidra_secvlt`), Ghidra VAs. Eight exports
(`SECVLT_store` `0x101544`, `SECVLT_load` `0x101768`, `SECVLT_delete` `0x1018a8`, `SECVLT_sync`
`0x101990`, `SECVLT_exists` `0x1019f8`, `SECVLT_get_size` `0x101a34`, `SECVLT_add_attr` `0x101a88`,
`SECVLT_get_attr` `0x101b78`); the GCM helper `FUN_00100f4c`; the RPC client pair `FUN_0010117c` /
`FUN_001010e8`; the item-id → slot resolver `get_vltinfo` `0x1013d8`; descriptor table at `0x101c30`
(4 × `0x20` bytes).

**Mechanism.**
- **Four fixed slots, no directory.** A caller addresses a slot only by passing its 32-bit *item magic*
  to the API; `get_vltinfo` maps the magic to `descriptor = 0x101c30 + slot*0x20` and returns status
  `2` for anything else. No allocator, no name lookup, capacity four.
- **Record layout** (`0x58`-byte header + ciphertext): `+0x00` magic `"SECVAULT"` (`"DEADDEAD"` after
  delete), `+0x08` 32-byte **wrapped DEK**, `+0x28` 12-byte GCM IV (clear), `+0x38` 16-byte GCM tag
  (clear), `+0x48` u64 plaintext length, `+0x50` attribute word, `+0x58` AES-256-GCM ciphertext.
- **Crypto.** `FUN_00100f4c` = one-shot `EVP_aes_256_gcm`, key length `0x20`, IV length `0x0c`, tag
  `0x10`. **No AAD** — only the value bytes are authenticated; the whole `0x58`-byte header is
  unauthenticated/malleable, though the length at `+0x48` is range-checked on read.
- **Key hierarchy.** On store: `RAND_bytes` makes a fresh 32-byte DEK; the record's own GCM tag is
  *imported* to the key service (op 2) and the DEK is *wrapped* (op 3, direction 1) → stored at `+0x08`.
  On load the inverse unwraps the DEK into a stack buffer. The **KEK never enters this library**.
- **Attributes** (accumulate-only, one-hot-validated): bit 0 read-blocked (slot 2; can never be
  added *or* cleared through the API), bit 4 resize, bit 5 overwrite, bit 6 immutable, bit 7 sync.
  `SECVLT_delete` is a crypto-erase (zero-fill + `DEADDEAD`), not an unlink.

**Verification.** *light overall.* Deep on the store mechanics: all eight exports, the GCM helper, and
the RPC pair decompiled by address; descriptor table and record magics byte-verified; `RAND_bytes` DEK
generation and the import/wrap/unwrap op sequence read directly. The provider-refutation (§C of the raw
doc) is decompile-backed. What stays inference: what the key service *does* with the imported tag (i.e.
whether an item is recoverable from the blob alone) — that is the KEK question, out of image.

**Boundary / open.** The KEK and the key-service provider are not in this image — libsecvlt is proven a
pure client (no `osal_reg_sync_msg_queue_cb` import; sends only). Confidentiality of every vault item
reduces to what the out-of-image service mixes in at import time. Also open: the bit-7 sync polarity
contradiction between the write path and `SECVLT_sync` (as shipped, no store ever fsyncs). See
[key-wrapping-root](key-wrapping-root.md), [key-service](key-service.md), and
[OPEN-QUESTIONS.md](../../OPEN-QUESTIONS.md) items 1–2.

**Source.** [framework-runs/secvault-map.md](../../framework-runs/secvault-map.md)
