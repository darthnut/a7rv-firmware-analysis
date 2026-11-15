# a7R V `libsecvlt.so` ("SECVAULT") — secure store map

Static RE of the user's own Sony a7R V firmware (`/srv/a7rv/a7rv-fw`), Ghidra project
`ghidra_secvlt`, binary `/srv/a7rv/a7rv-fw/fs/a15/lib/libsecvlt.so` (loaded as `/libsecvlt.so`,
`analysis_complete: true`). Mechanism, offsets and struct layout only — **no key material and no
vault contents are reproduced anywhere in this document.** All addresses are Ghidra virtual
addresses. Companion doc: `keyservice-map.md` (the Backup-side client of QID `0x25906be`).

Status: COMPLETE — store API mapped, AES-256-GCM + per-item DEK mechanism mapped, QID `0x25906be`
provider claim **REFUTED** (libsecvlt is a client, not the service); open items listed in the footer

## A. The store API

**Summary.** `libsecvlt.so` is **not** a name→value key/value store. It is eight fixed-function
wrappers over a compile-time table of **four vault slots**, each slot backed by one item in the Sony
`Backup_*` persistence subsystem. A "vault item" is therefore a slot index, not a name: there is no
directory, no allocator, no string lookup and no capacity beyond four entries. Each slot holds one
opaque **record** = 0x58-byte header + AES-256-GCM ciphertext. The internal source file name is
`sec_vault_internal.c` (`search_strings` → literal @0x101bff, used by `__assert_fail` @0x101380).
Every export funnels through one read path (`FUN_00101458` @0x101458) and one write path
(`FUN_00101324` @0x101324).

### A.1 Item identity — four slots keyed by a 32-bit magic

`get_vltinfo` @0x1013d8 (defined @0x1013d8; thunk @0x100d70 — decompile **by address**) is the only
identity→storage mapping in the library. It compares the caller's 32-bit item ID against four
constants and yields `descriptor = 0x101c30 + slot*0x20`, returning **2** for anything else (that is
the sole source of status `2`).

Descriptor table, decoded from `read_bytes` 0x101c30, 128 bytes (plain initialized data, no
relocations — the four magics appear in `get_vltinfo`'s own comparison order, confirming slot
indices). Subsystem/item IDs are routing metadata, not secrets:

| Slot | Item ID (desc `+0x00`) | Backup subsystem (`+0x04`, u16) | Backup item ID (`+0x08`, u32) | Max size (`+0x10`, u64) | Default attrs (`+0x18`, u32) |
|---|---|---|---|---|---|
| 0 | `0x50369614` | `0x02f9` (761) | `0x02f90029` | 4096 (`0x1000`) | `0x34` = bits 2,4,5 |
| 1 | `0x25f174ad` | `0x02f9` (761) | `0x02f90027` | 16384 (`0x4000`) | `0x32` = bits 1,4,5 |
| 2 | `0x35c1a8a2` | `0x02f9` (761) | `0x02f90028` | 4096 (`0x1000`) | `0x33` = bits 0,1,4,5 |
| 3 | `0x6ea8c226` | `0x02ec` (748) | `0x02ec0046` | 60000 (`0xea60`) | `0x30` = bits 4,5 |

`desc+0x1c` is padding. Note the u32 item ID embeds the u16 subsystem in its high half
(`0x02f9_0029`), i.e. `Backup_*` addressing is (subsystem, sub-index). `+0x0c` reads as zero in all
four entries.

**Slot 2 is write-only.** Its descriptor carries attribute **bit0**, and `SECVLT_load` @0x101768
refuses whenever `(desc+0x18 | rec+0x50) & 1 != 0` (returns 5). Bit0 cannot be cleared through the
API (A.5) and — as shown in A.5 — **cannot be set** through the API either, so write-only-ness is a
firmware-table property, not something a caller can trip. All four slots have bit4|bit5 set and
bit6 clear, so `SECVLT_store` is permitted on every slot.

### A.2 Record layout (0x58-byte header, ciphertext follows)

Written by `SECVLT_store` @0x101544, read back by `FUN_00101458`, zeroed by `SECVLT_delete` @0x1018a8:

| Off | Size | Field | Evidence |
|---|---|---|---|
| `+0x00` | 8 | Magic — ASCII `"SECVAULT"`, or `"DEADDEAD"` after delete | `memcmp(pvVar4,"SECVAULT",8)` @0x101458; per-byte stores `'S'…'T'` @0x101544 and `'D','E','A','D','D','E','A','D'` @0x1018a8 |
| `+0x08` | 32 | **Wrapped DEK** — AES-256 key produced by the key service | store step 5 (B.2): `FUN_0010117c(3,3,handle,…,__dest+8,&outlen,DEK,0x20)` |
| `+0x28` | 12 | **GCM IV/nonce, in the clear**, fresh per store | `RAND_bytes(__dest+0x28,0xc)` @0x101544 |
| `+0x34` | 4 | Gap — never read or written | no access in any decompiled function |
| `+0x38` | 16 | **GCM tag**, in the clear — and doubles as the key-service `import` input | `FUN_00100f4c(…,__dest+0x38,1)` then `FUN_0010117c(2,3,0,0x10,1,&handle,0,__dest+0x38,0x10)` @0x101544 |
| `+0x48` | 8 | Plaintext length (u64); on delete, set to `desc.maxsize` | `*(ulong*)(__dest+0x48) = param_3` @0x101544; read as `uVar5` @0x101458 |
| `+0x50` | 4 | **Attribute word** (u32) | `*(uint*)(rec+0x50)` in store/delete/add_attr/get_attr |
| `+0x54` | 4 | Gap — never read or written | no access found |
| `+0x58` | … | AES-256-GCM ciphertext (+16-byte tag is stored separately at `+0x38`, not appended) | `FUN_00100f4c(__dest+0x58, value, len, …)` @0x101544 |

Validity test applied on every read (`FUN_00101458`), all four required for status `0`:
`rec.size + 0x68 <= bytes_read` **and** `memcmp(magic,"SECVAULT",8)==0` **and**
`rec.size <= desc.maxsize` **and** `(desc.attrs & ~rec.attrs) == 0` — i.e. the record's attribute
word must be a **superset** of the descriptor's, else the item reads as status `6` ("present but
invalid"). The `size + 0x68` test can wrap for an attacker-chosen `size` near 2^64, but the
independent `size <= desc.maxsize` bound (max 0xea60) catches that — both checks are needed.
Nothing here is a *validity proof of the ciphertext*: the header is not covered by the GCM tag (B.1),
so these are sanity/range checks only, and `size`/attrs are malleable without tripping the tag.

### A.3 Persistence — the `Backup_*` subsystem, not a file

There is no `open`/`fopen`/`read`/`write`/`ioctl` anywhere in the import table (A.6); all persistence
goes through four imported `Backup_*` calls, addressed by `(u16 subsystem, u32 item)` from the
descriptor.

**Read — `FUN_00101458(item, &desc, &rec)`:**
```
get_vltinfo(item,&desc) != 0            → return 2
n = Backup_get_datasize(desc.item); ≤0  → return 4
if (n < 0x69) n = 0x69                  // clamp minimum read length up to 105 bytes
rec = malloc(n);      null              → return 3
Backup_nread(desc.item, rec, n) == 0    → free, return 4
else                                      validity test → 0 or 6
```
So "empty slot" is `4` (no data / read failure) and "slot holds garbage, or attrs lost, or oversized"
is `6`. Note `SECVLT_exists` @0x1019f8 is literally this status returned verbatim — the store has no
dedicate presence call.

**Write — `FUN_00101324(desc, rec)`:** `Backup_write(desc.subsystem, desc.item, rec)`; a return `< 1`
maps to status `4`, otherwise `0`. It then does `Backup_sync_subsystem(desc.subsystem)` **only when
bit7 of `(rec.attrs | desc.attrs)` is set**. With the shipped descriptors (`0x30`–`0x34`, bit7 clear)
that branch never fires, so **a store/add_attr does not fsync** — durability comes only from the
explicit `SECVLT_sync` @0x101990, which calls `Backup_sync_subsystem(desc+4)` when bit7 is **clear**.
The two conditions are exact opposites of each other (both quoted verbatim above); that looks like a
bug or a flag whose meaning flipped between call sites. Recording the inconsistency, not a resolution:
as shipped, `SECVLT_sync` is the only path that syncs.

**Free — `FUN_00101380(desc, rec)` (`clean_vlt_data`):** calls `Backup_get_datasize(desc.item)` and
`free(rec)`; asserts via `__assert_fail("maxsize > 0","sec_vault_internal.c",0xcc,"clean_vlt_data")`
@0x101380 — the source of the file name and the internal function name, and of line 204. Every export
calls it on the way out, so the record buffer is a transient per-call heap allocation, not a cache.

How much `Backup_write` commits is decided inside that out-of-image call. The record self-describes
its length at `+0x48`, and `SECVLT_delete` sets `+0x48 = desc.maxsize` then memsets `maxsize + 0x68`
bytes (0x10 more than the `0x58 + size` it spans), which is *consistent with* `Backup_write` sizing
from the record's own length field — **HYPOTHESIS**, `Backup_write` is not in this image.

### A.4 The eight exports

| Export | Addr | Gates / behaviour | Returns |
|---|---|---|---|
| `SECVLT_store(item, buf, len)` | 0x101544 | needs `buf && len` (→`1`); status must be `0` or `6`, else propagated. **Existing valid record:** overwrite needs `bit5` set **and** `bit6` clear in `rec.attrs \| desc.attrs`; then `len == rec.size` (in-place) **or** `bit4` set. **Status 6:** `len == desc.maxsize` **or** `bit4` set. Then `len <= desc.maxsize` else `1`. Allocates `len + 0x10010`, copies the old 0x58 header, runs B.2, stamps magic `"SECVAULT"`, persists. | `0` ok; `1` arg/policy/refused; `3` malloc, crypto or key-service failure (also if the import returns handle `0`); `2`/`4`/`6` from the read path |
| `SECVLT_load(item, buf, &size)` | 0x101768 | status must be `0`; **refuses (`5`) if `(rec\|desc) & 1`** — blocks slot 2. `*size = rec.size`. `SKData_Init`, then the B.2 inverse, `SKData_Exit`. | `0` ok; `3` crypto/service; `5` read-blocked or GCM auth failure |
| `SECVLT_delete(item)` | 0x1018a8 | status `0`/`6`; **refuses if bit6 set** in `rec \| desc`. Allocates `desc.maxsize + 0x10010`, copies header, `memset(0, …, desc.maxsize + 0x68)`, magic → `"DEADDEAD"`, `+0x48 = desc.maxsize`, `+0x50 = desc.attrs`, persists. | **crypto-erase, not unlink**: the slot is overwritten with zeros at full max size, destroying wrapped DEK/IV/tag/ciphertext; the `Backup_*` item itself remains |
| `SECVLT_sync(item)` | 0x101990 | status `0`/`6`; calls `Backup_sync_subsystem` only if bit7 of `rec\|desc` is **clear** | `0` (also when it skipped the sync) |
| `SECVLT_exists(item)` | 0x1019f8 | none | `FUN_00101458` status verbatim (`0` present, `4` empty, `6` invalid, `2` bad ID) |
| `SECVLT_get_size(item, &size)` | 0x101a34 | status must be `0` | `*size = rec+0x48` (plaintext length) |
| `SECVLT_add_attr(item, bits)` | 0x101a88 | `bits != 0`; status must be exactly `0`; OR-in then validate (A.5); persist | `0`/`4` from the write path; `1` on any rejection |
| `SECVLT_get_attr(item, &attrs)` | 0x101b78 | status must be `0` | `*attrs = rec+0x50` |

There is **no `SECVLT_set_attr`** — attributes are accumulate-only.

### A.5 Attribute model

Two words are OR'd together for every decision: `rec+0x50` (per-record, persists) and `desc+0x18`
(per-slot, fixed in `.rodata`). `SECVLT_store` takes **no** attribute argument — on success it writes
`rec+0x50 = desc+0x18` verbatim, so the only way extra bits ever enter a record is `SECVLT_add_attr`.

Behavioural bits, from the gates quoted above:

| Bit | Meaning | Evidence |
|---|---|---|
| 0 | **Read-blocked** — `SECVLT_load` returns 5. Set only by the descriptor table (slot 2). | @0x101768 gate; A.5 add_attr proof |
| 4 | **Resize allowed** — store with a length different from the current/max size | @0x101544 `LAB_00101730` |
| 5 | **Overwrite allowed** — required, with bit6 clear, to rewrite an existing valid record | @0x101544 status-0 branch |
| 6 | **Immutable / anti-shred** — blocks in-place store, and blocks `SECVLT_delete` | @0x101544; @0x1018a8 |
| 7 | Sync-policy bit, read with opposite polarity by `FUN_00101324` vs `SECVLT_sync` (A.3) | both quoted |

`SECVLT_add_attr` @0x101a88 validation, applied to `x = (rec.attrs \| new) \| desc.attrs` — all
conditions must hold or the call returns `1` and nothing is persisted:

```
popcount(x & 0x000e)     < 2      // bits 1..3: one-hot option group
popcount(x & 0x03ff00)   < 2      // bits 8..13: one-hot option group
popcount(x & 0x1c0000)   < 2      // bits 18..20: one-hot option group
(bits8..13 empty)  ⟹ (bits 1,2 empty AND bits 18..20 empty)
(bits8..13 nonempty) ⟹ (bit1 or bit2 set)
bit0 set ⟹ no bit of 1..3 set        // (x & ~popcount(x & 0xe) & 1) == 0
(x & 0x60) != 0x60                  // bits 5 and 6 mutually exclusive
(x & 0xffe00000) == 0               // bits 21..31 reserved, must stay clear
```
(`FUN_00100f00` @0x100f00 is a 32-bit popcount — the `x &= x-1` bit-hack loop.)

Two consequences worth stating. First, **bit0 can never be added by any caller**: whenever `x & 1` is
set, either `popcount(x & 0xe) == 1` (then `x & ~1 & 1 == 0` fails) or it is `0` (then `~0` keeps the
bit and the same test fails) — so the write-only property of slot 2 is fixed in the firmware table.
Second, on the three slots whose descriptor already carries a bit of `0xe` (slots 0/1/2 carry bit2/bit1/bit1),
adding *any other* bit of `1..3`, or bit0, is rejected by the one-hot test — i.e. those slots' option
group is largely pre-occupied by firmware. Bits 8..13 / 18..20 / 21..31 have no consumer anywhere in
this library: they are validated but never read by any gate here (presumably interpreted by the
caller or the key service — **HYPOTHESIS**).

### A.6 Status codes

| Code | Produced by | Meaning |
|---|---|---|
| `0` | all | success |
| `1` | store / add_attr / get_attr / get_size / delete | null arg, `len > maxsize`, policy refused, attribute validation failed, or the item was in a state the export does not accept |
| `2` | `get_vltinfo` | unknown item ID (not one of the four magics) |
| `3` | read path / store / load | `malloc` failed, or a crypto / key-service step failed |
| `4` | read path / `FUN_00101324` | slot empty (`Backup_get_datasize` ≤ 0), `Backup_nread` returned 0, or `Backup_write` returned < 1 |
| `5` | store / load | store: in-place policy denied (bit5 clear / bit6 set). load: read-blocked by bit0, **or** GCM authentication failed |
| `6` | read path | record present but fails validity (magic, size bound, or lost attribute bits) — treated as "stale, writable" by store/delete/sync |

`5` is genuinely overloaded on the load path: a caller cannot distinguish "policy blocked" from "the
ciphertext did not authenticate" (B.1). No export distinguishes them either, so tampering with a
record is detectable only by a caller that retries differently, not by the returned code.

## B. AES-256-GCM usage and the key source

### B.1 The GCM helper — `FUN_00100f4c` @0x100f4c

Ghidra signature: `FUN_00100f4c(uchar *dst, uchar *src, int len, uchar *key, uchar *iv, void *tag, int dir)`.
Every step below is verbatim from `decompile_function` 0x100f4c:

| Step | Call | Meaning |
|---|---|---|
| 1 | `EVP_CIPHER_CTX_new()` | fresh context, per call (no reuse/caching) |
| 2 | `EVP_aes_256_gcm()` | the only cipher in the library |
| 3 | `EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, dir)` | key **and** IV applied at init; `dir`: 1 = encrypt, 0 = decrypt |
| 4 | `EVP_CIPHER_CTX_set_key_length(ctx, 0x20)` | requests a **32-byte (AES-256)** key — equals the cipher's fixed length, so a confirmation no-op (OpenSSL-side behaviour not verified from this image) |
| 5 | `EVP_CIPHER_CTX_ctrl(ctx, 9, 0xc, NULL)` | `EVP_CTRL_AEAD_SET_IVLEN`, **12-byte IV/nonce** |
| 6a | encrypt: `EVP_CipherUpdate(ctx, dst, &n, src, len)` → `EVP_CipherFinal_ex(ctx, dst+n, &n)` → `EVP_CIPHER_CTX_ctrl(ctx, 0x10, 0x10, tag)` | one-shot encrypt, then `EVP_CTRL_AEAD_GET_TAG` writes the **16-byte tag** out |
| 6b | decrypt: `EVP_CIPHER_CTX_ctrl(ctx, 0x11, 0x10, tag)` → `EVP_CipherUpdate(ctx, dst, …, src, len)` → `EVP_CipherFinal_ex(...)` | `EVP_CTRL_AEAD_SET_TAG` supplies the expected tag **before** the update; the auth check surfaces as `EVP_CipherFinal_ex` != 1 |
| 7 | `EVP_CIPHER_CTX_free(ctx)` | always freed |

Return codes: `0` = success, `3` = context/init failure, `5` = **auth/final failure on the decrypt path**
(i.e. tag mismatch or corrupt ciphertext). `SECVLT_load` maps `3` onto its own error `3`, so a caller
cannot distinguish "crypto error" from "auth failure" through the public API.

**What is authenticated — and what is not.** There is **no AAD**: no zero-length `EVP_CipherUpdate`
pass and no AAD `ctrl` anywhere in the function, so the GCM AAD length is 0. Consequently only the
value bytes at record `+0x58` are authenticated; the **entire 0x58-byte record header is unauthenticated
and attacker-malleable** if one holds the stored blob — the magic, the IV at `+0x28`, the wrapped key at
`+0x08`, the length at `+0x48` and the attribute word at `+0x50` can all be edited without tripping the
tag. (The length at `+0x48` *is* range-checked on read — `FUN_00101458` @0x101458 requires
`size + 0x68 <= datasize` and `size <= descriptor.maxsize` — so a corrupt length yields an error, not
a buffer overrun; no overflow was found on this path.)

**Single-shot only.** The whole payload goes through one `EVP_CipherUpdate`, so this helper does not
stream — an item is encrypted/decrypted fully in memory.

### B.2 Per-item key hierarchy

Both paths read directly off `SECVLT_store` @0x101544 and `SECVLT_load` @0x101768.

`SECVLT_store` (write):
1. `RAND_bytes(rec + 0x28, 0xc)` → **12-byte IV/nonce, fresh per store**, stored in the clear.
2. `RAND_bytes(stack, 0x20)` → **256-bit data-encryption key (DEK), fresh per store**; kept only on
   the stack (`local_20[32]`), never written to the record.
3. `FUN_00100f4c(rec + 0x58, value, len, DEK, rec + 0x28, rec + 0x38, 1)` → ciphertext at `+0x58`,
   and the **16-byte GCM tag lands at `+0x38`**.
4. `FUN_0010117c(2, 3, 0, 0x10, 1, &handle, 0, rec + 0x38, 0x10)` → **key-service `import`** of the
   16 bytes at `rec+0x38` (i.e. the GCM tag) with direction **1 = encrypt** → opaque handle.
5. `FUN_0010117c(3, 3, handle, 0, 0, rec + 8, &outlen, DEK, 0x20)` → **key-service `crypt`**: the DEK
   is encrypted by the service and the **32-byte wrapped DEK is stored at `+0x08`**.
6. `FUN_001012d0(handle)` → release (`cmd 5`).
7. `rec+0x48 = len`, `rec+0x50 = attrs`, magic `"SECVAULT"` written, then persist (A.3).

`SECVLT_load` (read) is the exact inverse: `import(rec+0x38, 0x10, dir=0)` → handle;
`crypt(handle, rec+0x8, 0x20)` → DEK back onto the stack; `FUN_001012d0` release; then
`FUN_00100f4c(rec+0x58 /*src*/, outbuf, size, DEK, rec+0x28 /*iv*/, rec+0x38 /*tag*/, 0)`.
`SKData_Init`/`SKData_Exit` bracket the key-service exchange (imported OpenSSL init/shutdown helpers).

So the hierarchy is: **per-item random AES-256-GCM DEK → wrapped by the OSAL key service → wrapped DEK
stored in the record header; the IV and the tag travel in the clear in the same header.**

### B.3 Where the key comes from — mechanism only

* **Data key:** generated locally by `RAND_bytes` (OpenSSL userspace CSPRNG) at store time, 32 bytes,
  one per item. It is *not* derived from a password, a serial number, or any constant in this library.
* **No KDF and no static key anywhere in the library.** The complete import surface is 29 symbols
  (`list_imports`, unfiltered): the only crypto imports are `EVP_*` (8), `EVP_aes_256_gcm`, and
  `RAND_bytes`. There is **no** `PKCS5/PBKDF2`, `HKDF`, `HMAC`, `SHA*`, no `open`/`fopen`/`ioctl`, and
  no SPACC device access — so no key derivation, no file-sourced key, and no direct hardware
  crypto in this module. No hardcoded key bytes exist here.
* **Wrap key (KEK): not present in this image.** SecVault supplies the key service with a 16-byte
  import input and receives an opaque handle; the KEK itself lives inside the service on QID
  `0x25906be`. Note what that import input *is*: the record's own GCM tag, `rec+0x38`, which is stored
  **in the clear** in the same record.
* **Security consequence — and the one thing this image cannot settle.** Because the import input is a
  cleartext per-record value, the confidentiality of every vault item reduces entirely to *what the key
  service does with that 16 bytes at import time*:
  * If the service mixes in device-unique secret material (per-device key, SPACC/HSM-anchored) → the
    wrapped DEK is not recoverable from the blob alone. *(HYPOTHESIS — plausible given the SPACC/HSM
    substrate noted in `keyservice-map.md` §B, but that code is not in this image.)*
  * If the service simply AES-encrypts under the supplied 16 bytes → an item is decryptable by anyone
    holding the blob, since tag (=KEK input), IV, wrapped DEK and ciphertext all sit in one record —
    i.e. "encryption with a key stored next to the ciphertext". *(HYPOTHESIS, same caveat.)*
  Deciding between the two requires the QID `0x25906be` provider image; nothing in `libsecvlt.so`
  reveals it. **This is the decisive open item.**
* Contrast with the Backup client (`keyservice-map.md` §C): libBackupManager imports a **static,
  model-wide 16-byte placeholder** from `.rodata`, whereas SecVault's import input is **per-record
  random**. Same RPC, materially different key hygiene on the client side.

## C. Is SecVault the key service behind QID `0x25906be`?

**Verdict: REFUTED — `libsecvlt.so` is not the provider of QID `0x25906be`. It is a second *client*
of it, structurally identical to libBackupManager.** This corrects the leading candidate recorded in
`keyservice-map.md` §B ("strongest out-of-image candidate: `libsecvlt.so`"), which rested on
string/encoding evidence from a binary that had not been decompiled. It is now decompiled, and the
evidence points the other way.

`FUN_0010117c` @0x10117c is SecVault's RPC wrapper and `FUN_001010e8` @0x1010e8 its sender. Both
speak to the *same* queue ID, with the *same* message size, as libBackupManager:

```c
// @0x10117c — request side
iVar2 = osal_valloc_msg_wait(0x25906be, &local_8, 0x428, 1);   // identical QID + identical 0x428 size
*local_8   = param_1 & 0xffffffff;      // msg[0] = command
local_8[1] = param_3;                   // msg[1] = handle
local_8[2] = param_4;                   // msg[2] = client-supplied selector
local_8[3] = param_5;                   // msg[3] = direction
local_8[4] = 0;                         // msg[4] = payload length
...  // 0x400-byte chunk loop: memcpy(msg+5, param_8+off, ≤0x400) when (flags & 2), then FUN_001010e8(...)
osal_free_msg(0x25906be);
```
```c
// @0x1010e8 — send + response
iVar1 = osal_snd_sync_msg(0x25906be, param_5);
if (iVar1 == 0) {
  if (*param_5 == 0) { iVar1 = -0x3fa; }
  else if (((param_2 != 0) && ((param_1 & 1) != 0)) &&
          (memcpy((void *)(param_2 + param_4), param_5 + 5, param_5[4]), param_3 != 0)) {
    *param_3 = *param_3 + (int)param_5[4];
  }
}
```

Four independent reasons this is a client, not the server:

1. **It sends, never serves.** `osal_valloc_msg_wait` / `osal_snd_sync_msg` / `osal_free_msg` are the
   client trio (`keyservice-map.md` §A). The server-side primitive in this firmware is
   `osal_reg_sync_msg_queue_cb` (libosal_uipc.so @0x105b88, which keys its table on `qid & 0x7fff`) —
   **it is not in libsecvlt's import table at all.** `list_imports` (both unfiltered and filtered on
   `osal|pthread|reg|recv|crypt|Backup|EVP|RAND`) lists only the three client OSAL symbols; there is
   no receive, dispatch or callback-registration symbol of any kind.
2. **The send helper is a byte-for-byte sibling of libBackupManager's.** `FUN_001010e8` @0x1010e8 vs
   libBackupManager `FUN_00101050` @0x101050: identical `osal_snd_sync_msg(0x25906be,…)`, identical
   `*msg == 0 → -0x3fa` status convention, identical response-copy gated on flags bit0 with the length
   read back from `msg[4]`. Two libraries, one shared client stub pattern, one queue.
3. **No thread of its own.** `libpthread.so.0` appears in `DT_NEEDED` (`readelf -d`), yet no
   `pthread_create` / `pthread_*` symbol is imported — the dependency is inherited/unused. A library
   that never creates a thread and registers no callback cannot be hosting a message-queue service.
4. **Exactly one QID, and only in the RPC pair.** `search_code` literal `0x25906be` returns
   `literal_total: 2` — `FUN_0010117c` and `FUN_001010e8`, nothing else. SecVault talks to precisely
   this one queue and only through those two functions.

The command vocabulary matches too: `2` = import (`FUN_0010117c(2,3,0,0x10,1,&handle,0,buf,0x10)`),
`3` = crypt (`FUN_0010117c(3,3,handle,0,0,out,&n,in,0x20)`), `5` = release
(`FUN_001012d0` @0x1012d0 → `FUN_0010117c(5,2,handle,0,0,0,0,buf,1)`), with the same flags model
(bit1 = copy input into the message, bit0 = copy response payload out). So both clients, reached
independently, reproduce the protocol documented in `keyservice-map.md` §A — that layout is now
cross-confirmed rather than single-sourced.

Two refinements to the earlier doc. First, **`msg[2]` is not a constant**: libBackupManager sends `1`
on import, SecVault sends `0x10` on import and `0` on crypt/release. It is a per-call client
parameter; what it selects is not determinable from either client (algorithm or key-type id would fit —
**HYPOTHESIS**, needs the provider). Second, SecVault's import differs materially in *what* it imports:
a fresh per-record random value (the GCM tag) rather than libBackupManager's static model-wide
placeholder — see B.3.

**So who serves QID `0x25906be`?** Still not in any image analyzed here — the search that failed to
find it before still fails, and has now also excluded its best candidate. What this analysis *does*
add: since libsecvlt is an in-process client stub whose undefined symbols are resolved from the host
process (its `DT_NEEDED` is only `libuuid, libpthread, libstdc++, libm, libdl, libgcc_s, libc, librt`
— notably **no** `libcrypto`, no OSAL lib and no Backup lib, so `EVP_*`, `RAND_bytes`, `osal_*` and
`Backup_*` all bind at runtime to whatever the loader already has in the global namespace), and since
its only consumers are `libInfraCryptCore.so` and `libmpr.so` (`grep -l libsecvlt` over `fs/a15/lib`),
the service must be reached across the kernel uIPC boundary from one of those hosts — provider still
unknown, kernel-side (`kmod/osal_uipc.ko`) subscriber for slot `0x06be` never examined. **HYPOTHESIS,
and the decisive open item from B.3 stays open.** The recorded search signature in
`keyservice-map.md` §B (`movz #0x6be` + `movk #0x259,lsl 16`) remains the way forward; libsecvlt can
now be dropped from the candidate list.

## D. Scope / safety

- **Mechanism, offsets, struct layouts, protocol and status codes only.** No key material and no
  vault contents appear anywhere in this document. Specifically: the per-item DEK is generated at
  runtime by `RAND_bytes` and is never read out of the binary (there are no key bytes *in* the
  binary to read — B.3), the wrapped-DEK field at record `+0x08` and the tag at `+0x38` are
  described by offset and length only, and the KEK lives outside this image entirely, so nothing in
  §B is a transcription of live secrets. The only byte strings reproduced are the record's own
  format magics (`SECVAULT` / `DEADDEAD`) and slot magics, which are format constants.
- Static, read-only analysis of the **owner's own** extracted firmware at `/srv/a7rv/a7rv-fw`
  (`fs/a15/lib/libsecvlt.so`). No device was contacted, nothing was run, no live key material was
  dumped, no vault was opened. The firmware image itself is not reproduced or linked here.
- Ghidra access was restricted to read-only tools: project/binary listing, imports/exports,
  decompilation **by address**, xrefs, byte reads, symbol/code/string search. No rename, comment,
  type-application, prototype-setting, save or delete-project tool was invoked, so the Ghidra
  project is unmodified. Every function was analyzed by address rather than by name to avoid
  following PLT thunks.
- A finding is marked VERIFIED only where a quoted decompilation or byte read at a stated address
  supports it; anything inferred beyond this image is labelled HYPOTHESIS. Two things are
  deliberately *not* claimed as facts: who serves QID `0x25906be` (§C, open), and what `msg[2]`
  means (§C, open).
- Out of scope: the kernel side (`kmod/osal_uipc.ko` queue routing for slot `0x06be`, `backup.ko`,
  `elpspacc*.ko` / SPACC-HSM), `libInfraCryptCore.so` and `libmpr.so` (the two consumers), other
  cores' images, and any dynamic work — attaching, tracing, or reading a real owner's vault.

## How this was checked

All Ghidra calls are read-only against project `ghidra_secvlt`, binary loaded as `/libsecvlt.so`;
addresses are Ghidra virtual addresses.

**Ghidra `decompile_function` (by address, batched):**

| Address | Role |
|---|---|
| `0x101544` | `SECVLT_store` — gate ladder, `RAND_bytes`×2, GCM, import/crypt/release, persist |
| `0x101768` | `SECVLT_load` — read-gate, `SKData_Init`/`SKData_Exit` bracket, GCM decrypt |
| `0x1018a8` | `SECVLT_delete` — immutable-bit refusal, zero-fill, `DEADDEAD` stamp |
| `0x101990` | `SECVLT_sync` — `Backup_sync_subsystem`, bit7 polarity (inverted vs. `0x101324`) |
| `0x1019f8` | `SECVLT_exists` — read-status passthrough |
| `0x101a34` | `SECVLT_get_size` — returns header `+0x48` |
| `0x101a88` | `SECVLT_add_attr` — popcount one-hot validation, accumulate-only |
| `0x101b78` | `SECVLT_get_attr` — returns header `+0x50` |
| `0x1013d8` | `get_vltinfo` — item-id → 4-slot descriptor lookup (defined form; thunk at `0x100d70`) |
| `0x100f00` | popcount bit-hack (attribute group validation) |
| `0x100f4c` | AES-256-GCM helper (encrypt/decrypt, ctr0 vs. ivlen 0xc, tag ctrl `0x10`/`0x11`) |
| `0x1010e8` | RPC send — `osal_snd_sync_msg(0x25906be,…)`, `-0x3fa`, flags-bit0 copy-out |
| `0x10117c` | RPC wrapper — `osal_valloc_msg_wait(0x25906be,…,0x428,1)`, field fill, 0x400 chunking |
| `0x1012d0` | handle release (`cmd 5`) |
| `0x101324` | persist — `Backup_write(subsystem,item,rec)` + conditional `Backup_sync_subsystem` |
| `0x101380` | `clean_vlt_data` — `Backup_get_datasize`, `__assert_fail("maxsize > 0", "sec_vault_internal.c", 0xcc, …)`, `free` |
| `0x101458` | read/validate — magic memcmp, `+0x48` bound, attribute `desc & ~rec` test |

**Other Ghidra calls:** `list_project_binaries` (inventory / session gate). `read_bytes`
`0x101c30` ×128 → the four slot descriptors decoded for A.1 (id, subsystem, item, maxsize, attrs).
`list_exports` → the eight exported functions with addresses and `is_thunk:false`. `list_imports`
unfiltered (29 entries) and filtered on `osal|pthread|reg|recv|crypt|Backup|EVP|RAND` (19) → the
client-only OSAL trio, four `Backup_*`, eight `EVP_*`, `RAND_bytes`, and `_ITM_registerTMCloneTable`
/ `_ITM_deregisterTMCloneTable` / `_Jv_RegisterClasses`; **no** `osal_reg_sync_msg_queue_cb`, no
receive API, no `pthread_*` — the basis of §C. `search_code` **literal** mode `0x25906be` →
`literal_total: 2` (`FUN_0010117c`, `FUN_001010e8`) out of 26 functions. `search_strings`
`sec_vault` → source-path/assert strings. `search_symbols_by_name` for `get_vltinfo` and `osal_`
(name lookup, used to disambiguate). `disassemble` was used once, on the magic-store sequence, and
its result was superseded by the `memcmp(pvVar4,"SECVAULT",8)` literal in `0x101458` — the magic
spelling in §A.2 comes from the decompiler, not from manual byte transcription.

**Non-Ghidra read-only checks** (in `/srv/a7rv/a7rv-fw/fs/a15/lib`): `readelf -d libsecvlt.so` →
`DT_NEEDED` = `libuuid.so.1, libpthread.so.0, libstdc++.so.6, libm.so.6, libdl.so.2,
libgcc_s.so.1, libc.so.6, librt.so.1`; `SONAME libsecvlt.so`; `INIT 0xc00`, `FINI 0x1bcc`,
`INIT_ARRAY 0x11d60`, `PLTGOT 0x11fe8` — i.e. no `libcrypto`, no OSAL and no Backup library, so
`EVP_*`, `RAND_bytes`, `osal_*` and `Backup_*` all resolve from the host process namespace at
runtime (§C). `grep -l libsecvlt *.so` → `libInfraCryptCore.so`, `libmpr.so` (plus itself). No
AArch64 binutils are present in this environment, so no native disassembly was attempted.

**Known limitations.** `list_xrefs` on *imported symbol* names returned "Symbol … not found" in this
build, so PLT-entry cross-reference enumeration was not available; caller sets were instead
established from the decompiled bodies of the callers themselves (which is how the §A.4 per-export
gate table and the §B.2 call ordering were derived). Ghidra's prototypes are approximate here:
`FUN_00101458` appears with 2 arguments at some call sites and 3 at others, and `get_vltinfo`
appears argument-less inside `0x101458` despite taking the item id at its definition — both are
decompiler artifacts, not evidence of varargs. Two claims were corrected mid-analysis by
re-decompiling rather than trusting notes: the `0x101a88` one-hot tests mask with `&` (not `|`), and
the `0x101458` `0x69` bound is a clamp *up* (`if (size < 0x69) size = 0x69`).

**Open items.** (1) Provider of QID `0x25906be` — not in this image, and libsecvlt is now excluded
(§C); resolve via the `movz #0x6be` + `movk #0x259,lsl 16` code signature in remaining images, or
the kernel subscriber for slot `0x06be`. (2) What the KEK is bound to (per-device? per-model?
per-firmware?) — B.3's decisive unknown; `msg[2]` (import-only, client-supplied, `1` for
libBackupManager vs. `0x10` for SecVault) is the most likely handle on it. (3) The bit7 sync
contradiction between `0x101324` and `0x101990` — with the shipped attribute values no store ever
syncs; is that intended, or a shipped bug? (4) `SECVLT_add_attr` can never set attribute bit0 from
any input (§A.5) — so bit0 must be reachable only by a path absent from this library.
