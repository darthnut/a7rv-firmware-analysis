# Sony a7R V — Backup / Persistence Store Map (libBackupManager.so)

Static reverse-engineering notes on the a7R V firmware's persistence layer ("Backup" store),
focused on `libBackupManager.so`. Written for a public technical write-up.

**Safety ground rules respected throughout:** no key material and no firmware binary content is
reproduced here — only offsets, record/message layouts, protocol fields, and mechanisms. All
addresses are **Ghidra virtual addresses** (libBackupManager.so loaded at base `0x100000`; for
mapped segments, file offset ≈ vaddr − `0x100000`). Claims tagged **HYPOTHESIS** are inferences,
not verified facts. Everything else is backed by a specific decompilation or file citation
(see §E and the footer).

- Binary analyzed on disk: `/srv/a7rv/a7rv-fw/fs/a15/lib/libBackupManager.so`
- Ghidra project: `ghidra_extra` (decompiled by address, read-only tools)

---

## A. Store model

### A.1 The API surface

`libBackupManager.so` exports a small C++ class `BackupManager`. The constructor stores a
16-bit *type* and opens a crypto session:

```
BackupManager(ushort type):          [Ghidra decompile @0x101350]
    *(ushort*)this = type;
    SKData_Init();                   // session init, provider libInfraSKD.so
```

Public methods (virtual addresses):

| Method | Address | Role |
|---|---|---|
| `writeBackup(type, id, data)` | `@0x10135c` | plaintext write |
| `writeBackupEncryption(type, id, data)` | `@0x101454` | encrypted write |
| `readBackupDecryption(id, buf)` | `@0x101594` | encrypted read (auto) |
| `cipherUpdate(handle, out, in, len)` | `@0x1013b4` | crypto op (see §B) |
| `isReadDataEncrypt(buf, size)` | `@0x101414` | all-zero heuristic (see §B.4) |
| `isNeedPadding(size)` | `@0x101440` | block-size check (see §A.4) |
| `releaseClearMemory(p)` | `@0x10144c` | `free()` only (see §B.5) |

> Note on the task brief's signature `cipherUpdate(mode, in, out, len)`: the decompilation at
> `@0x1013b4` shows the actual order is `cipherUpdate(this, handle, param_2, param_3, len)`
> where **param_2 is the output buffer and param_3 is the input** — the response payload is
> memcpy'd into `param_2` (`FUN_00101050` @0x101050: `memcpy(param_2 + off, msg + 40, msg.w4)`)
> while `param_3` is memcpy'd *into* the request (`FUN_001010e4` @0x1010e4:
> `memcpy(msg + 40, param_8 + off, n)` with `param_8` ← `param_3`). Verified by re-decompile of
> `@0x1013b4`, `@0x1010e4`, `@0x101050`.

### A.2 (type, id) addressing

Every stored item is addressed by a 32-bit **id** whose high half is the **type** and low half
is the item number within the type:

```
id = (type << 16) | item
```

Direct evidence — `BkDmn_write(uint id, const void *data, int len)` (`@0x10128c`, a local
function, mangled `_Z11BkDmn_writejPKvi`, **not** an import) sends the type separately as
`id >> 16` and tags the IPC message source with it (`@0x10128c`):

```
msg.w1(u16 @+4)  = id >> 16                       // type
osal_set_msg_src(msg, (id >> 16 & 0x7fff) << 16)  // type in message source tag
```

Only the low 15 bits of the type survive the tag mask (`& 0x7fff`). Example: id
`0x3000000` = type `0x300`, item `0x000` (the SSH host key — §C).

`writeBackup` takes `(type, id)` explicitly but only uses `type` to look up the size; `id` alone
identifies the item on the wire.

### A.3 Where the bytes actually go

Two client paths reach the store:

1. **Encrypted/plaintext wrapper** (libBackupManager): both `writeBackup` and
   `writeBackupEncryption` finish with the same call, `BkDmn_write(id, data, size)`
   (`@0x10135c`, `@0x101454`). Reads use `Backup_read(id, buf)` (`@0x101594`).
2. **Raw store API** (what most consumers actually use): `Backup_read`,
   `Backup_write(type, id, data)`, `Backup_nread(id, buf, len)`, `Backup_read_4Byte`,
   `Backup_read_8Byte`, `Backup_sync_subsystem(type)` — imported by e.g. `libObj.so`
   (167 xrefs to `Backup_read` across its callers) and `libInfraSSHManager.so`. These are
   provided by **libbkdmn.so**, which also exports the `BkDmn_*` family
   (`BkDmn_init/exit/write/sync/dump/reg_sid/suspend/resume`).

The backup daemon `BkDmn_write` message is **asynchronous fire-and-forget** (`@0x10128c`):

```
osal_valloc_msg_wait(port 0x82cd08e0, &msg, len + 0x14, 1)
msg.w0 (u32 @+0)  = 2                 // write command
msg.u16 @+4       = id >> 16          // type
msg.u32 @+8       = id                // full id
msg.u32 @+12      = len               // payload length
bytes  @+16       = payload           // memcpy(msg + 16, data, len)
osal_set_msg_src(msg, (id >> 16 & 0x7fff) << 16)
osal_snd_msg(0x82cd08e0, msg)          // NO response — async
```

Consequences:

- **Writes cannot be confirmed by the client.** `writeBackup` returns the *size*, not a
  persistence status; the initial error value `-0x400` in `BkDmn_write` is unreachable from a
  send failure. Only the raw API's `Backup_sync_subsystem(type)` (used by SSHManager, §C)
  forces a flush to media.
- The store itself lives behind the daemon task on IPC port `0x82cd08e0`.

**Backing store on media:** `/bin/bk.elf` (the daemon) contains the strings
`/setting/Backup.bin` and `Backup_get_datasize_interchip` → the store is a file
`/setting/Backup.bin` on the `/setting` mount (plus an inter-chip variant). The kernel module
`/srv/a7rv/a7rv-fw/fs/a15/kmod/backup.ko` sits under it (**out of scope**, §D).

**On-store record layout inside `Backup.bin`:** not observable from `libBackupManager.so` — the
client only ever exchanges `(id, bytes)` pairs over IPC. What the client *can* see, and what a
record must at minimum support, is a **fixed per-item size** queried with
`Backup_get_datasize(id, type)` (2-arg form, used by the write path `@0x10135c`/`@0x101454`) or
`Backup_get_datasize(id)` (1-arg form, used by the read path `@0x101594`) — allocation is
always store-driven, never caller-chosen. **OPEN:** the file's internal header/record format is
owned by `bk.elf`/`backup.ko`; no `Backup.bin` image exists on the extracted filesystem
(`/srv/a7rv/a7rv-fw/tar/0110_backup/` holds only `MainDest.txt` and a `SYSIPSX-DSLR` dir), so
on-record layout remains daemon/kernel-side and is deliberately not reverse-engineered here.

### A.4 Block granularity: `isNeedPadding`

```
isNeedPadding(size):            [Ghidra decompile @0x101440]
    return (size & 0xf) != 0;
```

16-byte blocks. The *encrypted* paths treat any size not divisible by 16 as an error
(`writeBackupEncryption` / `readBackupDecryption` bail with `-1` when `isNeedPadding(size)`) —
i.e. **there is no padding scheme**; item sizes must already be a multiple of 16. The
16-byte block size is consistent with a 128-bit block cipher (§B).

### A.5 Read path

`readBackupDecryption(uint id, void *buf)` (`@0x101594`):

1. `size = Backup_get_datasize(id)` — store declares the item size.
2. Reject unless `size % 16 == 0`.
3. `Backup_read(id, buf)` — synchronous raw read into the caller buffer.
4. If `read == size && !isReadDataEncrypt(buf, size)` → return `size`, **data is already
   plaintext** (see §B.4).
5. Otherwise run the decrypt protocol (§B.2) and overwrite `buf` with the plaintext.

---

## B. The cipher

### B.1 It is not a library — it is an RPC to a key service

`cipherUpdate` (`@0x13b4`) and the key-management helpers all funnel into one IPC core,
`FUN_001010e4` (`@0x1010e4`), which talks to a **crypto/key service** on OSAL IPC port
**`0x25906be`** via synchronous request/response (`osal_snd_sync_msg`, `FUN_00101050` @0x101050).
Request/response buffers are `0x428` bytes; payload is chunked at **0x400 bytes per message**.

Message header (little-endian, 64-bit words; payload at byte offset `0x28`):

| Word | Offset | Field (observed) |
|---|---|---|
| w0 | 0x00 | command (see below); on response: status (`0` → client returns `-1018`) |
| w1 | 0x08 | key-handle (crypt op) / 0 (key import) |
| w2 | 0x10 | 1 on key-import, 0 on crypt |
| w3 | 0x18 | direction flag: **1 = encrypt, 0 = decrypt** on key-import |
| w4 | 0x20 | payload length this message (request and response) |
| 0x28+ | | payload (≤ 0x400 B) |

`FUN_001010e4` loops the payload in 0x400-byte chunks, sending one synchronous message each,
plus a trailing short message when `(flags & len) == 0` (observed in decompile; exact semantics
of the flush condition **OPEN**).

### B.2 Commands — a key-handle protocol

| cmd | Meaning | Evidence |
|---|---|---|
| **2** | Import key → returns opaque **handle** | `writeBackupEncryption`/`readBackupDecryption`: `FUN_001010e4(2, 3, 0, 1, dir, &handle, 0, &DAT_001120a8, 0x10)` @0x101454 / @0x101594 — 16-byte input, handle received in response payload |
| **3** | Crypt operation | `cipherUpdate`: `FUN_001010e4(3, 3, handle, 0, 0, out, &outlen, in, len)` @0x1013b4 |
| **5** | Release handle | `FUN_00101238`: `FUN_001010e4(5, 2, handle, …)` @0x101238 |

Full encrypted-write sequence (`writeBackupEncryption` @0x101454):

```
size = Backup_get_datasize(id, type);  if (size % 16) return -1;
handle = keyImport(w3=1 /*encrypt*/);          // cmd 2
plain = malloc; memcpy(plain, data, size);     // private copy
cipher = malloc;
cipherUpdate(handle, cipher /*out*/, plain /*in*/, size);   // cmd 3
free(plain);                                   // "releaseClearMemory" — see §B.5
BkDmn_write(id, cipher, size);                 // async store write
free(cipher); keyRelease(handle);              // cmd 5
```

### B.3 Algorithm and — crucially — where the key comes from

**What the client-side code shows:**

- 128-bit block cipher (`isNeedPadding` @0x1440 → 16-byte blocks), **no padding**, exact
  multiples of 16 only.
- The userland library **never holds or derives the real encryption key.** It sends a fixed
  **16-byte input constant** to the key service (cmd 2) and gets back an opaque handle; every
  crypt op references only that handle. The actual key material lives entirely inside the
  crypto service behind port `0x25906be` — a privileged task, not in any shipped userland
  library we examined. The 16-byte input is a static constant in `.rodata` at vaddr
  `0x1120a8` (read via `read_bytes`, 16 B): ASCII `0123456789abcdef` — a fixed placeholder-style
  string, **identical on every unit**, therefore *not* device-unique key material. Whether the
  service treats those 16 bytes as a literal key seed, a lookup label (`KeyId`-style), or
  derivation input is **service-side behavior — HYPOTHESIS: derivation/label input, not the key
  itself**; unresolvable from the client.
- Session context comes from `SKData_Init()`/`SKData_Exit()` (constructor/destructor; provider
  **libInfraSKD.so**). Supporting evidence for the algorithm family: libInfraSKD.so carries
  leaked mangled symbols for `Aes::EncryptECB`, `Aes::EncryptCBC`, `Aes::DecryptCBC` lambdas
  taking `SecureKey`/`Key` objects, plus (obfuscated) strings `AES`, `CBC`, `CTR`, `ECB`, `GCM`,
  `CMAC`, `KeyId`. **HYPOTHESIS (strong): the service implements AES.** Which mode this
  particular handle uses is not determinable from userland (the handle is opaque and the
  direction flag is the only mode-adjacent field); **HYPOTHESIS: AES-CBC**, no padding — ECB
  cannot be excluded. The service host task is also unidentified in userland terms — **OPEN**.
- Red herring noted: `/crypter.elf` in the project is an MS-crypt-format firmware **update**
  tool, unrelated to port `0x25906be`.

**Key-source summary:** per-unit secrecy, if any, is injected by the secure key service
(libInfraSKD `SKData` session + `SecureKey` machinery); userland contributes only a
public constant and a direction bit. This document deliberately contains no key bytes — none
are present in userland to contain.

### B.4 `isReadDataEncrypt` — which items are plaintext

```
isReadDataEncrypt(buf, size):   [Ghidra decompile @0x101414]
    if every byte in buf[0..size) == 0: return 0   // treated as PLAINTEXT, returned raw
    return 1 at first non-zero byte                // treated as ciphertext
```

This is a heuristic, not metadata: a fully-zero item is returned without decryption, anything
else is fed to the cipher. The zero-fill convention is *why* this works — deletion zeroes items
(see `deleteBackupKey`, §C.2), and unused/reserved items read back as all-zero and are thus
harmlessly "plaintext". So: **plaintext items = all-zero blobs = deleted/unused items**, not a
user-selectable flag. A real ciphertext that happens to be impossible to be all-zero, and a
plaintext item that is all zeros, both behave "correctly" only by accident — but no shipped
consumer writes nonzero plaintext through this wrapper (§C.4).

### B.5 `releaseClearMemory`

Despite the name, it is just `free()` — **no zeroing** of the buffer (`@0x10144c`; Ghidra's
arg parsing shows it freeing `param_2`, but either way it is a bare `free` from the import
table). Plaintext copies (`plain` in §B.2, `buf` in §A.5) are freed without scrubbing — a
memory-hygiene observation for the write-up, not a correctness bug.

---

## C. What's stored

### C.1 Resolved item ids

| id | type/item | Contents | Confidence | Evidence |
|---|---|---|---|---|
| `0x3000000` | 0x300 / 0x000 | **SSH ECDSA host private key** (PEM text, ≤600 B) | CONFIRMED (full lifecycle) | §C.2 |
| `0x2cf0014` | 0x2cf / 0x014 | GPS clock/time user setting ("clock adjust by user") | CONFIRMED call site; label HYPOTHESIS from function names | libObj.so `FUN_0029ec1c` (PsmGpsGetClockAdjustByUser / GpsGetUserTimeSetting) → `Backup_get_datasize(0x2cf0014)` + `Backup_read(0x2cf0014, …)` |
| `BKID_NET_SERVICE_AP_INFO_LIST` (`_NUM`) | — | saved WiFi access-point list | HYPOTHESIS (name-derived) | BKID_ string enum in NsBkSet.elf, appFw.so, libInfraRemote.so |
| `BKID_RSRC_BT_DEV_ADDRESS` | — | Bluetooth device address (MAC) | HYPOTHESIS (name-derived) | same |
| `BKID_USBLIB_COM_SERIAL_CODE` | — | USB serial number | HYPOTHESIS (name-derived) | same |
| `BKID_WIFI_POWER_TABLE_CCODE_STA` | — | country-code WiFi power table | HYPOTHESIS (name-derived) | same |
| `BKID_APP_*` (thousands) | — | camera settings (ISO, AF areas, screen speed, …) | HYPOTHESIS (name-derived) | BKID_ harvest across fs/a15 |

The `BKID_*` names are string enums compiled into NsBkSet.elf, appFw.so, several
libInfra*.so, Wltestcmd, and `mcmn_drv.ko`; they presumably map to (type,id) pairs, but each
mapping site would need individual resolution (out of the time budget here).

### C.2 The SSH host key (0x3000000) — confirmed lifecycle

From pre-exported decompiles of `libInfraSSHManager.so`
(`/srv/a7rv/a7rv-fw/work/ghidra_export/libInfraSSHManager_so/`, address-in-filename):

- **Boot / restore** — `SshFunctionWrapperImpl::createKeyFromBackup()`
  (`0185_createKeyFromBackup_10885c.c`): `calloc(1, 0x259)` →
  `Backup_nread(0x3000000, buf, 600)`; on success validates, writes the buffer to
  `/tmp_network/ssh/ssh_host_ecdsa_key`, `chmod 0600` (`wrapChMod(..., 0x180)`).
- **Regenerate** — `createKey()` (`0197_createKey_109004.c`): runs
  `/usr/bin/create_host_key.sh` =
  `ssh-keygen -q -b 256 -t ecdsa -N '' -f /tmp_network/ssh/ssh_host_ecdsa_key`
  (a shell wrapper because the in-house IM_System can't produce a passphrase-less key directly,
  per the script's Japanese comment). The key lives in tmpfs; the Backup store is what makes it
  persist across reboots.
- **Persist back** — `updateBackupKey()` (`0206_updateBackupKey_1097e8.c`): read the file,
  require `0 < len ≤ 600`, `Backup_write(0x300, 0x3000000, buf)` then
  `Backup_sync_subsystem(0x300)` (forced flush).
- **Delete** — `deleteBackupKey()` (`0186_deleteBackupKey_1089a4.c`): `Backup_write` of an
  **all-zero 0x259 buffer** + sync. This zero-fill deletion is exactly what `isReadDataEncrypt`'s
  all-zero heuristic (§B.4) detects.
- `deleteKey()` (`0193_deleteKey_108d68.c`): removes `/tmp_network/ssh/ssh_host_ecdsa_key{,.pub}`.

### C.3 What this means for the store's contents

Beyond thousands of camera-setting items (`BKID_APP_*`), the store carries at least: the SSH
host private key, the saved WiFi AP list, the BT MAC, a USB serial code, and GPS/time user
settings — i.e. **identity-bearing and security-relevant material**, not just photographic
preferences. (Item-content claims for BKID_ entries are name-based hypotheses.)

### C.4 Policy finding: the encrypted wrapper has no shipped consumer

`grep -rla 'writeBackupEncryption\|readBackupDecryption'` across all of `/fs/a15` matches
**only libBackupManager.so itself** — no shipped binary imports the encrypted API. Real
consumers (libInfraSSHManager, libObj, NsBkSet.elf) use the **raw** `libbkdmn` API
(`Backup_write`/`Backup_nread`/…). In particular the SSH host key is persisted via raw
`Backup_write` — plaintext on the client side, unless `bk.elf` encrypts internally
(daemon-side behavior: **out of scope / OPEN**). libObj.so is the only other binary containing
the literal string `"libBackupManager.so"` (found by string search @0x0010feee; the xref lookup
on that raw address returned "symbol not found", so **dlopen-vs-unused-NEEDED is OPEN**).
**HYPOTHESIS:** the `BackupManager` encrypted wrapper is a generic/legacy facility reserved for
specific item classes or other products, not the path this firmware uses for the SSH key.

---

## D. Scope & safety statement

- **Device ownership:** this analysis targets the user's own Sony a7R V firmware extraction
  (`/srv/a7rv/a7rv-fw/fs/a15/`), for an educational/interoperability write-up.
- **No key material in this document.** No real key bytes exist in the analyzed userland
  library to reproduce — the design deliberately keeps them in the key service (§B.3). The only
  16-byte constant shown is a fixed public `.rodata` placeholder string, explicitly *not*
  device-unique key material.
- **No firmware binary content reproduced** — no dumps, no `Backup.bin` image (none present in
  the extraction), no cryptographic outputs. Only offsets, layouts, and mechanisms.
- **Explicitly out of scope:** the kernel driver (`backup.ko`), the backup daemon internals
  (`bk.elf`) including any daemon-side encryption and the on-media format of `/setting/Backup.bin`,
  and the crypto service task behind port `0x25906be` (including its `SKData`/`SecureKey`
  implementation in libInfraSKD.so). These would be the next layer for a follow-up.
- Open items (flagged inline): cipher mode, role of the 16-byte constant, identity of the key
  service task, record layout inside `Backup.bin`, `Backup_get_datasize` 1- vs 2-arg semantics,
  the trailing-flush condition in `FUN_001010e4`, whether libbkdmn/daemon encrypts the raw path,
  and how libObj references libBackupManager.

---

## How this was checked

- **Ghidra project `ghidra_extra`** (read-only tools): `list_project_binaries`; batch
  `decompile_function` by numeric address of every function cited in §A–§B
  (`0x101050`, `0x1010e4`, `0x101238`, `0x10128c`, `0x101350`, `0x10135c`, `0x1013b4`,
  `0x101414`, `0x101440`, `0x10144c`, `0x101454`, `0x101594`); `list_imports` (19 imports,
  incl. `SKData_Init/Exit`, `osal_*`, `Backup_get_datasize`, `Backup_read`);
  `read_bytes @0x1120a8` (16 B); `search_strings` / `list_xrefs` on libObj.so;
  `import_binary` of further libraries was declined in this environment and not used.
- **Filesystem evidence** under `/srv/a7rv/a7rv-fw/`: `grep -rhoa` BKID_ name harvest across
  `fs/a15`; `grep -rla` for consumers of the encrypted API (negative result); strings of
  `/bin/bk.elf`; `/bin/create_host_key.sh`; confirmation that no `Backup.bin` image exists in
  the extraction.
- **Pre-exported decompiles** (not loaded in Ghidra this session):
  `/srv/a7rv/a7rv-fw/work/ghidra_export/libInfraSSHManager_so/*.c`, cited by filename + function
  name; the embedded address is the function's virtual address.
- **Limitations:** static analysis only — no device run, no dynamic tracing of port
  `0x25906be`/`0x82cd08e0`; the key service and daemon were never decompiled, so everything
  marked HYPOTHESIS/OPEN there stands as such. `libBackupManager.so` virtual base = 0x100000.
- Raw-LE byte greps for the two IPC ports found nothing (constants are built with mov/movk), so
  port identification rests on the decompiled `osal_*` call sites.
