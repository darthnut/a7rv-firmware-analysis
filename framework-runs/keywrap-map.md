# a7R V — Key-wrapping root: where the KEK comes from

Scope: static RE of the user's own Sony a7R V firmware (`/srv/a7rv/a7rv-fw/fs/a15/lib/`), for a
public write-up. **Mechanism, offsets, ports and call shapes only — no key material, no binary.**
Ghidra addresses are virtual (default AArch64 base). Evidence = Ghidra MCP call + address.
Inference beyond decompiled code is tagged **HYPOTHESIS**.

Binaries used: `libsecvlt.so` (ghidra_secvlt), `libBackupManager.so` (ghidra_extra),
`libosal_uipc.so` (ghidra_svctools); `libInfraSKD.so`, `appFw.so` + friends (ELF
readelf/nm/grep level only, never loaded into Ghidra).

## A. Where the KEK enters

**Answer: fetched — but not the KEK itself. The KEK never enters `libsecvlt.so`.** SecVault
holds only the *per-record DEK*; it is produced/consumed at runtime by an out-of-process key
service over OSAL message queue **QID `0x25906be`**. libsecvlt is a pure **client** of that
service (no `osal_reg_sync_msg_queue_cb` import — see B). Nothing in libsecvlt derives or stores
a KEK.

### A.1 Two-tier key structure (decompiled)

`FUN_00100f4c` @0x100f4c (ghidra_secvlt, `decompile_function` 0x100f4c) is a one-shot AES-256-GCM
wrapper: `EVP_aes_256_gcm` + `EVP_CipherInit_ex(ctx,cipher,NULL,param_4,param_5,dir)`,
`EVP_CIPHER_CTX_set_key_length(ctx,0x20)`, IV 0x0C, tag 0x10. `param_4` = key buffer, `param_5`
= IV, `param_6` = tag, `param_7` = 1 encrypt / 0 decrypt. Xrefs: exactly two callers —
`SECVLT_store` @0x101670 and `SECVLT_load` @0x10187c.

**`SECVLT_store` @0x101544** — key buffer shown (mechanism only, no bytes):

```c
iVar4 = RAND_bytes((uchar *)(__dest + 0x28),0xc);   // random 12-byte IV   → rec+0x28
iVar4 = RAND_bytes(local_20,0x20);                  // random 32-byte DEK  → local_20 (stack)
iVar4 = FUN_00100f4c(__dest + 0x58, param_2, param_3,
                     local_20,          // KEY = fresh per-record DEK (param_4)
                     __dest + 0x28,     // IV  (rec+0x28)
                     __dest + 0x38,     // out: GCM tag (rec+0x38)
                     1);                // encrypt payload
...
iVar4 = FUN_0010117c(2,3,0,0x10,1,&local_28,0,__dest + 0x38,0x10);
//  op 2 = IMPORT: input = the 16-byte GCM tag just computed (rec+0x38); returns handle local_28
iVar4 = FUN_0010117c(3,3,local_28,0,0,__dest + 8,&local_3c,local_20,0x20);
//  op 3 = WRAP: input DEK (local_20) → ciphertext written to rec+0x08 (0x20 bytes)
iVar4 = FUN_001012d0(local_28);                     // op 5 = release handle
```

**`SECVLT_load` @0x101768** — the inverse; this is the EVP key-argument back-trace:

```c
iVar3 = FUN_0010117c(2,3,0,0x10,0,local_28,0,lVar1,0x10);
//  op 2 = IMPORT: input = rec+0x38 (16-byte stored GCM tag), direction 0 → handle local_28[0]
iVar3 = FUN_0010117c(3,3,local_28[0],0,0,local_28 + 1,&local_3c,lVar2 + 8,0x20);
//  op 3 = UNWRAP: input = wrapped DEK at rec+0x08; plaintext DEK returned into local_28+1
iVar3 = FUN_001012d0(local_28[0]);                  // op 5 = release handle
iVar3 = FUN_00100f4c(lVar2 + 0x58, param_2, *(undefined8 *)(lVar2 + 0x48),
                     local_28 + 1,       // KEY = DEK unwrapped by the KEY SERVICE (RPC response)
                     lVar2 + 0x28,       // IV from record
                     lVar1,              // tag from rec+0x38, GCM auth here
                     0);                 // decrypt payload
```

So the AES key buffer (`local_28+1`) is filled **entirely by the RPC response payload** — the
unwrapped DEK arrives in `FUN_0010117c`'s output buffer. The record format (confirmed):
`+0x00 "SECVAULT"`, `+0x08` 32-byte wrapped DEK, `+0x28` 12-byte IV, `+0x38` 16-byte GCM tag,
`+0x48` payload size, `+0x58` payload. `SKData_Init()`/`SKData_Exit()` bracket each key-service
exchange; they are undefined imports resolved at runtime (see B.2).

### A.2 The RPC primitive

`FUN_0010117c` @0x10117c (ghidra_secvlt) is the whole key-service client:

```c
iVar2 = osal_valloc_msg_wait(0x25906be,&local_8,0x428,1);   // 0x428-byte msg on the key-service QID
*local_8    = op;          // msg[0]: 2=import, 3=crypt, 5=release
local_8[1]  = handle;      // msg[1]
local_8[2]  = param_4;     // msg[2]: 0x10 on SecVault imports, 0 on crypt (meaning unresolved — HYPOTHESIS: key-slot/length selector)
local_8[3]  = param_5;     // msg[3]: 1 = wrap/encrypt direction, 0 = unwrap/decrypt
local_8[4]  = 0;           // msg[4]: payload length (in/out)
/* then per ≤0x400-byte chunk: */
    puVar1[4] = __n; memcpy(local_8+5, in+off, __n);
    iVar2 = FUN_001010e8(flags,out,&outlen,off,local_8);
osal_free_msg(0x25906be);
```

`FUN_001010e8` @0x1010e8 does the synchronous round trip:

```c
iVar1 = osal_snd_sync_msg(0x25906be,param_5);
if (iVar1 == 0) {
  if (*param_5 == 0) { iVar1 = -0x3fa; }                      // response status word
  else if (((param_2 != 0) && ((param_1 & 1) != 0)) &&
          (memcpy((void *)(param_2 + param_4),param_5 + 5,param_5[4]), ...  // response payload → caller
```

This is byte-for-byte the same protocol as the libBackupManager key-service client
(`FUN_001010e4`/`FUN_00101050`, same QID, same msg layout, same op codes — prior analysis:
`keyservice-map.md` §A). **Cross-check, fresh decompile (ghidra_extra):** libBackupManager's
`writeBackupEncryption` @0x101454 imports its 16-byte key material from static `&DAT_001120a8`
(a printable-ASCII placeholder pattern, characterized not quoted in the prior map);
SecVault instead imports each record's own stored GCM tag. In both clients the KEK itself is
never transmitted: only import material + handles + wrapped/cleartext DEK cross the queue.

## B. The trail end

**The trail ends at the RPC boundary.** Everything inside `libsecvlt.so` bottoms out at
`osal_snd_sync_msg(0x25906be, msg)` (`FUN_001010e8` @0x1010e8). The KEK lives beyond that send,
inside a process that is **not in any Ghidra image analyzed for this project** (B.3). Per the
task: the provider is recorded by QID + request shape and **not invented**.

### B.1 QID and routing (established; libosal_uipc.so decompiles in `keyservice-map.md` §A)

- QID **`0x25906be`**: bit15 = 0 → **kernel-routed uIPC** (`u_osal_*` path, `kmod/osal_uipc.ko`),
  not a userland socket. Module/task field = `(qid>>16)&0xfff` = **`0x0259`**; queue slot =
  `qid & 0x7fff` = **`0x06be`**.
- The provider is the subscriber that registered a callback on that slot via
  `osal_reg_sync_msg_queue_cb` (libosal_uipc.so @0x105b88; table keyed on `qid & 0x7fff`; max msg
  0x1000 — our 0x428-byte messages with 0x400-byte chunks fit).

### B.2 Request/response shape (own decompiles: `FUN_0010117c` @0x10117c, `FUN_001010e8` @0x1010e8)

0x428-byte message, u64-indexed, same buffer reused for reply:

| field | request content | evidence |
|---|---|---|
| `msg[0]` | op: **2**=import → handle, **3**=crypt (wrap/unwrap under handle), **5**=release | fills @0x10117c; release helper `FUN_001012d0` @0x1012d0 |
| `msg[1]` | handle (0 on import) | `local_8[1] = handle` |
| `msg[2]` | selector: **`0x10`** on SecVault imports, 0 on crypt — vs **`1`** on Backup imports (libBackupManager `writeBackupEncryption` @0x101454) — meaning unresolved; HYPOTHESIS: key-slot/context selector | `local_8[2] = param_4` |
| `msg[3]` | direction: 1 = wrap/encrypt, 0 = unwrap/decrypt | store vs load call sites (A.1) |
| `msg[4]` | payload length in / out (≤0x400 per chunk; short/tail chunk ends the message) | chunk loop @0x10117c |
| `msg[5]…` | payload chunk | `memcpy(local_8+5,in+off,__n)` |
| reply `msg[0]` | status word (`0` → client maps to error `-0x3fa`) | @0x1010e8 |
| reply `msg[4]`, `msg[5]…` | output length + output payload | `memcpy(out+off,msg+5,msg[4])` |

SecVault's op sequence (A.1): **import** the record's own 16-byte GCM tag (`rec+0x38`) → handle;
**wrap** 32-byte DEK in, wrapped DEK out (→ `rec+0x08`); **unwrap** wrapped DEK in, **plaintext
32-byte DEK out into client stack**; **release**.

**Inference from the confirmed data flow** (the one non-code claim here, so tagged): the only key
material SecVault *gives* the service is a value already stored in plaintext in the record it
protects — it cannot by itself let the service compute the DEK. So the service must mix in its own
secret (a KEK, or a KDF over a device secret) that **never crosses the queue**. **HYPOTHESIS** on
the exact mechanism (dedicated KEK vs KDF vs HSM-internal); confirmed only that the KEK is
provider-side.

### B.3 Provider: where it is not, and the one on-disk candidate that fits

**Not in any loaded Ghidra image** (first-hand `list_project_binaries` this session + prior pass):

| project | images | QID literal hits |
|---|---|---|
| ghidra_secvlt | `libsecvlt.so` | client only (this map) |
| ghidra_extra | `crypter.elf`, `libBackupManager.so`, `libObj.so` | client only (libBackupManager) |
| ghidra_svctools | `adjstctl.elf`, `libtestcmd.so`, `libosal_uipc.so` | none (transport lib only) |
| ghidra_svc (prior pass) | `sen.elf`, `libsencore.so`, `libIMDB.so`, `libInfraSSHManager.so` | none |

- Raw little-endian dword `BE 06 59 02` sweep over `bin/`+`lib/`+`kmod/` (prior pass): **zero
  hits** — the QID exists only as `movz`/`movk` immediates, so only a code-encoding search can
  find the provider.
- libsecvlt proven **pure client**: `readelf --dyn-syms` UND list contains the send trio
  (`osal_valloc_msg_wait`, `osal_snd_sync_msg`, `osal_free_msg`) but **not**
  `osal_reg_sync_msg_queue_cb`. This also **disproves** the prior map's leading guess that
  libsecvlt itself hosts the service.
- On-disk narrowing: images containing **both** QID encodings (`movz #0x6be` +
  `movk #0x259,lsl16`; prior pass) = libBackupManager.so (client), libsecvlt.so (client, now
  proven), `appFw.so`, `libmpr.so`, `libAiDictionary.so`. Import check (`grep -la
  osal_reg_sync_msg_queue_cb`, this session): of those five, **only `appFw.so`** imports the
  registration API (libmpr/libAiDictionary don't — they are pass-through callers of libsecvlt).
  **HYPOTHESIS: the key-service provider thread runs inside `appFw.so`** — the only on-disk image
  holding both the QID constants and the server-side registration API. Not decompiled; encoding
  *adjacency* (register chain) not verified — the byte-pattern adjacency scan was blocked by the
  sandbox, so co-occurrence remains the standard here.
- `libInfraSKD.so` (7.6 MB; **not** in any Ghidra project — ELF level only): exports exactly six
  symbols — `SKData_Init` @0x64568 and `SKData_Exit` @0x646f8 (the pair bracketing SecVault's RPC,
  A.1) plus `SKD_Sign` @0x64b30, `SKD_SignBufAlloc` @0x64c34, `SKD_SignBufFree` @0x64c3c,
  `SKD_Verify` @0x64c48. Its UND list includes `osal_reg_sync_msg_queue_cb` /
  `osal_unreg_msg_queue_cb`, BSD-server calls (`bind`/`listen`/`accept`/`select`), `dlopen`,
  `getenv` — server-capable, **but it contains neither QID encoding** (absent from the
  co-occurrence set), so it cannot register slot 0x06be unless the QID is computed at runtime.
  DT_NEEDED by libBackupManager.so, libInfraCryptCore.so, appFw.so, libIMDB.so,
  libAiDictionary.so, libInfraCCPF(Static).so — but **not** by libsecvlt, whose `SKData_*`
  imports resolve from the host process's global namespace (its DT_NEEDED is libc-family only).
  **HYPOTHESIS: libInfraSKD is shared client-side glue for a "Secure Key Data" sign/verify
  service, not the key-wrapping provider itself.** Not investigated.

## C. Verdict + scope

**Per-record random DEK, service-held KEK, provenance unresolved — stated exactly as far as the
static evidence reaches:**

1. **Payload key (DEK): per-record, random.** `SECVLT_store` @0x101544 calls
   `RAND_bytes(local_20,0x20)` fresh for every store; the 32-byte DEK exists only on the client
   stack, is handed to the key service to be wrapped (op 3, direction 1), and its wrapped form is
   all that persists (`rec+0x08`). No two records can share a DEK. *(confirmed, decompiled)*
2. **KEK: lives inside the key service; not obtainable through this protocol.** No observed op
   returns KEK material — the reply payloads are handles and per-record DEKs only, and neither
   client ever sends or receives a KEK. Whether it is one model-wide key or one per device is
   decided *inside the provider*, which is out of every image analyzed here. *(client-side
   absence confirmed; provider-side existence = B.2 HYPOTHESIS)*
3. **Per-device vs model-wide: UNRESOLVED.** Supporting observations, neither decisive:
   - Backup's import blob is a **model-wide static placeholder** (prior map §C, confirmed
     client-side) — but B.2 shows import material doesn't have to be secret, so this says little
     about the effective key.
   - SecVault's import material (the record's own GCM tag) is record-specific **and public**, so
     the service's own input does all the work (HYPOTHESIS, B.2).
   - String-level (never decompiled) per-device machinery exists one layer over:
     `libInfraCryptCore.so` (a libsecvlt consumer) carries `ics_getSerialNumber`,
     `act_get_key_source`, `SerialPublicKey`, `FixKey`, `backup == abRedKey` — if the provider
     sources keys from iCrypt/serial, the KEK is **per-device**.
   - Hardware path: `kmod/elpspacc.ko` exposes an SPACC **HSM mailbox** (`SPACC_REG_HSM_*`,
     `/dev/spaccusr` per prior string analysis) — if the provider bottoms out there, the KEK is
     **hardware-rooted and non-exportable**.
   - Do **not** conclude device-specific security from this image set; the decisive code is
     behind the QID.

**What would resolve the rest**, in leverage order:
1. Load `appFw.so` into a Ghidra project and locate the `osal_reg_sync_msg_queue_cb` call whose
   immediate materializes `0x25906be` (movz/movk pair) → that callback is the provider; read its
   op-2/op-3 handlers to see what the KEK is derived from. The decisive single step.
2. `kmod/osal_uipc.ko`: kernel routing/subscriber table for slot `0x06be` — proves queue ownership
   without trusting the userspace candidate.
3. `libInfraSKD.so` (7.6 MB — own Ghidra project): semantics of `SKData_Init` @0x64568 around the
   exchange, and whether its own queue registrations touch the key service.
4. `kmod/elpspacc*.ko`: whether provider-side crypto reaches the HSM mailbox (→ hardware root).

**Scope/safety.** Owner's own extracted firmware, read-only static analysis only; Ghidra tools
were read-only and decompilation was by address. Mechanism, offsets and protocol shapes only —
**no key bytes appear in this document**; the two client-side blobs are characterized (length,
xrefs, pattern class) but never dumped.

## How this was checked

Ghidra (read-only, decompile **by address**):
1. `list_project_binaries` on ghidra_secvlt / ghidra_extra / ghidra_svctools this session
   (inventories in B.3); ghidra_svc inventory from the prior pass.
2. ghidra_secvlt `decompile_function`: `0x100f4c` (AES-256-GCM wrapper), `SECVLT_store` @0x101544,
   `SECVLT_load` @0x101768, `0x10117c` (RPC client), `0x1010e8` (sync send), `0x1012d0` (release),
   `0x101458` (record read + "SECVAULT" magic check); `list_xrefs` `0x100f4c` → exactly the two
   key-path callers.
3. ghidra_extra `decompile_function`: libBackupManager `writeBackupEncryption` @0x101454 —
   cross-check of the Backup import call `FUN_001010e4(2,3,0,1,1,&local_8,0,&DAT_001120a8,0x10)`.

On disk (`/srv/a7rv/a7rv-fw/fs/a15/`, read-only readelf/nm/grep):
4. `libsecvlt.so`: `readelf --dyn-syms` (UND set → client-only, no queue-reg API); `readelf -d`
   (DT_NEEDED libc-family only → `SKData_*` resolved from host global namespace).
5. `libInfraSKD.so`: `nm -D --defined-only` (the six exports listed in B.3); `readelf --dyn-syms`
   (reg-API + socket + dlopen imports); `grep -rla libInfraSKD lib bin` (who links it).
6. `grep -la osal_reg_sync_msg_queue_cb` restricted to the five QID-encoding images → appFw.so +
   libInfraSKD.so only (B.3 narrowing).
7. AArch64 `movz #0x6be` / `movk #0x259,lsl16` byte-pattern scan of the candidate libraries
   (co-occurrence counts; the adjacency scan was blocked by the sandbox → adjacency **unverified**).
   Raw-dword `BE 06 59 02` sweep of `bin/`+`lib/`+`kmod/` and the libosal_uipc QID-semantics
   decompiles (@0x105b88, @0x1067b0): prior pass, recorded in `keyservice-map.md`.
