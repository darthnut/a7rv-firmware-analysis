# a7R V Backup-store — subsystem/item id registry (backupmap-map)

Companion registry to `backup-map.md` (store model / cipher). This document resolves the
**(u16 subsystem, u32 item)** id scheme and inventories which ids exist and what each holds,
tying the persistence picture together (SSH host key `0x300/0x3000000`; SecVault slots 0–2 at
subsystem `0x02f9`, slot 3 at `0x02ec`).

All addresses are **Ghidra virtual addresses**; binaries: `libBackupManager.so` and callers in the
loaded Ghidra projects (`ghidra_extra`, `ghidra_svc`, `ghidra_svctools`, `ghidra_secvlt`,
`ghidra_cpapp`). Claims tagged **HYPOTHESIS** are inferences from caller context; everything else
is backed by a cited decompile.

## A. The id scheme

**Layout: a stored item is addressed by one 32-bit id, `id[31:16] = subsystem (u16)`,
`id[15:0] = item index within subsystem (u16)` — i.e. `id = subsystem << 16 | index`.**

Evidence (all from `ghidra_extra`, binary `/libBackupManager.so`, decompiled this session by
address):

1. **`BackupManager::writeBackup(ushort subsystem, uint id, const void *data)`** @`0x10135c`
   (`decompile_function "BackupManager::BackupManager::writeBackup"`):

   ```c
   iVar1 = Backup_get_datasize(param_2, param_1);        // (id, subsystem) — 2-arg size query
   ... BkDmn_write(param_2, param_3, iVar1);             // only the FULL 32-bit id goes onward
   ```

   The separate `ushort` subsystem argument is used *only* for the size lookup; the item itself
   is identified by the full id — the subsystem is redundant because it is embedded in it.

2. **`BackupManager::readBackupDecryption(uint id, void *buf)`** @`0x101594`: takes **id alone**
   (`Backup_get_datasize(param_1)` — 1-arg form, then `Backup_read(param_1, buf)`). No subsystem
   parameter exists on the read path, which only works because the subsystem is derivable from
   the id.

3. **`BkDmn_write(uint id, const void *data, int len)`** @`0x10128c` (local function, not an
   import — the store-client that `writeBackup`/`writeBackupEncryption` both end in) splits the
   id back apart when building the IPC message to the backup daemon on OSAL port `0x82cd08e0`:

   ```c
   *local_8 = 2;                                       // u32 @+0  = write command
   *(short *)(local_8 + 1) = (short)(param_1 >> 0x10); // u16 @+4  = SUBSYSTEM = id >> 16
   local_8[2] = param_1;                               // u32 @+8  = full id
   local_8[3] = param_3;                               // u32 @+12 = len
   memcpy(local_8 + 4, param_2, len);                  // payload @+16
   osal_set_msg_src(puVar1, (param_1 >> 0x10 & 0x7fff) << 0x10); // src tag = subsystem,
                                                      // truncated to 15 bits by & 0x7fff
   ```

   The daemon-side message carries subsystem and full id **as separate fields derived from one
   u32**, which is the direct confirmation of the split: high 16 bits = subsystem, low 16 = item.

**Worked examples of the encoding (all cross-checked against §B callers):**

| id | subsystem = id>>16 | item = id & 0xffff | seen at |
|---|---|---|---|
| `0x3000000` | `0x300` (768) | `0x0000` | SSH host key (§B) |
| `0x2f90027/28/29` | `0x02f9` (761) | `0x27/0x28/0x29` | SecVault slots 1/2/0 (§B) |
| `0x02ec0046` | `0x02ec` (748) | `0x46` | SecVault slot 3 (§B) |
| `0x2cf0014` | `0x2cf` (719) | `0x14` | GPS clock-adjust in libObj (§B) |

Corroborating detail from `secvaultslots-map.md` §A (descriptor dump `read_bytes libsecvlt.so
0x101c30 len 128`, prior session): libsecvlt's per-slot descriptors store subsystem and Backup
item as **separate u16/u32 fields** (`+0x04 subsystem`, `+0x08 backup item`), and the item field
equals `subsystem<<16 | index` verbatim in all four entries — two independent producers build
ids with the same layout.

Caveats:
- The 15-bit mask on the *message source tag* (`& 0x7fff`) affects only the IPC audit tag, not
  the routing field (`msg.u16@+4` keeps all 16 bits); every subsystem observed in this firmware
  (0x2cf, 0x2ec, 0x2f9, 0x300) is < 0x8000 anyway.
- The raw API used by most consumers (`Backup_write(subsystem, id, data)`, `Backup_nread(id,…)`,
  `Backup_sync_subsystem(subsystem)` — exports of `libbkdmn.so`) takes the subsystem explicitly
  where a message needs it (write, sync), and id-only where it doesn't (nread), consistent with
  the same layout. Store-side per-item sizes are fixed and store-declared
  (`Backup_get_datasize`), per `backup-map.md` §A.3.

## B. The registry

Method: for each loaded binary, resolve the `Backup_*` PLT thunks (`search_symbols_by_name
"Backup"`), list xrefs to every thunk (`list_xrefs <thunk addr>`), and decompile each real caller
to read the id immediates. A row is **CONFIRMED** when an id immediate appears verbatim in the
caller's decompile; payload identity is CONFIRMED only when the caller's own strings/symbols say
so, else **HYPOTHESIS**.

### B.1 Resolved (subsystem, item) → payload

| subsystem | item / full id | Payload | Confidence | Caller (binary @ VA) |
|---|---|---|---|---|
| `0x300` | `0x000` / `0x3000000` | **SSH ECDSA host private key** (PEM text, ≤ 600 B; restored to `/tmp_network/ssh/ssh_host_ecdsa_key`, mode 0600) | **CONFIRMED** (ids + payload strings, §B.2) | libInfraSSHManager.so: `createKeyFromBackup` @0x10885c, `updateBackupKey` @0x1097e8, `deleteBackupKey` @0x1089a4 |
| `0x02f9` | `0x29` / `0x2f90029` | **SecVault slot 0** record (magic `"SECVAULT"`, ≤4 KiB) — C2PA signing companion object | id **CONFIRMED** (descriptor→API path, §B.3); payload HYPOTHESIS (from `secvaultslots-map.md` §B, libmpr.so `InfraC2PA` sites) | libsecvlt.so: write `FUN_00101324` @0x101324, read `FUN_00101458` @0x101458, via descriptor table @0x101c30 |
| `0x02f9` | `0x27` / `0x2f90027` | **SecVault slot 1** record (≤16 KiB) — C2PA certificate payload | id **CONFIRMED**; payload HYPOTHESIS (same basis) | idem (descriptor slot 1) |
| `0x02f9` | `0x28` / `0x2f90028` | **SecVault slot 2** record (≤4 KiB) — C2PA secret (write-only via vault API) | id **CONFIRMED**; payload HYPOTHESIS | idem (descriptor slot 2) |
| `0x02ec` | `0x46` / `0x2ec0046` | **SecVault slot 3** record (≤60000 B) — **unknown payload**; no consumer found in any shipped image | id **CONFIRMED** (§B.3); payload **unresolved** (§B.4) | idem (descriptor slot 3) |
| `0x2cf` | `0x14` / `0x2cf0014` | 1-byte "clock adjusted by user" flag (accessors self-name `"PsmGpsGetClockAdjustByUser"`, `"GpsGetUserTimeSetting"`) | id + read op **CONFIRMED** (full decompile, §B.5); semantic label from literal in-function strings | libObj.so `FUN_0029ec1c` (get_datasize+`Backup_read`, 1 B) |
| `0xa1` | `0x03,0x04,0x05,0x12,0x17,0x18` write; `0x19` read ×5; item also written **dynamically** | GPS-infrastructure persistent settings/state (1–4-byte values; whole subsystem is `Backup_sync_subsystem`-flushed together) | ids **CONFIRMED** (disasm immediates at cited sites, §B.5); payload HYPOTHESIS (GPS-infra region: `"GpsInfraMainThread"` log string, sibling GPS accessors) | libObj.so: `FUN_00296b94` (writes 3/4/5), `FUN_00299098` (writes 0x12/0x17/0x18 + sync), `FUN_0029dfe4@0x29e3cc` (dynamic item), `Backup_nread(0xa10019,…,1)` @0x28f490, 0x298cc0, 0x29aed0, 0x29ae78, 0x28e1dc (§B.5) |
| `0x7a` | `0x02–0x05`, `0x06`, `0x07` (u32 each) | "InfraInput" persistent settings | ids **CONFIRMED** (disasm immediates + one pseudocode literal, §B.6); payload HYPOTHESIS (only tag is the `"[INFRAINPUT]%s, err..."` log string) | libObj.so: `FUN_001ce860`, `FUN_001ce9c8`, `FUN_001cef74` (pseudocode shows `Backup_write(0x7a,0x7a0004,…)` verbatim), `FUN_001cfd10` |
| `0x7b` | `0x06`, `0x27`, `0x36` enumerated; ~22 further write sites in the same functions not itemized | touch-position / line-touch calibration config (read-modify-write: `Backup_read(0x7b00xx)` precedes each write) | ids for 6/0x27/0x36 **CONFIRMED** (disasm); payload HYPOTHESIS (from class names `InfraTp::SetTpConfig`, `InfraTp::SetLineTpConfig`) | libObj.so: `FUN_001d3a94` @0x1d3b88, 0x1d3e9c; `InfraTp::SetTpConfig` @0x1d4734, 0x1d4bf0 (25 call sites, stride 0x28); `InfraTp::SetLineTpConfig` @0x1d5068 |
| `0x102` | `0x00` (u64), `0x01` (16 B → `DAT_003d1080`) | **unknown** | ids **CONFIRMED** (disasm); payload unresolved (§B.7) | libObj.so: `FUN_001e9600@0x1e96f0` (`Backup_nread(0x1020000,…,8)`), `FUN_001e95e8` (`Backup_nread(0x1020001,&DAT_003d1080,0x10)`; callers `FUN_001e9c50`, `FUN_001ea04c`, `FUN_001ea2a0` + one vtable slot) |
| `0x0f9` | `0x89, 0x14e, 0x156, 0x39f, 0x3a0` (u32 via `Backup_read_4Byte`) | **unknown** (two are read adjacently and combined arithmetically) | ids **CONFIRMED** (disasm immediates, §B.7); payload unresolved | libObj.so GPS-infra state-machine region: `Backup_read_4Byte` calls @0x29da5c, 0x29da6c, 0x29daac, 0x29dac4 (+0x29dab4/68 for `0x14e`) |
| `0x0fa` | `0xa3` = base, `0xa4` = length (u64 via `Backup_read_8Byte`) | physical-memory carve-out: base+size fed to `open("/dev/mem")` + `mmap` + `memset(…,0x5a,…)` | ids **CONFIRMED**; mechanism CONFIRMED from the decompile itself (§B.7) — semantics beyond "mmap'd/scrubbed region" HYPOTHESIS | libObj.so `FUN_001fbaf0` @0x1fbaf8, 0x1fbb1c |
| `0x91` | `0x40` / `0x910040` | **unknown** — seen only as a first argument at one call of unidentified PLT thunk `0x00156410` | id **observed**, API/meaning unresolved (§B.8) | libObj.so `FUN_001e9600` region |

**Coverage:** among the binaries loaded in the five Ghidra projects, only `libObj.so`,
`libInfraSSHManager.so` and `libsecvlt.so` import the `Backup_*` API (negative `list_imports
"Backup"` for `libsencore.so`, `sen.elf`, `libIMDB.so`, `adjstctl.elf`, `libtestcmd.so`).
`libbkdmn.so` (exporter) and the backup daemon itself are out of scope. Generic helpers
`FUN_002bc53c`/`FUN_002bc600` read ids from a runtime table (`0x2f51b8`), so additional ids may
exist that no immediate reveals (§B.8).

## B.2 SSH host key — subsystem `0x300`, item `0` (`0x3000000`)

Binary `/libInfraSSHManager.so` (ghidra_svc). PLT thunks: `Backup_nread`@`0x106c70`,
`Backup_write`@`0x106d70`, `Backup_sync_subsystem`@`0x1069e0`. Three functions (decompiled by
address; names from Ghidra):

- `createKeyFromBackup` @`0x10885c`: `calloc(1, 0x259)` → `Backup_nread(0x3000000, buf, 600)`
  (call @`0x1088b4`) → validator `FUN_001085d0` → `wrapFopen("/tmp_network/ssh/ssh_host_ecdsa_key","w")`
  → write → `wrapChMod(..., 0x180)` (0600). The id literal `0x3000000` is in the decompile.
- `updateBackupKey` @`0x1097e8`: `readHostKeyData_abi_cxx11_` from the on-disk key file, rejects
  length 0 or >600, then `Backup_write(0x300, 0x3000000, ptr)` (call @`0x10985c`) +
  `Backup_sync_subsystem(0x300)` (call @`0x1098b4`).
- `deleteBackupKey` @`0x1089a4`: writes an all-zero 600-byte buffer via the same
  `Backup_write` (call @`0x1089f0`) + sync pair — delete-by-overwrite in the backup store.

Lifecycle detail (boot restore / regeneration) in `backup-map.md` §C.2.

## B.3 SecVault slots — subsystem `0x02f9` (slots 0–2) and `0x02ec` (slot 3)

Binary `/libsecvlt.so` (ghidra_secvlt). A descriptor table of four 0x20-byte entries sits in
`.rodata` @`0x101c30` (verbatim dump in `secvaultslots-map.md` §A): per entry, item magic (u32),
**subsystem u16@+0x04**, **backup id u32@+0x08**, maxsize @+0x10, attrs @+0x18:

| slot | subsystem | backup id | maxsize | attrs |
|---|---|---|---|---|
| 0 | `0x02f9` | `0x2f90029` | 4096 | 0x34 |
| 1 | `0x02f9` | `0x2f90027` | 16384 | 0x32 |
| 2 | `0x02f9` | `0x2f90028` | 4096 | 0x33 |
| 3 | `0x02ec` | `0x02ec0046` | 60000 | 0x30 |

Every vault access goes through these fields, which is what makes the four ids CONFIRMED:

- write path `FUN_00101324`: `Backup_write(*(u16 *)(desc + 4), *(u32 *)(desc + 8), record)`
  (thunks `Backup_write`@`0x100dc0`), and calls `Backup_sync_subsystem` (thunk @`0x100d10`) only
  when attr bit 7 is set (`((rec + 0x50 | desc + 0x18) >> 7) & 1`) — attr bit 7 = fsync gate.
- read path `FUN_00101458`: `Backup_nread` (thunk @`0x100d90`) / `Backup_get_datasize`
  (thunk @`0x100d20`) then validates the wrapper: `"SECVAULT"` 8-byte magic, u64 data-size @+0x48,
  u32 attrs @+0x50, 0x68-byte header.
- erase `FUN_00101380` (`clean_vlt_data`, assert file `"sec_vault_internal.c"` line 0xcc);
  `SECVLT_sync` @`0x101990`.

Payload meanings (slots 0–2 = C2PA signing material: cert chain / signing companion / secret) are
carried over as **HYPOTHESIS** from `secvaultslots-map.md` §B — the consumers are libmpr.so
`InfraC2PA` sites, which call the vault API but never the Backup API directly, so no caller
string here names the payload.

## B.4 SecVault slot 3 (`0x02ec` / `0x02ec0046`) — unresolved payload

The id is CONFIRMED (descriptor row above) and the slot is reachable through the same
read/write/erase functions, but **no consumer was found**: across all five Ghidra projects, nothing
calls `SECVLT_*`/the vault-internal wrappers with slot 3 in a way that names a payload, and no
other binary references subsystem `0x02ec` (prior session's negative searches, re-checked via
thunk xrefs this session). Its 60000-byte maxsize and attrs `0x30` (fsync gate **off**) distinguish
it from the C2PA slots. Left explicitly as: *present in the store, payload unknown — do not
attribute*.

## B.5 GPS infrastructure — subsystems `0x2cf` and `0xa1` (libObj.so)

**`0x2cf0014`** — `FUN_0029ec1c` decompiled in full (small): `Backup_get_datasize(0x2cf0014)` must
return 1, `Backup_read(0x2cf0014, &byte, 1)`; the byte then gates an
`osal_snd_sync_direct(0x90013d, …)` PSM message, and the result flag is returned. In-function
log strings: `"PsmGpsGetClockAdjustByUser"`, `"PsmGpsGetClockForceSettled"`,
`"GpsGetUserTimeSetting"`. Sole occurrence of the literal `0x2cf0014` in libObj (literal
`search_code` hit list).

**`0xa1` family** — write sites (each `mov w0,#0xa1; mov w1,#<item>; bl Backup_write` @thunk
`0x158570`, disassembly windows): `FUN_00296b94` items 3 (@`0x29765c`), 4 (@`0x2976a8`, 2-byte
buffer `strh #0x2d4`), 5 (@`0x2976d8`, `strb #1`); `FUN_00299098` items 0x17 (@`0x29a1bc`),
0x18 (@`0x29a1ec`), 0x12 (@`0x29a6f0`, 4-byte) — and the **only `Backup_sync_subsystem` call in
all of libObj**: `mov w0,#0xa1; bl 0x157300` @`0x29a730–4`, i.e. one flush point for the whole
GPS subsystem. `FUN_0029dfe4@0x29e3cc` writes item `w25` (runtime-computed id). Reads:
`Backup_nread(0xa10019, buf, 1)` at five sites — `FUN_0028f394@0x28f490`, `FUN_00298c98@0x298cc0`,
`FUN_0029aeac@0x29aed0`, `FUN_0029ae1c@0x29ae78` (which logs `"GpsInfraMainThread"` and calls
`FUN_00299098`), `FUN_0028e1bc@0x28e1dc`. The 0x299xxx–0x29exxx function cluster is GPS-infra code
(task name string); individual item meanings are not asserted (HYPOTHESIS: GPS settings/state).

## B.6 InfraInput `0x7a` and touch calibration `0x7b` (libObj.so)

- `0x7a`: four-byte values, items 2–5 written by `FUN_001ce860` (@`0x1ce890/8b0/8d0/8f0`) and again
  by `FUN_001ce9c8` (@`0x1ce9fc/a28/a48/a68`); item 4 by `FUN_001cef74` (@`0x1cefa4` — whose
  pseudocode literally shows `Backup_write(0x7a,0x7a0004,…)` beside the log string
  `"[INFRAINPUT]%s, err..."`); items 7 and 6 by `FUN_001cfd10` (@`0x1cfda0`, `0x1cfdc0`).
  Payload = some persistent "InfraInput" settings blob; nothing more is supported by strings →
  HYPOTHESIS.
- `0x7b`: read-modify-write pattern — `FUN_001d3a94` first calls `Backup_read(0x7b00xx,…)`
  (thunk `0x157850`), mutates, then `Backup_write(0x7b, 0x7b0006|0x7b0027)` (@`0x1d3b88`,
  `0x1d3e9c`). `InfraTp::SetTpConfig` writes `0x7b/6` (@`0x1d4734`) and `0x7b/0x36` (@`0x1d4bf0`)
  among **25** `Backup_write` sites at stride 0x28 (same function writing a per-entry item array —
  the other item ids were not individually enumerated); `InfraTp::SetLineTpConfig` writes
  `0x7b/6` (@`0x1d5068`). With `"_InfraTpPositionConfig"`-style names, HYPOTHESIS: touch-position
  calibration tables.

## B.7 `0xfa` memory carve-out, `0x0f9` settings, `0x102` (libObj.so)

- `FUN_001fbaf0`: `u64 base = Backup_read_8Byte(0xfa00a3)` (@`0x1fbaf8`),
  `u64 len = Backup_read_8Byte(0xfa00a4)` (@`0x1fbb1c`); sanity-ranges the base, opens
  `/dev/mem`, `mmap`s `len` bytes at the aligned base and `memset(base, 0x5a, len)`. So subsystem
  `0xfa` holds a **physical address + size pair** for a scrubbed memory region; which region
  (HYPOTHESIS: some camera/secure carve-out) is not named anywhere.
- `0x0f9`: all four `Backup_read_4Byte` sites in libObj (thunk `0x157f00`) live in one
  computed-jump state machine in the GPS region (call sites `0x29da5c`→`0xf9039f`,
  `0x29da6c`→`0xf903a0`, `0x29daac`→`0xf90156`, `0x29dac4`→`0xf90089`, plus `0xf9014e` via the
  shared `mov w0,#0x14e; b` tail @`0x29dab4–68`). Two of the values are combined by
  `FUN_0029b3e0` with `[ctx+0x2c]`. Payload unknown → HYPOTHESIS-free "unresolved".
- `0x102`: `FUN_001e9600@0x1e96f0` reads `0x1020000` (8 B); `FUN_001e95e8` reads
  `0x1020001` (16 B into global `DAT_003d1080`), called from `FUN_001e9c50`, `FUN_001ea04c`,
  `FUN_001ea2a0` and one function-pointer table slot (`INDIRECTION` from `0x2f8288`). No strings
  name it → payload unresolved.

## B.8 Unresolved / dynamic ids

- **Generic helpers**: `FUN_002bc53c` (@`0x2bc578`) and `FUN_002bc600` (@`0x2bc64c`) call
  `Backup_get_datasize` with ids taken from a runtime table (@`0x2f51b8`), then `Backup_nread` —
  a table-driven path, so the immediate-based inventory above is a lower bound on live ids.
- **Thunk `0x00156410`** (libObj): one call passes `0x910040` (subsystem `0x91`, item `0x40`);
  the thunk's import identity was not resolved. Recorded, not attributed.
- **Secondary thunk group** `0x003d6xxx` (e.g. sync thunk `0x3d6718`) has no code xrefs — reached
  only via `COMPUTED_CALL`/DATA from the primary group; counted as duplicates, not new callers.
- `Backup_read` (thunk `0x157850`) has **167** xrefs in libObj — far more read sites than the
  write sites enumerated above; reads of unenumerated items can therefore exist. The write-side
  list (`Backup_write`/`Backup_nread`/`read_4/8Byte` = 114+9+4+2 refs, all windows examined) is the
  authoritative id inventory; the read side is sampled.

## C. Scope / safety

- This document records **identifiers and mechanism only**: subsystem/item numbers, function
  addresses, message layout, accessor names. **No stored bytes, no key material, no plaintext
  payloads are reproduced anywhere here** — for the SSH host key only its *length bound* (600 B)
  and restore *path* are given; for SecVault only wrapper framing (magic, header size, attrs),
  never contents. Nothing here is needed to *read* the store; the cipher/format analysis lives in
  `backup-map.md`, which likewise contains no key material.
- The device and firmware are the user's own; analysis was static (Ghidra + on-disk filesystem
  images), read-only against the Ghidra projects — no functions were renamed, no saves performed.
- Item payloads marked HYPOTHESIS are caller-context inferences; consumers should treat §B rows
  as a starting map, not ground truth.

## How this was checked

- **§A**: `mcp ghidra_extra` → `decompile_function /libBackupManager.so` by address:
  `writeBackup` @0x10135c, `readBackupDecryption` @0x101594, `BkDmn_write` @0x10128c; plus the
  descriptor-table dump (`read_bytes libsecvlt.so 0x101c30 128`) recorded in `secvaultslots-map.md` §A.
- **Thunk resolution**: `search_symbols_by_name "Backup"` per binary (PLT thunks), then
  `list_xrefs` on each thunk address (xrefs on bare import names fail — the local thunks carry
  them). Thunks used: libObj `write 0x158570`, `nread 0x158010`, `read 0x157850`,
  `get_datasize 0x157350`, `read_4Byte 0x157f00`, `read_8Byte 0x157e00`, `sync 0x157300`;
  libsecvlt `0x100dc0/0x100d90/0x100d20/0x100d10`; libInfraSSHManager `0x106d70/0x106c70/0x1069e0`.
- **Id extraction**: `search_code` literal mode found whole-function hits but truncated previews,
  so every write/read call site was read with `disassemble` windows (~10–18 instructions ending at
  the thunk `bl`), decoding `mov wX,#imm; movk wX,#imm2,LSL#16` operand pairs. All §B addresses
  are those call sites (this session unless noted "prior session", where the same method was used).
- **Full decompiles this session**: `FUN_0029ec1c` (0x2cf0014, complete), `FUN_001fbaf0`
  (0xfa00a3/a4, complete), SSH trio `0x10885c/0x1097e8/0x1089a4`, `FUN_00101324/0x101458/0x101380`
  (prior session), `SECVLT_sync 0x101990`.
- **Coverage bounds**: `list_imports "Backup"` = empty for `libsencore.so`, `sen.elf`,
  `libIMDB.so` (ghidra_svc) and `adjstctl.elf`, `libtestcmd.so` (ghidra_svctools); `list_xrefs`
  sweeps of the read-side thunks (`read_4Byte` 4 refs, `read_8Byte` 2 refs, `get_datasize` 12 refs
  — all examined; `read` 167 refs — sampled, see §B.8).
- Ghidra addresses are **virtual** (as-loaded), not file offsets; payload bytes were never read
  from the store (`/setting/Backup.bin` was not opened for this document).
