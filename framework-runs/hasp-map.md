# a7R V HASP License/Entitlement Store — Map

Static RE of the user's own Sony a7R V firmware (`/srv/a7rv/a7rv-fw/fs/a15`), for a public
write-up. Offsets, paths and mechanism only — **no key bytes, no license blobs, no firmware
bytes**. Ghidra addresses are virtual (module base = 0). Evidence: every claim cites the
Ghidra call + address actually run this session; inference is tagged **HYPOTHESIS**.

## A. The HASP store format

**File:** `/setting/.hasp` — a fixed **88-byte (0x58)** raw blob. No magic, no CRC visible in any
accessor. One implementation lives in `libObj.so`; `libsencore.so` contains a byte-identical
second copy (same function sizes via `readelf -Ws`: `Read_Hasp` 144 B, `Reset_Hasp` 200 B in both;
the error-string blob appears in both at file off 0x1de07e / 0x56a36).

**Accessors** (evidence: `decompile_function`, libObj.so):
- `Read_Hasp(buf)` @0x001ebd5c (libObj; libsencore copy @0x00114260):
  `open("/setting/.hasp", 0x101000)` = O_RDONLY|O_DSYNC|O_CLOEXEC → `read(fd, buf, 0x58)` →
  `close`. True **iff exactly 88 bytes** read, else `logrec(0xffffff81, "Hasp Read Failed")`.
  (Wrappers: FUN_001ece4c=open, FUN_001ecbb8=read, FUN_001ecb70=close, FUN_001eac70=logrec.)
- `Reset_Hasp()` @0x001ebc94 (libObj; libsencore copy @0x00114198):
  `open("/setting/.hasp", 0x101241)` = O_WRONLY|O_CREAT|O_TRUNC|O_DSYNC|O_CLOEXEC →
  `write(fd, <88 zero bytes>, 0x58)` → `fsync` (FUN_001ecc54) → close. Failure logs
  "Hasp Reset Failed". **Reset = zero-wipe in place, not unlink.** This is the backend of the
  `command001F` reset verb (HYPOTHESIS: matches already-mapped `command001F`; not re-run here).
- `Regist_HaspId(uint16 id)` — **defined only in libsencore.so** @0x001142f0 (readelf size 568):
  `access("/setting/.hasp", F_OK)`; if file absent → returns 1 (success, no store). Else
  `Read_Hasp` into an 88-byte stack buffer, append one entry at slot = buf[0], set timestamp +
  id, `DeviceIo::open("/setting/.hasp", 0x101241)` + `write(..., 0x58)` + close + `sync()`.
  If buf[0] ≥ 10: logs `"Hasp last_histroy data error.%d"` and does not write.
  Write failure logs `"Hasp Write Failed"`.

**Layout** (all offsets from `Regist_HaspId` @0x001142f0 pseudocode; total = 8 + 10×8 = 88 = 0x58):

| Offset | Size | Field | Evidence |
|---|---|---|---|
| 0x00 | 1 B | `next_slot` ring index, valid 0–9 (after insert: +1, wraps 9→0). ≥10 → "last_histroy" error | `local_58[0]`, wrap code @0x114470s |
| 0x01–0x07 | 7 B | unused (zero after reset; never written by these functions) | Reset zeros all 0x58 |
| 0x08–0x57 | 10 × 8 B | entry ring, slot *i* at `0x08 + 8*i` | `slot*8 + 8` addressing |
| entry +0x00–0x01 | 2 B | **HASP id**, uint16 LE — written from `Regist_HaspId` param_1 | `*(undefined2 *)(buf + slot*8 + 8) = param_1` |
| entry +0x02 | 1 B | BCD year `% 100` | `buf[slot*8+0xa] = itoh(tm->tm_year % 100)` |
| entry +0x03 | 1 B | BCD month (tm_mon+1) | `itoh(tm->tm_mon + 1)` |
| entry +0x04 | 1 B | BCD day | `itoh(tm->tm_mday)` |
| entry +0x05 | 1 B | BCD hour | `itoh(tm->tm_hour)` |
| entry +0x06 | 1 B | BCD minute | `itoh(tm->tm_min)` |
| entry +0x07 | 1 B | 0x00 (reserved / terminator) | `buf[slot*8+0xf] = 0` |

Notes:
- Timestamp is camera wall-clock (`time()`/`localtime()`); if `localtime` fails, the 8 entry bytes
  are zeroed first and then id+terminator are written (timestamp left 0).
- `itoh()` = int→packed-decimal/BCD encode (HYPOTHESIS, by name + value ranges).
- The store is a **10-slot ring history log of (id, timestamp) check-ins** — "last_histroy"
  [sic] in the error string. It is *not* a key table; per-id gating (if any) must happen in
  readers of the blob (→ §B).
- The 88-byte block `command001F` returns is exactly `Read_Hasp`'s buffer — reconciled by size
  and by libObj exporting only `Read_Hasp`/`Reset_Hasp`.

## B. What it gates

**Bottom line found this session:** no in-firmware branch on `.hasp` **contents** was located.
The store behaves as a (id, timestamp) check-in **history** consumed by a factory/service channel,
the trace log, and exactly one direct-API module. Any per-feature gating decision is made
off-device. **HYPOTHESIS** (flagged below where inferred).

### B.1 Two access paths exist

1. **In-process file API** — `Read_Hasp` / `Reset_Hasp` (exported by `libObj.so`; private copies in
   `libsencore.so`; inlined copies in `sen.elf`). A firmware-wide ELF import scan
   (`readelf` over `fs/a15/{bin,lib,sbin,scenario}`): **`libpro00.so` is the only module anywhere
   that imports `Read_Hasp` or `Reset_Hasp`**; nothing imports `Regist_HaspId` / `registHaspId` /
   `tlog_set_hasp` (those are reached through internal function-pointer tables, not dynsym).
2. **Service channel** — adjcmd command **`/@HASP`**, handler `FUN_00111714` @0x00111714
   (libsencore.so, ghidra_svc, decompiled): request byte `param_1[0x28]`: `0x00` → read path
   (`FUN_00110994(1, 0, namebuf, &out, 0x58)`; response = 88 B at `param_1+0x1c`, length `0x58`
   written at `param_1+0x18`) — **this is the `command001F` block**; `0x80` → write path
   (`FUN_00110994(9, …)`). Path built by `FUN_00110898(buf, buf, 0, "/.hasp")` → `/setting/.hasp`.
   Handler is registered from dispatcher `FUN_00112630` (call @0x112850) + command table entry @0x1599c0.

### B.2 Who references the `/@HASP` command name

Files containing the literal **`/@HASP`** (definitive `grep -l '/@HASP'` over the binaries):
15 modules — `bin/adjstctl.elf` (factory CLI), `lib/libsencore.so` (the handler side, §B.1),
`lib/libJiritsu.so`, `lib/libGetLog.so`, `lib/libInfraAdjMedia.so`, and **all 10**
`scenario/AVBB_SCN_START/STOP_*.so` plugins. **False positives of the case-insensitive sweep:**
`lib/appFw.so`, `lib/libInfraRemote.so`, `lib/libInfraCrypt.so` match only
`iCrypt_Has{Private,Public}Key` / `hasProxyProfile`; `sbin/dhcpcd` on
`dhcp6_hasprefixdelegation`; `lib/libInfraNetworkCommon.so` on
`util::TaskRunner::hasPendingTask()`; `share/network/cert/RTMPcert.pem` on a random base64
sequence in the cert body (line 2374) — none have any HASP content. With these, the
firmware-wide case-insensitive `hasp` sweep (§ top of B) is fully resolved into real hits +
explained noise.
Caveat established this session: the name sits in an **adjcmd command-name table embedded
identically in every adjcmd client** — same neighbor sequence `GPIO_READ, TIMER, #@GET_LOG,
/@HASP, SSBI_MK_MODE, READ_SSBI, READ_NFLASHA8, ILOG_*` appears at file off 0x11622
(adjstctl.elf), 0x22212 (libJiritsu.so), 0x13d1a (AVBB_SCN_START_HDMI.so), 0x12c65
(AVBB_SCN_START_VIDEO.so) — identical ordering, different base. So a string hit proves
*channel availability*, not a per-feature call site; no individual client call site was
isolated. `libObj.so` and `sen.elf` contain **zero** `/@HASP` strings (file-API users only).

### B.3 Registration side = the sensor engine

`Regist_HaspId(uint16 id)` @0x001142f0 (libsencore) appends `(id, BCD timestamp)`; `sen.elf`
holds a byte-behaviour-identical inlined duplicate @0x004025d0 (fully disassembled, 140 instrs:
`access()` guard → `FUN_00402540` Read → entry write `strh w23,[buf+slot*8+8]` ← id comes in as
**first argument** → `open(0x101241)`/`write(0x58)`/`sync()`). Xrefs to 0x4025d0 are GOT 0x404158 +
data table 0x4045a8 + relocs only — **no direct `bl`**, i.e. dispatched via a plugin table. No
feature-name → id mapping table exists anywhere in the firmware (string + dynsym searches): the u16
ids are assigned by an out-of-band spec. **HYPOTHESIS:** ids enumerate factory/service operations
logged as check-ins, not product features.

### B.4 `libpro00.so` — the sole direct consumer

6,032-byte plugin; DT_NEEDED = libc/stdc++/pthread/m/dl/gcc/rt only (its `Read_Hasp`/`Reset_Hasp`
U N D s resolve from the global scope at `dlopen`); unique error strings "HASP Read Failed"@0xa7c,
"HASP Wrt Failed"@0xa8d. Since `Reset_Hasp` (zero-wipe) is the *only* write API it can import,
libpro00 reads and zero-wipes the store. **HYPOTHESIS:** provisioning / re-provisioning agent
("pro00"); its internal logic could not be disassembled here (no aarch64 binutils; gdb blocked by
approval gate), so this rests on imports + strings.

### B.5 Trace-log embedding (logging, not gating)

`tlog_set_hasp(u16)` @0x001132c4 stores the id in global `DAT_0016cfc0`; `tlog_update_file`
@0x00113788 copies that global into bytes 0–1 of every `StraceData` record written to the
StraceLog ring. The HASP id therefore rides along in the camera trace log — a service/diagnostic
consumer, not a gate.

### B.6 Negative results

- No module was found that parses entry bytes and branches on the id value (only consumer via file
  API is libpro00; adjcmd returns the raw blob to callers).
- `DWN_INIT_LICENSE_DATA` (factory command name; found in `adjstctl.elf`, `libGetLog.so`,
  `libInfraAdjMedia.so`, `libJiritsu.so`, `libsencore.so` + all 10 `AVBB_SCN_START/STOP_*.so` —
  same shared command table) is the counterpart **init-license** verb; see §C.
- No signature / MAC / CRC in any accessor ⇒ contents are forgeable in principle — consistent with
  telemetry/attestation rather than a security gate. **HYPOTHESIS.**

## C. Lifecycle

- **Absent file is a normal state.** `Regist_HaspId` @0x001142f0 does `access("/setting/.hasp",
  F_OK)` first and **returns success without creating anything** when the file is missing
  (pseudocode, §A); `Read_Hasp` just logs "Hasp Read Failed". The store only comes into existence
  through a write path.
- **Factory / provisioning creation.** The `/@HASP` adjcmd handler `FUN_00111714` sub-op `0x80`
  performs the write path (`FUN_00110994(9, …)` → `/setting/.hasp`) — i.e. a service-tool can
  write the whole 88-byte blob directly (evidence: handler pseudocode, §B.1). The factory verb
  **`DWN_INIT_LICENSE_DATA`** ("download init license data") lives in the same adjcmd command
  namespace (string pool @0x31184 in libsencore, adjacent to production commands like `RTC_RESET`;
  present in every adjcmd client's shared table — §B.6). **HYPOTHESIS:** `DWN_INIT_LICENSE_DATA`
  provisions/zero-inits the store via `Reset_Hasp`; not proven call-chained — the string is
  unlabeled data (`list_xrefs` on it: "Symbol not found"), and no in-libsencore `bl` to the
  internal `Reset_Hasp` copy exists (xrefs @0x114198: export/INDIRECTION 0x1579fc/DATA tables only).
- **Runtime append (check-in).** Each `Regist_HaspId(u16 id)` call appends `(id, BCD localtime)` at
  `buf[0]`, then increments/wraps the ring (9→0). A corrupted header (`buf[0] ≥ 10`) refuses the
  write and logs `"Hasp last_histroy data error.%d"`. Ring depth 10, oldest overwritten — a
  *last-seen* history, not a ledger.
- **Reset = in-place zero-wipe.** `Reset_Hasp` @0x001ebc94: `O_WRONLY|O_CREAT|O_TRUNC` +
  88 zero bytes + `fsync` — the file survives with all-zero content (never unlinked). After reset,
  `buf[0]=0` → ring restarts, so "factory-default" state is all-zeros, not file-absent.
- **Who can reset.** Imports scan (readelf, whole `fs/a15`): only `libpro00.so` imports
  `Reset_Hasp`; `libsencore`'s own copy has no internal caller (xrefs above) ⇒ a zero-wipe happens
  only from that dlopen'd plugin, or from an external `/@HASP` 0x80 write. **HYPOTHESIS:** the
  factory flow is *tool → `/@HASP`/`DWN_INIT_LICENSE_DATA` → libsencore → store*, with libpro00 as
  the in-camera provisioning helper.
- **Dispatch, not direct call.** The registration chain is
  `WorkerThreadManager::registHaspId(int)` @0x0010c190 (decompiled: tail-calls) → thunk
  `Regist_HaspId` @0x0010a910 (decompiled) → body @0x001142f0. The class method itself has **no
  in-module callers** — `list_xrefs` (mangled `_ZN19WorkerThreadManager12registHaspIdEi`):
  Entry Point + INDIRECTION 0x15742c + DATA 0x158100 / 0x16b618 (a method-table slot) only;
  likewise sen.elf's duplicate @0x004025d0 has GOT/data xrefs only (0x404158 / 0x4045a8).
  So check-ins are triggered through WorkerThreadManager method dispatch from elsewhere —
  exact trigger not pinned down (HYPOTHESIS: sensor-engine / worker init path).
- **Integrity: none.** No magic, version, CRC, MAC or signature in any accessor (all decompiled
  this session: §A) — plain blob; any writer of `/setting` can forge entries.

## D. Scope and safety

- **Owned device, static analysis only.** Everything here comes from reading the user's own
  firmware dump under `/srv/a7rv/a7rv-fw/fs/a15` with Ghidra (read-only projects) and binutils
  `readelf`/`strings`. Nothing was run on the camera; no device write was performed.
- **No secrets reproduced.** By construction there are none to reproduce: the store holds only
  `(uint16 id, BCD timestamp)` pairs — no keys, no license payloads (§A). No key bytes, blob
  contents, or firmware bytes are printed in this document.
- **What touching the store would mean (documentation, not recommendation):** the file is plain
  and unauthenticated, so a write forges the check-in history; `Reset_Hasp` / `/@HASP` op `0x80`
  are destructive — a single zero-wipe with immediate `fsync`, one blob, no backup/shadow copy in
  any accessor (§A), so recovery is re-provisioning or nothing.
- **What this document is not:** an unlock guide. No cryptographic material exists anywhere on the
  HASP path (all accessors decompiled), so nothing here "defeats" a protection — the store is
  telemetry/attestation; any real entitlement decision belongs to Sony factory/service tooling
  that consumes the check-ins.
- **Limits:** `libpro00.so` never entered Ghidra (import permission denied) — its role rests on
  imports + strings (§B.4); pointer-table dispatch (sen.elf 0x404158/0x4045a8, libsencore tables)
  was not fully chased; everything here is static-evidence-bounded and the doc says so per-claim.

## How this was checked

All on 2026-11-14. Ghidra addresses virtual (module base 0). Gate first: `list_project_binaries`
(ghidra_extra + ghidra_svc) and a `Read_Hasp` decompile before any analysis.

**Decompiled (Ghidra):**

| Function | Binary / project | Address |
|---|---|---|
| `Read_Hasp` (+ inline callee pseudocode: FUN_001ece4c open / FUN_001ecbb8 read / FUN_001ecb70 close / FUN_001eac70 logrec) | libObj.so / ghidra_extra | 0x001ebd5c |
| `Reset_Hasp` (+ FUN_001ecc54 fsync) | libObj.so / ghidra_extra | 0x001ebc94 |
| `Read_Hasp` copy | libsencore.so / ghidra_svc | 0x00114260 |
| `Reset_Hasp` copy | libsencore.so / ghidra_svc | 0x00114198 |
| `Regist_HaspId` | libsencore.so / ghidra_svc | 0x001142f0 |
| `Regist_HaspId` thunk | libsencore.so / ghidra_svc | 0x0010a910 |
| `WorkerThreadManager::registHaspId(int)` | libsencore.so / ghidra_svc | 0x0010c190 |
| `/@HASP` adjcmd handler FUN_00111714 | libsencore.so / ghidra_svc | 0x00111714 |
| `tlog_set_hasp` | libsencore.so / ghidra_svc | 0x001132c4 |
| `tlog_update_file` | libsencore.so / ghidra_svc | 0x00113788 |
| `Read_Hasp` inlined copy FUN_00402540 | sen.elf / ghidra_svc | 0x00402540 |
| `Reset_Hasp` inlined copy FUN_00402478 | sen.elf / ghidra_svc | 0x00402478 |

**Disassembled:** sen.elf 0x004025d0–0x004027fc (140 instrs; inlined `Regist` duplicate — no
Ghidra function symbol there, `decompile_function` → "not found", `disassemble` used instead).

**Raw reads / strings:** `read_bytes` sen.elf .rodata @0x403e40 (+0x88, error strings only — no
blob/key data read or printed anywhere this session); `search_strings` libsencore command-name
pools @0x27252 / 0x31184 / 0x469ea.

**Xrefs / metadata:** `list_xrefs` on `Reset_Hasp`@0x114198 (no internal callers), thunk
0x10a910, `registHaspId` 0x10c190, sen.elf GOT/data entries (§B.3);
`search_symbols_by_name` `registHaspId`; `readelf -Ws` (function sizes), `readelf -d`
(libpro00.so DT_NEEDED + UND list) and a firmware-wide `readelf` UND scan for
`Read_Hasp`/`Reset_Hasp`/`Regist_HaspId`/`tlog_set_hasp`; `grep -rila` + `strings -a -t x`
context windows over all modules in `fs/a15`.

**Blocked / unavailable (disclosed):** `import_binary` libpro00.so → "permissions not granted"
(not retried); `gdb` → "requires approval"; no aarch64 objdump/r2 on this host (x86 binutils only).
