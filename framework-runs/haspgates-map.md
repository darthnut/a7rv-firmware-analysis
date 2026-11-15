# a7R V HASP id → feature gate map

Static reverse-engineering of the user's own Sony a7R V firmware (a15 userspace), cross-referencing
the `/setting/.hasp` entitlement store (`gptoss-out/hasp-map.md`) against the code that actually
reads HASP ids. Mechanism and offsets only — **no license/key bytes and no firmware binary content**.
This documents the camera reading its **own** entitlements; it is not a bypass.

STATUS: complete. Headline result: **no branch on any HASP id value exists in any indexed
firmware module.** Every in-firmware path either *appends* an id (write side) or *transports* the
whole 88-byte blob to an external service tool. The id→feature dictionary below is therefore a
dictionary of **id pathways**, and the feature-gating, where it exists, is enforced **outside** the
firmware (service/factory harness side).

All addresses are Ghidra virtual addresses, per binary. Cited tool = Ghidra MCP call unless noted.

## A. The HASP id dictionary

**A.0 Key finding — no id constants.** A literal pseudocode search (`search_code`, case variants
`hasp`/`Hasp`/`HASP`) across every indexed binary returns only accessor/wrapper functions; no
`switch`/`cmp` on an id constant appears anywhere (§A.3 table). `Regist_HaspId` writes
`*(u16 *)(buf + idx*8 + 8) = param_1` — the id is always caller-supplied
(`search_code` literal `Regist_HaspId`, libsencore import @`0x001142f0`). So HASP ids are
**runtime data**, arriving via the five pathways below.

### A.1 The id pathways (read sites)

| # | Site | Binary @ addr | Where the id value comes from |
|---|------|---------------|-------------------------------|
| 1 | `tlog_set_hasp(int)` | libsencore @`0x001132c4` | Sole caller `NinThread` @`0x0010bbfc` (call @`0x0010beac`): in KICK handlers (cmd 5/7) `xxkick(...)` runs an external factory op and the id = **u16 LE of response bytes 0–1** (`if (1 < local_658) uVar4 = CONCAT11(local_610, local_60f); … tlog_set_hasp(uVar4)`). `decompile_function 0010beac`. |
| 2 | `WorkerThreadManager::registHaspId(int)` | libsencore @`0x0010c190` (thunk @`0x0010a910`) | Tail-calls `Regist_HaspId` @`0x001142f0`. `list_xrefs 0010c190`: Entry Point + INDIRECTION `0x15742c` + method-table slots `0x158100`, `0x16b618` — reachable **only** via WorkerThreadManager method dispatch; the int is a dispatch argument, no constant call site exists in the library. |
| 3 | `command001F` (RPC verb 0x1F) | libpro00 @`0x001009a4` (exported; cmd-table slot `0x100b20`) | `decompile_function 001009a4` + `list_xrefs 001009a4`; sole "Hasp" reference in libpro00 (`search_code` literal = 1 function). op byte `0x00` → `operator_new(0x58)`, `Read_Hasp()`, returns the **entire 88-byte blob** to the RPC client (fail → `"HASP Read Failed"`, status `0x82`); op `0x80` → `Reset_Hasp()` (fail → `"HASP Wrt Failed"`); else `"InvalidParameter!"`. Never inspects ids. |
| 4 | `/@HASP` adjcmd channel | libsencore handler `FUN_00111714` (per hasp-map.md) | ops 0x00 read / 0x80 write via `FUN_00110994` (`decompile_function 00110994`): a **generic file-operation backend** (switch op: mkdir/access/read/write/size/remove/rmdir/fgetc) — zero HASP-specific logic; the blob is exposed as raw file read/write. |
| 5 | sen.elf private copies | Read `FUN_00402540`, Reset `FUN_00402478`; Regist duplicate region `0x4025d0`–`0x4027fc` | `list_xrefs FUN_00402540`: sole code caller = UNCONDITIONAL_CALL from `0x40260c`, inside the un-symbolized Regist duplicate. `disassemble 004025f0 ×24`: `bl 0x4019b0` (BCD time), `bl 0x402540` (read), `ldrb w0,[x29,#0x88]; cmp w0,#0x9; b.le …` = ring-index validity check + append — write side only, no id gate. |

### A.2 Store accessors (definitions, for cross-ref)

- libObj.so exports: `Read_Hasp` @`0x001ebd5c`, `Reset_Hasp` @`0x001ebc94` (impls), thunk @`0x00157bd0`.
  `search_code` literal `Hasp` over libObj = **2 functions** (the accessors); thunk's sole caller
  `0x001ebe28` is not inside any function → no internal libObj consumer.
- libsencore private copies: Read @`0x00114260` (sole caller = `Regist_HaspId` @`0x11432c`),
  Reset @`0x00114198` — internal use is append-support only.
- `tlog_set_hasp` global: `list_xrefs 0016cfc0` → exactly one WRITE (`tlog_set_hasp` @`0x001132c8`,
  body `DAT_0016cfc0 = (short)param_1`) and one READ (`tlog_update_file` @`0x001137d8`), which stamps
  the id into bytes 0–1 of every StraceData record (hasp-map.md). Telemetry only.

### A.3 Negative sweep (where HASP is *not*)

`search_code` literal, case variants, per indexed binary:

| Binary (Ghidra project) | hasp-referencing functions |
|---|---|
| libsencore.so (svc) | accessors/wrappers only (`Read_Hasp`, `Reset_Hasp`, `Regist_HaspId`, `registHaspId`, `tlog_set_hasp`) |
| libObj.so (extra) | 2 — accessors only |
| sen.elf (svc) | 2 — the two copies |
| libpro00.so (plugins, `/libpro00.so-1a073e`) | 1 — `command001F` |
| libIMDB.so, libInfraSSHManager.so (svc) | 0 |
| crypter.elf, libBackupManager.so (extra) | 0 |
| adjstctl.elf, libtestcmd.so, libosal_uipc.so (svctools) | 0 |
| av-cam.bin (avcam, 10 739 funcs), cpapp-b.bin (cpapp, 53 843 funcs) | 0 |

On-disk (no Ghidra), `/srv/a7rv/a7rv-fw/fs/a15/`:

- `nm -D --undefined-only lib/*.so bin/*` → **exactly one module** imports `Read_Hasp`/`Reset_Hasp`:
  libpro00.so. (`iCrypt_HasPrivateKey`/`iCrypt_HasPublicKey` hits are crypter "Has…" symbols,
  unrelated.) Same sweep over `scenario/*.so`: 0 Hasp imports.
- `grep -ril hasp` lib/+bin+scenario → true HASP holders are only: libObj, libsencore, sen.elf,
  libpro00 (implementations) + libJiritsu, libGetLog, libInfraAdjMedia, adjstctl, 10 scenario
  plugins (all four/ten carry only the string `/@HASP`). **appFw.so** (97 MB, UI/app layer, not in
  Ghidra): strings grep → only `iCrypt_HasPrivateKey`/`iCrypt_HasPublicKey` — substring artifact.
  The application layer has **zero** HASP awareness.
- `grep -rl '/@HASP' fs/a15` → adjstctl.elf, libGetLog, libInfraAdjMedia, libJiritsu, libsencore,
  and `AVBB_SCN_{START,STOP}_{HDMI,HDMI_INPUT,HDMI_INPUT_SUB,HDMI_SUB,PANELEVF,VIDEO}.so`.
  In the scenario plugins the string sits in a **factory-test verb table**, adjacent to
  `@TST_MODE`, `SELECT_LSI`, `TERM_MODE`, `GPIO_READ`, `TIMER`, `#@GET_LOG`, `SSBI_MK_MODE`,
  `READ_SSBI`, `READ_NFLASHA8`, `ILOG_WRITE/READ/DEL` (`strings -a AVBB_SCN_START_HDMI.so |
  grep -i -B6 -A6 hasp`; identical table in AVBB_SCN_START_VIDEO.so, START_HDMI_INPUT, STOP_*).

## B. id → feature mappings

**No firmware feature gate found.** No indexed module reads a HASP id and changes behavior on its
value — the honest id→feature table is therefore "id read here, effect (if any) decided off-device",
per pathway:

| id source | What the firmware does with it | Feature gated |
|---|---|---|
| xxkick response u16 → `tlog_set_hasp` | Tags the process's StraceData trace records (bytes 0–1) with the id (A.1#1, A.2) | **None in-firmware** — telemetry tag identifying which factory op ran; resolved mechanism, no gate. |
| `registHaspId` dispatch arg → `Regist_HaspId` | Appends `(u16 id, BCD localtime)` record to `/setting/.hasp` ring (max 10, else `"Hasp last_histroy data error"`) | **HYPOTHESIS:** id enumerates a completed factory/service operation (check-in log); meaning assigned by the external tool that later reads the store. Not resolvable statically — no in-firmware consumer. |
| libpro00 `command001F` op 0x00 | Ships the entire 88-byte blob to the RPC client (service app protocol); op 0x80 wipes it | Ids are read **by the external tool**, not here — effect not resolvable statically from firmware. |
| `/@HASP` verb in AVBB factory scenarios + adjstctl/libJiritsu/libGetLog/libInfraAdjMedia | Blob available to the factory-test command vocabulary during board-inspection scenarios (HDMI out/in, panel EVF, video START/STOP) | **HYPOTHESIS:** pass/fail checks (which ids must be present) live in the factory harness / scenario data, not in firmware constants; scenario modules import no Hasp symbol and their verb table treats `/@HASP` like any other test command. |
| `DWN_INIT_LICENSE_DATA` factory write verb (hasp-map.md) | Write-side path only | 0 literal hits in pseudocode (`search_code`, libsencore) — factory-side verb; no gate. |

**Overall:** this upgrades the hasp-map.md hypothesis to an evidenced finding *for the indexed
surface* (≈65 k functions incl. both coprocessor binaries and the app-side protocol lib): the
firmware is a **recorder/transport** of HASP ids; entitlement decisions — if any are enforced for
this product — are made by Sony service/factory tools after reading the store or the trace logs.
No menu, mode, or product feature in any indexed module branches on a HASP id. (Not
resolvable: the 97 MB appFw.so at function level — but it contains no HASP string at all, so it
cannot reference the store by name; and the factory harness itself, which is not in the firmware.)

## C. Scope and safety

- **Mechanism/offsets only; no license bytes.** This document records function addresses, call
  graphs, and control flow. No content of `/setting/.hasp`, no key material, and no firmware
  binary content is reproduced here or was needed for the analysis.
- **Owned device.** Analysis was performed on the user's own extracted a7R V firmware image
  (`/srv/a7rv/a7rv-fw/`), read-only.
- **This is the camera reading its own entitlements, not a bypass.** Every site documented is
  stock firmware accessing its own store through its own APIs; nothing here modifies, forges, or
  bypasses an entitlement check — and per §B the firmware itself performs no such check on id
  values.
- Ghidra use was read-only (decompile/xref/search); no binaries were imported, renamed, or saved.

## How this was checked

Ghidra MCP projects queried (2026-11-14): `ghidra_svc` (`/libsencore.so`, `/sen.elf`,
`/libIMDB.so`, `/libInfraSSHManager.so`), `ghidra_extra` (`/libObj.so`, `/crypter.elf`,
`/libBackupManager.so`), `ghidra_plugins` (`/libpro00.so-1a073e`), `ghidra_svctools`
(`/adjstctl.elf`, `/libtestcmd.so`, `/libosal_uipc.so`), `ghidra_avcam` (`/av-cam.bin`),
`ghidra_cpapp` (`/cpapp-b.bin`). All functions cited above were reached by `decompile_function`
**by address** (or `search_code` literal → address) and cross-checked with `list_xrefs`;
xref targets given as bare hex are Ghidra virtual addresses.

Method: enumerate consumers (`list_xrefs`/`search_symbols_by_name` on `Read_Hasp`/`Reset_Hasp`/
`Regist_HaspId`/`registHaspId`/`tlog_set_hasp`), enumerate branch sites (`search_code` literal
`hasp`/`Hasp`/`HASP` per binary), decompile each consumer, and sweep the remainder on disk
(`nm -D`, `strings`, `grep`).

Caveats:
- **No AArch64 binutils** on this host (`objdump --info` has no aarch64 target), so binaries not in
  Ghidra (scenario plugins, libJiritsu, libGetLog, libInfraAdjMedia, libInfraCrypt, appFw.so) got
  string/symbol-level analysis only.
- `search_code` literal matching appears case-sensitive → each binary was searched under
  `hasp`, `Hasp`, and `HASP`.
- libpro00.so **is** available in the `ghidra_plugins` Ghidra project as `/libpro00.so-1a073e`
  (correction to hasp-map.md, which could not import it) — §A.1#3 is real decompiled code, not
  strings inference.
- libObj thunk `0x00157bd0`'s only caller (`0x001ebe28`) lies in an unanalyzed region
  (`decompile_function` → no function); treated as no internal consumer, consistent with the
  libObj literal-search result (2 functions).
- Odd-address DATA xrefs to imports are relocation entries, not calls; only PLT/thunk and
  8-aligned table slots were followed.
- Deliverable path note: task spec said `/srv/gptoss-out/`; the writable sandbox root is
  `/srv/a7rv/`, so the file lives at `/srv/a7rv/gptoss-out/haspgates-map.md` (same relative
  location as the prior `hasp-map.md`).
- Unresolved by design: meaning of specific id values (assigned by external service/factory tools,
  not present in firmware); factory-harness logic (not part of the image).
