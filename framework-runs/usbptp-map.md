# a7R V USB / PC-Remote (PTP) command surface — static map (Sony a7R V firmware)

Static RE of the user's **own** a7R V firmware, for a public write-up. Offsets and mechanism only;
no firmware bytes reproduced. Ghidra addresses are **virtual** (per-image load base noted).
Evidence tags: *observed* = tool output this session; *HYPOTHESIS* = inference, labeled as such.

## A. The PTP responder — where it lives, how opcodes dispatch

**Location (observed).** The PTP/PC-Remote responder is **not** in the coprocessor images
(`cpapp-b.bin`, `av-cam.bin` contain no PTP/SDIO/OperationCode strings — Ghidra
`search_strings` hits nothing relevant in either). It lives in the **main-SoC AArch64 Linux
userspace (`fs/a15`)** plus one kernel gadget module:

```
USB host
  └─ kmod usbg_stillimage.ko          "USB Still Image Class function driver" (SICD)
       /dev/usb/sicd_core | sicd_data | sicd_event
  └─ libInfraPtpControl.so            gadget FSM + transport threads (sole consumer of sicd_*)
  └─ libInfraRemote.so                per-operation handlers + opcode→handler dispatcher
       └─ libptp.so                   PTP packet codec + session FSM
  (gadget start/stop: libUsbControl.so; host daemon: im.elf via libIMDB.so)
```

**1. Kernel transport — `fs/a15/kmod/usbg_stillimage.ko`** (*observed*, `strings`):
banner "USB Still Image Class function driver"; ioctls `sicd_core_ioctl` / `sicd_data_ioctl`
(with ioctl magic/sequence validation), event channel `sicd_event_open/release/write`; TX via
`usb_ep_queue` with log strings `SICD data send (Bulk-in)`, `SICD event send (Int.-in)`,
`ptp header send error!`, `ptp response send error!`. It creates the three device nodes
`/dev/usb/sicd_core`, `/dev/usb/sicd_data`, `/dev/usb/sicd_event` (node names appear in
userspace, see below). So the kernel side is a classic PTP-style bulk-in/bulk-out/int-in
gadget exported to userspace over ioctls — no opcode logic in the kernel.

**2. Transport/FSM userspace — `fs/a15/lib/libInfraPtpControl.so`** (*observed*):
the **only** userspace object in the whole `fs/a15` tree containing the strings
`/dev/usb/sicd_core|sicd_data|sicd_event` (`grep -la sicd_data lib/*.so bin/*` → this file
alone). Dynamic symbols: `PtptMainThread`, `PtptConnMgrThread`
(`procWaitInitEvent`, `sendResponseForInitCommandRequest`, `respondInitCommandAck`,
`sendPairingDeviceDetection`), `PtptEvtThread`, plus an IP-remote twin
(`PtptIpRemote`, `PtptSocketContainer`, `PTPT_open_remote`,
`PTPT_set_pairing_mode_ip_remote`) and `usb_still_unregister_gadget`. `readelf -d` NEEDED:
`libosal_uipc.so`, `libosal_utm.so`, `libbkdmn.so` — it links **neither** `libptp.so` nor
`libInfraRemote.so`, so it hands frames on via messages, not direct calls. Gadget power/
lifecycle is a separate FSM in `libUsbControl.so` (`UsbIfWrapper::StartGadget(int,int)`,
`MSGID_START/STOP_GADGET_CMD`, `/dev/usb/buspwric`, `/dev/usb/portmon`).

**3. PTP codec + session FSM — `fs/a15/lib/libptp.so`** (*observed*, `readelf --dyn-syms`):
packet layer `ptp_check_cmd_header_packet`, `ptp_get_u8/16/32/64`,
`ptp_make_res_packet_noparam/_params`, `ptp_make_dat_header_packet`, `ptp_make_evt_packet`;
worker FSM `ptpm_*` (`ptpm_act_cmd_recvd`, `ptpm_act_cmd_recvd_with_reset`,
`ptpm_act_dat_rx_recvd`, `ptpm_exec_cmd_worker`, `ptpm_recv_message`, `ptpm_get_state`,
`ptpm_register_upper_cb`, `ptpm_store_op_info`, …) — a state machine that turns a received
container into a `PTPW_OP_INFO` and calls an upper callback; standard-operation wrappers
`ptpw_cmd_OpenSession/CloseSession/GetDeviceInfo/GetStorageIDs/GetStorageInfo/
GetObjectHandles/GetNumObjects/GetObjectInfo/GetObject/GetPartialObject/GetThumb` with
matching `ptpw_res_*`; supported-list writers `put_supported_op_codes/_num`,
`put_supported_ofc_codes/_num`, `put_supported_evt_codes/_num`; `PTP_init`, `PTP_send_event`.

**4. The opcode→handler table — `fs/a15/lib/libInfraRemote.so`** (*observed*,
`readelf --dyn-syms`, `readelf -r`). This is the real responder: ~50 vendor operation
classes `MrpwSDIO<Op>` (516 matching dynamic symbols), each a subclass of
`MrpwOperationsBase`, whose interface is the dispatch contract:

- `MrpwOperationsBase::Init(unsigned short opCode, char* name, int, unsigned char)`;
  `GetOperationCode()`, `GetOperationName()`, `GetDirection()`, `GetBridgeEnable()`,
  `IsValidOutsideSession()`, `IsActivated(unsigned session)`;
  per-op 3-phase handlers `CommandFunction(const PTPW_OP_INFO*, const void*, int)`,
  `DataFunction(const PTPW_OP_INFO*, void*, unsigned, int*, int*)`,
  `ResponseFunction(const PTPW_OP_INFO*, void*, unsigned, int*)`.
- Dispatcher singleton `MrpwOperationsManager`: `Get()`, `Init()/Fin()`, `EntryList()`,
  `ClearOperationTable()`, and the same `CommandFunction/DataFunction/ResponseFunction`
  triple — the facade that receives a command and forwards to the registered op object.
- **The table itself is a runtime `std::map<unsigned short, MrpwOperationsBase*>`** (the
  mangled instantiations `std::map<unsigned short, MrpwOperationsBase*>::operator[]` and
  `_Rb_tree<...,unsigned short...>::find/insert` are imported), keyed by the 16-bit PTP
  OperationCode. Four registrar classes populate it, all with the signature
  `Entry(std::map<u16,MrpwOperationsBase*>&, u8, u8, char)`:
  `MrpwOperationCodeManager`, `MrpwOperationCodeEntryManager`,
  `MrpwDebugOperationEntryManager`, and `MrpwVendorExtensionOperationEntryManager`
  (+ `makeInstance(int)`) — i.e. separate namespaces of codes (standard / vendor
  extension / debug) register into one op-code map.
- Self-registration is static: `.init_array` at ELF vaddr `0x144168` (size `0xa0` =
  20 constructors), and `.data.rel.ro` (vaddr `0x144218`) holds **513 relocations**
  (`readelf -r`, `R_AARCH64_ABS64` → `_ZTI/_ZTS…MrpwSDIO…`) — the per-op static objects
  and their vtables/typeinfo. (libInfraRemote.so is a PIE .so; add its runtime load base.)
- Session/activation gating lives in `MrpwProtocolManager`: per-session
  `std::map<unsigned, SessionStateData>`, `IsOperationCodeActivated(u16, u32 session)`,
  `openSession/closeSession`, `AuthSeqConnect/AuthSeqCheckVersion/AuthSeqGetExtDeviceInfo/
  ExecAuthSequence`, `SendRemoteAuthenticationEvt`, version negotiation
  (`IsInitiatorVersionSupported`, `GetVendorCodeVersion`, static `s_VendorCodeVersion`).
  So an opcode is only executable after the Sony auth/connect sequence for that session.

**Operation surface (observed class names, representative).**
`MrpwSDIOConnect`, `OpenSession`, `PtpOperation`, `ControlDevice`,
`GetExtDeviceProp` / `GetExtDevicePropValue` / `SetExtDevicePropValue`, `GetDeviceRegInfo`,
`GetVenderCodeVersion`, `SetFirmwareUpdateMode`, `RequestFirmwareUpdateCheck`,
`ExecuteEFraming`, `ControlSynchronizedRelease`, `GetContentListProtocolBuffers`, … (~50).
Vendor *parameter* names survive as strings: `PARAMID_RAW_FILE_MEM_OFFSET_LIST`,
`PARAMID_JPG_FILE_MEM_OFFSET_LIST`, `PARAMID_HEIF_FILE_MEM_OFFSET_LIST`,
`EVENT_ID_SET_MEDIA_REMAIN_CMD`, `EVENT_ID_SET_CONTENT_TRANSFER_MODE`; debug logs show the
conversion bookkeeping (`[RemotePcWorker]Add vendor ope %d, ptp_num=%d conv_num=%d`,
`Add standard event num=%d vendor event num=%d mtp event num=%d`).

**Sony vendor opcode values.** Not resolvable from this image: the numeric codes are baked
into the static registrars (need disassembly of the `.init_array` ctor bodies).
`libInfraPtpExtCmd.so` (35 KB, classes `PtpExtCmd::Service/Pipe`, `MSGID_EXTCMD_*`) reads an
on-target data file **`ptpExt.map`** which almost certainly is the host-visible extension
map, but that file is **absent from the extracted fs** (*observed*: not found under
`fs/a15`). **HYPOTHESIS:** `ptpExt.map` enumerates the vendor opcode ↔ handler mapping
consumed by the ExtCmd service.

**Boundary.** `libInfraRemote.so`, `libptp.so` and `libInfraPtpControl.so` are **not
imported into any Ghidra project** available here, and importing is a write operation the
read-only tool constraint forbids. Therefore the "decompile one handler by address" step of
the gate was not possible this session; everything in this section is ELF-symbol,
relocation and string evidence (commands listed in the footer), which is enough to fix the
responder's location, the dispatch data structure, and the registration mechanism, but not
per-opcode values.

## B. The bridge to the FW command table (0x40xx / 0x78xxxx)

The 0x40xx SET_ table (TABLE A, 306 entries) and the 0x78xxxx property table (TABLE B) live
on the **coprocessor** image `cpapp-b.bin` (file `0xFF6E4C`–`0xFF8FE4`; **VA = file +
0x108000**, so TABLE A at VA `0x10FF6E4C`) — see `gptoss-out/cpappcmd-map.md`. The USB/PTP
responder lives on the **a15 Linux core**. The bridge therefore crosses a processor
boundary, and the only observed inter-processor plumbing between them is **uIPC**:

**a15 side (observed).**
- The `MrpwSDIO` handlers do not call a command API directly; `libInfraRemote.so` imports
  the MWF/UFW object-message API: `MWF::ObjMsg::ObjMsg(unsigned, unsigned)`,
  `MWF::ObjMsg::GetMessageId()`, `UFW::MsgSender::SendEvt(MWF::ObjMsg*)`,
  `MWF::ParamStd_Template<u16/u32/int>::GetValue()`, `MWF::ParamArray_Template<…>`
  (`readelf --dyn-syms … UND`), and its log strings name the message ids it posts:
  `[InfraRemoteUsb] msg_id = MSGID_SET_CURRENT_CAMERA_STATUS_CMD`,
  `MSGID_SET_REMOTE_CONTROL_CMP`, `MSGID_SET_LIVE_VIEW_STATUS_CMD`, `MSGID_BUS_RESET_EVT` …
  plus one direct UIPC string (`[UTIMER]ERR! Recv Unknwon UIPC Msg from 0x%x`).
- `libInfraPtpControl.so` (the sicd owner) links `libosal_uipc.so` directly — the userspace
  half of the inter-processor channel (`/dev/uipc`, `osal_reg_sync_msg_queue_cb` @0x105b88
  in libosal_uipc.so; QID bit15=0 = kernel-routed — see `gptoss-out/osal-uipc-map.md`).
- The app model `appFw.so` (also loaded into `im.elf` via `libIMDB.so`, same process as the
  PTP infra) contains 350 `PID_*` strings (e.g. `PID_SET_DRIVE_MODE`) and calls
  `osal_snd_msg` (error strings `osal_snd_msg() err:%d`), i.e. the property/command layer
  that talks uIPC.

**cpapp side (observed, Ghidra `ghidra_cpapp` `/cpapp-b.bin`, `search_strings "uipc"`).**
Full receive stack present: `UIPCReceiver::Receiver::receive(0x%x)` @VA `0x21a4e8` and
`0x220b64`, `UIPCMsg::Receiver::receive(%d)` @VA `0x21ad60`, `UIPCSender::send` @VA
`0x21b2bc`, `**UIPC ERROR** … qid 0x%08x` @VA `0x0053b890`, header path string
`./common/../osal/osal_uipc.h` @VA `0x219fe8`, and
`CpApp::AppManager::getOsalUipcMsgNum(OSAL_ID)` @VA `0x169384`. Prior work (README
"Investigation 2") showed TABLE A dispatch is **runtime-registered** and that the concrete
non-PTP command path reaches it via UIPC queue messages
(`sens_adjCmd_init` → queue `0x3D025F` → dispatcher `FUN_00112630` in libsencore; relay posts
a 4-word sync msg to UIPC queue `0x80924220`).

**Name-level correspondence (observed, suggestive).** The a15 app layer addresses commands
by property id — `PID_SET_DRIVE_MODE` in `appFw.so` — while cpapp's TABLE A entry `0x4008`
logs `FW: SET_DRIVE_MODE`. The base names match 1:1 for the sampled entries.

**What is NOT established — boundary.** The concrete chain *PTP vendor opcode →
`MrpwSDIO<Op>::CommandFunction` → MWF/UFW message → UIPC QID → cpapp TABLE A/B entry* is
**not traced end-to-end** with disassembly in this session; no numeric opcode→0x40xx
translation table was located (the a15 side speaks symbolic `MSGID_*`/property names, the
cpapp side dispatches on numeric ids, and the two were never seen in the same binary).

> **HYPOTHESIS (labeled):** PC-Remote operations that mutate camera state are translated in
> a15 (MWF/UFW `ObjMsg` / `PID_*` property writes by `appFw.so`/`libInfraRemote.so`),
> sent over `/dev/uipc` to a registered cpapp queue, and land on the same runtime-registered
> dispatcher that serves TABLE A (0x40xx) / TABLE B (0x78xxxx) — the identical mechanism
> already traced for the sensor service channel. Supporting: `GetBridgeEnable()` flag on
> every `MrpwOperationsBase` operation (per-op "bridge to FW" switch), `osal_snd_msg` in
> the same process, `UIPC*Receiver` stack in cpapp, and `PID_SET_*` ↔ `FW: SET_*` name
> parity. Missing: the queue id(s) and the id translation site.

Note also that the *file* operations (`GetObject`, `GetPartialObject`, object handles,
storage — `ptpw_cmd_*`/`ptpw_objmgr_*`/`ptpw_fwrap_*` in libptp.so) terminate on the a15
filesystem and never need cpapp at all; only device-control/vendor ops plausibly bridge.

## C. Scope / safety

- Static map only of the host-reachable surface, on the owner's own device firmware. Mechanism
  description, not an exploit; no payload, no fuzzing guidance, no byte-for-byte image dumps.
  No offsets in this document are paired with crafted inputs, and no hardware was touched;
  nothing here is verified on-device.
- Cross-processor / other-image sides are out of scope except where cited as a boundary.
- One adjacent surface is deliberately **out of scope**: the separate service/test USB
  channel handled by `sen.elf`/`libsencore.so` (`NinThread` @VA `0x10BBFC`, 0x204-byte
  frames, `CmdDecode` verbs HOP/STEP/KICK with a SHA-256 challenge/key ladder, `xxstep`
  @VA `0x115C1C` — see `gptoss-out/keyservice-map.md`). It shares the uIPC plumbing but is
  not part of the PTP/PC-Remote surface and is not mapped further here.
- IP control (Imaging Edge over Wi-Fi) reaches the same `Ptpt*`/`MrpwSDIO` machinery via
  `PtptIpRemote`/`PTPT_open_remote` in `libInfraPtpControl.so`; only the USB path is
  in scope, and the IP path is named here solely to mark where the maps converge.

## How this was checked

All on the extracted firmware under `/srv/a7rv/a7rv-fw/fs/a15/` (ELF64 AArch64) and the
Ghidra MCP projects. Read-only tools only; no import/rename/save performed. No AArch64
binutils and no `c++filt` are available here, so names are quoted as raw mangled strings
plus `strings`. No function body was read whole.

**Ghidra (virtual addresses; per-image load base as noted):**
- `list_project_binaries` across all 7 projects (`ghidra_cpapp` → `/cpapp-b.bin`;
  `ghidra_avcam` → `/av-cam.bin`; `ghidra_svc` → `/libsencore.so`, `/sen.elf`, `/libIMDB.so`,
  `/libInfraSSHManager.so`; `ghidra_svctools` → `/adjstctl.elf`, `/libtestcmd.so`,
  `/libosal_uipc.so`; plus `ghidra_extra`, `ghidra_plugins`, `ghidra_secvlt`) — confirmed no
  PTP-related binary is loaded anywhere.
- `search_strings("/cpapp-b.bin", "uipc")` → the UIPC receive/send stack cited in §B
  (0x21a4e8, 0x21ad60, 0x21b2bc, 0x0053b890, 0x219fe8, 0x169384).
- `search_strings` for `OperationCode` / `SDIO` in `/cpapp-b.bin` and `PTP` / `SDIO` in
  `/av-cam.bin` → **no relevant hits** (basis for "the responder is not in those images").
- `list_xrefs("/cpapp-b.bin", …)` on the raw TABLE A VAs (`0x10FF6E4C` …) →
  `Symbol not found`: the table has no symbol, so its consumers were taken from the prior
  write-up rather than re-derived.
- Gate step "decompile one PTP operation handler by address": **not possible** — the PTP
  libraries are not in any project and importing is a write op; recorded as the §A boundary.

**On-disk ELF/string evidence (`readelf`, `strings`, `grep`):**
- `usbg_stillimage.ko`: `strings -a` → SICD function-driver banner, `sicd_*_ioctl`,
  `sicd_event_*`, `usb_ep_queue`, PTP header/response error strings.
- `grep -la "sicd_data" lib/*.so bin/*` → exactly one hit, `libInfraPtpControl.so`
  (plus its `strings` → `/dev/usb/sicd_core|sicd_data|sicd_event`).
- `readelf --dyn-syms -W` on `libInfraRemote.so` → the `Mrpw*` class surface quoted in §A
  (`MrpwOperationsBase`, `MrpwOperationsManager`, `MrpwProtocolManager`, the four
  `*EntryManager::Entry` registrars, the `std::map<u16, MrpwOperationsBase*>`
  instantiations, and ~50 `MrpwSDIO<Op>` classes / 516 matching symbols).
- `readelf -r` on `libInfraRemote.so` → 513 relocations into `MrpwSDIO` typeinfo/vtables;
  `readelf -SW` → `.rela.dyn` @0x55540, `.init_array` @0x144168 (size 0xa0),
  `.data.rel.ro` @0x144218.
- `readelf --dyn-syms -W libptp.so` → `ptpm_*` / `ptpw_cmd_*` / `ptpw_res_*` / `ptp_make_*`
  / `put_supported_*` list quoted in §A.
- `readelf -d` NEEDED lists for `libInfraPtpControl.so`, `libInfraRemote.so`;
  `readelf --dyn-syms -W | grep UND` on `libInfraRemote.so` → the `MWF::`/`UFW::` imports
  quoted in §B.
- `strings -a` on `appFw.so` (350 `PID_*`, `osal_snd_msg` errors),
  `libInfraRemote.so` (`PARAMID_*`, `MSGID_*`, `[UTIMER] … UIPC Msg`),
  `libInfraPtpExtCmd.so` (`ptpExt.map`, `MSGID_EXTCMD_*`), `libUsbControl.so`, `im.elf`.
- DT_NEEDED consumer map via `grep -l "<soname>" lib/*.so bin/*` (the `.dynstr` trick, since
  a Python DT_NEEDED walk needed approval): `libInfraRemote`/`libInfraPtpControl`/`appFw`
  ← `libIMDB.so` ← `im.elf`; `libptp.so` ← `libInfraRemote.so`, `libInfraPtpExtCmd.so`,
  `libInfraMtpServer.so`.
- `libSTMcmdexecute.so` is DT_NEEDED by `im.elf` but is **not present** under
  `fs/a15/lib/` — location unresolved.

**Prior write-ups cited (not re-derived):** `gptoss-out/cpappcmd-map.md` (TABLE A/B geometry,
VA = file + 0x108000, runtime-registered dispatch), `gptoss-out/osal-uipc-map.md`
(`/dev/uipc`, QID semantics), `gptoss-out/keyservice-map.md` (NIN service channel), and
`a7rv-firmware-analysis/README.md` + `docs/command-table.txt` (queue `0x3D025F` /
`0x80924220`, `FW: SET_*` log strings).

**Open items.** (1) Numeric Sony vendor opcodes — inside the `.init_array` ctor bodies
(needs the libs disassembled). (2) `ptpExt.map` absent from the extraction. (3) The
a15→cpapp queue id(s) and the `PID_*`→0x40xx numeric translation for the §B hypothesis.
(4) `libSTMcmdexecute.so` location.
