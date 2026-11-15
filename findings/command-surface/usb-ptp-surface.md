# USB / PC-Remote (PTP) command surface

**Summary.** The PC-Remote / PTP responder is not in the coprocessor images — it lives in a15 Linux
userspace as a runtime `std::map<u16 OperationCode, handler>` in `libInfraRemote.so`, distinct from the
internal FW command table; the bridge to `cpapp` commands crosses the processor boundary over OSAL and
was not traced end to end.

**Where.** `fs/a15` (ELF-symbol / relocation / string level — these libs are **not** in any Ghidra
project). Kernel gadget `kmod/usbg_stillimage.ko` (`/dev/usb/sicd_{core,data,event}`); transport FSM
`libInfraPtpControl.so`; codec `libptp.so` (`ptpm_*`/`ptpw_*`); the responder `libInfraRemote.so`
(`MrpwOperationsManager`, ~50 `MrpwSDIO<Op>` classes); gadget lifecycle `libUsbControl.so`.

**Mechanism.**
- **Stack:** USB host → `usbg_stillimage.ko` (SICD bulk-in/bulk-out/int-in gadget; no opcode logic) →
  `libInfraPtpControl.so` (the sole consumer of `sicd_*`; FSM + transport threads) → `libInfraRemote.so`
  (per-op handlers + dispatcher) → `libptp.so` (packet codec + session FSM).
- **The dispatch table** is a runtime `std::map<unsigned short, MrpwOperationsBase*>` keyed by the 16-bit
  PTP OperationCode, populated by four static `.init_array` registrars (standard / vendor-extension /
  debug namespaces). Each op is a 3-phase handler (`CommandFunction`/`DataFunction`/`ResponseFunction`)
  with `GetBridgeEnable()` / `IsValidOutsideSession()` flags.
- **Session gating:** `MrpwProtocolManager` holds per-session state and `IsOperationCodeActivated(op,
  session)` — an opcode is executable only after the Sony auth/connect sequence for that session.
- **The bridge:** `MrpwSDIO` handlers post MWF/UFW `ObjMsg` messages (named `MSGID_*`) over OSAL
  `/dev/uipc`; `appFw.so` (same process) holds 350 `PID_*` strings and calls `osal_snd_msg`; `cpapp`'s
  `UIPCReceiver` stack receives. Name parity (`PID_SET_DRIVE_MODE` ↔ `FW: SET_DRIVE_MODE`) is suggestive.

**Verification.** *light (boundary recorded).* The responder's location, the dispatch data structure
(the `std::map` instantiations are imported symbols), the four registrars, and the `.init_array`/513-
relocation self-registration are all fixed from `readelf`/`strings`/`grep`. No per-opcode value and no
handler body was read.

**Boundary / open.** The PTP libraries are not imported into any Ghidra project (importing is a write op
the read-only constraint forbids), so no handler was decompiled. **Numeric Sony vendor opcodes are not
resolvable** (baked into constructor bodies); `ptpExt.map` (the likely extension map) is **absent from
the extraction**. The concrete `PTP opcode → MrpwSDIO::CommandFunction → MWF message → UIPC QID → cpapp
TABLE A entry` chain is **HYPOTHESIS** — the a15 side speaks symbolic `MSGID_*`/`PID_*`, the cpapp side
dispatches numeric ids, and the two were never seen in one binary. File ops (`GetObject`, storage)
terminate on the a15 filesystem and never need cpapp. See
[OPEN-QUESTIONS.md](../../OPEN-QUESTIONS.md) item 5.

**Source.** [framework-runs/usbptp-map.md](../../framework-runs/usbptp-map.md)
