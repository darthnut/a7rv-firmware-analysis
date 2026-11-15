# HASP id → feature gates — the exhaustive negative

**Summary.** No firmware module anywhere branches on a HASP id value. Every in-firmware path either
*appends* an id (write side) or *transports* the whole 88-byte blob to an external tool — so HASP is a
recorder/transport, and any entitlement decision is enforced outside the firmware.

**Where.** Searched across all indexed projects: `libsencore.so`, `libObj.so`, `sen.elf`, `libpro00.so`,
`libIMDB.so`, `libInfraSSHManager.so`, `crypter.elf`, `libBackupManager.so`, `adjstctl.elf`,
`libtestcmd.so`, `libosal_uipc.so`, and both coprocessor binaries **`av-cam.bin` (10,739 funcs)** and
**`cpapp-b.bin` (53,843 funcs)** — ~65k functions total.

**Mechanism — the five id pathways, none of which gates:**
1. `tlog_set_hasp` (`0x001132c4`) — stamps the id into bytes 0–1 of every StraceData trace record
   (telemetry tag identifying which factory op ran).
2. `WorkerThreadManager::registHaspId` (`0x0010c190`) → `Regist_HaspId` — appends `(id, BCD time)` to the
   ring; id is a dispatch argument.
3. `libpro00.so` `command001F` op `0x00` — ships the whole 88-byte blob to the RPC client; op `0x80`
   wipes it. **Never inspects ids.**
4. `/@HASP` adjcmd channel — a generic file-op backend exposing the blob as raw read/write; zero
   HASP-specific logic.
5. `sen.elf` private copies — write-side append only, no id gate.

**Verification.** *deep (negative).* A literal pseudocode search (`search_code`, case variants
`hasp`/`Hasp`/`HASP`) across every indexed binary returns only accessor/wrapper functions — **no
`switch`/`cmp` on an id constant anywhere**. `Regist_HaspId` writes `*(u16*)(buf+idx*8+8) = param_1` — the
id is always caller-supplied. On disk: `nm -D` shows exactly one module imports the accessors
(`libpro00.so`); `appFw.so` (the 97 MB app layer) contains **no HASP string at all**, so it cannot even
reference the store by name.

**Boundary / open.** This upgrades the [hasp-store](hasp-store.md) hypothesis to an evidenced finding
*for the indexed surface* (~65k functions incl. both coprocessor binaries and the app protocol lib). Not
resolvable: the meaning of specific id values (assigned by external service/factory tools, not in the
firmware) and the factory-harness logic (not part of any image). `appFw.so` was not decompiled at
function level, but its total absence of HASP strings bounds it. See
[OPEN-QUESTIONS.md](../../OPEN-QUESTIONS.md) item 10.

**Source.** [framework-runs/haspgates-map.md](../../framework-runs/haspgates-map.md)
