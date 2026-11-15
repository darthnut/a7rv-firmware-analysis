# Factory adjustment command vocabulary (`adjstctl.elf`)

**Summary.** The factory adjustment CLI holds one flat, byte-verified table of **1,779** command names,
each mapped to a `(block, code)` opcode pair and an OSAL id; lookup is a linear scan keyed on the 16-bit
`adjust_block`, and there is no name-based lookup at all.

**Where.** `fs/a15/bin/adjstctl.elf` (AArch64 ET_EXEC, non-PIE; Ghidra VAs are real `0x40xxxx`). The
table occupies VA `0x401a64`…`0x420ebc` = **1779 records × 72 bytes**. The lookup function is
`FUN_00401474` (base `0x401a68`, stride `0x48`, 1779 records); the `--abid` printer `FUN_00401408`.

**Mechanism.**
- **Record (72 bytes):** `{u16 adjust_block @+0x00; u16 code @+0x02; char name[0x40] @+0x04; u32 osal_id
  @+0x44}`. The table is physically sorted; first record is `APP_TESTCMD` (block `0x0101`, code `0x1001`),
  last is the `UNKNOWN` sentinel (`code 0xffff`).
- **Lookup:** `FUN_00401474` is a plain linear scan over 1779 records comparing the u16 `adjust_block`
  key (typed on the command line) and returning the record's `osal_id`; the command *name* is
  display-only. The mapping is **not injective** — `ADC_GET_DATA` appears twice (disambiguated by block),
  and `APPFWINFRA_INPUT_GETEVENT`/`APPFWINFRA_TP_GETEVENT` share one id.
- **Verb families (measured counts):** read-ish (`GET_` 57 + `READ_` 23) = 80, write/execute-ish
  (`EXEC_` 97 + `SET_` 64 + `WRITE_` 9 + `LOAD_` 1) = 171, diagnostics (`DIAG_`/`C_DIAG`) 53, and **84
  names contain `ADJ`** — the adjustment surface is much wider than the 5 that lead with it, spread
  across sensor/AF/gyro/mic/OLED-WB/keystone families. ~250 distinct namespace prefixes.
- **CLI frame:** `<options> [adjust_block] [adjust_code] [size]:[data]`; the host→wire framing is in
  [adjustment-message-framing](adjustment-message-framing.md).

**Verification.** *deep (byte-verified table).* The 72-byte stride, phase, and sentinel were pinned by
three independent byte measurements; all 1779 records decode cleanly (256176 hex chars = 1779 × 72) with
pure-NUL padding; the lookup function and record layout were disassembled verbatim. (A `strings`-based
read would carry 184 phantom `@NAME` commands — the `@` is byte 3 of the id word, not a name prefix;
corrected here.)

**Boundary / open.** This maps the *sender* only — **what the camera does with any command is out of
scope and not described**: not what `ADJSTART` opens, not what `DIAG_READ_SENSOR_ALL` reads. The `f0`/
block/code field *labels* are inference from the tool's format strings (the byte layout is measured).
**Safety:** these are manufacturing calibration/adjustment ops; a write/`*_FORMAT`/`*_STAT_RST` form can
persist a wrong calibration or discard one, and `ADJSTART`/`ADJEND` bracket a state the camera may not
expect outside a production line. **No command here is safe**, `GET_`-prefixed ones included (the prefix
is a host-side label, not a device-side guarantee).

**Source.** [framework-runs/service-framing-map.md](../../framework-runs/service-framing-map.md)
