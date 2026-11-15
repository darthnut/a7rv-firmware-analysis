# HASP store — the `/setting/.hasp` check-in log

**Summary.** `/setting/.hasp` is an 88-byte, 10-entry ring of `(u16 id, BCD timestamp)` check-ins with
no magic, CRC, MAC or signature — a tamper-forgeable *history log*, not a key table or a security gate.

**Where.** Accessors in `libObj.so` (project `ghidra_extra`) and a byte-identical copy in `libsencore.so`
(`ghidra_svc`): `Read_Hasp` `0x001ebd5c` (libObj) / `0x00114260` (libsencore), `Reset_Hasp` `0x001ebc94`
/ `0x00114198`, `Regist_HaspId` `0x001142f0` (libsencore only). The `/@HASP` adjcmd handler
`FUN_00111714`. A dead inlined copy also sits in `sen.elf` (`0x004025d0`).

**Mechanism.**
- **Format:** fixed 88 bytes (`0x58`): byte `0x00` = ring index (0–9; ≥10 → "last_histroy data error"),
  then 10 × 8-byte entries at `0x08 + 8*i` of `{u16 id, 5× BCD time bytes, 0}`.
- **Accessors:** `Read_Hasp` opens `O_RDONLY|O_DSYNC|O_CLOEXEC`, reads 88 bytes. `Reset_Hasp` is an
  in-place **zero-wipe** (`O_WRONLY|O_CREAT|O_TRUNC` + 88 zero bytes + `fsync`), never an unlink —
  factory-default state is all-zeros. `Regist_HaspId(id)` appends `(id, localtime BCD)` at the ring index
  and wraps; an absent file is a normal state (returns success without creating anything).
- **Access paths:** the in-process file API (`libpro00.so`'s `command001F` is the **only** module that
  imports `Read_Hasp`/`Reset_Hasp`) and the `/@HASP` service-channel verb (a generic file-op backend).
  The 88-byte block `command001F` returns is exactly `Read_Hasp`'s buffer.

**Verification.** *light.* All accessors decompiled (libObj + libsencore); the layout read from
`Regist_HaspId`'s stores; the single-importer result from a firmware-wide `readelf` UND scan; the
`sen.elf` inlined duplicate disassembled (140 instrs). `itoh()` = BCD encode is HYPOTHESIS by name/value
range.

**Boundary / open.** **No in-firmware branch on HASP contents was located** — any per-feature gating is
off-device (see [hasp-id-gates](hasp-id-gates.md) for the exhaustive negative). The id → operation
meaning is assigned by external Sony service/factory tooling and is **HYPOTHESIS** (ids enumerate
factory/service operations logged as check-ins). `libpro00.so`'s internal logic rests on imports +
strings only (it would not import into Ghidra in that run). **Integrity: none** — any writer of
`/setting` can forge the history; `Reset_Hasp`/`/@HASP` op `0x80` are destructive with no backup copy.

**Source.** [framework-runs/hasp-map.md](../../framework-runs/hasp-map.md)
