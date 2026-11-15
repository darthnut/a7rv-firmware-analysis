# Backup id registry — `(subsystem, item)` → payload

**Summary.** The id *scheme* is solid (`id = subsystem<<16 | item`, proven three ways), but the *registry*
— which id holds what — is mostly inference: only the SSH host key, the four SecVault ids, and a GPS clock
flag are CONFIRMED; the rest are read from caller context with name-derived labels.

**Where.** `libBackupManager.so` (`ghidra_extra`) for the scheme; callers in `libObj.so`,
`libInfraSSHManager.so`, `libsecvlt.so` across the loaded projects. `writeBackup` `0x10135c`,
`readBackupDecryption` `0x101594`, `BkDmn_write` `0x10128c` (the split); the SecVault descriptor table at
`libsecvlt.so` `0x101c30`.

**Mechanism.**
- **Scheme:** `id[31:16] = subsystem (u16)`, `id[15:0] = item` — confirmed by `writeBackup` (subsystem
  used only for the size lookup), `readBackupDecryption` (id alone), and `BkDmn_write` (splits the id into
  separate wire fields). SecVault's descriptors independently build ids the same way — two producers, one
  layout.
- **CONFIRMED rows:** SSH ECDSA host key `0x300/0x3000000` (restored to `/tmp_network/ssh/ssh_host_ecdsa_key`
  mode 0600; full lifecycle in [ssh-provisioning](../service-mode/ssh-provisioning.md)); SecVault slots
  0–2 at subsystem `0x02f9` (`0x2f90029/27/28`) and slot 3 at `0x02ec0046`; a 1-byte GPS "clock adjusted
  by user" flag `0x2cf0014`.
- **HYPOTHESIS rows (ids CONFIRMED by disasm immediate, payload name-derived):** GPS-infra `0xa1` family
  (whole subsystem flushed together), InfraInput `0x7a`, touch calibration `0x7b`, `0x102`, `0x0f9`, a
  **physical-memory carve-out `0xfa`** (base+size fed to `open("/dev/mem")` + `mmap` + `memset 0x5a`), and
  `0x91`. The `BKID_*` string enums (Wi-Fi AP list, BT MAC, USB serial, country-code power table,
  thousands of `BKID_APP_*` settings) are name-derived only.

**Verification.** *light (scheme proven; payloads OPEN).* The id scheme is proven three ways; each row's
id is a disasm immediate at a cited call site; payload *identity* is CONFIRMED only where the caller's own
strings/symbols say so, else **HYPOTHESIS**.

**Boundary / open.** The **payload owners are backup-daemon-side** (`libbkdmn.so` / `bk.elf`), not in
scope. The registry is a lower bound: generic table-driven helpers read ids from a runtime table, and
`Backup_read` has **167 xrefs** in `libObj.so` alone (the read side is sampled, the write side
enumerated). The store carries identity-bearing and security-relevant material (SSH key, Wi-Fi, BT MAC,
serial), not just photographic preferences. See [OPEN-QUESTIONS.md](../../OPEN-QUESTIONS.md) item 4.

**Source.** [framework-runs/backupmap-map.md](../../framework-runs/backupmap-map.md)
