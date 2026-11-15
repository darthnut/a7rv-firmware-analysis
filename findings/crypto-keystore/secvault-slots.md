# SecVault — what each of the four slots holds

**Summary.** The four SecVault slots are a compile-time descriptor table; slots 0–2 are addressed only
by the C2PA signing code (`InfraC2PA` in `libmpr.so`), slot 3 has no consumer anywhere, and the "C2PA"
payload identities are inference, not proof.

**Where.** Descriptor table `read_bytes libsecvlt.so 0x101c30` (4 × `0x20`-byte entries, Ghidra VAs).
Caller sites in `libmpr.so` `.text` (addr == file offset there): `InfraC2PA::UnlockCertificateFileAndStore`
`0x95638`, `DeleteCertificateInfo` `0x9610c`, `LoadCertificateInfo` `0x9642c`. The `tbl_vault_id` table
in `libInfraCrypt.so` (`.rodata` offset `0x4158`, 7 × u32).

**Mechanism.**
- **Descriptor table** (slot → magic / Backup subsystem / Backup item / maxsize / attrs):

  | Slot | Item magic | Subsystem | Backup item | Max size | Attrs |
  |---|---|---|---|---|---|
  | 0 | `0x50369614` | `0x02f9` | `0x2f90029` | 4096 | `0x34` |
  | 1 | `0x25f174ad` | `0x02f9` | `0x2f90027` | 16384 | `0x32` |
  | 2 | `0x35c1a8a2` | `0x02f9` | `0x2f90028` | 4096 | `0x33` (bit 0 → read-blocked) |
  | 3 | `0x6ea8c226` | `0x02ec` | `0x2ec0046` | 60000 | `0x30` |

- **Payload reading (HYPOTHESIS):** slot 1 = the certificate payload read at signing time (the only slot
  `LoadCertificateInfo` addresses, largest readable); slot 2 = the private key from the unlocked
  PKCS#12 (write-only, touched by Unlock/Delete but never read); slot 0 = the companion object
  (public key / handle). Named from `libmpr.so` `.rodata` strings (`sigcert.p12`,
  `/sony.indv_aut.v1/sony.cert_sony_1`, `CreateC2paSigStructureHashData`).
- **A second referencer:** `libInfraCryptCore.so` reads slot ids out of `tbl_vault_id` (populated only
  for slots 2 and 0) and only `stat`s them (`SECVLT_exists`/`get_attr`/`get_size`) — never reads or
  writes. It stats the read-blocked slot 2 without being able to read it, corroborating the §A property.
- **Evidenced negatives:** the SSH host key is **not** in the vault (`libInfraSSHManager.so` doesn't link
  libsecvlt; its key goes to Backup subsystem `0x300`). No Wi-Fi/HASP/license material references any
  slot magic.

**Verification.** *light.* The descriptor table and `tbl_vault_id` are byte-verified; the `InfraC2PA`
call sites are located by a validated `movz`/`movk` instruction-pattern sweep (control-tested against
`libsecvlt.so` itself). The slot → payload *identity* is **HYPOTHESIS** — no AArch64 disassembler was
available, so which `SECVLT_*` call each magic-materialising site feeds is not proven.

**Boundary / open.** Payload contents never read (by design). Slot 3's payload is a clean negative — no
consumer in any extracted image; it alone sits on subsystem `0x02ec` and is the largest slot, consistent
with a reserved/field-provisioning slot written by code not in this dump. See
[OPEN-QUESTIONS.md](../../OPEN-QUESTIONS.md) item 3.

**Source.** [framework-runs/secvaultslots-map.md](../../framework-runs/secvaultslots-map.md)
