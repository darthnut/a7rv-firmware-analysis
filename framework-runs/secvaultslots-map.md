# a7R V SecVault — what each of the 4 slots holds

Static RE of the user's **own** Sony a7R V firmware (`/srv/a7rv/a7rv-fw`). Ghidra projects
`ghidra_secvlt` (binary `/libsecvlt.so`, project `a7rv_sv`) for the vault itself, and
`ghidra_svc` / `ghidra_svctools` / `ghidra_extra` / `ghidra_cpapp` for its callers.
Companion docs: `secvault-map.md` (the store mechanism), `backup-map.md` (the persistence layer).

Scope: **slot ids, subsystem/item routing ids, sizes, attribute bits, and payload identity only.**
No key material, no wrapped DEKs, no IVs, no GCM tags, no plaintext, and no firmware binary is
reproduced here. All addresses are Ghidra **virtual** addresses.

Status: COMPLETE — §A fully evidenced from the shipped binary; §B evidenced to the call-site, with
payload *identity* marked HYPOTHESIS; slot 3 is an evidenced negative. See §C for caveats.

## A. The 4 slots

The vault has **no name→value directory**. The four slots are a compile-time descriptor table in
`libsecvlt.so` `.rodata`, and a caller addresses a slot **only** by passing its 32-bit *item magic*
to `SECVLT_store`/`SECVLT_load`/… — there is nothing to enumerate at runtime.

**Descriptor table — `read_bytes libsecvlt.so 0x101c30 len 128` (4 × 0x20-byte entries):**

| Slot | `+0x00` item magic | `+0x04` subsystem (u16) | `+0x08` Backup item (u32) | `+0x0c` | `+0x10` max size (u64) | `+0x18` attrs (u32) | `+0x1c` |
|---|---|---|---|---|---|---|---|
| 0 | `0x50369614` | `0x02f9` (761) | `0x02f90029` | `0` | `0x1000` = **4096** | `0x34` = bits 2,4,5 | pad |
| 1 | `0x25f174ad` | `0x02f9` (761) | `0x02f90027` | `0` | `0x4000` = **16384** | `0x32` = bits 1,4,5 | pad |
| 2 | `0x35c1a8a2` | `0x02f9` (761) | `0x02f90028` | `0` | `0x1000` = **4096** | `0x33` = bits 0,1,4,5 | pad |
| 3 | `0x6ea8c226` | `0x02ec` (748) | `0x02ec0046` | `0` | `0xea60` = **60000** | `0x30` = bits 4,5 | pad |

`+0x0c` is zero and `+0x1c` is padding in all four entries (observed in the 128-byte dump).

**Magic → slot index, and the fallback.** `decompile_function libsecvlt.so @0x1013d8` (`get_vltinfo`)
is the only resolver: it compares the caller's item against the four magics in table order and sets
`*param_2 = &LAB_001c30 + idx * 0x20` — `0x50369614`→0, `0x25f174ad`→1, `0x35c1a8a2`→2,
`0x6ea8c226`→3. Any *other* item also returns `2` and therefore resolves to **slot 2's descriptor**.
The index-2 fallback is observed in the decompilation; that it lands on the write-only slot is the
interesting part (below), and reading it as a deliberate fail-safe is **HYPOTHESIS** — an
"unimplemented slot" default explains the code just as well.

**Attribute bits** (per `secvault-map.md` §A.5: every gate tests `rec.attrs | desc.attrs`, and
`SECVLT_store` stamps `rec.attrs = desc.attrs` verbatim, so these table values are what ship):

| bit | meaning | who can set it |
|---|---|---|
| 0 | **read-blocked** — `SECVLT_load` @0x101768 returns `5` whenever `(desc+0x18 \| rec+0x50) & 1` | descriptor table only; `SECVLT_add_attr` @0x101a88 can never add it (one-hot validation) |
| 1 | slot option present in slots 1, 2 | descriptor; `add_attr` for the others is rejected by the one-hot test |
| 2 | slot option present in slot 0 | idem |
| 4 | allows a store whose `len` differs from the live record's size (resize on overwrite) | descriptor / `add_attr` |
| 5 | allows overwrite of an existing valid record | descriptor / `add_attr` |
| 6 | delete-protected (store-in-place and `SECVLT_delete` both refuse) | `add_attr` — **clear in all four shipped descriptors** |
| 7 | would force an fsync on write | **clear in all four** → no fsync on store; durability comes only from `Backup_sync_subsystem` |

Consequences that matter for reading the slots (all from the shipped table, not from a live device):

- **Slot 2 is write-only — unreadable by design.** Its descriptor carries **bit0**, so `SECVLT_load`
  refuses (`5`) for every caller, forever: bit0 is unaddable *and* unclearable through the API
  (accumulate-only, `SECVLT_set_attr` does not exist). Whatever slot 2 holds, **no** firmware caller
  and no API user can ever read it back — only overwrite (`SECVLT_store`) or crypto-erase
  (`SECVLT_delete`). Same applies to the unknown-item fallback, which also resolves to slot 2.
- **Slots 0/1/2 are overwrite-in-place-ish**: all three carry bit5 (overwrite allowed) and bit4
  (size may change), and none carries bit6 (so none is delete-protected). Slot 3 (bit4|bit5) behaves
  the same way. Practically: no slot on this device is delete-protected or resize-locked as shipped.
- **Size budget**: 4 KiB + 16 KiB + 4 KiB + 60000 B ≈ 84 KiB total, and each slot's ceiling is a hard
  `len <= desc.maxsize` check in `SECVLT_store` @0x101544. The 60000-byte outlier (slot 3) also sits
  on a **different Backup subsystem** (0x02ec) from the other three (0x02f9) — the one structural
  split in the table, which is what makes slot 3 the most separable of the four (§B).

## B. What each slot holds

**Why this is hard, and how it was searched.** The magics are not strings, not filenames, and not
import names — a caller bakes them in as an *immediate*, and AArch64 splits a 32-bit constant into a
`movz` + `movk` pair, so the magic never appears as contiguous bytes. Nor can callers be found from
the Ghidra projects: **none of the 12 loaded binaries references any `SECVLT_*` symbol** — the
callers live in stripped libraries that are not in any project. So the search was done on-disk,
three ways, and a candidate is only counted if it passes **all** of:

1. a valid `movz`+`movk` *pair* for one magic (encodings taken from Ghidra's own bytes for
   `get_vltinfo` @0x1013d8, not hand-derived), 4-byte-aligned (**instruction boundary**),
2. the pair lying inside an exported function (`.dynsym` nearest-preceding symbol),
3. a payload story from that function's own `.rodata` strings.

Every candidate that failed alignment was discarded as a data coincidence — which retracted two
earlier leads (see slot 3).

### Slots 0, 1, 2 = the C2PA content-credential signing material (one consumer: `libmpr.so`)

All three are addressed **only** by the `InfraC2PA` class in `libmpr.so`. `.text` there has
**addr == file offset** (`readelf -SW`: `[10] .text PROGBITS 00000000000837f0 000837f0`), so grep
byte offsets below *are* virtual addresses.

| site (libmpr.so VA) | materializes | slot | enclosing exported symbol (`nm -D`) |
|---|---|---|---|
| `0x95C88` + `0x95C90` | `0x35c1a8a2` | **2** | `InfraC2PA::UnlockCertificateFileAndStore` @`0x95638` |
| `0x95D94` + `0x95D9C` | `0x50369614` | **0** | *same* |
| `0x95EA0` + `0x95EA8` | `0x25f174ad` | **1** | *same* |
| `0x961A0` + `0x961A4` | `0x35c1a8a2` | **2** | `InfraC2PA::DeleteCertificateInfo` @`0x9610c` |
| `0x961C4` + `0x961C8` | `0x50369614` | **0** | *same* |
| `0x9621C` + `0x96220`, `0x96274` + `0x96278` | `0x25f174ad` | **1** (×2) | *same* |
| `0x964FC` + `0x96504` | `0x25f174ad` | **1** | `InfraC2PA::LoadCertificateInfo` @`0x9642c` |

Two more `InfraC2PA` methods — `GetCertificateInfo` @`0x95fec` and `Exists` @`0x96984` — materialize
**no** magic at all, i.e. they work on already-loaded state rather than re-addressing a slot.

The payload names itself in that same library's `.rodata` (no vault bytes, just identifiers):

- `sigcert.p12`, `sigcert.pfx` — a **PKCS#12** certificate-and-key file, i.e. what
  `SearchCertificateFile` @`0x9534c` looks for and `UnlockCertificateFileAndStore` consumes
  (OpenSSL imports in the same lib: `d2i_PKCS12_bio`, `PKCS12_parse`, `PKCS12_free`,
  `PEM_write_bio_PrivateKey`).
- `/tmp_mpr/certificate.info`, `"certificate_format": "private"`,
  `"certificate_path": "self#jumbf=%s/%s"`, `/sony.indv_aut.v1/sony.cert_sony_1` — C2PA manifest
  URN / jumbf box path.
- public-side artifacts written out beside the signature:
  `tar -C /tmp_mpr -cf /tmp_mpr/PUB_INFO.TAR epk.bin certificate.info siginfo.dat inst_siginfo.dat uniq_property.dat`
  and the shorter `… publickey.pem certificate.info siginfo.dat`.
- size assertions tying the payload together:
  `sizeof( sigPayload ) - certInfoSize >= publicKeySize`,
  `(int32_t)(sizeof( sigPayload ) - publicKeySize - certInfoSize) >= licenseSize`.
- the consumer is downstream and named: `libMp4SignaturePrivate::CreateC2paSigStructureHashData`
  @`0x1a9d38` takes `InfraC2PA::getCertificateInfoOutParam const&` — the loaded cert info becomes
  the hash data of the **MP4/C2PA signature**.
- `appFw.so` is the only other library importing `UnlockCertificateFileAndStore` and
  `DeleteCertificateInfo` — so enroll/delete are driven from the camera UI, not from a background service.

**Per-slot reading** (identity of the bytes is inference; the *addresses* are not):

| Slot | What it holds | Basis |
|---|---|---|
| **1** — 16 KiB, readable | The **certificate payload read at signing time** (cert chain / `certificate.info`). It is the *only* slot `LoadCertificateInfo` ever addresses, and the largest of the three readable slots, which fits a chain of X.509 certs. | proven: site `0x964FC`; content of the blob **HYPOTHESIS** |
| **2** — 4 KiB, **read-blocked** (bit0) | The **secret** — the private key from the unlocked PKCS#12. Touched by `Unlock…Store` (`0x95C88`) and `Delete…` (`0x961A0`), **never** by `LoadCertificateInfo`. A write-only, crypto-eraseable key slot is exactly what bit0 buys, and it also catches the unknown-item fallback (§A). | proven: write-only + touched-never-read; that it is the *private key* is **HYPOTHESIS** |
| **0** — 4 KiB, readable | The **companion object** to the above (public key / key id / cert handle). Touched by both `Unlock…Store` (`0x95D94`) and `Delete…` (`0x961C4`), never read by `LoadCertificateInfo`, and it is one of only two ids in `tbl_vault_id` (below) — i.e. the object the crypto core wants to *stat*. | proven: sites + table entry; identity **HYPOTHESIS** |

Caveats on the attribution: symbols are `.dynsym` exports and a site is assigned to the
**nearest preceding** one, so a file-local static helper inside those ranges could own an individual
site; and with no AArch64 disassembler available here, **which `SECVLT_*` call each site feeds is
not proven** — only that the magic is materialized there.

### Slots 0 and 2 have a second, independent referencer: `tbl_vault_id`

A caller can also address a slot with **no magic in its own code** — by reading the id out of a
data table in another library. That path exists, and an instruction sweep alone misses it:

- `libInfraCrypt.so` exports `54: 0000000000004158 28 OBJECT GLOBAL DEFAULT 12 tbl_vault_id`
  — a **28-byte** (7 × u32) table in `.rodata` (VA == file offset there too).
- Decoded (`od -An -tu4 -j16728 -N28`, ids only — in scope, not key material):
  `[0]=0  [1]=0  [2]=0  [3]=0  [4]=901884066 = 0x35c1a8a2 → slot 2  [5]=1345754644 = 0x50369614 → slot 0  [6]=0`.
  Exactly two entries are populated, and they are **exactly slots 2 and 0**.
- `libInfraCryptCore.so` imports it (`UND tbl_vault_id`) and links **only** `SECVLT_exists`,
  `SECVLT_get_attr`, `SECVLT_get_size` — no `SECVLT_store`, no `SECVLT_load`. So the crypto core
  merely **stats** those two slots (presence / attribute bits / stored size) and never reads or
  writes their contents. Its own magic-immediate hits turned out to be misaligned false positives,
  consistent with the id coming from the table rather than from code.

That the crypto core stats the **read-blocked** slot 2 without ever being able to read it is a nice
corroboration of the §A property: on this device, slot 2 is usable-but-unreadable by design.

### Slot 3 (60000 B, subsystem `0x02ec`) — no consumer found anywhere

Every lead for slot 3 died on the alignment test, so this is a clean negative rather than a guess:

- 32-bit `mov` sweep: hits only in `libsecvlt.so` and `a8/cpapp-b.bin`; the cpapp hit
  (`0xC3C1E3` / file offset 12829155) is a **`movk` half with no `movz` partner anywhere in the
  blob**, and `12829155 % 4 = 3` → not an instruction boundary.
- 64-bit (`mov x`) sweep, run to close the encoding gap: `cpapp-b.bin` is **absent entirely**.
- Ghidra `/cpapp-b.bin`: literal pseudo-C search for `0x6ea8c226` (and `0x50369614`) → **0 hits of
  53,843 indexed functions**; `list_xrefs 0xc3c1e3` → "Symbol not found".
- The other two candidates that survived the first sweep were both retracted on alignment:
  `libInfraCryptCore.so` @1071625 and @1302361 are both `% 4 = 1`; `default.nab` and `image.uxb`
  hits have no `movz`/`movk` partner at all (they are data blobs).

So **nothing in the A15 userland, and nothing in the A8 coprocessor blob, addresses slot 3.** It is
also the only slot on its own Backup subsystem (`0x02ec` vs `0x02f9`) and by far the largest
(60000 B). **HYPOTHESIS**, unproven: a reserved/field-provisioning slot, or one written by code not
present in this dump (service-side provisioning, or a coprocessor image other than the one
shipped here).

**Negative results worth stating, because they are what the question was really asking:**

- The **SSH host key is not in this vault.** `libInfraSSHManager.so` does not link `libsecvlt` at
  all, and the SSH manager's persistence goes through `Backup_sync_subsystem(0x300)` — a *third*
  subsystem, distinct from both `0x02f9` and `0x02ec` (`backup-map.md` line 287).
- No wireless/networking library anywhere in the tree references any slot magic, so **Wi-Fi
  credentials are not in the vault either**.
- No `HASP`/dongle string or symbol exists in `libsecvlt.so`; the vault is not a licence store.
- The four slots are *not* "one per purpose" as the question assumed: **three of the four belong to
  a single feature** (C2PA signing), and the fourth has no owner at all.

## C. Scope / safety

What is in this document and what deliberately is not:

- **In scope, and documented:** descriptor-table offset and field layout, the four item magics (they
  are compile-time constants in `.rodata`, not secrets — they are the *addresses* of the API),
  subsystem/item routing ids, per-slot maximum sizes, attribute bits and their enforcement points,
  and the identity of the code that uses each slot.
- **Not documented, by design:** no vault contents, no plaintext, no AES keys or wrapped DEKs, no
  IVs or GCM tags, no certificate/key bytes, no dumps of the firmware image. The one byte-level read
  beyond the descriptor table was 28 bytes of the `tbl_vault_id` **id table**, reported as decoded
  integers because ids are the routing information under study; nothing read from any `Backup`
  record or vault payload appears here.
- **Ownership:** this is the user's own Sony a7R V, firmware extracted from its own memory card.
  The analysis is static — nothing was run against the device, and no vault on any device was
  opened, written, or erased as part of this work.
- **Nothing here is an exploit or an unlock.** The headline result is the opposite of a break:
  slot 2's payload **cannot be read** through the API by anyone, including firmware, because its
  descriptor sets the one attribute the API cannot clear (§A). The private-key-like slot stays
  write-only. Sizes and ids alone let you *stat* a slot (`SECVLT_exists`/`get_attr`/`get_size`, which
  is exactly what Sony's own crypto core does) — they do not yield contents.
- **Practical caution for anyone repeating this:** `SECVLT_store` on a live device overwrites in
  place (all four descriptors set bit5/bit4), and there is **no fsync** (bit7 clear in all four), so
  a store followed by a power loss is a durability hazard for the C2PA signing material. Write
  paths here were read, never exercised.
- **Reproducibility caveat:** the strongest claims are (a) the shipped descriptor table, (b) the
  per-slot call sites inside `InfraC2PA`, and (c) the `tbl_vault_id` contents. The mapping
  *slot 1 = certificate chain, slot 2 = private key, slot 0 = companion public object* is a reading
  of the code paths and the library's own string constants, not something proven by observing data —
  it is marked **HYPOTHESIS** in §B and should be treated as the paper's open inference.

## How this was checked

Ghidra (read-only tools, virtual addresses; binary name `/libsecvlt.so` in project `a7rv_sv`):

| step | call | what it gave |
|---|---|---|
| gate | `list_project_binaries` (ghidra_secvlt) | `/libsecvlt.so` present, analysis complete → proceed |
| §A table | `read_bytes libsecvlt.so 0x101c30 size 128` | the four 0x20-byte descriptors verbatim |
| §A resolver | `decompile_function libsecvlt.so 0x1013d8` (`get_vltinfo`) | magic→index mapping, `idx*0x20` descriptor arithmetic, unknown→2 fallback |
| encoding reference | `disassemble libsecvlt.so 0x1013d8 count 40 include_bytes=true` | the **actual** `movz`/`movk` bytes for all four magics |
| slot 3 negative | `search_code /cpapp-b.bin "0x6ea8c226"` (literal), `"0x50369614"` | 0 hits / 53,843 functions |
| slot 3 negative | `list_xrefs /cpapp-b.bin 0xc3c1e3` | symbol not found |

On-disk (strings/ELF only; no AArch64 binutils in this environment, so **no disassembly**):

1. **Derived the instruction patterns from Ghidra's bytes, not by hand.** The first attempt assumed
   a `MOVZ` base of `0x52000000` and hit nothing anywhere; the real encodings are
   `movz w: 0x52800000`, `movk w: 0x72800000 | (hw<<21)` (and the `sf=1` variants `0x92800000` /
   `0xB2800000`), with `imm16<<5 | rd` — so the register number lives in the low 5 bits of byte 0.
   Each pattern therefore wildcards byte 0 over the even registers, e.g. slot 0 =
   `[\x80-\x9f]\xc2\x92\x52` + `[\xc0-\xdf]\x06\xaa\x72`.
   **Control test:** run against `libsecvlt.so` itself, the patterns hit exactly the 8 instructions
   Ghidra reports at `0x1013d8`–`0x101410` and nowhere else. That validation is what makes the
   firmware-wide sweep meaningful.
2. **Swept the whole tree twice**, 32-bit and 64-bit encodings, `LC_ALL=C grep -rlaP` from
   `/srv/a7rv/a7rv-fw/fs` (`LC_ALL=C` is required or the high-byte `\xNN` escapes are rejected as
   invalid UTF-8). Then per-file `grep -obaP` to get offsets.
3. **Filtered by alignment.** AArch64 instructions are 4-byte aligned, so `% 4 != 0` disqualifies a
   hit. This is what turned `libInfraCryptCore.so` and `a8/cpapp-b.bin` from "callers" into data
   coincidences; the genuine `libmpr.so` sites are all aligned and pair up `movz`→`movk` 8–12 bytes
   apart. Data blobs (`default.nab`, `image.uxb`, `image_00_32_IPSX.uxc`) have no adjacent partner
   half at all.
4. **Named the enclosing functions** despite the libraries being stripped: `.dynsym` survives
   stripping, so `nm -D --defined-only libmpr.so | sort` + nearest preceding symbol attributes each
   aligned site. This is sound only because `.text` in `libmpr.so` and `.rodata` in
   `libInfraCrypt.so` have **addr == file offset** (`readelf -SW`), making grep offsets directly
   comparable to Ghidra virtual addresses.
5. **Closed the "no magic in code" gap** by also sweeping for the magics as **raw little-endian
   u32** — which found `libInfraCrypt.so` and nothing else, leading to the `tbl_vault_id` table
   (`readelf --dyn-syms`, then `od -An -tu4 -j16728 -N28` to decode 7 u32 ids).
6. **Named the payload** from `.rodata` identifiers in `libmpr.so` (`strings -n 5 | grep -iE 'cert|p12|pfx|pkcs|…'`),
   and found the API's other importer with a plain ASCII grep for the mangled symbol names across
   the tree (`appFw.so`).

Limitations, stated plainly: no disassembler was available (`objdump` here has no AArch64 target,
`python3`/capstone were blocked by the sandbox), so **call-site → specific `SECVLT_*` routine is
not proven anywhere** — §B says which magic is materialized where, not which API call consumes it.
Function attribution is by nearest preceding exported symbol and could name a file-local static
helper's site. The per-slot payload identities in §B are labelled **HYPOTHESIS** for exactly this
reason, and slot 3's "no consumer" is a negative over this dump only.

Scratch note: the abandoned first-pass scanner `/srv/a7rv/gptoss-out/scan_magics.py` is still on
disk (a byte-oriented LE-u32 scan, superseded by the instruction-pattern method above; its approach
is the one that produced no results). Removal needed an approval that wasn't granted during the run.
