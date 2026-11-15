# Investigation 3 — a7R VI firmware (blocked)

**The question:** can the same approach read the newer a7R VI body firmware?

**Answer: no — blocked at the crypto, and no feature claims are made from it.** The a7R VI update
package (`BODYDATA`, ~338 MB) is the same UFU container family, but the package-format version has moved
on (`DATV = 04` vs the a7R V's `01`) and the payload is **fully encrypted** — entropy 8.00/8 throughout,
no plaintext islands. The a7R V (Gen5) AES keys were tested against every plausible header / frame /
trailer split and produced **zero valid checksums**: they do not apply. The 338 MB size (vs the a7R V's
751 MB plaintext) suggests a **partial / delta** package rather than a full image.

## The container layout (the shareable part)

For reference, the a7R V updater the keys *do* open has this container layout — our mapping, with **no
keys or payload reproduced**:

- an `89 55 46 55 0d 0a 1a 0a` magic,
- then big-endian `{u32 size, u32 tag}` chunks — `DATV` (format version: `1` on the a7R V, `4` on the
  a7R VI), `PROV`, `UDID` (92 bytes on the a7R V, 44 on the a7R VI), the `FDAT` payload, and `DEND` + a
  CRC-32 over the preceding bytes.
- `FDAT` is 1024-byte frames (each a 2-byte word-sum checksum + a flags word, `bit15` = last frame), the
  first frame's leading 512 bytes under a header cipher, and a trailer of a 16-byte IV plus a 256-byte
  RSA-2048 signature.

The AES decryption of that payload is the community's work (credited in the
[README](../README.md#acknowledgments--prior-work)), not ours; the **container framing** is what this
project mapped, and it is the shareable part.

## Why it stops here

Reading the a7R VI package would require the a7R VI generation's updater keys (the kind of thing that
historically comes from community RE of the updater), or a flash dump taken off the body directly.
Until then, **nothing about a7R VI features can be asserted from this file** — anything claimed would be
speculation, and is deliberately not recorded here.

This is tracked as an open boundary rather than a dead end: see
[OPEN-QUESTIONS.md](../OPEN-QUESTIONS.md) item 8. If a7R VI updater keys ever surface, the same pipeline
([method/](../method/README.md)) applies unchanged.
