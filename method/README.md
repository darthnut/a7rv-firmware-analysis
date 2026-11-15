# Method & reproducibility

How the analysis in this repo was produced, what the tools were, and — most importantly — what the
verification labels on every finding mean. If you are reading one of the [findings](../findings/) pages
and want to know how much weight its **Verification** line carries, this is the page that defines the
terms.

---

## Targets and load bases

Two processors, two address conventions. Get these right or every offset is wrong.

| Image | ISA | Load base | Convention |
|---|---|---|---|
| `cpapp-b.bin` (main SoC, camera app) | ARM / Thumb-2, flat binary | `0x00108000` | **VA = file offset + `0x108000`** (and file offset = VA − `0x108000`) |
| `av-cam.bin` (main SoC, develop) | ARM / Thumb-2, flat binary | per Ghidra project | addresses are Ghidra virtual addresses |
| `fs/a15/**/*.so`, `*.elf` (a15 Linux) | AArch64 ELF | per-image | Ghidra VA; for many `.so` the `.text` has addr == file offset, noted per finding. `nm` file offsets usually equal Ghidra VA minus the project's `0x100000` base. |

The firmware image itself is **not** in this repo and is not ours to redistribute. Every offset here is
derived analysis against a locally extracted copy of the user's own camera's firmware.

---

## The toolchain

- **Ghidra** (12.2 headless, Temurin JDK 25) driven through a read-only MCP server, one project per
  image group (`ghidra_cpapp`, `ghidra_avcam`, `ghidra_svc`, `ghidra_extra`, `ghidra_svctools`,
  `ghidra_secvlt`, `ghidra_plugins`). Only read-only tools were used: project/binary listing,
  decompilation, disassembly, xrefs, byte reads, symbol/code/string search. No binary was imported,
  renamed, retyped, commented, or saved, so every Ghidra project is left exactly as found.
- **Binutils** (`readelf`, `nm`, `strings`, `objdump`) on the a15 ELFs — but **no AArch64 disassembler**
  was available on the analysis host, so where a claim needed instruction-level AArch64 decoding and the
  binary was not in a Ghidra project, the finding says so and stops at symbol/relocation/string
  evidence.
- A standalone Python byte-verifier (run with `python -I`, isolated mode, so it cannot import code
  sitting next to the untrusted binary) asserts exact bytes at offsets of interest.

### Two Ghidra gotchas that shape every finding

1. **Decompile by real body address, not by name.** Many exports appear twice — a real body and a
   same-named PLT thunk — so decompiling by name follows the forwarding thunk and returns the wrong
   thing (or "Ambiguous match"). Every function in these studies was reached **by address**.
2. **The `movw`/`movt` trap (`cpapp`).** This firmware constructs 32-bit RAM addresses from `movw` +
   `movt` immediate pairs, not from literal pools. A naïve "scan the image for the 4-byte address"
   finds **zero** references to known-live addresses and will fool you into thinking a counter is
   unused. Ghidra, which resolves the ~95k immediate pairs, is the right instrument; a literal-word
   scan is not. The same pairing is why table-reached handler/checker pointers (stored with the Thumb
   LSB set) are invisible to `list_xrefs` — the dispatcher reaches them through masked table values, so
   "who calls this handler?" must be answered by byte-scanning the table.

---

## The analysis pipeline

Each subsystem study followed the same shape:

1. **Gate.** Confirm the binary is loaded and analysis is complete (`list_project_binaries`), and
   decompile one load-bearing function, before committing to the study.
2. **Locate by string → xref, or by symbol.** On stripped images (e.g. `av-cam.bin`, `sen.elf`)
   function identities come from embedded log/assert strings → xrefs → the containing function; names
   like `ExecRcAcquire` are the firmware's own log strings, not linker symbols.
3. **Decompile by address**, read the control flow, and quote the lines that support each claim.
4. **Cross-check** with `read_bytes` on tables, `list_xrefs` on globals (a global with one WRITE and no
   READ in-image means the consumer is elsewhere), and `disassemble` where the decompiler is blocked or
   the exact instruction bytes are the point.
5. **Record the boundary.** Where the trail reaches an image not in hand, a kernel module, the other
   processor, or a hardware root, stop and name it — do not guess past it.

Much of the digging was AI-assisted (GLM-5.3 via the Z.ai coding plan; a local Flash-Next model on a
Framework desktop driving Ghidra MCP over ~29 hours). **Every finding was then verified against the
binary by a separate pass** before it was recorded; AI "VERIFIED" tags were never trusted on their own.

---

## The verification policy

Every finding carries one of three labels. This is the key feature of the reference — it lets a reader
tell solid from inferred from out-of-image at a glance.

- **deep** — the claim is backed by a quoted decompilation *and* an independent cross-check (byte-verified
  table, a second decompile reaching the same conclusion, or a decompile of the real function body
  rather than a thunk). Example: the OSAL ioctl numbers, verified by decompiling the real `u_osal_*`
  bodies by address *and* reading the `movk`/`movz` immediates that build each request constant.
- **light** — the claim is backed by a decompilation or a byte read at a stated address, but rests on a
  single source: a catalog cross-reference, a strings/imports reading, or one decompile without an
  independent second check. Solid as far as it goes, but not corroborated two ways.
- **hypothesis** — an inference beyond what the decompiled code states: a payload identity read from
  caller context, a semantic label on a numeric field, a purpose read into a structure's shape, or
  anything that depends on an image not in hand. Always flagged inline in the raw studies as
  **HYPOTHESIS**, and surfaced in each finding's **Boundary / open** section.

A finding's header may be, say, "light overall" while individual sub-claims inside it are deep or
hypothesis; the **Verification** line gives the headline classification plus what was actually checked,
and the **Boundary / open** line says where the trail ends and why. The authoritative per-subsystem
verification index is the appendix table in
[framework-runs/CONSOLIDATED.md](../framework-runs/CONSOLIDATED.md).

---

## What is deliberately not here

- No firmware bytes, no key material, no license blobs, no credential values, no extracted binary
  content — only offsets, addresses, struct layouts, protocol fields, and short decompiled fragments
  used as evidence. Format constants (e.g. the `SECVAULT`/`DEADDEAD` record magics) are the only byte
  strings reproduced.
- No dynamic analysis beyond the single observe-only service-mode hardware session in
  [Investigation 2](../investigations/02-service-mode-and-auth.md) (no writes). Nothing was executed on
  a camera, no device was patched, and no live secret was dumped.
- The kernel side (`osal_uipc.ko`, `backup.ko`, `elpspacc*.ko`), the out-of-image key-service provider,
  and the main-SoC-side queue consumers are out of scope and recorded as boundaries.

For the one candidate firmware patch's risk write-up, see [docs/patch.md](../docs/patch.md). For the raw
per-subsystem studies with their full "How this was checked" sections, see
[framework-runs/](../framework-runs/).
