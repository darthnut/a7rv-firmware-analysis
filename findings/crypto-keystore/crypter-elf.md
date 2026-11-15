# `crypter.elf` — the crypt-file provisioning tool

**Summary.** A non-interactive factory/service tool that runs the camera's crypt-file write path against
a removable card and deletes the artifact afterward; it contains no crypto and no file I/O itself — all
of it is behind the `libcryptfileinputupdaterapi.so` boundary.

**Where.** `fs/a15/bin/crypter.elf` (10,352 bytes, AArch64, stripped; project `ghidra_extra`, Ghidra
VAs). `main` recovered as `FUN_00400bc0` from `_start`'s literal pool. 15 imports total; the whole tool
is argv parsing + `snprintf`/`strncmp` + five `Fsys_*` calls + three vtable calls.

**Mechanism.**
- **CLI:** four fixed tokens — `chunk=fdat|full` (writer chunk policy), `fs=fsys` (enable the Fsys
  mount path), and a filename. Without `fs=fsys` it calls no `Fsys_*` at all.
- **Target:** probes a two-entry device table (`/dev/mmca` first, `/dev/ms` fallback), mounts whichever
  removable medium is present, builds a DOS-style `<drive>:\<filename>` path.
- **The updater sequence:** `GetCryptFileInputModeUpdater()` returns an object; the tool drives its
  vtable `Initialize(+0x10)` → `StartWriting(+0x20)` → `Finalize(+0x18)` → `ReleaseMsCryptFileInputUpdater`,
  then `Fsys_Remove` the same path, unmount, exit. **The delete-after-success is the tell:** the on-card
  artifact is deliberately transient — a provisioning step whose payload lives inside the API.
- **Zero crypto, zero file I/O imports** (provable negatives): no `AES`/`EVP`/`crypt`, no
  `open`/`read`/`write`, no S-box/IV/key constants anywhere reachable from `main`. The cipher and key
  source live in the unloaded `libcryptfileinputupdaterapi.so`; `mcmn_init` is the only IPC-flavoured
  hook.

**Verification.** *light.* Control flow fully decompiled (~90 lines), vtable slot args and the
`fs=fsys`/`Fsys_Mount` branches confirmed at the instruction level, the 15-import boundary read from the
import table. The tool's *purpose* (manufacturing/service provisioning) is judgement built on the verified
control flow, flagged as inference.

**Boundary / open.** One genuinely open question: whether `StartWriting` **consumes** a plaintext input
from the card (encrypt-into-store) or **generates** the encrypted file there (then deletes it as a
write-path self-test). crypter.elf never opens the file, so direction is the library's decision —
settling it needs `libcryptfileinputupdaterapi.so`. Whether it shares the Backup store's cipher is
**HYPOTHESIS, mildly disfavoured**: the two front-ends are disjoint (Fsys/drive-letter vs OSAL/`SKData`),
but both hide their crypto below a boundary that names no algorithm. `crypter.elf` is unrelated to the
key service at QID `0x25906be` (it's a Memory-Stick crypt-file updater).

**Source.** [framework-runs/crypter-map.md](../../framework-runs/crypter-map.md)
