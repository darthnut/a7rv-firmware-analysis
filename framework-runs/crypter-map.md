# `crypter.elf` — encrypted-file tool map (Sony a7R V)

Static RE of the user's own a7R V firmware for a public write-up. Mechanism, offsets and paths
only. **No key bytes and no firmware binary are reproduced here.**

Subject: `/srv/a7rv/a7rv-fw/fs/a15/bin/crypter.elf`, analyzed in the Ghidra project
`ghidra_extra` as program `/crypter.elf` (analysis_complete, code+strings indexed).
All addresses are **Ghidra virtual addresses**.

Status: **complete** — A–D filled; open items marked inline and in the footer.

---

## A. What it runs

Argument/mode handling, the `Fsys_Mount` target, and the
`GetCryptFileInputModeUpdater` → write → `Finalize` sequence. What file is produced, and where.

### Artifact

`/srv/a7rv/a7rv-fw/fs/a15/bin/crypter.elf`, 10,352 bytes. ELF header (on-disk `od`, file offset 16):
`e_type = 0x0002` (ET_EXEC), `e_machine = 0x00b7` (**AArch64**), 64-bit (EI_CLASS 2). Ghidra
program `/crypter.elf`, analysis complete, code + strings indexed.

**Import boundary is the whole story.** The ELF has exactly **15 undefined symbols**
(`list_imports`, `/crypter.elf`):

```
Fsys_Init  Fsys_Mount  Fsys_Remove  Fsys_Unmount  Fsys_Exit
GetCryptFileInputModeUpdater  ReleaseMsCryptFileInputUpdater
mcmn_init
snprintf  strncmp  fprintf  fputs  abort  __libc_start_main  __gmon_start__
```

There is **no `open`/`read`/`write`/`fopen`/`fread`/`fseek`, no `malloc`/`memcpy`, and no crypto
symbol of any kind**. crypter.elf is a thin CLI driver: argv parsing, formatting, three virtual
calls, and mount/teardown bookkeeping. Everything substantive is behind the two
`*CryptFileInputUpdater` imports.

### Entry → `main`

The binary is stripped (only PLT thunks carry names), so `main` had to be recovered from `_start`.
`entry` @ `0x00400f20` is the standard AArch64 `_start`: `0x00400f38 ldr x0,0x400f50` pulls the
`main` pointer out of the literal pool at `0x00400f50`, which holds `c00b400000000000` →
**`0x00400bc0`**, then `0x00400f44 bl __libc_start_main`.

> **`main` = `FUN_00400bc0` @ `0x00400bc0`** (Ghidra auto-name). Confirmed at instruction level,
> not inferred from a name.

### Command line

`main` walks `argv[1..argc-1]` (`strncmp`) and sets four globals in the `0x412xxx` writable region:

| argument | effect |
|---|---|
| `chunk=fdat` | `DAT_00412094 = 0` |
| `chunk=full` | `DAT_00412094 = 1` |
| `fs=fsys` | `DAT_004120a4 = 1` |
| *anything else* | if `DAT_00412098 == NULL`, this argv becomes the filename |

First non-flag positional wins; later ones are ignored. A `chunk=` with any other value silently
leaves the default (which equals the `chunk=fdat` value, 0). Missing filename →
`"[crypter.elf] no filename\n"` @ `0x00401142`, exit 1.

### The `fs=fsys` gate

@ `0x00400d08-0x00400d10`: `ldr w19,[x21,#0xa4]` / `cmp w19,#1` / `b.ne 0x00400db4`.

Without `fs=fsys`, crypter.elf **calls no `Fsys_*` function at all** — no `Fsys_Init`, no mount,
no `Fsys_Remove`, no unmount. Note `0x00400d04 mov w0,#0` pre-zeroes the value that later becomes
the path-prefix length, so the path buffer gets no drive prefix and `StartWriting` is handed the
**bare filename** exactly as typed.

### `Fsys_Mount` target

With `fs=fsys`: `Fsys_Init()` @ `0x00400d14` (nonzero → `"[crypter.elf] Fsys_Init error 0x%x\n"` @
`0x0040115d`, return 1). Then a probe loop over a NULL-terminated device table, whose address
comes from `0x00400d58 adrp x19,0x401000` + `0x00400d60 add x19,#0x110` = **`0x00401110`**:

| address | contents | resolves to |
|---|---|---|
| `0x00401110` | `bf12400000000000` | `0x004012bf` = `"/dev/mmca"` |
| `0x00401118` | `c912400000000000` | `0x004012c9` = `"/dev/ms"` |
| `0x00401120` | `00…` | NULL — end of table |

Loop body @ `0x00400d68`: `ldr x0,[x20,x19]` (scaled register load), `0x00400d6c cbz x0` on the
terminator, then `Fsys_Mount(dev, 0, &DAT_004120a0, 0)` with the out-param built from
`0x00400d5c adrp x23,0x412000` + `0x00400d64 add x24,#0xa0` → `0x004012a0`, passed as x2 @
`0x00400d70`. It iterates until `DAT_004120a0 != 0`.

> **Target = whichever removable medium is actually present, `/dev/mmca` probed first, `/dev/ms`
> as fallback.** Not a fixed partition: a two-candidate probe.

All candidates failing → `"[crypter.elf] Fsys_Mount error. devices not found\n"` @ `0x00401186`, exit 1.

### Path construction

`Fsys_Mount`'s third argument is an **out-param returning a drive letter**, and that letter is fed
straight into the path:

```
0x00400d8c  ldrb w3,[x23,#0xa0]      ; w3 = DAT_004120a0 = drive letter from Fsys_Mount
0x00400d90  cbz  w3, 0x00400dfc      ; still zero -> "devices not found"
0x00400d9c  add  x2,x2,#0x181        ; x2 = 0x00401181 = "%c:\"
0x00400da0  add  x0,x0,#0xa8         ; x0 = 0x004120a8 = path buffer
0x00400da4  mov  x1,#0x400           ; size 1024
0x00400dac  bl   snprintf            ; snprintf(buf, 0x400, "%c:\\", drive)
```

The format string at `0x00401181` is the bytes `25 63 3a 5c 00` = `%c:\` + NUL — a **single**
backslash (source would read `"%c:\\"`). A second `snprintf` @ `0x00400dd8` (`x2 = 0x004011b9` =
`"%s"`, dst `0x00400dd4 add x0,x20,x0` = buffer + previous length, size `0x400 - length` @
`0x00400dcc`) appends the filename.

> **Produced path: `<drive>:\<filename>`** — e.g. `R:PROV.BIN` — in a 1 KiB static buffer at
> `0x004120a8`. DOS-style drive-letter namespace provided by the Fsys layer, not by the kernel
> VFS (`/dev/mmca`, `/dev/ms` are the underlying block devices).

### The updater sequence

`GetCryptFileInputModeUpdater()` is called @ `0x00400ddc`. **It takes no arguments**: between the
`snprintf` returning at `0x00400dd8` and the `bl`, no argument register is written — the
decompiler's `GetCryptFileInputModeUpdater(iVar1)` is an artifact of `iVar1` still being live, not
a real parameter. (Worth stating because it means the path is *not* handed over at object
creation; it arrives later, at `StartWriting`.)

It returns a pointer to an object whose first member is a vtable. Three slots are used:

| address | instruction | vtable slot | call | args |
|---|---|---|---|---|
| `0x00400e20` | `blr x2` | `+0x10` | **Initialize** | x0 = object, x1 = `DAT_00412094` chunk mode (`ldr w1,[x1,#0x94]` @ `0x00400e1c`) |
| `0x00400e4c` | `blr x2` | `+0x20` | **StartWriting** | x0 = object, x1 = `0x004120a8` path buffer (`mov x1,x20` @ `0x00400e40`) |
| `0x00400e74` | `blr x1` | `+0x18` | **Finalize** | x0 = object only |
| `0x00400e94` | `bl 0x00400b50` | — | `ReleaseMsCryptFileInputUpdater` | x0 = object |

Slots `+0x00` and `+0x08` are never referenced — the interface has ≥5 slots and crypter.elf uses 3.

Each returns an `int`; nonzero jumps to `LAB_00400cf0` (`fputs` + return 1). The error strings
*independently corroborate* the slot→name mapping, because their addresses fall out of the exact
string layout in `.rodata`:

- `0x004011ee` `"[crypter.elf] Initialize error\n"` — 32 bytes → `0x0040120e`
- `0x0040120e` `"[crypter.elf] StartWriting error\n"` — 34 bytes → `0x00401230`
- `0x00401230` `"[crypter.elf] Finalize error\n"`

…loaded respectively by the failing branches at `0x00400e34` (`add #0x1ee`, after slot `+0x10`),
`0x00400e60` (`add #0x20e`, after slot `+0x20`), and `0x00400e88` (`add #0x230`, after slot
`+0x18`). Three separate slots, three distinct named stages, in matching order.

### Teardown — and the detail that defines the tool

Only in the `fs=fsys` case (re-checked @ `0x00400e98 ldr w0,[x21,#0xa4]` / `cmp w0,#1`), and only
after `Finalize` returned 0 and the object was released:

```
Fsys_Remove(&DAT_004120a8)      ; the SAME path buffer handed to StartWriting
Fsys_Unmount(DAT_004120a0, 0)   ; drive handle from the probe
Fsys_Exit(...)
```

Each is checked and its failure logged (`Fsys_Remove error 0x%x`, `Fsys_Unmount error 0x%x`,
`Fsys_Exit error 0x%x`) but **non-fatal** — the tool still returns 0.

> **What file, where:** `<drive>:\<filename>` on the mounted `/dev/mmca` or `/dev/ms` medium, in a
> 1 KiB buffer at `0x004120a8`. But crypter.elf **never creates or writes it itself** — it has no
> I/O imports. Creation/writing happens inside `libcryptfileinputupdaterapi.so` during
> `StartWriting`/`Finalize`, and the tool **deletes the path afterwards**. So its net observable
> effect on the card is *transient*: the artifact is gone when it exits.

## B. The crypt path

What `CryptFileInput`/the updater does; whether the encryption lives in this ELF or behind an
import boundary; visible block size / mode; key *source* mechanism only.

### The encryption is not in this ELF — and that is provable, not merely absent

Three independent negatives, all from the import table and string pool:

1. **Zero crypto imports.** All 15 undefined symbols are listed in §A — no `AES_*`, `EVP_*`,
   `arc4random`, `sha*`, no vendor `ut_*`/`sce*` crypto symbol, and no crypto-named library is
   pulled in beyond the updater API itself.
2. **Zero file I/O imports.** No `open`/`read`/`write`/`fopen`/`fread`/`fseek`/`stat`. The ELF
   cannot read a keyfile, read an input file, or write the output file. Even the file's existence
   is only reachable through `Fsys_Remove`.
3. **No crypto constants.** The whole initialized-data/string region reachable from `main`
   (`0x00401108`–`0x004012bf`, read raw) contains only: the two device pointers, the argv tokens
   `chunk=`/`fdat`/`full`/`fs=`/`fsys`, the `%c:\` and `%s` formats, and the `[crypter.elf] …`
   error strings. No S-box, no round constants, no IV, no key blob, no key path.

The control flow is equally bare: `main` is ~90 decompiled lines and every operation is either
argv parsing, `snprintf`/`strncmp`, one of the 5 `Fsys_*` calls, or the 3 vtable calls. There is
no arithmetic loop that could be a cipher.

### The import boundary, named

| symbol | PLT thunk | external slot | provider |
|---|---|---|---|
| `GetCryptFileInputModeUpdater` | `0x00400b90` (also `0x00413050`) | `<EXTERNAL>::…@00000007` | `libcryptfileinputupdaterapi.so` |
| `ReleaseMsCryptFileInputUpdater` | `0x00400b50` (also `0x00413048`) | `<EXTERNAL>::…@00000006` | `libcryptfileinputupdaterapi.so` |

plus the **vtable reached through the returned object** — `+0x10` Initialize, `+0x18` Finalize,
`+0x20` StartWriting — which is a second, non-symbol boundary: those three entry points have no
names in crypter.elf at all and are reached only by computed `blr` through the object pointer.

The provider library **is present on disk** — `a7rv-fw/fs/a15/lib/libcryptfileinputupdaterapi.so`,
27,072 bytes, same firmware volume as crypter.elf — but is **not among the three programs loaded
in `ghidra_extra`** (`/crypter.elf`, `/libBackupManager.so`, `/libObj.so`). This run was
restricted to read-only Ghidra tools, so it was not imported and its internals are **unexamined
here**. The linkage itself is taken from the firmware brief plus the confirmed undefined symbols;
I did not resolve `DT_NEEDED` (the extraction command needed approval I did not press).

### Block size / mode: nothing observable, and no temptation to invent one

There is **no block size, cipher mode, or key length visible anywhere in crypter.elf**. The only
mode the ELF exposes is the `chunk` flag:

- `chunk=fdat` → `0`, `chunk=full` → `1`, passed as the second argument of `Initialize`
  (`0x00400e1c`/`0x00400e20`).

That is a **chunking/flush policy for the writer, not a cipher mode** — it selects how the payload
is pushed through the updater, and its meaning is decided inside the unloaded .so.
*HYPOTHESIS, unprovable from this ELF:* `full` writes the crypt file in one pass while `fdat`
commits it in chunks with a flush per chunk (the token reads like "flush data"). Not evidence —
a reading of one string.

### Key source mechanism

No key material, key name, keyfile path, or key derivation code exists in crypter.elf. What the
ELF *does* show about where the work goes:

- `mcmn_init()` is called @ `0x00400d00`, immediately **before** the updater sequence, and is
  **never paired with an exit/teardown** — the only import in the whole binary that smells of
  inter-task or inter-processor setup.
- The ELF has no file I/O and no crypto, yet `Fsys_Mount` is done *by the tool* rather than by the
  library — i.e. crypter.elf stages the medium, then hands a drive-lettered path to an API that
  performs the actual reads/writes and the cryptography.

*HYPOTHESIS (mechanism-level, flagged):* key handling — and therefore any real cipher — lives in a
**separate security task or hardware engine reached over that IPC boundary**, with
`libcryptfileinputupdaterapi.so` as the client stub. This is the shape the import set implies; the
specific engine is **not identified** here, and no key bytes were sought or found. Per the task
constraint, only the *source mechanism* is described.

### One genuinely open question in the crypt path

The path buffer is passed to `StartWriting` @ `0x00400e4c` **and** to `Fsys_Remove` at teardown.
Both are consistent with the ELF as seen:

- **(a) input-consumed** — the card holds a plaintext "crypt file input"; the API encrypts/ingests
  it into the camera's secure store and the tool then deletes the plaintext from the card
  (consistent with the name `CryptFileInput`, and with the `Ms` prefix on `ReleaseMs…` — Memory
  Stick).
- **(b) output-generated-then-cleaned** — the API *generates* the encrypted file at that path from
  data inside the library, and the delete makes the whole run an artifact-free **write-path
  self-test**.

I cannot distinguish these from crypter.elf: it never opens the file, so which direction the bytes
move is entirely the library's decision. **Settling it requires `libcryptfileinputupdaterapi.so`**
(check whether it opens the path for read vs write). This is the single highest-value follow-up.


## C. Role

One-paragraph judgement of what the tool is for, and whether it shares the Backup store's cipher.

### The Backup store, for comparison (it *is* in reach)

`/libBackupManager.so` is loaded in the same project. It is also stripped: its crypto surface
survives only as **exported names in `.dynstr`**, not as analyzable functions — decompiling
`_ZNK13BackupManager13BackupManager21writeBackupEncryptionEtjPKv` fails with *"Function or symbol
not found"*; the mangled name exists only as a string (`0x00100913`). The three relevant names:

| address | demangled shape |
|---|---|
| `0x00100864` | `BackupManager::isReadDataEncrypt(unsigned char const*, unsigned long long) const` |
| `0x00100913` | `BackupManager::writeBackupEncryption(unsigned short, unsigned int, void const*) const` |
| `0x0010095a` | `BackupManager::readBackupDecryption(unsigned int, void*) const` |

So the Backup store is **record-level**: encrypt on write, decrypt on read, with a per-buffer
`isReadDataEncrypt` predicate deciding whether a given region is encrypted at all (i.e. encryption
is selective/opt-in per record).

Its 18 imports are the more interesting evidence: **no crypto import of any kind**, no
`AES`/`crypt`/`cipher`/`key` string, and **no `Fsys` string anywhere in the library**. What it does
import is a completely different stack:

```
SKData_Init, SKData_Exit                              <- Sony SKData media layer
osal_snd_msg, osal_snd_sync_msg, osal_valloc_msg_wait,
osal_free_msg, osal_set_msg_src                       <- OSAL message-passing IPC
Backup_get_datasize, Backup_read                      <- the actual backup store accessors
```

### Judgement

**crypter.elf is a non-interactive factory/service-mode driver that runs the camera's crypt-file
write path against a removable card, and leaves nothing behind.** It is not a user-facing utility:
there is no usage/help string, no option parsing beyond four fixed tokens, no error recovery, and
no way to influence it beyond `filename`, `chunk=fdat|full`, and `fs=fsys`. It mounts whichever of
MMC-A or Memory Stick is present, builds a DOS-style `<drive>:\<name>` path, drives a
`Initialize → StartWriting → Finalize → Release` state machine over it, then **deletes that exact
path and unmounts**. The delete-after-success is the tell: this tool exists to make the crypt-file
pipeline *happen once, correctly, on real media* — a provisioning step whose payload lives inside
the API and whose on-card artifact is deliberately transient — which is the shape of a
manufacturing/service-path flow (flash a provisioning or settings crypt file, or validate that the
write path works on a card in that unit), not of producing a file anyone will use. The
`chunk=fdat|full` switch being operator-selectable fits a production line choosing between a
chunked write and a whole-file write depending on the artifact. *This paragraph is judgement
built on the verified control flow; the purpose attribution is inference, not a claim from a
string.*

**Does it share the Backup store's cipher? HYPOTHESIS — not provable, and mildly disfavoured.**

*Structurally parallel:* both are thin front-ends in the same firmware volume, both stripped, and
**both do their cryptography below a boundary that exposes no algorithm** — no crypto import and no
crypto string in either one. Neither names a cipher, a block size, or a key source. Whatever the
algorithm is, it is not in either of these libraries' observable surface.

*Toward "different subsystems":* their front-end stacks are disjoint in a way that is real
evidence, not absence. crypter.elf reaches storage through **`Fsys_*` over a DOS drive-letter
namespace on `/dev/mmca`/`/dev/ms`**, with `mcmn_init` as its only IPC hook. libBackupManager.so
never touches `Fsys` (zero matching strings) and instead talks over **OSAL message IPC to an
`SKData`/`Backup_read` backend**. Two different storage abstractions and two different IPC
primitives. That makes a *shared code path* unlikely, though it says nothing directly about
whether the two backends ultimately use the same cipher.

*Why it cannot be settled:* a cipher-sharing claim requires comparing implementations, and on
neither side is one visible — crypter.elf's crypto is inside `libcryptfileinputupdaterapi.so`
(unloaded), and BackupManager's is either hand-rolled inside its stripped `.so` or, given that all
its data movement is `osal_snd_msg`/`osal_snd_sync_msg` IPC to `Backup_read`, over the wire in
another module. **Any statement that they use the same cipher would be unsupported.** To close it:
import `libcryptfileinputupdaterapi.so` and the `Backup_read`/`SKData` provider, then compare their
crypto routines and key-schedule constants.

## D. Scope / safety

- **Everything here is mechanism**: offsets, code paths, argument syntax, API boundaries, and
  which device is probed. No key bytes, no key material, no derived secrets, and no firmware or
  ELF binary content are reproduced. Raw bytes appear only as (a) 12 bytes of ELF identification
  header, (b) pointer-table entries and the short ASCII strings needed to prove a code path —
  device names, argv tokens, format strings and error messages.
- **No key was sought or extracted.** §B describes only the *source mechanism* for key handling,
  and explicitly notes that the key itself is unreachable from this ELF. No memory dump, no
  runtime capture, no cryptanalysis, no attempt to recover or validate any key.
- **No crypto was attacked, broken, or bypassed.** The finding is that this ELF contains none.
- **No writes.** Analysis was static and read-only on a firmware copy. The Ghidra project was used
  read-only: no binary was imported, no rename/comment/type mutation, no `save` — the project was
  left exactly as found. Nothing was run, mounted, or executed: `crypter.elf` is an AArch64 binary
  for a camera, and executing it would have touched the very storage device the document describes.
- **Ownership.** This is the user's own Sony a7R V firmware, extracted from their own device, for
  a public write-up. The tool is a manufacturing/service utility on a memory card the owner
  controls; the documented invocation syntax is not an attack technique and requires physical media
  in the owner's camera.
- **Real-world impact of the syntax, stated plainly:** running `crypter.elf <name> fs=fsys` on a
  live camera would mount the card and delete `<drive>:\<name>` on success (the `Fsys_Remove`
  guarded by `cmp w0,#1` @ `0x00400e9c`). That is data destruction on a card the
  user owns, which is why this document records the behavior rather than exercising it.
- **One caveat carried forward:** the drive letter, the exact file the API creates, and the cipher
  itself all live in `libcryptfileinputupdaterapi.so`, which is outside the loaded Ghidra project.
  §B/§C mark every claim that depends on it.

## How this was checked

All work was done through the read-only `ghidra_extra` MCP tools against the already-loaded
program `/crypter.elf` (plus `/libBackupManager.so` for §C). Every address is a **Ghidra virtual
address**, and every claim above cites the call that produced it.

| step | tool + arguments | what it established |
|---|---|---|
| 1 | `list_project_binaries` | gate passed; 3 programs loaded, incl. BackupManager for §C |
| 2 | `decompile_function(main)` | *not found* → binary is stripped |
| 3 | `search_symbols_by_name(main\|start\|crypt…, functions_only)` | only PLT thunks named; both crypt-API thunks present |
| 4 | `list_xrefs(00400b20, 00413040, 00400b90, 00400b50)` | `FUN_00400bc0` is the sole caller of both crypt APIs → candidate `main` |
| 5 | `decompile_function(FUN_00400bc0, callees, strings)` | full control flow (~90 lines), argv tokens, all error strings |
| 6 | `list_imports(/crypter.elf, limit 60)` | **15 imports total; no crypto, no file I/O** |
| 7 | `read_bytes(0x00401108, 64)` / `read_bytes(0x004012bf, 32)` | device table `0x401110`/`0x401118` + NULL; `"/dev/mmca"`, `"/dev/ms"` |
| 8 | `od -j16 -N12` on the on-disk ELF | `e_type=ET_EXEC`, `e_machine=0xb7` AArch64 |
| 9 | `disassemble(0x00400da8, 18)` / `(0x00400e10, 36)` / `(0x00400d00, 30)` / `(0x00400d8c, 12)` / `(0x00400f18, 14)` | vtable slots + register args; `GetCryptFileInputModeUpdater` takes no args; `fs=fsys` branch; `Fsys_Mount` out-param → `%c`; literal pool → `main` |
| 10 | `read_bytes(0x00400f50, 24)` | literal pool = `0x00400bc0` → `main` confirmed |
| 11 | `read_bytes(0x00401120, 288)` | string pool: `%c:\` single backslash, no key/path strings |
| 12 | `search_strings(/libBackupManager.so, …)` | `crypt` hit 3 mangled names; `AES` and `Fsys` → **0 results**; matcher is case-sensitive literal, so queries were re-issued per case |
| 13 | `list_imports(/libBackupManager.so, limit 45)` | 18 imports: no crypto, `SKData_*`, `osal_*` IPC, `Backup_read` |
| 14 | `decompile_function(_ZNK13BackupManager…writeBackupEncryptionEtjPKv)` | *not found* → names are `.dynstr` exports only, BackupManager is stripped |

**Method notes and honest caveats.**

- **Instruction level, not just pseudocode.** Ghidra's pseudocode was wrong in one place that
  matters — it rendered `GetCryptFileInputModeUpdater(iVar1)` as if the path length were an
  argument. The disassembly at `0x00400dd8→0x00400ddc` shows no argument register written between
  the two `bl`s, so it is argument-less. The `%c` argument and the vtable slot arguments were also
  taken from registers, not from pseudocode.
- **String addresses were re-derived from instructions.** An offset read off the raw dump by hand
  gave `0x40119f` for `%c:\`; the `add x2,#0x181` at `0x00400d9c` gives **`0x401181`**. The
  instruction wins, and the §A table uses it. The slot→error-string mapping was then cross-checked
  by exact string-length arithmetic (32 and 34 bytes), which it satisfies.
- **`DT_NEEDED` was not resolved.** The `python3`/`od` pipeline that would have confirmed the
  dependency name from the dynamic section needed sandbox approval; I did not press it. The
  provider attribution in §B therefore rests on the firmware brief plus the confirmed undefined
  symbols plus the library's confirmed on-disk presence, and is labelled as such.
- **Not done, deliberately:** `libcryptfileinputupdaterapi.so` was not imported (read-only
  constraint), so §B's chunk-mode semantics, the input-vs-output question, and §C's cipher-sharing
  question are all left as marked HYPOTHESIS rather than answered.
- **Process deviation:** the task asked for a running TodoWrite list. No task-list tool was
  available in this session (`TodoWrite` is not exposed; `TaskCreate` is deferred). The job was
  single-pass and short enough that the deliverable stayed the focus — the file was created
  immediately after the first-step gate and every section was filled from cited evidence, but there
  is no task log to point at.
- **Reproduce it:** `main` at `0x00400bc0`, device table at `0x00401110`, vtable calls at
  `0x00400e20` / `0x00400e4c` / `0x00400e74`, mount-probe branch at `0x00400d10`,
  `Fsys_Remove` at the `0x00400e9c` branch. Any of these can be checked against the table above.
