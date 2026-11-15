# Plugin command-verb map — Sony a7R V firmware (extracted filesystem)

Date: 2026-11-13. Static analysis only. Every claim below is backed by a command or tool
output actually run this session; anything reasoned beyond that is labelled **HYPOTHESIS**.
Background (established previously, not re-derived here): the app dispatches plugin verbs by
building names `command%04X` / `open%04X` / `close%04X` / `memory%04X` and `dlsym`-ing them
(`CreatePluginCommand` → `FUN_0010d584`); a missing `commandNNNN` yields a DiscardRecvData
object with status byte `0x80`.

## Part A — the real verb inventory

A genuine verb export is a **defined, exported dynamic symbol** whose name is exactly
`command`/`open`/`close`/`memory` + 4 hex digits. The regex below is anchored to end-of-line,
so mangled names that merely *contain* such a substring cannot match (see counter-example).

Command actually run (over all 188 `.so` files in `fs/a15/lib`; count from
`ls /srv/a7rv/a7rv-fw/fs/a15/lib/*.so | wc -l` → `188`):

```console
$ nm -A -D --defined-only /srv/a7rv/a7rv-fw/fs/a15/lib/*.so | grep -E ' (command|open|close|memory)[0-9A-Fa-f]{4}$'
/srv/a7rv/a7rv-fw/fs/a15/lib/libpro00.so:00000000000009a4 T command001F
/srv/a7rv/a7rv-fw/fs/a15/lib/libpro00.so:0000000000000a64 T command00F1
```

That is the **complete** output — the entire extracted a15 filesystem exports exactly **two**
genuine verb handlers, both from **`libpro00.so`**:

| Verb    | File offset | Type | Library        |
|---------|-------------|------|----------------|
| `0x001F`| `0x9a4`     | `T` (defined, exported text) | `fs/a15/lib/libpro00.so` |
| `0x00F1`| `0xa64`     | `T` (defined, exported text) | `fs/a15/lib/libpro00.so` |

No `openNNNN`, `closeNNNN`, or `memoryNNNN` exports exist anywhere in `fs/a15/lib`.
Bonus check beyond the required scope — the same anchored scan over **every** partition's
lib dir in the image (`/srv/a7rv/a7rv-fw/fs/*/lib/*.so`, partitions `a3 a5 a7 a8 a15` per
`ls /srv/a7rv/a7rv-fw/fs/`) returns the identical two lines, nothing else.

`file` output for the handler library:
```console
$ file /srv/a7rv/a7rv-fw/fs/a15/lib/libpro00.so
/srv/a7rv/a7rv-fw/fs/a15/lib/libpro00.so: ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV), dynamically linked, stripped
```

### Why the earlier "six plugins" claim was wrong (counter-example)

The previous claim was built on loose/substring matching. Reproduced on `libgpe.so`:

```console
$ nm -D --defined-only /srv/a7rv/a7rv-fw/fs/a15/lib/libgpe.so | grep -i 'command' | head -4
000000000000b03c W _ZN5mpgpe10RingBufferINS_7CommandEE4NextEv
000000000000b1f4 W _ZN5mpgpe10RingBufferINS_7CommandEED0Ev
000000000000b130 W _ZN5mpgpe10RingBufferINS_7CommandEED1Ev
000000000000b130 W _ZN5mpgpe10RingBufferINS_7CommandEED2Ev
```

These are mangled C++ members of `mpgpe::RingBuffer<mpgpe::Command>` — a case-insensitive
`command` search hits them; the anchored `^...$`-style regex above rejects them. (In fact an
unanchored `command[0-9a-f]{4}` regex yields **0** matches in libgpe —
`nm -D --defined-only libgpe.so | grep -cE 'command[0-9a-f]{4}'` → `0` — so the earlier
false positives came from an even looser pattern than verb-shaped-with-hex.)

## Part B — what the two handlers do

Ghidra project `ghidra_plugins`, program `/libpro00.so-1a073e`
(`list_project_binaries`: `analysis_complete: true`).

Symbol addresses from `search_symbols_by_name` (not assumed from `nm`):

```json
{"name":"command001F","address":"001009a4","type":"Function",...}
{"name":"command00F1","address":"00100a64","type":"Function",...}
```

Measured load base: Ghidra `0x001009a4` − `nm` file offset `0x9a4` = **0x100000** (same for
`0xa64`). Same search returned `_fini` at `0x00100a6c`, `_init` at `0x001007b8`.

### `command001F` @ 0x001009a4 — HASP (anti-piracy token) read / reset

Full decompilation (via `decompile_function`, with callees/strings/xrefs):

```c
undefined8 command001F(undefined8 *param_1)

{
  char cVar1;
  void *pvVar2;

  if (param_1[1] == 0) {
    return 0x81;
  }
  if (*(char *)*param_1 == '\0') {
    pvVar2 = operator_new__(0x58);
    param_1[3] = pvVar2;
    param_1[4] = 0x58;
    param_1[5] = operator_delete__;
    cVar1 = Read_Hasp();
    if (cVar1 == '\0') {
      cpp_logrec('\x01',"HASP Read Failed");
      param_1[4] = 0;
      return 0x82;
    }
  }
  else {
    if (*(char *)*param_1 != -0x80) {
      cpp_logrec('\x01',"InvalidParameter!");
      return 0x81;
    }
    cVar1 = Reset_Hasp();
    if (cVar1 == '\0') {
      cpp_logrec('\x01',"HASP Wrt Failed");
      return 0x82;
    }
  }
  return 1;
}
```

Walkthrough (all directly visible in the code above):

- **Argument:** one pointer `param_1` to an 8-byte-slot block. Measured uses:
  `param_1[1]` must be non-zero (else immediate `0x81`); `*param_1` points to a byte that is
  the **operation selector**; on the read path it writes a buffer pointer to `param_1[3]`,
  the capacity `0x58` (88) to `param_1[4]`, and the deleter `operator delete[]` to
  `param_1[5]`. *What the surrounding struct is (the dispatcher's in/out argument vector)
  is* **HYPOTHESIS** *— inferred from these slot writes, not from the dispatcher code.*
- **Selector `*param_1 == 0` → read:** allocates an 88-byte buffer and hands it to the caller
  (ptr/size/deleter triple in slots 3/4/5), then calls `Read_Hasp()`. If it returns 0: logs
  `"HASP Read Failed"`, zeroes the size slot `param_1[4]`, returns **`0x82`**. Success falls
  through to `return 1`.
- **Selector `*param_1 == 0x80` (shown as `-0x80` for signed char) → reset:** calls
  `Reset_Hasp()`. Failure → logs `"HASP Wrt Failed"`, returns **`0x82`**. Success → `return 1`.
- **Any other selector:** logs `"InvalidParameter!"`, returns **`0x81`**.
- **Return convention:** plain integer, not a tail-call — `1` = success; `0x81` = bad
  parameter; `0x82` = HASP hardware op failed. (Note the `0x80` here is an *input* selector
  byte, distinct from the dispatcher's `0x80` "missing symbol" status byte.)
- **Callees (from the tool's callee list):** `operator.new[]`, `cpp_logrec`, `Read_Hasp`,
  `Reset_Hasp`. **Strings referenced:** `HASP Read Failed`, `HASP Wrt Failed`,
  `InvalidParameter!`.
- **Xrefs (raw tool output):** `Entry Point`, `INDIRECTION` from `0x100ac4`, `DATA` at
  `0x100b20`. *That these two are the .dynsym/relocation table entries for the export, and
  that the only functional caller is the external `dlsym` path, is* **HYPOTHESIS** — the
  addresses were not resolved to section names this session.

HASP is SafeNet/Aladdin **H**ardware **A**nti-piracy **S**upport — i.e. verb `0x001F` is a
licence-dongle read (mode 0) / reset (mode 0x80) interface. *Interpretation of the acronym —*
**HYPOTHESIS** *(naming convention); the read/reset behaviour itself is measured above.*

**One level in — who provides `Read_Hasp`/`Reset_Hasp`?** They are *imports* of libpro00
(not in libpro00). Grepping the whole extracted fs for the name strings
(`grep -rl -e Read_Hasp -e Reset_Hasp /srv/a7rv/a7rv-fw/fs/`) hits three files; `nm` shows
which define them:

```console
$ nm -A -D --defined-only /srv/a7rv/a7rv-fw/fs/a15/lib/libObj.so /srv/a7rv/a7rv-fw/fs/a15/lib/libsencore.so | grep Hasp
/srv/a7rv/a7rv-fw/fs/a15/lib/libObj.so:00000000000ebd5c T Read_Hasp
/srv/a7rv/a7rv-fw/fs/a15/lib/libObj.so:00000000000ebc94 T Reset_Hasp
/srv/a7rv/a7rv-fw/fs/a15/lib/libsencore.so:0000000000014260 T Read_Hasp
/srv/a7rv/a7rv-fw/fs/a15/lib/libsencore.so:00000000000142f0 T Regist_HaspId
/srv/a7rv/a7rv-fw/fs/a15/lib/libsencore.so:0000000000014198 T Reset_Hasp
/srv/a7rv/a7rv-fw/fs/a15/lib/libsencore.so:000000000000c190 T _ZN19WorkerThreadManager12registHaspIdEi
```

So **two** libraries in the image define both functions, and neither imports them
(`nm -D | grep ' U .*Hasp'` on both → empty). Which one libpro00 actually binds at runtime
depends on link/load order — **unresolved**; not investigated further (one-level rule).
The bodies of `Read_Hasp`/`Reset_Hasp` were **not opened** this session and are not described
here. `libsencore.so` additionally exports `Regist_HaspId` and
`mpgpe`-unrelated C++ `WorkerThreadManager::registHaspId(int)`.

### `command00F1` @ 0x00100a64 — trivial always-success stub

Decompilation (complete — nothing elided):

```c
undefined8 command00F1(void)

{
  return 1;
}
```

Disassembly at 0x00100a64 (`disassemble`, `include_bytes=true`):

```
00100a64 20008052 mov w0,#0x1
00100a68 c0035fd6 ret
```

Stated plainly: **`command00F1` is a 2-instruction stub, not a tail-jump.** It takes no
arguments, calls nothing (callee list empty, no strings), and unconditionally returns `1`
(success) — a registered no-op that always acks the verb. Its span is exactly 8 bytes:
`0xa64` → `_fini` at `0xa6c` (both from the Ghidra symbol search above), consistent with the
two instructions shown. Xrefs (raw): `Entry Point`, `INDIRECTION` from `0x100acc`, `DATA` at
`0x100b50` — same table-entry pattern as above (same **HYPOTHESIS** caveat).

*Why* Sony ships a permanently-succeeding handler for verb `0x00F1` (feature placeholder?
license bypass? disabled feature?) cannot be determined from this binary — **unresolved**.

### libpro00.so imports (`list_imports`, complete list, all `<EXTERNAL>`)

```
operator.new[]   __cxa_finalize   operator.delete[]   Reset_Hasp   logrec
Read_Hasp        __gmon_start__   _ITM_deregisterTMCloneTable   _ITM_registerTMCloneTable   _Jv_RegisterClasses
```

Mapping to what the decompiler shows: `cpp_logrec` (decompiler name) = import `logrec`;
`operator_new__`/`operator_delete__` = `operator.new[]`/`operator.delete[]`. So the handlers'
reachable world is exactly: memory alloc/free, logging, the two HASP calls, and libc++/runtime
plumbing. `__cxa_finalize`, `__gmon_start__`, `_ITM_*`, `_Jv_RegisterClasses` are standard
ELF init/teardown references — none is called from the two verb handlers (their callee lists
contain only the four names above).

## Part C — scope statement

This inventory covers the **extracted a15 filesystem only**
(`/srv/a7rv/a7rv-fw/fs/a15/lib/*.so`, 188 shared objects), plus a bonus repeat of the same
anchored `nm` scan over the sibling partitions' `lib/` dirs present in the image
(`a3 a5 a7 a8`). Consequences:

- `libSnr.so`, referenced elsewhere as plugin-module id **`0xff02`, is absent from
  `fs/a15/lib/`** — checked this session: glob for `*Snr*` in that directory → no files.
- Verb handlers can therefore exist in modules that are simply **not in this image**, and
  would be invisible to any static inventory. The two handlers documented above are
  exhaustive *for this extraction*, not for the shipping camera.
- Module id `0xff03` was not re-investigated, per task scope.

## How this was checked

Binaries/files opened or scanned this session:
- `fs/a15/lib/*.so` (188 files) and `fs/*/lib/*.so` — `nm -A -D --defined-only` + anchored
  grep (Part A; command and full output inlined above).
- `fs/a15/lib/libpro00.so` — the Ghidra target (also `file`).
- `fs/a15/lib/libgpe.so` — `nm -D` (counter-example only; no code read).
- `fs/a15/lib/libObj.so`, `fs/a15/lib/libsencore.so` — `nm -D` (Hasp provider check only;
  no code read).

Ghidra (`ghidra_plugins`, program `/libpro00.so-1a073e`) — functions actually opened:
- `command001F` — `decompile_function` (full body inlined above).
- `command00F1` — `decompile_function` (full body) + `disassemble` (both instructions).
- Supporting: `list_project_binaries`, `search_symbols_by_name` (`command`, and
  `fini|init|memory|open|close`), `list_imports`.
- **Not opened:** `Read_Hasp`, `Reset_Hasp` (external, provided by libObj/libsencore —
  deliberately stopped at one level), `_init`/`_fini`/`_INIT_0`/`_FINI_0`.
