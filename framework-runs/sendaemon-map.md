# sen.elf — the a7R V SENSER service daemon (a15)

Static reverse-engineering map of `fs/a15/bin/sen.elf`, the process behind the factory/service
channel whose authentication was decoded in Investigation 2. Offsets and mechanism only; no key
material, no firmware bytes.

**Binary as loaded in Ghidra project `ghidra_svc`:** `/sen.elf` (on-disk
`/srv/a7rv/a7rv-fw/fs/a15/bin/sen.elf`), AArch64, ET_EXEC-style PIE-less load at image base
`0x400000`. All addresses below are **Ghidra virtual addresses** (on-disk file offsets differ).
Analysis state: `analysis_complete: true`, `code_indexed: true`, `strings_indexed: true`
(`list_project_binaries`).

**Symbol status:** the binary is stripped of local symbols. There is **no `main` symbol** —
`search_symbols_by_name("^main$")` returns `[]`. The real `main` is recovered from the entry
stump (see §A.1). Ghidra auto-names (`FUN_xxxxxx`) are used throughout.

## A. Daemon structure

sen.elf is **small**: 62 `FUN_*` functions plus `_init`/`entry`/`_fini`, all within
`.text` `0x401858`–`0x403c98` (~9.3 KB). It is a thin **supervisor/loader shell**: it reads a
mode word, registers one OSAL queue callback, `dlopen`s `libsencore.so`, calls two named entry
points in it, and then runs a generic `poll()` reactor. It contains **no verb handler itself**
(see §B).

### A.1 Entry → main

`search_symbols_by_name("^main$")` → `[]`. `list_exports` shows only `entry` @ `0x401e08`,
`_init` @ `0x401858`, `_fini` @ `0x403c98`, and the `_bss`/`_edata` markers.

`decompile_function("0x401e08")` — the entry stump hands **`FUN_00401cb0` to `__libc_start_main`
as `main`**:

```c
void entry(undefined8 param_1) {
  __libc_start_main(FUN_00401cb0, in_stack_00000000, &uStack0000000000000008,
                    FUN_00403c08, &DAT_00403c80, param_1);
  abort();
}
```

So **`main` = `FUN_00401cb0`** (evidence: it is the first argument of `__libc_start_main` at
`0x401e20`, confirmed by an `INDIRECTION` xref from `0x4040e8`).

`main` itself is a two-branch stub (`decompile_function("0x401cb0")`):

| `argc` | Behaviour |
|---|---|
| `argc != 2` | **daemon path**: log `"PROCESS_START-%d"` with `getpid()` via `FUN_00402468` (record type `0x184`), then `FUN_00402a60()` (mode), `FUN_00401f80()` (register + core start), then `FUN_00402e58(&DAT_00416240)` — the reactor, which never returns (`do {…} while(true)`). |
| `argc == 2` | CLI stub: `strcmp(argv[1],"-v")` → prints `" 1.3.4 / 2012.8.23"`; `"‑b"` → `" [ built options ]"` + `" PRINT_METHOD : OSAL"`; anything else → `" v\tVERSION"` / `" b\tBUILT OPTIONS"`. Then `exit(0)`. |

Two facts worth noting for the service-mode picture: the build banner says
**`PRINT_METHOD : OSAL`** (this binary's log output is deliberately routed over OSAL IPC, which
§A.5 confirms), and the version stamp is the string `" 1.3.4 / 2012.8.23"`.

### A.2 Initialization — `FUN_00402a60` (SENSER mode) and `FUN_00401f80` (core start)

`FUN_00402a60` @ `0x402a60` — resolves and caches the **SENSER mode word**:

```c
iVar1 = access("/setting", 0);
pcVar2 = (iVar1 == 0) ? "/setting/sen/smode" : "/boot/sen/smode";
DAT_00416228 = FUN_00402808(pcVar2);              /* read int from file */
FUN_004028d0((undefined1)DAT_00416228, "/var/.sen/", "/var/.sen/.smode");
... FUN_00402468(&local_20);                      /* log "SENSER_MODE = %d" */
```

`DAT_00416228` is the global mode; `FUN_00402b60` @ `0x402b60` is a one-line accessor
(`return DAT_00416228;`). So the mode is a **persisted integer on disk**, read from
`/setting/sen/smode` when `/setting` exists, else `/boot/sen/smode`, mirrored into
`/var/.sen/.smode`.

`FUN_00401f80` @ `0x401f80` — the real startup, and the only registration site:

```c
if ((DAT_00416288 == 0) &&
    (iVar2 = osal_reg_sync_msg_queue_cb(0x3d032e, &DAT_00416288, FUN_00402020), iVar2 != 0))
    FUN_00401f4c(0xffffff81, "Failed to regist callback.");
iVar2 = FUN_00402b60();                            /* senser mode */
if (iVar2 == 0) return;                            /* mode 0 => no core, log loop only */
cVar1 = FUN_00402b84(&DAT_00416238, &DAT_00416240);
if (cVar1 == '\0') { FUN_00401f4c(0xffffff81, "SENSER CORE module start failed!"); abort(); }
FUN_00402c94(&DAT_00416238);
return;
```

Two objects live in `.bss`: **`DAT_00416238`** = the `libsencore` module handle/manager, and
**`DAT_00416240`** = the poll reactor that `main` runs. Note the gate: **if `SENSER_MODE == 0`,
`FUN_00401f80` returns before loading anything** — the daemon then runs only the reactor with an
empty fd set (see §A.4, the `sleep(1)` spin).

`FUN_00402b84` @ `0x402b84` is where the real service core is acquired:

```c
cVar1 = FUN_00402b78();                            /* dlopen("libsencore.so") */
if (cVar1 == '\0') return 0;
UNRECOVERED_JUMPTABLE = (code *)FUN_00403a20(param_1, "senser_usb_mode_start");
uVar2 = (*UNRECOVERED_JUMPTABLE)(param_2);         /* senser_usb_mode_start(&reactor) */
```

and `FUN_00402c94` @ `0x402c94` calls a second named entry point, `**"sens_adjCmd_init"()`**,
guarded by `*param_1 != 0` (handle non-NULL). `FUN_00403a20` @ `0x403a20` is a plain `dlsym`
wrapper (`lVar1 = dlsym(*param_1); if (lVar1 == 0) FUN_004039b4(...); return lVar1;`), and
`FUN_00402b78` @ `0x402b78` is `FUN_004039d4(param_1, "libsencore.so")` — `dlopen`.
Strings `"libsencore.so"`, `"senser_usb_mode_start"`, `"sens_adjCmd_init"` are all present in
the binary (returned in the `referenced_strings` field of those decompiles).

**Consequence for the whole picture:** sen.elf *hosts* the SENSER core by `dlopen`ing
`libsencore.so` and calling `senser_usb_mode_start(reactor)` + `sens_adjCmd_init()`. The verb
logic is therefore in libsencore, not in sen.elf (see §B). The `senser_usb_mode_start` name is
also the direct evidence that the service channel here is the **USB** path, and that libsencore
is the component handed the reactor.

The suspend/resume twin of `FUN_00402b84`/`FUN_00402c94` is `FUN_00402c40` (stop core) and
`FUN_00402cbc` (deinit) — same dlsym-by-name pattern (called from `FUN_00402020`, §A.3).

### A.3 OSAL queues — QIDs registered and used

`list_imports` shows sen.elf imports **exactly seven OSAL functions**, and no async-queue
registration API at all — there is **no `osal_reg_msg_queue_cb`** and **no `osal_rcv_msg_tmo`**
in this binary:

`osal_reg_sync_msg_queue_cb`, `osal_snd_sync_msg`, `osal_snd_sync_direct`, `osal_snd_msg`,
`osal_valloc_msg_wait`, `osal_set_msg_src`, `osal_free_msg`.

Complete QID inventory (every OSAL call site is inside just two functions, `FUN_004021a4` and
`FUN_0040213c`, plus the one registration — verified by `list_xrefs` on all PLT thunks
`0x401be0`, `0x4018d0`, `0x401980`, `0x4019e0`, `0x4018f0`, `0x401c10`, `0x401c80` and their
`0x417xxx` twins; all returned call sites only inside `FUN_00401f80`, `FUN_004020c0`-family
wrappers, `FUN_004021a4`, `FUN_0040213c`):

| QID | Direction / API | Role | Evidence |
|---|---|---|---|
| **`0x3d032e`** | **registered** sync-queue callback → `FUN_00402020`, token `&DAT_00416288` | Power/suspend-resume control for this process | `decompile_function("0x401f80")`, `osal_reg_sync_msg_queue_cb(0x3d032e, &DAT_00416288, FUN_00402020)` |
| **`0x8f013a`** | send — `osal_valloc_msg_wait(0x8f013a,…)` + `osal_set_msg_src(…,0x8f013a)` + `osal_snd_msg(0x8f013a,…)` | Log sink (the documented a15 log collector) | `decompile_function("0x4021a4")` @ `0x40233c`/`0x402398`/`0x4023b8`/`0x4023f0` |
| **`0x8f0313`** | send — `osal_snd_sync_msg(0x8f0313,…)` + `osal_free_msg` | Log-path error notification (payload length 0) | `decompile_function("0x4021a4")`, failure branch @ `0x402400` |
| **`0x910042`** | send — `osal_snd_sync_direct(0x910042,&local_20)` | Time-of-day query (request len `0x20`, reply yields 2 words → sec/nsec) | `decompile_function("0x40213c")` @ `0x402178` |

`0x8f013a` is already decomposed in `gptoss-out/osal-uipc-map.md` (module `0x08f`, index
`0x013a`, local scope — §"The connect targets `0x8f013a` and `0x94020a`"), which matches the
header sen.elf writes: the log message's 2-byte prefix is `{subtype, 0x3d}` — see below.

**The QID `0x3d032e` callback is power management, not the service channel.**
`decompile_function("0x402020")` — payload is a **single status byte**:

```c
if (*param_1 == '\0') { FUN_00401f4c(0xffffff84, "PROCESS_RESUME"); FUN_00401f80(); return; }
if (*param_1 != '\x01') { FUN_00401f4c(0xffffff81, "get power status failed"); abort(); }
iVar2 = FUN_00402b60();                    /* senser mode */
if (iVar2 != 0) { FUN_00402cbc(&DAT_00416238);
                  if (FUN_00402c40(&DAT_00416238,&DAT_00416240) == 0) { /* "SENSER CORE module stop failed!" */ abort(); } }
FUN_00401f4c(0xffffff84, "PROCESS_SUSPEND");
```

i.e. byte `0` = resume → full re-init (re-`dlopen`/re-`senser_usb_mode_start`); byte `1` =
suspend → stop + deinit the core; any other value → `abort()`. This is the same
register-once/re-init-on-resume pattern documented for other a15 daemons, and it is the reason
`DAT_00416288` guards double registration.

### A.4 Receive loop — `FUN_00402e58`, a `poll()` reactor with C++ fd-handler objects

`decompile_function("0x402e58")` (the reactor `main` runs; ~150 lines, read in full). Object
layout at `param_1` (= `&DAT_00416240`):

| Offset | Field |
|---|---|
| `+0x08` | `std::_Rb_tree` header (registered fd entries) |
| `+0x18` | tree root/`leftmost` link walked by the loop |
| `+0x28` | count of "spare" pollfd slots to keep reserved |
| `+0x30` | `std::vector<pollfd>` begin |
| `+0x38` | vector end |
| `+0x40` | vector capacity end |
| node `+0x20` | the **fd** (int key) |
| node `+0x28` | pointer to a **handler object with a vtable** |

Loop body, in order:

1. `pthread_testcancel(); if (*(param_1+0x28) == 0) { sleep(1); continue; }` — **the reactor
   idles at 1 Hz while no fd is registered.** Since fd registration happens in
   `senser_usb_mode_start` (libsencore), the empty-fd spin is what sen.elf does when the core is
   absent (e.g. `SENSER_MODE == 0`).
2. Grow/trim the `pollfd` vector (`operator_new`/`memmove`/zero-fill 8-byte `pollfd`s,
   `std::__throw_length_error("vector::_M_default_append")` on overflow).
3. Walk the rb-tree with `std::_Rb_tree_increment` and copy each fd into a `pollfd` with
   `events = POLLIN` (`*(ushort *)(puVar8+6) = 0; *puVar8 = uVar2;` — `revents` cleared, `fd`
   written).
4. `iVar3 = poll(*(param_1+0x30), nfds, -1);` — **indefinite blocking poll**, then
   `FUN_00402d44(4, "EVENT ready:%d", iVar3)`.
5. `if (iVar3 < 1)` → log `"poll error! - errno is %d"` (level `0xffffff81`) and loop again —
   **no `EINTR`/`poll` failure is fatal.**
6. For each `pollfd` with `revents & POLLIN`: `FUN_00402d84(param_1, &fd)` → that is
   `std::_Rb_tree::lower_bound` on the int fd key (`decompile_function("0x402d84")`: descends
   `+0x10`/`+0x18` comparing `*param_2` against `node+0x20`), and if the node was found then:

```c
(**(code **)(**(long **)(p_Var6 + 0x28) + 0x10))(*(long **)(p_Var6 + 0x28), param_1);
```

i.e. **`handler->vtable[2](handler, reactor)`** — slot `+0x10` of the object at node `+0x28`.

That is the whole receive path: **fd → vtable slot 2**, polymorphic, resolved at runtime. The
handler objects and their vtables are **constructed inside `libsencore.so`**, so no fd handler's
code, and no `open()` of the service device, appears in sen.elf — see §B.1.

### A.5 Log path over OSAL — `FUN_004021a4`

`FUN_004021a4` @ `0x4021a4` is the sink the log front-ends (`FUN_00401f4c`, `FUN_00402d44`,
`FUN_00402468`) funnel into; its error strings name the source file **`logging.cpp`**, function
`write`, lines `0x49`/`0x65`. Record header built before send:

```c
iVar7 = osal_valloc_msg_wait(0x8f013a, &local_8, uVar6 + 0x20, 0);
if (iVar7 == 0) {
  *local_8 = 2;                        /* subtype/command tag */
  local_8[1] = 0x3d;                   /* module id 0x3d */
  *(undefined4 *)(local_8 + 2) = 1;
  *(uint *)(local_8 + 4) = uVar6;      /* payload length */
  FUN_0040213c(local_8 + 8);           /* stamp time via QID 0x910042 */
  memcpy(puVar5 + 0xc, __s, (int)uVar6);
  osal_set_msg_src(local_8, 0x8f013a);
  iVar7 = osal_snd_msg(0x8f013a, local_8);
```

The payload is built as `[byte0 = level | subtype<<4][tag C string][buffer][0x0D 0x0A]`, with a
`0x4000` cap on the payload (`if (0x4000 < uVar6) { uVar6 = 0x4000; … }`). The **`0x3d` byte is a
second, independent sighting of sen.elf's module id `0x3d`**, which matches the high byte of the
QID it registers, `0x3d032e` — consistent with the QID decomposition documented in
`osal-uipc-map.md`. *(Inference — HYPOTHESIS: `0x3d` is this process's OSAL module id and
`0x32e` its queue index; the QID format itself is documented in `osal-uipc-map.md`, and I did
not re-derive it here.)* The synchronous flag is bit 7 of the level byte
(`if ((char)bVar3 < '\0')` selects the send path), so `0x84` = "level 4, sync" and `0xffffff81`
= "level 1, error". *(Partial decode — the record layout is read directly; the exact meaning of
each level value is not provable from this binary alone.)*

## B. Verb dispatch

**Headline finding: sen.elf contains no verb dispatch at all.** There is no verb→handler table
and no verb `switch` anywhere in the image. The only dispatch construct in the whole binary is
the polymorphic *fd* dispatch of §A.4, and the only `switch`-like branch on a message payload is
the one-byte power-status branch of §A.3. Verb handling lives in `libsencore.so`, which sen.elf
`dlopen`s and hands the reactor to.

### B.1 Dispatch mechanism — fd → vtable slot, verbs delegated

What sen.elf actually dispatches is **file descriptors, not verbs**:

```c
/* FUN_00402e58, per ready pollfd, after _Rb_tree::lower_bound on the fd key */
(**(code **)(**(long **)(p_Var6 + 0x28) + 0x10))(*(long **)(p_Var6 + 0x28), param_1);
```

= `handler->vtable[2](handler, reactor)` (`decompile_function("0x402e58")`). The handler objects
and their vtables are **not defined in sen.elf** — `list_exports` returns no callable symbols
(only `__DT_INIT`/`_init`@`0x401858`, `_INIT_1`@`0x401d9c`, `entry`@`0x401e08`,
`_INIT_0`@`0x401f10`, `_FINI_0`@`0x401ee0`, `__DT_FINI`/`_fini`@`0x403c98`, and the `_edata` /
`_end` data markers), so nothing in sen.elf can be registered *as* a handler by another module
either.

The handoff into libsencore is explicit — sen.elf passes the reactor **object** into the core
(`decompile_function("0x402b84")`):

```c
cVar1 = FUN_00402b78();                            /* dlopen("libsencore.so") */
pc = (code *)FUN_00403a20(param_1, "senser_usb_mode_start");   /* dlsym */
uVar2 = (*pc)(param_2);                            /* param_2 = &DAT_00416240 = the reactor */
```

so libsencore obtains `&DAT_00416240` and is the only party that can insert an fd into the
rb-tree at `reactor+0x08`. That fd is the service channel; its handler — in libsencore's text
segment — is what parses verbs. `sens_adjCmd_init()` (called next, `FUN_00402c94` @ `0x402c94`)
is the initializer of the **adjust-command** subsystem inside libsencore, i.e. the table sen.elf
neither owns nor sees.

Two further corroborations that the verb path is not in this image:

* **No service device is opened here.** `search_strings("/dev/")` → `{"strings":[]}`. The five
  `open()` call sites in sen.elf are: `FUN_00402808`@`0x402880` and `FUN_004028d0`@`0x402a0c`
  (the `smode` files of §A.2), `FUN_00402478`@`0x4024a4` and `FUN_00402540`@`0x402570` and the
  orphan writer at `0x40275c` (all three the `hasp` file of §B.3), plus the generic lazy-open
  wrapper `FUN_004036b0`, whose **path argument comes from the caller**.
* **No ioctl request codes are hardcoded here** except one. The two `ioctl` wrappers
  `FUN_00403520` and `FUN_00403558` (identical bodies, `ioctl(*param_1, param_2)`) have no
  in-image callers other than each other / `FUN_00403590`, and the only constant request is
  **`0x1260`** = `BLKGETSIZE`, used by `FUN_00403590` @ `0x403590` to size a block device
  (`(st_mode & 0xf000) == 0x8000` → regular file size; `== 0x6000` → `ioctl(fd, 0x1260)`;
  otherwise logs `"Not Support file: couldn't get size"`). Nothing device-specific for a service
  endpoint.

**Ruled out with evidence — the pointer-looking regions are not handler tables.** Two runs of
8-byte-aligned pointers xref'd from function heads exist (`0x404148–0x4042a8` and
`0x404548–0x404c70`), and it is tempting to read them as a verb table. They are not:
`list_xrefs` on `0x404148,0x404150,0x4041c8,0x404258,0x404260,0x404268,0x404280,0x4042a8` shows
they map **one per function, strictly monotonic with function address** (`FUN_00402478`,
`FUN_00402540`, `FUN_00402ce4`, `FUN_00403520`, `FUN_00403558`, `FUN_00403590`, `FUN_004036b0`,
`FUN_00403858` — i.e. including plain libc wrappers), and
`read_bytes(0x404140, 64)` returns
`8ce3ffff4c040000 9ce3ffff64040000 64e4ffff94040000 f4e4ffffc4000000 …` — pairs of a
**negative 32-bit relative offset** and a small positive 32-bit value, i.e.
unwind / exception-handling metadata, not `{verb, handler}` pairs. No jump table over verb ids
appears anywhere.

### B.2 Verb → handler table

**Not present in sen.elf — cannot be enumerated from this image.** Stating this plainly rather
than dressing up an inference: the verbs documented in `gptoss-out/plugin-verb-map.md` and
`gptoss-out/service-adjust-map.md` are handled by the module that owns the fd handler, i.e.
`libsencore.so`. What this image contributes to that picture is only:

| Name (string + `dlsym` arg) | Call site | What it establishes |
|---|---|---|
| `senser_usb_mode_start` | `FUN_00402b84` @ `0x402b84`, arg = `&DAT_00416240` | libsencore owns the service fd and therefore verb framing; the channel is **USB** |
| `sens_adjCmd_init` | `FUN_00402c94` @ `0x402c94` | an "adjust command" subsystem is initialised inside libsencore — name-matches the `adjustCmd` verb family of `service-adjust-map.md` *(HYPOTHESIS: identity of the two, based on the name only)* |
| `sens_adjCmd_exit` | `FUN_00402cbc` @ `0x402cbc` (suspend path) | its teardown |
| `NinThread` | `FUN_00402ce4` @ `0x402ce4` → `FUN_00403858` = `pthread_create(&handle, dlsym("NinThread"), param_2, 0)` | libsencore also runs a worker thread; **`FUN_00402ce4` itself has no in-image caller** |

### B.3 The memory-dump verb `0xff03`

**`0xff03` is not referenced anywhere in sen.elf.** This is a searched-for negative, not an
absence of looking:

* `search_code(binary, "0xff03", search_mode="literal")` over the indexed decompiled code
  (67 functions) → `literal_total: 0`.
* No `/dev/*` path string exists (§B.1), no socket/syscall imports exist, and the only `ioctl`
  constant is `0x1260`.

So **the gate that made the live `0xff03` request return `0x80` / "locked" is not in this
binary**, and nothing here lets me prove what it *is*. What can be said with evidence is the
shape of the gate: it must be enforced in `libsencore.so` (the module holding the verb dispatch
and the `sens_adjCmd_*` state), or downstream of it. *(**HYPOTHESIS**, consistent with the live
observation but not provable from sen.elf: the `0xff03` authorization check lives in libsencore
and not in the daemon shell.)*

Three gates **are** visible in sen.elf, all coarse and none verb-specific — recorded because any
of them can produce a "no handler / locked"-shaped result from the outside:

1. **`SENSER_MODE` gate** — `FUN_00401f80` returns *before* `dlopen` when the mode word read from
   `/setting/sen/smode` (else `/boot/sen/smode`) is `0` (§A.2). A mode-0 unit therefore never
   loads libsencore, never registers an fd, and its reactor sits in the `sleep(1)` spin (§A.4).
   Externally that is indistinguishable from "the service is locked".
2. **Suspend gate** — a power-status byte of `1` on QID `0x3d032e` stops and deinits the core
   (§A.3), tearing the handler down until resume.
3. **Reactor emptiness** — `*(reactor+0x28) == 0` → `sleep(1)`, so no fd is ever polled.

**The one security-flavoured state in sen.elf: a 10-slot timestamped history log,
`/setting/.hasp`.** Independently of the verb question, sen.elf carries a small "hasp"
subsystem operating on an **88-byte (`0x58`) record** at `/setting/.hasp` (string @ `0x403e79`):

* **Read** — `FUN_00402540` @ `0x402540`: `open` via `FUN_004036b0(..., "/setting/.hasp", 0x101000)`,
  `FUN_0040341c(fd, buf, 0x58)` (a `read` wrapper), `close`; if the short read ≠ `0x58` it logs
  `"Hasp Read Failed"` and returns false.
* **Reset** — `FUN_00402478` @ `0x402478`: opens with flags `0x101241`
  (`O_WRONLY|O_CREAT|O_TRUNC` + `0x100000`), writes **88 zero bytes**, then `fsync`; on failure
  `"Hasp Reset Failed"`.
* **Append** — an orphan body spanning `~0x4025c0–0x4027e8` that **Ghidra never made a function
  symbol for** (`decompile_function("0x402600")` → *"Function or symbol '0x402600' not found"*;
  the string xrefs at `0x402658`/`0x4027c0` report `function_name: null`). Recovered with
  `disassemble(0x402600, 120)`:
  * calls the hasp read at `0x40260c`; loads the **index byte** at `[x29,#0x88]`;
    `cmp w0, #0x9` — **if the index exceeds 9 it refuses**: it builds an error record (level
    `0xffffff81`, sync bit, tag pointer `0x403e47` = `"Hasp last_histroy data error.%d"` *(sic)*,
    field `4`) and emits it through `FUN_00402468`@`0x402668`, then returns 0.
  * otherwise `bl 0x401b30` = **`time()`**, `bl 0x401a30` = **`localtime()`** (both confirmed as
    caller-side import thunks for `<EXTERNAL>::time` / `<EXTERNAL>::localtime`), and on non-NULL
    `struct tm *` stamps five fields through `FUN_00403bd0` into slot `base + idx*8`:
    `[tm+0x14]/100` and `%100` (`sdiv`/`msub` by `0x64` = year), `[tm+0x10]+1` (month),
    `[tm+0xc]` (mday), `[tm+8]` (hour), `[tm+4]` (minute) — a wall-clock timestamp per slot.
  * increments the index **mod 10** (`add w0,w0,#1; uxtb w0,w0; cmp w0,#9; csel` @
    `0x402724–0x402734`) → a **10-entry ring**; the NULL-`localtime` branch at `0x402774`
    zero-fills the next slot instead.
  * then rewrites the whole 88-byte record: `adrp/add` → path `0x403e79`, `mov w2,#0x1241;
    movk w2,#0x10,LSL#16` → flags `0x101241`, `bl 0x4036b0`@`0x40275c`, `bl 0x403450(fd,buf,0x58)`
    @`0x40276c`, `bl 0x4033d4` (close); on `-1` logs `0x403e67` `"Hasp Write Failed"` via
    `FUN_00401f4c`; on success calls the unnamed thunk `0x401930` (a caller-side PLT stub loading
    GOT slot `0x416050` — `disassemble(0x401930)`; not resolvable to an import name from this
    view) and returns 1.

  Mechanically this is a **timestamped 10-deep history log with a hard stop once full**, i.e. the
  classic shape of an anti-rollback / tamper-or-usage history counter. *(**HYPOTHESIS** on the
  purpose — "anti-rollback / tamper history" is an interpretation of the shape; the field names
  and consumer are not in this image.)*
* **Crucially, none of it is wired up here.** `list_xrefs` shows **no `UNCONDITIONAL_CALL` xref
  in-image** to `FUN_00402478`, `FUN_00402540`, the orphan appender, `FUN_00403590`, or
  `FUN_00402ce4` — only DATA/INDIRECTION/metadata references — and sen.elf exports nothing
  callable. So as far as this image shows, the hasp history code is **dead in this build**
  (reachable only if something outside this image reaches it, which the export table forecloses
  for direct symbol calls).

## C. Relation to auth / other services

**Headline: sen.elf touches exactly four other things: `libsencore.so` (as a loaded module) and three OSAL
queues (log sink, log-error notice, time service). It makes no service-to-service call of any
other kind, and it contains no authentication code.**

### C.1 The one real dependency: `libsencore.so`

The relation is host→guest via `dlopen`/`dlsym`, not a link-time dependency — `libsencore.so`
does **not** appear in the `DT_NEEDED` list (shared libs listed by the binary's string table are
only `libdl.so.2`, `libstdc++.so.6`, `libpthread.so.0`, `libosal_uipc.so`, `libm.so.6`,
`libgcc_s.so.1`, `libc.so.6`, `librt.so.1`). The four entry points sen.elf resolves by name:

| Entry point | Resolved at | Called from | Direction of data |
|---|---|---|---|
| `senser_usb_mode_start` | `FUN_00403a20` (`dlsym`) via `FUN_00402b84` | `0x402b84` | **sen.elf → libsencore: `&DAT_00416240`**, the poll reactor object |
| `sens_adjCmd_init` | `FUN_00403a20` via `FUN_00402c94` | `0x402c94` | none (no args) |
| `sens_adjCmd_exit` | `FUN_00403a20` via `FUN_00402cbc` | `0x402cbc` (suspend) | none |
| `NinThread` | `FUN_00403a20` via `FUN_00402ce4` | `0x402ce4` → `pthread_create` (`FUN_00403858`) | thread start fn + caller-supplied arg |

`FUN_00402b78` → `FUN_004039d4(param_1, "libsencore.so")` is the `dlopen`; `FUN_00403a20`
validates `*param_1 != 0` and calls `dlsym`, logging through `FUN_004039b4` when the symbol is
missing. **This is where the SENSER core, the USB service channel, the `adjustCmd` verbs, and
(since §B) any verb gate live.** sen.elf is the process wrapper that keeps that library alive
across suspend/resume.

### C.2 The named service QIDs from the brief

| Claim | Status in this image | Evidence |
|---|---|---|
| libsencore performs the SHA-256 authentication | **Consistent — but the crypto is not in sen.elf.** sen.elf imports **no** crypto/hash/SSL symbol of any kind and links no crypto library; there are no `SHA*`/`EVP*`/`md5`/`hmac` symbols and no crypto strings | full `list_imports` review; dependency list above |
| `libInfraSSHManager` / SSH manager | **Absent from sen.elf.** No such string, no SSH-related string, and **no socket API at all** — no `socket`/`connect`/`bind`/`listen`/`accept`/`send`/`recv`/`getaddrinfo` imports, and no `syscall` import; all I/O is POSIX-file (`open`/`read`/`write`/`lseek`/`fsync`/`fcntl`/`ioctl`/`mmap`/`munmap`/`opendir`/`readdir`/`closedir`/`mkdir`/`rmdir`/`remove`/`access`/`__fxstat`) | `list_imports`, `search_strings` (full inventory, ~110 strings) |
| key service QID `0x25906be` | **Not contacted by sen.elf.** `search_code("0x25906be", search_mode="literal")` → `literal_total: 0`; the only QID literals in the image are the four in §A.3 | `search_code` literal search over all 67 functions |

So the auth chain documented in `gptoss-out/service-verb-auth.md` and the key service documented
in `gptoss-out/keyservice-map.md` connect **through `libsencore.so`**, not through this daemon
shell. *(**HYPOTHESIS**, and an explicitly out-of-image one: that the `0x25906be` key-service
conversations and the SHA-256 challenge/response happen inside `libsencore.so`. The evidence here
is negative — those symbols/strings/constants are absent from sen.elf while the module that owns
the channel is loaded by it — not positive.)*

### C.3 OSAL links named

| Link | sen.elf role | Peer |
|---|---|---|
| `0x3d032e` | **server** — `osal_reg_sync_msg_queue_cb(0x3d032e, &DAT_00416288, FUN_00402020)`; one-byte payload `0`=resume, `1`=suspend | the a15 power/state manager (module `0x3d` = sen.elf itself, per the `0x3d` log module id in §A.5) |
| `0x8f013a` | client — `osal_valloc_msg_wait` + `osal_set_msg_src` + `osal_snd_msg` | log collector (module `0x08f`, index `0x013a`; already decomposed in `osal-uipc-map.md`) |
| `0x8f0313` | client — `osal_snd_sync_msg` (len 0) + `osal_free_msg` | log-path error notice, same `0x08f` module |
| `0x910042` | client — `osal_snd_sync_direct(0x910042, &local_20)`, request len `0x20` | time-of-day service, used by `FUN_0040213c` to stamp every log record |

Note the asymmetry that matters for the auth story: sen.elf is a **log/time consumer and a power
callee**. It is not a peer in any authentication exchange that this image can show.

## D. Scope and safety

This is a **static map of one userspace binary**, produced against the owner's own camera
firmware for a public write-up on mechanism.

* **In scope:** `fs/a15/bin/sen.elf` as loaded in the Ghidra project `ghidra_svc` — its control
  flow, its OSAL registrations, and the interface it exposes to `libsencore.so`.
* **Out of scope (and not touched here):** the kernel and its drivers, the USB/PTP transport
  below userspace, the other firmware images, `libsencore.so` itself, and the runtime behaviour
  of the peer services named in §C.3. Every statement about those is marked HYPOTHESIS and is
  offered as a pointer for whoever maps those images next, not as a finding about them.
* **No key material is handled, reproduced, or needed** by this analysis. sen.elf contains no
  cryptographic code, no keys, and no credentials (§C.2) — the only persistent state it owns is
  a mode word on disk (§A.2) and the `/setting/.hasp` history record (§B.3), neither of which is
  secret material. Nothing in this document is a secret; it is offsets and mechanism.
* **No firmware binary and no bulk binary content is reproduced.** Quoted decompilations are
  short excerpts of the control flow needed to support a claim, cited by Ghidra virtual address so
  a reader with the same image can re-check them. No memory dumps, no extracted blobs.
* **The camera is an owned device**, and the live observations referenced here (the `0xff03`
  `0x80`/locked result, the service-verb framing) came from that device under the same
  mechanism-not-secrets framing as the rest of the series. This document adds no live request and
  makes no attempt to bypass the `0xff03` gate; §B.3 deliberately stops at "the gate is not in
  this binary" rather than speculating about how to satisfy it.

## How this was checked

All work was done through the Ghidra MCP server **`ghidra_svc`** against the project binary
`sen.elf` (on disk `/srv/a7rv/a7rv-fw/fs/a15/bin/sen.elf`). Status from
`list_project_binaries`: `analysis_complete: true`, `code_indexed: true`, `strings_indexed: true`.

**All addresses in this document are Ghidra virtual addresses** (image base `0x400000`, PIE-less
load), *not* on-disk file offsets. The binary is stripped of local
symbols, so `FUN_xxxxxx` / `DAT_xxxxxx` are Ghidra-generated names; `main` was recovered as
`FUN_00401cb0` from the first argument of `__libc_start_main` inside `entry`@`0x401e08`, after
`search_symbols_by_name("^main$")` returned `[]`.

Tools used, and what each contributed:

* `decompile_function` **by address** (never by name, to avoid the PLT/caller-side thunks — this
  binary has *two* thunk sets per import, `0x417xxx` PLT and `0x401xxx` caller-side, plus
  `<EXTERNAL>` ordinal entries) for the functions cited: `0x401e08` (entry), `0x401cb0` (main),
  `0x402a60`/`0x402b60` (mode), `0x401f80` (startup), `0x402020` (power cb), `0x402e58` (reactor),
  `0x402d84` (`_Rb_tree::lower_bound`), `0x4021a4`/`0x40213c` (log/time), `0x402b84`/`0x402b78`/
  `0x402c94`/`0x402c40`/`0x402cbc`/`0x402ce4`/`0x403a20`/`0x4039d4` (libsencore glue),
  `0x402478`/`0x402540`/`0x403590`/`0x40367c`/`0x4036b0` (file + hasp). Functions were read
  individually; the largest (`FUN_00402e58`, ~150 lines) is still under the 300-line limit.
* `disassemble` for the region Ghidra never turned into a function (`0x402600`, 120 instructions)
  and for tail/thunk confirmation (`0x4027c0`, `0x401930`).
* `search_code` in **literal** mode for the negatives: `"0xff03"` → `literal_total: 0`,
  `"0x25906be"` → `literal_total: 0` (semantic mode was also used for orientation).
* `search_strings` for the full string inventory (~110 strings) and for targeted negatives:
  `"/dev/"` → `{"strings":[]}`; no auth/lock/crypto/SSH strings exist in the image.
* `search_symbols_by_name` for `^main$`, the OSAL import set, and the import thunks used to name
  `0x401b30` = `time`, `0x401a30` = `localtime`, `0x401a60` = `getpid`, `0x401ae0` = `fsync`,
  `0x401920` = `sleep`.
* `list_imports` / `list_exports` for the API surface (7 OSAL functions, POSIX-file I/O only, no
  sockets, no crypto; **no callable exports**).
* `list_xrefs` on every OSAL thunk (`0x401be0`, `0x4018d0`, `0x401980`, `0x4019e0`, `0x4018f0`,
  `0x401c10`, `0x401c80` and their `0x417xxx` twins), on the `hasp` strings' addresses, and on the
  candidate pointer regions — the last being how §B.1's "that's unwind metadata, not a handler
  table" was established, together with `read_bytes(0x404140, 64)`.

**Confidence labels used above:** anything derived purely from decompiled control flow at a cited
address is stated as fact; anything that reads purpose into a structure (the `0x3d` module-id
reading in §A.5, the "adjustCmd" name match and `NinThread` role in §B.2, the anti-rollback
reading and `0xff03` gate location in §B.3, the libsencore-owns-the-auth claim in §C.2) is tagged
**HYPOTHESIS**. Two things worth restating as open rather than resolved: (1) the actual verb table
and the `0xff03` gate are in `libsencore.so` and unexamined here; (2) the `/setting/.hasp` history
code has **no caller in this image**, so who calls it — and whether it is reached at all in this
build — is unresolved.
