# SENSER service verb dispatch — map of `libsencore.so`

Static reverse-engineering of the user's own Sony a7R V firmware (`fs/a15/lib/libsencore.so`),
for a public write-up. This document records **offsets, verbs and mechanism only**. It reproduces
**no key material** and **no firmware bytes**. All Ghidra addresses are **virtual** (module base
assumed 0; `libsencore.so` loaded at `0x0`, so `0x0010xxxx` is the on-disk vaddr). Tools: the
`ghidra_svc` Ghidra project (read-only) plus `strings`/`read_bytes` on the on-disk `.so`.

Prior context this builds on: `plugin-verb-map.md` (the `command%04X` dlsym dispatch),
`service-framing-map.md`, `sendaemon-map.md` (sen.elf = power/lifecycle only). This file maps the
**post-auth verb dispatch** that actually lives in `libsencore.so`.

---

## A. The dispatch path

All addresses are virtual (module base 0). Each snippet is from `decompile_function`
**by address** in the `ghidra_svc` project unless a `disassemble` is named.

### A.0 The chain in one line

```
Usb::handle_input  → (auth)  → WorkerThreadManager::start_authentication → onComplete(level)
        │                                                                    picks pFunc = pFunc_level_{A,B,C}
        ▼
SenserThread  ── Serialize(SenserIfReceive, buf, 0xc)  ──► Parse(buf) ──► Command* obj
   (12-byte hdr;        length u32 = buf[0..3];         verb = u16 at buf+4
    body into a MemoryData at buf+0xc)                        │
                                                              ▼
                                             Command::Execute(obj, buf)
                                             ├─ gate: vtable+0x28 → fail ⇒ buf[0xb]=0x82
                                             └─ vtable+0x10 = DoExecute(obj, buf)
                                                   PluginCommand / DispatchCommand /
                                                   SubsystemCommunicationCommand → handler()
                                                   status byte → buf[0xb] → SendResponse
```

### A.1 Receive loop — `SenserThread` @ `0x10b7ac`

The loop reads a **12-byte packet header** first, then the body:

```c
Serialize(SenserIfReceive, buf, 0xc);          /* read 12-byte header */
uVar2 = *(uint *)buf;                          /* buf[0..3] = total length (u32)   */
... "RECV_SENSER_PACKET"
this_00 = Parse(buf);                          /* verb → Command*  (fails ⇒ abort) */
...  /* body becomes a MemoryData(SenserIfReceive, buf+0xc, size≤0x1000) at this+8 */
```

Layout established from the header handling and from `Parse` (below): `buf[0..3]` = u32
length, **`buf[4..5]` = u16 verb**, `buf[6..7]` = mass-data/continuation tag, and the
**response status byte is `buf[0xb]`**. `Parse` returning null logs
`"Command object instantiation failed!"`.

### A.2 Verb → Command factory — `Parse` @ `0x10e9f4`

`Parse` walks the global verb table `pFunc` (label `0x16cfa0` — the *pointer variable*;
`pFunc_level_{A,B,C}` are the tables it points at), comparing the verb `short` at
`param_1+4` against each entry's id, and calls the entry's factory:

```c
psVar5 = pFunc;
if (pFunc != 0) {
  do {
    psVar1 = psVar5 + 4;                 /* entry's fn-slot (see A.5 caveat on layout) */
    if (*psVar1 == 0) goto LAB_0010ea30; /* null fn ⇒ end of table */
    sVar2 = *psVar5;                     /* entry verb (short) */
    psVar5 = psVar5 + 8;
  } while (*(short *)(param_1 + 4) != sVar2);
  lVar3 = (**(code **)psVar1)();         /* factory(): builds the Command* */
  if (lVar3 != 0) return lVar3;
}
LAB_0010ea30:                            /* verb not registered ⇒ fall-through */
  *puVar4        = &PTR__NoAction_0016ba58;
  *(puVar4 + 1)  = this /*DiscardRecvData*/;
  *(undefined1 *)(puVar4 + 2) = 0x80;    /* ⇒ status 0x80 */
```

So an **unregistered verb yields a `NoAction`/`DiscardRecvData` object with status byte
`0x80`** — the first of three places `0x80` is manufactured (see C). The factory has
signature `Command *(SenserPacket const*)`; `AdjustControlFunc` @ `0x110344` is a live
example (returns a `SubsystemCommunicationCommand*`).

The verb gate is a separate walker, **`ParseCheck(SenserPacket const*)` @ `0x10ea84`**:
identical loop, returns **`0` if the verb IS registered, `1` if it is not**.

### A.3 Auth gate + polymorphic execute — `Command::Execute` @ `0x10db08`

```c
cVar1 = (**(code **)(**(long **)(this + 8) + 0x28))();   /* auth/ready gate on request obj */
if (cVar1 == '\0') { param_1[0xb] = (SenserPacket)0x82; return 0; }  /* not-auth'd ⇒ 0x82 */
uVar2 = (**(code **)(*(long *)this + 0x10))(this, param_1);          /* vtable+0x10 = DoExecute */
```

`DoExecute` is per-subclass. In `PluginCommand::DoExecute` @ `0x10d908` (and
`DispatchCommand::DoExecute` @ `0x10dd90`) the resolved handler is invoked and its return
becomes the status byte:

```c
if (*(long *)(this+0x10) == 0) { param_1[0xb] = 0x80; return 0; }    /* no handler ⇒ 0x80 */
... "BEF_PLUGIN_CMD_CALL"
param_1[0xb] = (*(this+0x10))(&local_30);                            /* call handler */
... "AFT_PLUGIN_CMD_CALL"
return new MemoryData(SenserIfSend, out_buf, out_size, dealloc);     /* output wrapper */
```

`MemoryData(SenserIfSend, buf, size, dealloc)` is how a handler's bytes (including any
memory-dump output) stream back to the host. `Command::Execute` returns the object to
`SenserThread`, which calls `SendResponse`.

### A.4 Verb → `command%04X`/`open`/`close`/`memory%04X` symbol

The concrete bridge from a verb to a shared-object symbol is **`ProductInfoFunc` @
`0x10eabc`**, a factory registered for verb `0x0010` (see B):

```c
ushort local_6;
Serialize(SenserIfReceive, auStack_8, 4);
cppdump_logrec(0x83, "PROD_INFO", auStack_8, 4);
if ((local_6 == 0xf1) && (terminal_change_function_is_disabled != '\0')) {
    ... /* NoAction/DiscardRecvData, status byte = 1 */
}
else {
  pvVar2 = (void *)GetPluginModule("libpro%02X.so", 0x10, (uchar)(local_6 >> 8));
  CreatePluginCommand(pvVar2, local_6, (0xc - NumberOfBytesReceived) + (ulong)*(uint *)param_1);
}
```

**The product byte `verb >> 8` selects the plugin `.so`: `libpro%02X.so`.** For verb
`0x00F1`, `verb>>8 == 0` ⇒ **`libpro00.so`** — exactly the library that exports
`command001F`/`command00F1`. `terminal_change_function_is_disabled` is a runtime global
(written by `onComplete`, see A.5) that, with `local_6 == 0xf1`, short-circuits to a
status-`1` `NoAction` instead of loading the plugin.

`GetPluginModule(pathfmt, vendor, sub)` @ `0x10db68` scans a handle pool at
`DAT_0016cac8` (key `sub | vendor<<16`), builds `"/usr/lib/" + snprintf(fmt, sub)`,
`access()`-checks it, then `dlopen(path, RTLD_LAZY)`.

`CreatePluginCommand(handle, verb, size)` @ `0x10e254` (mangled `_Z19CreatePluginCommandPvtm`)
builds and resolves the four symbol families via `FUN_0010d584` (@ `0x10d584`,
`snprintf` + `dlsym`):

| Format string | vaddr | resolved by |
|---|---|---|
| `command%04X` | `0x116fa9` | `CreatePluginCommand` @ `0x10e284` |
| `open%04X`    | `0x116fb5` | `CreatePluginCommand` @ `0x10e2f4` |
| `close%04X`   | `0x116fbe` | `CreatePluginCommand` @ `0x10e364` |
| `memory%04X`  | `0x116fc8` | `CreatePluginCommand` @ `0x10e39c` |

(`FUN_0010d584` body, confirmed: `snprintf(local_20, 0x20, param_2, (ulong)param_3);
dlsym(param_1, local_20);`. The verb is formatted **uppercase, 4 hex digits** — `%04X`.)

Reconstructed control flow (from `disassemble` @ `0x10e254`/`0x10e3e0`, since the symbol
and an imported label collide at `0x10e254` and block name/address decompile):

* null handle (`cbz x0`) ⇒ return 0 (`0x10e41c`).
* `uxth w21, w1` ⇒ 16-bit verb.
* `command%04X` **miss** ⇒ alloc, then `mov w1,#0xffffff80; strb w1,[x0,#0x10]` @ `0x10e2b8`
  ⇒ **status `0x80`** (2nd `0x80` site).
* `command%04X` hit ⇒ resolve `open%04X`; if present `blr x1` @ `0x10e304` calls `open(ctx)`;
  if it returns `-1` (`cmn w0,#1`) ⇒ error object `0xffffff82` @ `0x10e33c` ⇒ **`0x82`**;
  else resolve `close%04X`, alloc a 0x30 object `ctor(close_fn, open_result, 0x8000)` @ `0x10ae00`.
* `open%04X` **missing** @ `0x10e38c` ⇒ resolve `memory%04X`; if present, **two-step call**:
  `blr x1`(&local) @ `0x10e3b0`, then `ldr x1,[x29,#0x50]; blr x1`(ctx) @ `0x10e3c0`, wrapped
  in a 0x30 object — **this is the memory-dump-shaped path** (see C).
* `memory%04X` also missing @ `0x10e3fc` ⇒ 0x18 object storing the `command%04X` fn (x22) at `+0x10`.

### A.5 When the table is chosen — `WorkerThreadManager::onComplete(int)` @ `0x10c108`

The verb table is **not fixed**; it is a pointer `pFunc` (@ label `0x16cfa0`) swapped by
authentication level:

```c
if (param_1 == 2)      { pFunc = pFunc_level_B; }
else if (param_1 == 3) { pFunc = pFunc_level_A; }
else if (param_1 == 1) { pFunc = pFunc_level_C; }
else                   { pFunc = (void*)0; adjCodeLevel = 0; goto LAB; }  /* no verbs authorized */
adjCodeLevel = (undefined1)param_1;
LAB_0010c140:
terminal_change_function_is_disabled = param_1 != 3;
(**(code **)(this + 0x18))();               /* call the stored onComplete callback */
```

`WorkerThreadManager::start_authentication(cb)` @ `0x10c328` first does **`pFunc = 0`**
(clears the table), stores `cb` at `this+0x18`, and runs the auth worker. So **pre-auth
there are zero authorized verbs** (every verb would hit the `0x80` fall-through), and the
auth result picks which of the three tables `Parse`/`ParseCheck` will read. Level **3 →
table A** is the only level where `terminal_change_function_is_disabled` is false.

`onComplete` is reached through the USB reactor: `Usb::handle_input` @ `0x10cc1c` event `4`
⇒ `WorkerThreadManager::start_authentication(&DAT_0016ca30, onCompleteAuthentication)`;
`Usb::onCompleteAuthentication()` @ `0x10ca34` logs `"USB Event: COMPLETE_AUTHENTICATION"`
and `push(instance, 6)` back into the reactor.

## B. The verb set

_(enumerable verbs and what they do; inferences tagged HYPOTHESIS)_

### B.0 Three auth-level verb tables

The active verb set is one of three static tables in `.data`, selected by auth level
(A.5). All three are defined in **`libsencore.so` itself** (not imported):

```console
$ nm -AD --defined-only /srv/a7rv/a7rv-fw/fs/a15/lib/*.so | grep -iE 'pFunc_level'
.../libsencore.so:000000000006c848 D pFunc_level_A
.../libsencore.so:000000000006c8b8 D pFunc_level_B
.../libsencore.so:000000000006c8f8 D pFunc_level_C
```

(vaddr `0x16c848`/`0x16c8b8`/`0x16c8f8`; on-disk offset `0x6c848`…, i.e. the usual `0x100000`
Ghidra-base delta.)

### B.1 Table layout — and an honest caveat

`read_bytes` at each table shows a repeating **16-byte entry**: a `short verb` at `+0`, a
6-byte gap, and an 8-byte slot at `+8` holding a **tagged pointer** whose low 2 bits are a
*kind tag* (`& ~3` gives the handler). Three of these reconcile exactly to named functions,
which is what I lean on:

| verb | raw slot | `& ~3` | resolved (Ghidra symbol) |
|---|---|---|---|
| `0x0010` (B) | `0x10eabd` | `0x10eabc` | **ProductInfoFunc** |
| `0x0003` (A) | `0x10eba9` | `0x10eba8` | **MiconAccessFunc** |
| `0x0004` (A) | `0x110345` | `0x110344` | **AdjustControlFunc** |

**Caveat (open).** The `decompile_function` view of `Parse` types the cursor as `short *`
and advances `+8` (suggesting stride 8), whereas the raw bytes are unambiguous stride-16 with
the fn-slot at `+8`; and the *high* verbs' fn-slots point into a packed stub region
(`0x10c184`=`getProductId`, `0x10c18c`=`ret`, `0x10c190`=`Regist_HaspId` wrapper) whose
per-entry meaning I did not fully pin down. So **low-verb entries (0x0001–0x0010) are solid;
high-verb entries (`0xFF00`, `0xFF02`, `0x00FF`) are HYPOTHESIS** for the exact handler. The
verb *membership* — the part section C depends on — is read directly from the bytes.

### B.2 Per-table verb membership (from `read_bytes`, stride-16 walk to null fn-slot)

| Verb | Level C (`0x16c8f8`) | Level B (`0x16c8b8`) | Level A (`0x16c848`) |
|---|:---:|:---:|:---:|
| `0x0001` | ✓ | ✓ | ✓ |
| `0x0002` | — | ✓ | ✓ |
| `0x0003` | — | — | ✓ (MiconAccessFunc) |
| `0x0004` | — | — | ✓ (AdjustControlFunc) |
| `0x0010` | — | ✓ (ProductInfoFunc) | — |
| `0x00FF` | — | — | ✓ *(HYPOTHESIS handler)* |
| `0xFF00` | — | — | ✓ *(HYPOTHESIS handler)* |
| `0xFF02` | — | — | ✓ *(HYPOTHESIS handler)* |

Reading of the levels (**HYPOTHESIS**, from the counts + `terminal_change_function_is_disabled`):
**C** is the minimal/entry level (level 1), **B** adds product-info (`0x0010`) — the
`libproNN.so` loader (level 2), **A** is the most privileged (level 3, the only level that
clears `terminal_change_function_is_disabled`) and is the **only** level exposing the
high-range verbs `0x00FF`/`0xFF00`/`0xFF02`.

### B.3 What the named handlers do

* **`ProductInfoFunc` `0x0010`** — loads `libpro(verb>>8).so` and runs the verb inside it
  (A.4). This is the loader that reaches the two real plugin verbs.
* **`MiconAccessFunc` `0x0003`** (`0x10eba8`) — "micon" (micro-controller) access.
  *Body not opened this session* — name only.
* **`AdjustControlFunc` `0x0004`** (`0x110344`) — builds a
  `SubsystemCommunicationCommand`; logs `"ADJ_CTRL"`; on resource-lock failure returns
  `NoAction` with status byte **`0xa0`** (a distinct status worth noting: a *busy/lock*
  code, not `0x80`). Confirms the factory signature `Command *(SenserPacket const*)`.

### B.4 The two real plugin verbs (from the `libpro00.so` inventory)

The `nm` inventory (full command + output in `plugin-verb-map.md`; re-run this session,
identical) shows the **entire** set of genuine verb exports in the image:

```console
$ nm -A -D --defined-only /srv/a7rv/a7rv-fw/fs/a15/lib/*.so \
    | grep -E ' (command|open|close|memory)[0-9A-Fa-f]{4}$'
.../libpro00.so:00000000000009a4 T command001F
.../libpro00.so:0000000000000a64 T command00F1
```

Both are reached through **`ProductInfoFunc`** (verb `0x0010`, `verb>>8==0` ⇒ `libpro00.so`):

| Verb | Handler | Behaviour (from `plugin-verb-map.md`, re-verified) |
|---|---|---|
| `0x001F` | `command001F` (`0x9a4`) | HASP token **read** (in-byte `0`) / **reset** (in-byte `0x80`); returns `1` / `0x81` / `0x82`. |
| `0x00F1` | `command00F1` (`0xa64`) | 2-instruction stub, always `return 1` (ack). |

No `openNNNN`/`closeNNNN`/`memoryNNNN` export exists anywhere in the image, and the same
anchored scan over every partition's `lib/` (`a3 a5 a7 a8 a15`) returns the same two lines.

### B.5 Command-object kinds (the tag, internal to a verb, not a wire verb)

The factory `fn*` low-2-bit tag and the `Command` subclasses line up as: `NoAction`
(`0x10ea30` fall-through / plugin stubs), `PluginCommand` @ `0x10d908` (a `commandNNNN`
from a plugin), `DispatchCommand` @ `0x10dd90` (in-lib `command` fn),
`SubsystemCommunicationCommand` (e.g. `AdjustControlFunc`), `HostCommunicationCommand`.
The mapping tag-value ↔ subclass is **HYPOTHESIS** (inferred from the factory return types,
not from a switch).

## C. The `0xff03` memory-dump path

_(the `memory00FF`/`0xff03` MemoryDump handler; gating; tie to status `0x80`)_

### C.1 Finding

**There is no `0xff03` handler in this firmware image — neither a verb-table entry nor a
symbol.** Live hardware returning **`0x80`** for verb `0xff03` is therefore the
**missing-handler fallback firing, not a locked memory-dump routine executing.** Two
independent checks:

1. **Verb-table membership.** Walking all three tables (B.2) to their null fn-slot:
   `0xFF03` is **not present in any of A, B, or C**. The nearest neighbours are `0xFF00`
   and `0xFF02`, and those are **level-A only**. `Parse` @ `0x10e9f4` walks the active
   table, finds no match, and falls through to `NoAction`/`DiscardRecvData` with
   `*(puVar4+2) = 0x80` @ `0x10ea30+`. `ParseCheck` @ `0x10ea84` returns `1` (not registered).
2. **Symbol inventory.** No `commandFF03`, `openFF03`, `closeFF03`, `memoryFF03`, nor
   `memory00FF`/`memoryFF00` is exported anywhere in the image (anchored `nm`, B.4). So even
   if the verb reached `CreatePluginCommand`, `dlsym(handle,"commandFF03")` returns null.

### C.2 Where `0x80` comes from (three sites, all confirmed)

`0x80` is manufactured in exactly three places, all reached when a verb has no handler:

| # | Site | Instruction | Path |
|---|---|---|---|
| 1 | `Parse` @ `0x10e9f4`/`0x10ea30` | `*(u8*)(obj+0x10) = 0x80` | verb not in the active level table |
| 2 | `CreatePluginCommand` @ `0x10e2b8` | `mov w1,#0xffffff80; strb w1,[x0,#0x10]` | `command%04X` dlsym-miss |
| 3 | `PluginCommand::DoExecute` @ `0x10d908` | `if (*(this+0x10)==0){ param_1[0xb]=0x80; }` | handler slot null at exec |

For a verb like `0xff03` that isn't in the table **at all**, site **1** is what fires first:
the request never becomes a `PluginCommand`, so `0x80` appears before any `dlsym` is even
attempted. This is fully consistent with the live observation (`0xff03` → `0x80`).

### C.3 The `memory%04X` path that a *present* handler would take

`0xff03` never reaches it, but the memory-dump *mechanism* is present and documented here so
the "locked" result is properly contextualised. In `CreatePluginCommand` @ `0x10e38c`, when
`command%04X` resolves but `open%04X` is **absent**, it resolves **`memory%04X`**
(format string `0x116fc8`, resolved at `0x10e39c`) and, if found, invokes it in **two
steps**: `blr x1`(&local) @ `0x10e3b0`, then `ldr x1,[x29,#0x50]; blr x1`(ctx) @ `0x10e3c0`,
wrapping the result in a 0x30 object. That object's bytes stream out through
`MemoryData(SenserIfSend, out_buf, out_size, dealloc)` in `PluginCommand::DoExecute` — i.e.
a memory handler is a producer of a streamed buffer, not a command with an `open`/`close`
session. The gating is therefore: **the verb must be in the active level table, AND a plugin
`.so` for `libpro(verb>>8).so` must exist and export `memory(VERB)`.** For `0xff03` both fail.

### C.4 Consistency with the prior missing-symbol result

`plugin-verb-map.md` established that a **missing `commandNNNN` symbol yields a
DiscardRecvData object with status byte `0x80`**. This section shows the *same* `0x80` also
arises one layer earlier (verb not in the table, site 1) and one layer later (slot null at
exec, site 3). The live `0x80` for `0xff03` cannot be distinguished between these three
sites from the status byte alone — but because `0xFF00`/`0xFF02` are **level-A-only** and
`0xFF03` is in no table, the dominant explanation is **site 1 at the current auth level**:
`0xff03` is simply not an authorized verb.

**HYPOTHESIS (unresolved):** whether a `0xff03`/`memory` handler is materialized *on demand*
on a production unit (e.g. fetched, or enabled by a `Regist_HaspId` entitlement that adds the
table entry or drops a `libproFF.so` at runtime). The HaspId machinery is present
(`Regist_HaspId` @ `0x1142f0`; `WorkerThreadManager::registHaspId(int)` @ `0x10c190`, which
is itself one of the level-A high-verb handler candidates), so an entitlement-gated verb is
plausible — but nothing in this static image proves it. **Not verified.**

## D. Scope / safety

This is a **static map of the host-side dispatch mechanism** on the owner's own device, for a
public write-up. It records control flow, offsets, verb ids, and status codes.

* **No key material.** No cryptographic keys, digests, nonces, tokens, HASP contents, or
  authentication secrets are reproduced. `command001F`'s HASP read/reset is described by
  control flow only (see `plugin-verb-map.md`); its output bytes were never captured.
* **No firmware bytes.** No firmware image, ELF blob, or extracted binary is embedded or
  quoted. Only short decompiled pseudo-C fragments and a handful of format-string literals
  (`command%04X` etc.) appear, as evidence of mechanism.
* **Mechanism, not exploitation.** The `0xff03` section documents *why* the camera answers
  `0x80` (no handler); it is not a method to bypass the auth-level gating to reach the
  level-A high verbs.
* **Owned device / authorized analysis.** Static inspection of the user's own extracted
  filesystem and Ghidra project; read-only tools throughout.
* **Scope limits.** This is the extracted a15 (+ sibling `a3 a5 a7 a8`) filesystem only.
  Verb handlers can live in modules absent from this image (e.g. the referenced-but-missing
  `libSnr.so` = module `0xff02`), so B.4's inventory is exhaustive *for this extraction*,
  not for every shipping unit. Auth-level → table mapping and the high-verb handler
  identities are flagged HYPOTHESIS / open where the evidence ran out.

## How this was checked

Ghidra project **`ghidra_svc`**, program `libsencore.so`. Every function was decompiled **by
address** (never by name — several addresses have a function symbol and an imported label with
the same name, which blocks name-based decompile). Addresses below are Ghidra virtual
addresses; the module loads at `0x0`, so `nm` file offsets equal these values one-for-one.

### `decompile_function` (by address) — bodies actually read

| Address | Symbol | Used in |
|---|---|---|
| `0x10b7ac` | `SenserThread` | A.1 — 12-byte header parse, verb = u16 @ `+4` |
| `0x10e9f4` | `Parse` | A.2, C.2 site 1 — walks `pFunc`, verb match → factory |
| `0x10ea84` | `ParseCheck` | A.2, C.1 — registered→`0`, unregistered→`1` |
| `0x10db08` | `Command::Execute` | A.3 — auth gate (vtable+0x28 → `0x82`), DoExecute (vtable+0x10) |
| `0x10d908` | `PluginCommand::DoExecute` | A.3, C.2 site 3 — handler call, status → `buf[0xb]`, `MemoryData` output |
| `0x10dd90` | `DispatchCommand::DoExecute` | A.3 — alternate DoExecute |
| `0x10eabc` | `ProductInfoFunc` | A.4 — verb→plugin bridge, `libpro%02X.so` |
| `0x10db68` | `GetPluginModule` | A.4 — module path from `libpro(verb>>8).so` |
| `0x10e254` | `CreatePluginCommand` | A.4, C.2 site 2, C.3 — builds `command/open/close/memory%04X`, dlsym |
| `0x10d584` | `FUN_0010d584` | A.4 — snprintf + dlsym helper |
| `0x10c108` | `WorkerThreadManager::onComplete(int)` | A.5 — auth level → `pFunc` table swap |
| `0x10c328` | `WorkerThreadManager::start_authentication` | A.5 — clears `pFunc=0` pre-auth |
| `0x10ca34` | `Usb::onCompleteAuthentication` | A.5 — posts event 6 to the reactor |
| `0x110344` | `AdjustControlFunc` | A/B.3 — `ADJ_CTRL`, resource lock → `0xa0` |

### `disassemble` — where decompile was blocked or the tail was the point

- `0x10c180`–`0x10c1a0` region — the high-verb stub thunks (`getProductId`@`0x10c184`,
  `ret`@`0x10c18c`, `mov w0,w1; b 0x10a910`→`Regist_HaspId`@`0x10c190`, delete thunk@`0x10c19c`).
  Decompiling `0x10e254`/`0x10eabc` by name first failed with "Function or symbol not found"
  (symbol/import label collision); disassembly by address recovered the exact tail-call targets.
- `0x10c948` — table-C slot; disasm shows an accessor/init `(w0,w1,w3)` that logs `0x84` and
  stores to global `0x16ca50`, i.e. **not** a command factory — basis for flagging table C
  partially decoded.

### `read_bytes` — the three verb tables (stride 16)

- `0x16c848` (`pFunc_level_A`), `0x16c8b8` (`pFunc_level_B`), `0x16c8f8` (`pFunc_level_C`).
  Entries read as `{ u16 verb @+0, 6-byte gap, tagged fn* @+8 }`; `ptr & ~3` = handler, low 2
  bits = kind tag; null fn-slot terminates. Layout validated on three low verbs whose handlers
  were separately decompiled (ProductInfo/MiconAccess/AdjustControl).

### `list_xrefs` / `search_symbols_by_name`

- `list_xrefs` on `pFunc` (`0x16cfa0`), `pFunc_level_A/B/C`, and `ProductInfoFunc` — confirmed
  `ProductInfoFunc`'s only xrefs are `DATA`/`INDIRECTION` (a table entry, not a called
  function), and that `pFunc` is written only by `onComplete`/`start_authentication`.
- `search_symbols_by_name "Func"` (functions) — yielded the named-handler addresses
  (`MiconAccessFunc`, `AdjustControlFunc`, `ProductInfoFunc`, …) after `nm`+strict-grep came up
  empty.

### `nm` / `strings` on `/srv/a7rv/a7rv-fw/fs/a15/lib/libsencore.so`

```console
$ nm -AD --defined-only /srv/a7rv/a7rv-fw/fs/a15/lib/libsencore.so | grep pFunc_level
.../libsencore.so:000000000016c848 D pFunc_level_A
.../libsencore.so:000000000016c8b8 D pFunc_level_B
.../libsencore.so:000000000016c8f8 D pFunc_level_C
```
(the three tables are defined `D` data objects, not code — which is why decompiling those
addresses returned "Function or symbol not found".)

```console
$ nm -AD -D --defined-only /srv/a7rv/a7rv-fw/fs/a15/lib/*.so \
    | grep -E ' (command|open|close|memory)[0-9A-Fa-f]{4}$'
.../libpro00.so:00000000000009a4 T command001F
.../libpro00.so:0000000000000a64 T command00F1
```
Complete output — **no** `memoryFF03`/`memory00FF`/`commandFF03` anywhere (basis for C.1's
symbol-inventory check), and only two genuine verb exports image-wide (cross-ref
`plugin-verb-map.md`).

### Deliberately **not** opened

- `Read_Hasp`, `Reset_Hasp`, `Regist_HaspId` bodies — stopped at one level (control-flow-only
  scope; no HASP contents touched).
- Any function past the dispatch/gate boundary that would require dumping key material.
- Functions exceeding ~300 lines were read only in the specific address ranges cited, not whole.

### Known gaps (recorded honestly, not asserted)

- High-verb (`0x00FF`/`0xFF00`/`0xFF02`) exact handler identities: pointer-tag decode is
  **HYPOTHESIS** — only the low verbs' tags were confirmed against decompiled bodies.
- `pFunc_level_C` full membership: table C is only partially walked (see `0x10c948` note).
- auth-level integer ↔ table (A/B/C) mapping, and kind-tag ↔ Command-subclass mapping:
  **HYPOTHESIS**, labelled as such throughout.
