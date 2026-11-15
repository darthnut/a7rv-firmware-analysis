# Sony a7R V — service "adjust" message framing map (run 2)

**Date:** 2026-11-13 · **Method:** static reverse engineering (Ghidra headless MCP `ghidra_svctools`, read-only) · **Author:** automated research pass

**Binaries examined** (firmware files on the user's own a7R V extraction; not reproduced here):

| Program | Source path (per Ghidra project) | Notes |
|---|---|---|
| `adjstctl.elf` | host-side CLI tool | Ghidra addresses are actual virtual addresses (`0x40xxxx`) |
| `libtestcmd.so` | `/srv/a7rv/a7rv-fw/fs/a15/lib/libtestcmd.so` | ELF image base 0x0 (relocatable); Ghidra loaded it at 0x100000 — **file-relative vaddr = Ghidra addr − 0x100000**. Built with `GCC (20201211 (Sony CE Linux 14.0.1.0)) 6.4.0`; **NEEDED: `libosal_uipc.so`** (the OSAL user-IPC library that provides `osal_snd_sync_msg` etc. — *not* examined this run) |

This document describes the **host-side** (Linux userland) half of the mechanism only: how `adjstctl` turns argv into a message and hands it to an OSAL IPC send call. **What the camera firmware does with the message after `osal_snd_*` is out of scope and was not examined** — every statement below about the payload covers only bytes produced on the host side.

This run supersedes `service-adjust-map.run1.md` (run 1) on the table model; see §1.

---

## 0. Scope and safety — read first

* **Host-side tool vs camera-side handler.** Everything decompiled here runs in the host tool (`adjstctl.elf` + `libtestcmd.so`). The **camera-side handler** for these OSAL messages was **not examined at all this run**. The message layout in §4 describes what the host *writes*; the camera's interpretation of each field is inferred only from the host's own field naming (`--abid` printer, response parser) and is tagged accordingly.
* **These are manufacturing/service calibration operations.** The table of 1 779 entries enumerated by `--abid` (`adjstctl --help` string: `adjust block: 0x%04x, code: 0x%04x OSAL ID: 0x%08lx cmdname: %s`) drives per-block adjust commands — the kind of operation that, on Sony service menus of this era, touch sensor/ADC, AF, and gyro (SteadyShot) calibration data.
* **Adjust/write commands can permanently alter calibration data** stored by the camera. The request header carries an opaque `code` and arbitrary payload bytes whose semantics live entirely in the unexamined camera-side handler; nothing in the host code validates what a code does.
* **This is not a run guide.** Knowing a block key, code, or OSAL ID does not mean a given command is safe or meaningful to send; several entries are read-only-looking (`*_GET_*`) but the split is **not** established by any evidence here. **No command is claimed safe.**
* No encryption keys, key material, or firmware binaries are reproduced here.

---

## 1. Corrections to run 1 (`service-adjust-map.run1.md`)

Run 1 modelled the `--abid` table as records with base `0x401a64` and fields "f0" (u32) / "f1" (u32). This run's disassembly of the table lookup function `FUN_00401474` (§5) pins the true base and layout; run 1's base was **4 bytes early**, which shifted all field names one notch:

| Run 1 | Run 2 (corrected, byte-confirmed) | Evidence |
|---|---|---|
| table base `0x401a64` | **`0x401a68`** | `FUN_00401474`: `adrp x2,0x401000` + `add x3,x2,#0xa68` (below) |
| `f0` (u32 at name−4) | **not a field** — it is the *previous* record's `osal_id` (`u32` at rec+0x44), read because the scan base was 4 bytes early | `ldr w0,[x2,#0x44]` return of `FUN_00401474`; see §6 B3.1 |
| `f1` (u32 at name−4+4…name−2) | a **u16 pair**: `adjust_block` at rec+0x00 (the lookup key) and `code` at rec+0x02 | `uxth w0,w0` + `ldurh w5,[x5,#-0x48]` key compare; `--abid` printer prints `name-4` as "adjust block" and `name-2` as "code" (§5) |
| "name → opcode lookup" | **there is no name lookup anywhere in `adjstctl`**; the only lookup is a linear scan keyed on the u16 `adjust_block` (§5) | `FUN_00401474` full disassembly; `strncmp` import used only for `"stdout"` (§5) |

First table record, raw bytes at `0x401a68` (72 bytes, `read_bytes`): `01 01 01 10` + `"APP_TESTCMD\0…"` → block `0x0101`, code `0x1001`, name `APP_TESTCMD`, and at +0x44: `4b 01 83 00` → OSAL id `0x0083014b`.

---

## 2. B1 — the real call chain from argv to the OSAL send

All addresses from this run. `libtestcmd.so` addresses are Ghidra-image (subtract 0x100000 for file vaddr).

### 2.1 Chain (host side; camera side ✂ cut here)

```
argv
 │  adjstctl main() 0x4010c0
 │   ├─ memcpy(x29+0x160, 0x420f50, 0x100)          # install getopt longopts template
 │   ├─ cmdline_init(sndstruct@x29+0x58, cfg@x29+0x80)
 │   ├─ cmdline_get_opts(cfg, opttable, argc, argv)  # getopt_long + per-option handlers
 │   ├─ cmdline_get_sync(NULL, &sndstruct)           # UNCONDITIONAL → flags bit0 = SYNC
 │   ├─ cmdline_get_id() ×2                          # positional [adjust_block] [adjust_code] → u16s
 │   ├─ FUN_00401474(block)                          # linear scan 1779-entry table → OSAL id
 │   ├─ sndstruct = { 0x150, FUN_004018a8, FUN_00401644, (flags already set), &cfg }
 │   └─ testcmd_sndmsg(osal_id, &sndstruct, sid=0xdc0000)
 │        │  libtestcmd
 │        ├─ testcmd_invalid_param()
 │        ├─ osal_valloc_msg_wait(id, &msg, 0x150, 1)     # allocate host msg buffer
 │        ├─ osal_set_msg_src(msg, sid)
 │        ├─ do_read(ss, msg, 0x150)  →  FUN_004018a8(msg, 0x150, &cfg)
 │        │     = 40-byte request header + payload from argv tokens / ifile / ibfile
 │        │       + total-size patch (FUN_004014c4)
 │        ├─ flags&1 == 1  →  osal_snd_sync_msg(id)        # adjstctl always takes this branch
 │        │     (async path: osal_snd_msg(id, msg)        # dead in adjstctl — flags bit0 always set)
 │        ├─ do_write(ss, msg, 0x150)  →  FUN_00401644(msg, …, &cfg)   # reply parse/print
 │        │     addr!=0 → open("/dev/mem") + mmap(PROT_READ|MAP_SHARED) dump
 │        └─ osal_free_msg(id, msg)
 │
✂  osal_snd_sync_msg → libosal_uipc.so → kernel → camera service handler  (NOT examined)
```

Byte-level evidence for every hop is in §3 (function bodies) and §7 (main's disassembled tail).

### 2.2 Per-function decompiles (quoted verbatim this run)

> `libtestcmd.so` decompiler output as returned by `decompile_function`; Ghidra-address in heading.

#### `cmdline_get_id` — `0x1029f0` (file vaddr 0x29f0)

Consumes **one positional argv token** as a number, via the cursor at cfg+0x20 and the remaining-count at cfg+0x24; refuses if the token has trailing junk.

```c
/* WARNING: Type propagation algorithm not settling */
undefined4 cmdline_get_id(undefined4 *param_1,long param_2)

{
  long lVar1;
  undefined4 uVar2;
  ulong uVar1;
  char *local_8;

  if (*(int *)(param_2 + 0x24) < 1) {
    return 0xffffffff;
  }
  uVar1 = strtoul(*(char **)(*(long *)(param_2 + 0x28) + (long)*(int *)(param_2 + 0x20) * 8),
                  &local_8,0);
  *param_1 = (int)uVar1;
  uVar2 = 0xffffffff;
  if (*local_8 == '\0') {
    *(int *)(param_2 + 0x24) = *(int *)(param_2 + 0x24) + -1;
    *(int *)(param_2 + 0x20) = *(int *)(param_2 + 0x20) + 1;
    uVar2 = 0;
  }
  return uVar2;
}
```
*Reads:* cfg+0x20 (argv cursor), cfg+0x24 (remaining positional count), cfg+0x28 (argv). *Writes:* `*param_1` (out u32); on success cfg+0x20 += 1, cfg+0x24 -= 1. *Callees:* `strtoul`. *Returns:* 0 / -1. (In `main` the u32 is then range-checked `tst w0,#0xffff0000` and stored as a u16 — §7.)

#### `cmdline_get_sid` — `0x10284c` (not imported by `adjstctl`)

```c
undefined4 cmdline_get_sid(char *param_1,long param_2)

{
  long local_8;
  undefined4 uVar2;
  ulong uVar1;

  uVar1 = strtoul(param_1,&local_8,0);
  if (*(char *)local_8 == '\0') {
    *(int *)(param_2 + 0x1c) = (int)uVar1;
    uVar2 = 0;
  }
  else {
    uVar2 = 0xffffffff;
  }
  return uVar2;
}
```
*Reads:* option string `param_1`. *Writes:* cfg+0x1c (message source id; default 0xdc0000 set by `cmdline_init`). Not in adjstctl's import list → adjstctl always uses the default sid.

#### `cmdline_get_sync` — `0x102838`

```c
undefined8 cmdline_get_sync(undefined8 param_1,long param_2)

{
  *(uint *)(param_2 + 0x18) = *(uint *)(param_2 + 0x18) | 1;
  return 0;
}
```
Unconditionally sets bit0 of sendstruct+0x18. `main` calls it **unconditionally** itself (not as an option handler — §7), so for adjstctl this flag is always on (B3.5, §6).

#### `cmdline_get_size` — `0x102b0c` (not imported by `adjstctl`)

Computes a payload size three ways — sum of `[size]:[data]` argv tokens (`FUN_0010203c` per token), lines of a text file (`fgets` + `FUN_00102440` + `FUN_0010203c`), or `st_size` of a named file (`FUN_00102cb8` is the `__xstat` wrapper; `*param_1 = *param_1 + local_50;` where local_50 is `st_size`):

```c
  pcVar6 = (char *)param_2[1];
  if (pcVar6 == (char *)0x0) {
    if (*param_2 == 0) {
      ...
        iVar2 = FUN_0010203c(*puVar1,0,0);
        if (iVar2 < 0) { return -1; }
        *param_1 = *param_1 + (long)iVar2;
      ...
    }
    else {
      ...  fgets(acStack_80,0x40,__stream) ...  FUN_0010203c(lVar4,0,0) ...
    }
  }
  else {
    iVar2 = FUN_00102cb8(pcVar6,acStack_80);
    if (iVar2 == 0) {
      *param_1 = *param_1 + local_50;
    }
    else {
      perror(pcVar6);
    }
  }
```

#### `cmdline_read_data_from_args` — `0x102220`

Packs the remaining positional argv tokens (`[size]:[data]` syntax) into the buffer via `FUN_00102104(buf, token, space)`:

```c
  uVar2 = 0;
  uVar3 = (ulong)*(uint *)(param_3 + 0x20);
  ...
  while( true ) {
    if (*(int *)(param_3 + 0x20) + *(int *)(param_3 + 0x24) <= (int)uVar3) {
      return uVar2;
    }
    iVar1 = FUN_00102104(param_1,*(undefined8 *)(*(long *)(param_3 + 0x28) + uVar4),param_2 - uVar2);
    if (iVar1 < 0) break;
    uVar2 = uVar2 + iVar1;
    param_1 = param_1 + iVar1;
    ...
    if (param_2 <= uVar2) { return uVar2; }
  }
  return 0xffffffff;
```
*Reads:* cfg+0x20/+0x24/+0x28 (cursor/count/argv). *Writes:* `param_1` buffer (≤ param_2 bytes). *Callees:* `FUN_00102104` (the `[size]:[data]` token parser; usage string: `size: b|w|d|digit`, `data: decimal or hex(0x) or string`).

#### `cmdline_write_data_via_args` — `0x102658`

Symmetric writer used on the **reply** side in other tools: same loop, but per token calls `FUN_00102550(cfg, buf, token)` (echoes reply bytes back per token, `"%s:%s"` / `"%c:0x%x"`). adjstctl does **not** import it; adjstctl's reply writer is `FUN_00401644` (§4.3).

```c
    iVar1 = FUN_00102550(param_3,param_1,*(undefined8 *)(*(long *)(param_3 + 0x28) + uVar4));
```

#### `testcmd_sndmsg` — `0x101e3c` (file vaddr 0x1e3c) — the send driver

```c
undefined8 testcmd_sndmsg(undefined4 param_1,undefined4 *param_2,undefined4 param_3)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  void *local_8;

  iVar2 = testcmd_invalid_param();
  iVar3 = -0x400;
  if (iVar2 == 0) {
    iVar3 = osal_valloc_msg_wait(param_1,&local_8,*param_2,1);
    if (iVar3 == 0) {
      osal_set_msg_src(local_8,param_3);
      uVar1 = local_8;
      iVar2 = do_read(param_2,local_8,*param_2);
      if (iVar2 < 0) {
        iVar2 = -0x4ff;
      }
      else {
        if ((param_2[6] & 1) == 0) {
          iVar2 = osal_snd_msg(param_1,local_8);
        }
        else {
          iVar2 = osal_snd_sync_msg(param_1);
        }
        if (iVar2 == 0) {
          if ((param_2[6] & 1) == 0) {
            return 0;
          }
          iVar4 = do_write(param_2,uVar1,*param_2);
          iVar2 = 0;
          if (iVar4 < 0) {
            iVar2 = -0x4fe;
          }
        }
      }
      if (iVar2 != 0 || (param_2[6] & 1) != 0) {
        osal_free_msg(param_1,local_8);
        iVar3 = iVar2;
      }
    }
  }
  return iVar3;
}
```
`param_1` = OSAL queue id, `param_2` = sendstruct, `param_3` = sid. `*param_2` = buffer size (0x150 for adjstctl); `param_2[6]` = u32 at sendstruct+0x18, bit0 = sync. **Sync path (adjstctl's only path):** allocate → `osal_set_msg_src` → fill via `do_read` (fill cb) → `osal_snd_sync_msg(param_1)` → reply handled in-place via `do_write` (reply cb) on the *same* buffer → `osal_free_msg`. Note the decompiled `osal_snd_sync_msg(param_1)` shows only the queue id — the message handle may be passed in an argument Ghidra didn't model or picked up by the OSAL from context; not resolvable from this binary (OSAL lives in `libosal_uipc.so`, not examined). **HYPOTHESIS** (labelled): the sync variant blocks until the reply lands in the allocated buffer, which is why the reply callback runs on `local_8` directly.

#### `__rcvmsg` — `0x101b80` (async receive plumbing — **not imported by `adjstctl`**)

```c
ulong __rcvmsg(ulong param_1,long param_2,code *param_3,code *param_4,undefined4 param_5)

{
  ulong uVar1;
  undefined *local_8;
  ulong uVar2;

  *(uint *)(param_2 + 0x24) = (uint)param_1;
  uVar2 = (*param_3)(param_1,&local_8,testcmd_cb,param_2);
  if ((int)uVar2 == 0) {
    do_wait(param_2,param_5);
    uVar2 = (*param_4)(param_1 & 0xffffffff,local_8);
    if ((int)uVar2 == 0) {
      uVar1 = 0;
      if ((uint)param_1 != *(uint *)(param_2 + 0x24)) {
        uVar1 = *(uint *)(param_2 + 0x24);
      }
      uVar2 = (ulong)uVar1;
    }
  }
  return uVar2;
}
```
Registers `testcmd_cb` as the receive callback (`param_3` = register fn, `param_4` = unregister fn), waits (`do_wait`), then reports the id that actually responded (callback stores it at ctx+0x24, and `testcmd_cb` overwrites that slot with −0x3fa on error — see below). adjstctl's import table (§8) contains **no** `__rcvmsg`/`testcmd_rcvmsg` entry — the whole async path is dead for this tool.

#### `do_read` / `do_write` — `0x1019b0` / `0x1019e4` (sendstruct trampolines)

```c
undefined8 do_read(long param_1,undefined8 param_2,undefined4 param_3)
{
  if (*(code **)(param_1 + 8) == (code *)0x0) { return 0; }
  uVar1 = (**(code **)(param_1 + 8))(param_2,param_3,*(undefined8 *)(param_1 + 0x1c));
  return uVar1;
}

undefined8 do_write(long param_1,undefined8 param_2,undefined4 param_3)
{
  if (*(code **)(param_1 + 0x10) == (code *)0x0) { return 0; }
  uVar1 = (**(code **)(param_1 + 0x10))(param_2,param_3,*(undefined8 *)(param_1 + 0x1c));
  return uVar1;
}
```
`do_read` calls sendstruct+0x08 (the *fill* callback) — "read" = read data *from the host* into the message; `do_write` calls sendstruct+0x10 (the *reply* callback). Both pass sendstruct+0x1c (the tool context, `&cfg`) as third arg.

#### `cmdline_init` — `0x101ffc`

```c
void cmdline_init(long param_1,undefined8 *param_2)

{
  testcmd_init();
  param_2[2] = 0; ... param_2[6] = 0;                    /* zero cfg[0x00..0x37] */
  *(undefined4 *)((long)param_2 + 0x1c) = 0xdc0000;      /* default msg source id */
  *(undefined8 **)(param_1 + 0x1c) = param_2;            /* sendstruct+0x1c = &cfg */
  return;
}
```

#### `testcmd_cb` — `0x101a18` (async receive callback, for completeness)

```c
  printf("rcv msg from 0x%x size %d @ %p\n",param1,iVar2,param_1);
  for (lVar3 = 0; iVar2 = osal_msg_size(param_1), (int)lVar3 < iVar2; lVar3 = lVar3 + 1) {
    printf("%02x ",(uint)*(byte *)((long)param_1 + lVar3));
  }
  ...
  iVar2 = do_write(param_2,param_1,*param_2);
  if ((iVar2 < 0) || (((param_2[6] & 1) != 0 && (iVar2 = do_read(param_2,param_1,*param_2), iVar2 < 0)))) {
    iVar2 = -0x3fa;
  }
```
Dumps the received message as hex to stdout, then runs the tool's reply callback. Not reachable from adjstctl (no import).

### 2.3 adjstctl glue: option handling (`cmdline_get_opts` — `0x1028d8`)

```c
  iVar5 = param_3 + -1;
  while( true ) {
    local_4 = 0;
    iVar1 = getopt_long(param_3,param_4,"",param_2[1],&local_4);
    iVar2 = 0;
    if ((-1 < iVar1) && (iVar1 < (int)param_2[2])) {
      iVar5 = iVar5 - (*(int *)(param_2[1] + … + 8) + 1);
      pcVar3 = *(code **)(*param_2 + (long)(int)local_4 * 0x18);
      if (pcVar3 != (code *)0x0) {
        iVar2 = (*pcVar3)(_optarg,*(undefined8 *)(*param_2 + (long)(int)local_4 * 0x18 + 8));
      }
    }
    if (iVar1 == 0x3f || iVar2 != 0) break;
    if (iVar1 == -1) {
      *(int *)(param_1 + 0x24) = iVar5;
      *(undefined8 *)(param_1 + 0x28) = param_4;
      …
      *(int *)(param_1 + 0x20) = _optind;
      return 0;
    }
  }
  return 0xffffffff;
```

opttable (main's x29+0x40) = `{ handler-array@+0, longopts-array@+8, count@+0x10 }`; handler array stride 0x18 = `{ cb@+0, cbdata@+8, help-text-ptr@+0x10 }`; longopts is the `memcpy`'d `struct option` template from `0x420f50` (stride 0x20). Remaining positional count = `argc-1-Σ(has_arg+1)` (`iVar5`), stored at cfg+0x24; argv at cfg+0x28; cursor `cfg+0x20 = _optind`.

The **7 handlers** (main's table at x29+0xb8, names from GOT-resolved PLT stubs, help text read from .rodata):

| idx | cb | cbdata | longopt (name string byte-confirmed @0x421201+) | help |
|---|---|---|---|---|
| 0 | `cmdline_show_revision` (PLT 0x400ee0 → GOT 0x432010) | 0 | `ver` | `show version number of testcmd module` |
| 1 | `cmdline_get_ifile` (PLT 0x400fa0) | &cfg | `ifile` | `payload text filename to input` |
| 2 | `cmdline_get_ibfile` (PLT 0x4010b0) | &cfg | `ibfile` | `payload binary filename to input` |
| 3 | `cmdline_get_obfile` (PLT 0x400ed0) | &cfg | `obfile` | `payload binary filename to output` |
| 4 | `FUN_0040196c` (--abid dump, calls FUN_00401408 + exit) | 0 | `abid` | `show supported adjust block ID` |
| 5 | `FUN_00401980` (`strtoul` → `DAT_00432110`) | &cfg | `step` | `set step number` |
| 6 | `FUN_00401630` (sets `DAT_00432124=1`, disasm: `mov w1,#0x1; str w1,[x0,#0x124]`) | 0 | `getlog` | `use for G…` (string truncated by tool read cap) |

Positionals after options: `[adjust_block] [adjust_code] [size]:[data] …` (usage string at 0x42118c: `… "<options> [adjust_block] [adjust_code] [size]:[data]"`, continuation at 0x4211d4: `"digit\ndata\t\tdecimal or hex(0x) or string"`).

---

## 3. Structs and buffers handed around (offsets, by evidence)

**Sendstruct** — `main`'s x29+0x58, 0x20 bytes. Fields written by `cmdline_init`, `main` (§7 disasm) and `cmdline_get_sync`:

| off | value | written by |
|---|---|---|
| +0x00 | u64 buffer size = `0x150` | `main`: `bl 0x004014bc; str x0,[x29,#0x58]` (FUN_004014bc: `return 0x150;`) |
| +0x08 | fill cb = `FUN_004018a8` | `main`: `adrp 0x401000 / add #0x8a8 / str x0,[x29,#0x60]` |
| +0x10 | reply cb = `FUN_00401644` | `main`: `adrp 0x401000 / add #0x644 / str x0,[x29,#0x68]` |
| +0x18 | u32 flags, bit0 = SYNC | `cmdline_get_sync` (always set — §2.2) |
| +0x1c | `&cfg` | `cmdline_init`: `*(undefined8 **)(param_1 + 0x1c) = param_2;` |

**cfg** — `main`'s x29+0x80 (zeroed by `cmdline_init`), offsets used across both binaries:

| off | meaning | evidence |
|---|---|---|
| +0x00 | `--ifile` path ptr | `FUN_004018a8`: `if (*param_3 == 0) … else cmdline_read_data_from_file(…)` |
| +0x08 | `--ibfile` path ptr | `FUN_004018a8`: `if (param_3[1] == 0) … else cmdline_read_data_from_ibfile(…)` |
| +0x10 | `--obfile` path ptr | `FUN_00401644`: `__s1 = *(char **)(param_3 + 0x10);` |
| +0x1c | u32 msg source id (default **0xdc0000**) | `cmdline_init`; read at call site: `ldr w2,[x29,#0x9c]` (x29+0x80+0x1c) |
| +0x20 | argv cursor (= `_optind` after parse) | `cmdline_get_opts` / `cmdline_get_id` |
| +0x24 | remaining positional count | same |
| +0x28 | argv | same |
| +0x30 | ptr to `{u16 block, u16 code}` | `main`: `add x0,x29,#0x38; str x0,[x29,#0xb0]` (x29+0xb0 = cfg+0x30) |

---

## 4. The message: exact layout handed to `osal_snd_*`

One 0x150-byte buffer, allocated by `osal_valloc_msg_wait(id, &msg, 0x150, 1)`, source id set by `osal_set_msg_src(msg, 0xdc0000)`, then filled by `FUN_004018a8` (fill cb, below). Message-level framing (source id, OSAL headers) is added inside `libosal_uipc.so` — **not examined**; the layout below is the payload buffer itself.

### 4.1 Request header — `FUN_004014d0` (0x28 bytes, decompiled verbatim)

```c
undefined8 FUN_004014d0(undefined1 *param_1,undefined2 param_2,undefined2 param_3,short param_4)

{
  if (param_1 == (undefined1 *)0x0) { return 0; }
  memset(param_1,0,0x150);
  if (param_4 == 0) { param_4 = 1; }
  *(undefined2 *)(param_1 + 0x24) = param_2;      /* adjust_block */
  *param_1 = 1;                                    /* +0x00 = 1 */
  param_1[1] = 1;                                  /* +0x01 = 1 */
  *(undefined2 *)(param_1 + 0x26) = param_3;      /* code */
  *(undefined2 *)(param_1 + 8) = 0x40;             /* +0x08 = 0x40 */
  *(short *)(param_1 + 2) = param_4;               /* step (--step, default 1) */
  *(undefined4 *)(param_1 + 4) = 0;                /* total size (patched later) */
  return 0x28;
}
```

| off | size | value | notes |
|---|---|---|---|
| +0x00 | u8 | `1` | constant. **HYPOTHESIS:** request-side counterpart of the response `mode` byte (parser prints `*resp+0` as `mode`) |
| +0x01 | u8 | `1` | constant. **HYPOTHESIS:** counterpart of response `res` |
| +0x02 | u16 | `step` | from `--step` (`DAT_00432110`), forced to 1 if 0 |
| +0x04 | u32 | total length | `FUN_004014c4`: `*(int *)(param_1 + 4) = param_2 + 4;` — patched to payload_total+4 after fill |
| +0x08 | u16 | `0x40` | constant (header length 0x40? — unverified) |
| +0x0c…0x23 | 24 B | `0` | zeroed by memset |
| +0x24 | u16 | `adjust_block` | table key (u16, from argv positional 1) |
| +0x26 | u16 | `code` | argv positional 2 |
| +0x28…0x3f | 24 B | `0` | zeroed |
| **+0x28** | → | **payload** | `FUN_004018a8` starts payload at buf+0x28 (= header return 0x28) |

### 4.2 Payload fill — `FUN_004018a8` (fill cb, decompiled verbatim)

```c
  iVar2 = FUN_004014d0(param_1,*(undefined2 *)param_3[6],((undefined2 *)param_3[6])[1],
                        (undefined2)DAT_00432110);
  if (-1 < iVar2) {
    lVar1 = param_1 + iVar2;                       /* buf + 0x28 */
    uVar5 = param_2 - iVar2;
    iVar2 = cmdline_read_data_from_args(lVar1,uVar5 & 0xffffffff,param_3);
    if (iVar2 < 0) { return -1; }
    lVar1 = lVar1 + iVar2;
    lVar4 = uVar5 - (long)iVar2;
    if (param_3[1] == 0) {
      if (*param_3 == 0) goto LAB_00401944;
      iVar3 = cmdline_read_data_from_file(lVar1,lVar4,param_3);
    }
    else {
      iVar3 = cmdline_read_data_from_ibfile(lVar1,lVar4,param_3);
    }
    iVar2 = iVar2 + iVar3;
    if (-1 < iVar2) {
LAB_00401944:
      FUN_004014c4(param_1,iVar2);                 /* +0x04 = payload_total + 4 */
      return param_2;
    }
  }
  return -1;
```
So: argv `[size]:[data]` tokens first, then `--ibfile` bytes (if set) else `--ifile` text bytes; block/code come from `param_3[6]` = cfg+0x30 = the `{u16,u16}` pair; `+0x04` = payload_total + 4.

### 4.3 Response header — parsed by reply cb `FUN_00401644` (0x1c-byte header, then data)

Decompiled verbatim (abridged to the load-bearing lines; full body in the transcript):

```c
  param2 = *(uint *)(param_1 + 0x18);              /* datasz */
  if ((int)param2 < 0) { return -1; }
  uVar4 = (uint)*(undefined8 *)(param_1 + 0x10);   /* addr (u32) */
  if (uVar4 == 0) {
    __addr = param_1 + 0x1c;  uVar3 = 0;  __fd = -1;      /* inline payload */
  }
  else {
    __fd = open("/dev/mem",0);
    if (__fd < 0) { return -1; }
    uVar3 = uVar4 & 0xfff;  …
    __addr = mmap((void *)0x0,(long)(int)(param2 + uVar3),1 /*PROT_READ*/,1 /*MAP_SHARED*/,__fd,
                  (long)((int)uVar4 / 0x1000 << 0xc));
    …
  }
  if (DAT_00432124 == 0) {                          /* unless --getlog */
    fprintf(stdout,"mode:   0x%02x\n",(uint)*param_1);
    fprintf(stdout,"res:    0x%02x\n",(uint)param_1[1]);
    fprintf(stdout,"step:   0x%02x\n",(uint)*(ushort *)(param_1 + 2));
    fprintf(stdout,"addr:   0x%08x\n",0);
    fprintf(stdout,"datasz: 0x%02x\n",param2);
  }
```

| off | size | name (from the tool's own printf labels) |
|---|---|---|
| +0x00 | u8 | `mode` |
| +0x01 | u8 | `res` |
| +0x02 | u16 | `step` |
| +0x10 | u32 | `addr` — if ≠0: physical address; tool maps it via `/dev/mem` and dumps `datasz` bytes from it instead of the inline data |
| +0x18 | u32 | `datasz` |
| +0x1c | → | inline payload (used when `addr==0`) |

Output routing (same function): no `--obfile` → `cmdline_write_bindata_to_stdout(__addr+pgoff, datasz, cfg)`; `--obfile stdout` → `fwrite(resp+1,1,1,stdout)` (the `res` byte) + data; otherwise `cmdline_write_data_to_obfile(…)`, or (with `--getlog`) raw `fopen(obfile,"wb")` + `fwrite(resp+1,1)` + data. `strncmp(__s1,"stdout",6)` is the *only* use of the `strncmp` import in adjstctl. A second, near-identical parser `FUN_00401548` (0 xrefs — dead) ends with `*param_1 = (long)(param_3 + 0x1c); return *(u32 *)(param_3 + 0x18);` — confirming `data@+0x1c`, `datasz@+0x18`.

---

## 5. B2 — the name/ID lookup: linear scan keyed on u16, **not** a name lookup

`FUN_00401474` @0x401474, disassembled verbatim:

```
00401474 adrp x2,0x401000
00401478 uxth w0,w0                    ; key = u16 arg
0040147c add  x3,x2,#0xa68             ; table base = 0x401a68
00401480 mov  x1,#0x0
00401484 mov  x4,#0x48                 ; stride 72
00401488 cmp  x1,#0x6f3                ; 1779 records
0040148c sxtw x2,w1
00401490 b.ne 0x0040149c
00401494 mov  w0,#0x0
00401498 ret                            ; not found → 0
0040149c add  x1,x1,#0x1
004014a0 madd x5,x1,x4,x3
004014a4 ldurh w5,[x5,#-0x48]           ; rec[i].u16 at +0x00
004014a8 cmp  w5,w0
004014ac b.ne 0x00401488
004014b0 madd x2,x2,x4,x3
004014b4 ldr  w0,[x2,#0x44]             ; return rec[i].u32 at +0x44
004014b8 ret
```

* **Plain linear scan** (not bsearch, not a hash): up to 0x6f3 = **1779** records, stride **0x48**, comparing the **u16 at rec+0x00** against the zero-extended argument; returns the **u32 at rec+0x44**, or **0** if not found (callers treat 0 as usage error: `cbz w0,0x004012ac`).
* Record layout: `{ u16 adjust_block @+0x00; u16 code @+0x02; char name[0x40] @+0x04; u32 osal_id @+0x44 }` — corroborated independently by the `--abid` printer `FUN_00401408`, which iterates name strings by stride 0x48 and prints `adjust block: 0x%04x` from `name-4`, `code: 0x%04x` from `name-2`, `OSAL ID: 0x%08lx` from `name+0x40`.
* **No function anywhere in adjstctl compares a command name.** The names are display-only (`--abid` dump). `strncmp` appears exactly once, in `FUN_00401644` against `"stdout"` (§4.3). Callers pass the u16 **block key typed on the command line** as the argument (§7 disasm: `ldrh w0,[x19]; bl 0x00401474`).
* **The `ADC_GET_DATA` duplicate** is therefore disambiguated by its u16 key alone. Byte evidence (this run, `read_bytes`; string addresses from `search_strings`):

```
0x413d38:  01 09 01 00 "ADC_GET_DATA\0…"   block=0x0901 code=0x0001  osal_id@0x413d7c = 0x00720207
0x413ea0:  02 09 01 00 "ADC_GET_DATA\0…"   block=0x0902 code=0x0001  osal_id@0x413ee4 = 0x90720835
```
Both records sit exactly on the stride grid ((0x413d38−0x401a68)/0x48 = 1034, (0x413ea0−0x401a68)/0x48 = 1039 — records 1034 and 1039). Identical name, identical code; the camera-side dispatch target (OSAL id) is selected purely by `adjust_block` 0x0901 vs 0x0902.

---

## 6. B3 — the five open questions from run 1

1. **What is `f0`? — RESOLVED: an artifact.** Run 1's "f0" (u32 at `name-4`) is the **previous record's `osal_id`** (u32 at rec+0x44), read because the base was 4 bytes early. The real fields are the u16 pair at rec+0x00/+0x02 (§1, §5). Evidence: `add x3,x2,#0xa68` + `ldr w0,[x2,#0x44]` (FUN_00401474 disasm).
2. **f1 low half — "block" vs "code"? — RESOLVED: low half = block.** `FUN_00401474` keys on the u16 at rec+0x00 (`uxth`+`ldurh`), main stores argv-positional-1 there (`strh w0,[x19]`), and the `--abid` printer labels `name-4` (= rec+0x00) as *"adjust block"* and `name-2` (= rec+0x02) as *"code"*. Low half = **adjust_block (lookup key)**; high half = code.
3. **Are mode/res/step/addr/datasz stored in the sent buffer or printf-only? — RESOLVED (split).** The **request** stores only: constants `1`,`1` at +0x00/+0x01, `step` at +0x02, length at +0x04, `0x40` at +0x08, block at +0x24, code at +0x26 (FUN_004014d0 stores, §4.1) — `mode`/`res`/`addr`/`datasz` are **never stored in the request**. The names come from the **response** buffer: every `printf("mode: …")`/`"addr:"`/`"datasz:"` in `FUN_00401644` reads the *reply* buffer (§4.3). What the constants at request +0x00/+0x01 mean is **HYPOTHESIS** (request/response counterpart of mode/res) — camera-side, unverified.
4. **The `/dev/mem` function — RESOLVED.** `/dev/mem` (string @0x42122a) is referenced by the **reply callback `FUN_00401644`**, i.e. the host tool's *output* path, only: if the **response** header's `addr` (@+0x10) ≠ 0, the tool `open("/dev/mem",0)` + `mmap(..., PROT_READ=1, MAP_SHARED=1, fd, addr & ~0xfff)` and dumps `datasz` bytes of that physical memory to stdout/obfile (§4.3 verbatim). It is reached on adjstctl's sync path (`testcmd_sndmsg → do_write → FUN_00401644`). The other `/dev/mem`-style parser `FUN_00401548` has **0 xrefs** (dead). `/dev/mem` use is host-side only — nothing here shows the *camera* touching `/dev/mem`.
5. **Sync vs async selection — RESOLVED: adjstctl is always sync.** Two independent facts: (a) the selector in `testcmd_sndmsg` is `param_2[6] & 1` (sendstruct+0x18 bit0) — §2.2; (b) that bit is **unconditionally** set: `cmdline_get_sync` itself has no condition (`*(uint *)(param_2 + 0x18) = *(uint *)(param_2 + 0x18) | 1; return 0;`), and `main` calls it unconditionally right after option parsing, not as a CLI handler:
   ```
   004011f0 bl 0x00401060          ; cmdline_get_opts
   00401200 add x1,x29,#0x58
   00401204 mov x0,#0x0
   00401208 bl 0x00401040          ; cmdline_get_sync(NULL, &sndstruct) — always
   ```
   (PLT stubs resolved by decompile: 0x401060 = `cmdline_get_opts`, 0x401040 = `cmdline_get_sync`.) Hence `osal_snd_msg` (async) and the `__rcvmsg`/`testcmd_cb` receive machinery are dead code for this tool; the async plumbing exists in `libtestcmd.so` for other tools (none examined).

---

## 7. Main's positional handling (disasm, verbatim, `0x4011e8–0x401294`)

```
004011e8 add x1,x29,#0x40           ; opttable
004011ec mov x0,x19                 ; &cfg
004011f0 bl 0x00401060              ; cmdline_get_opts
004011f4 cmp w0,#0x0
004011f8 ccmp w20,#0x1,#0x4,ge      ; argc>=1 too, else usage
004011fc b.le 0x004012ac
00401200 add x1,x29,#0x58
00401204 mov x0,#0x0
00401208 bl 0x00401040              ; cmdline_get_sync(NULL,&snd) → always sync
0040120c ldur x20,[x29,#0x74]       ; x20 = snd+0x1c = &cfg
00401210 add x0,x29,#0x3c           ; scratch u32
00401214 mov x1,x20
00401218 ldr x19,[x20,#0x30]        ; x19 = &{u16 block, u16 code}
0040121c bl 0x00400f50              ; cmdline_get_id  (positional 1)
00401220 tbnz w0,#0x1f,0x004012ac   ; error → usage
00401224 ldr w0,[x29,#0x3c]
00401228 tst w0,#0xffff0000         ; must fit u16
0040122c b.ne 0x004012ac
00401230 strh w0,[x19]              ; block
00401234 mov x1,x20
00401238 add x0,x29,#0x3c
0040123c bl 0x00400f50              ; cmdline_get_id  (positional 2)
00401240 tbnz w0,#0x1f,0x004012ac
00401244 ldr w0,[x29,#0x3c]
00401248 tst w0,#0xffff0000
0040124c b.ne 0x004012ac
00401250 strh w0,[x19,#0x2]         ; code
00401254 ldrh w0,[x19]              ; block → key
00401258 bl 0x00401474              ; table lookup (linear, u16 key)
0040125c mov w19,w0
00401260 cbz w0,0x004012ac          ; unknown block → usage
00401264 bl 0x004014bc              ; 0x150
00401268 sxtw x0,w0
0040126c str x0,[x29,#0x58]         ; snd.size = 0x150
00401270 adrp x0,0x401000
00401274 add x0,x0,#0x8a8           ; FUN_004018a8
00401278 ldr w2,[x29,#0x9c]         ; cfg+0x1c = sid (0xdc0000)
0040127c str x0,[x29,#0x60]         ; snd.fill
00401280 adrp x0,0x401000
00401284 add x0,x0,#0x644           ; FUN_00401644
00401288 add x1,x29,#0x58           ; &snd
0040128c str x0,[x29,#0x68]         ; snd.reply
00401290 mov w0,w19                 ; OSAL id from table
00401294 bl 0x00400ff0              ; testcmd_sndmsg(id, &snd, sid)
```

---

## 8. adjstctl import surface (full, `list_imports`)

`cmdline_get_ibfile, cmdline_get_id, cmdline_get_ifile, cmdline_get_obfile, cmdline_get_opts, cmdline_get_sync, cmdline_init, cmdline_read_data_from_args, cmdline_read_data_from_file, cmdline_read_data_from_ibfile, cmdline_show_revision, cmdline_show_usage, cmdline_write_bindata_to_stdout, cmdline_write_data_to_obfile, testcmd_sndmsg` — plus libc (`open, fopen, fclose, fread-family: fwrite, fputc, fprintf, printf-family, mmap, munmap, close, strtoul, strncmp, strlen/stdio bits, memcpy, memset, exit, abort, __libc_start_main, __gmon_start__`).
**Absent:** `testcmd_rcvmsg`, `__rcvmsg`, `cmdline_get_size`, `cmdline_get_sid`, `cmdline_write_data_via_args`, `osal_*` (OSAL calls are inside `libtestcmd.so`, which `NEEDED`s `libosal_uipc.so`).

---

## 9. Still open (after this run)

* **Camera-side handling** of OSAL id + `{block, code, step, payload}` — the actual adjust semantics, validation, and any auth checks. Not in these two host binaries.
* **Request bytes +0x00/+0x01 = 1,1 and +0x08 = 0x40** — constants; meaning unverified (HYPOTHESIS §6.3).
* **`osal_snd_sync_msg` exact ABI** (whether the msg handle travels in an unmodelled argument) — needs `libosal_uipc.so`.
* **`--getlog` mode**: `DAT_00432124==1` switches the reply dump to raw (`fwrite` of `res` byte + data to obfile, no header print) — the log-message framing (0x150 reply buffer vs `testcmd_cb`'s 0xdc8187 ack port) is not fully mapped.
* `FUN_00102104` / `FUN_0010203c` internals (exact `[size]:[data]` token grammar — b/w/d widths) not decompiled this run; only their call sites and the usage string.

---

## How this was checked

All decompiles/disassemblies below were run this session through the read-only Ghidra MCP server `ghidra_svctools` (Ghidra 12.2 project; binaries as shipped in the user's own firmware extraction). Beyond `decompile_function`, this run also used the server's read-only tools **`disassemble`, `read_bytes`, `list_xrefs`, `list_imports`, `list_project_binaries`, `list_project_binary_metadata`, `search_symbols_by_name`, `search_strings`** — e.g. `main` and `FUN_00401474` have no usable symbols, so they were read via `disassemble`; table/rodata bytes via `read_bytes`; PLT-stub identities via stub disasm → `list_xrefs` on the GOT slot; the `ADC_GET_DATA` strings via `search_strings`. No binutils/objdump/other external tooling was used.

**`libtestcmd.so` functions decompiled this run:** `cmdline_get_id` 0x1029f0 · `cmdline_get_sid` 0x10284c · `cmdline_get_sync` 0x102838 · `cmdline_get_size` 0x102b0c · `cmdline_read_data_from_args` 0x102220 · `cmdline_write_data_via_args` 0x102658 · `cmdline_get_opts` 0x1028d8 · `testcmd_sndmsg` 0x101e3c · `__rcvmsg` 0x101b80 · `testcmd_cb` 0x101a18 · `do_read` 0x1019b0 · `do_write` 0x1019e4 · `cmdline_init` 0x101ffc · plus `cmdline_setup_cb` 0x102c44, `testcmd_rcvmsg` 0x101f44, `testcmd_init` 0x101e1c, `testcmd_invalid_param` 0x1019a0, `cmdline_write_bindata_to_stdout` 0x102a70, `FUN_0010203c`, `FUN_00102104`, `FUN_00102550`, `FUN_00102cb8` (earlier in the session; summarized in §2.2/§9 where quoted).

**`adjstctl.elf` functions decompiled or disassembled this run:** `main` 0x4010c0 (full disasm) · entry 0x4012c8 · `FUN_00401310`/`00401328`/`00401360`/`0040139c` (ELF init boilerplate) · `FUN_00401408` (--abid printer) · `FUN_00401474` (decomp + full disasm) · `FUN_004014bc` · `FUN_004014c4` · `FUN_004014d0` · `FUN_00401548` (dead reply parser, 0 xrefs) · `FUN_00401630` (disasm) · `FUN_00401644` (reply cb, full) · `FUN_004018a8` (fill cb, full) · `FUN_0040196c` · `FUN_00401980` · PLT stubs decompiled: 0x400ec0 `memcpy`, 0x400ed0 `cmdline_get_obfile`, 0x400f40 `cmdline_show_usage`, 0x400f50 `cmdline_get_id`, 0x400f60 `cmdline_init`, 0x400fa0 `cmdline_get_ifile`, 0x400ff0 `testcmd_sndmsg`, 0x401040 `cmdline_get_sync`, 0x401060 `cmdline_get_opts`, 0x4010b0 `cmdline_get_ibfile`; 0x400ee0 `cmdline_show_revision` identified via disasm + GOT 0x432010 `list_xrefs`.

**Byte reads (this run):** 0x401a68 (first table record, 72 B) · 0x413d38, 0x413d78, 0x413ea0, 0x413ee0 (the two `ADC_GET_DATA` records + OSAL ids) · 0x421167–0x42122b (help/usage strings, longopt names `ver/ifile/ibfile/obfile/abid/step/getlog`, `/dev/mem` at 0x42122a).

**Limitations:** Ghidra auto-analysis artifacts (`FUN_` names, `param_N`) retained; sync-ABI note in §2.2; every claim about camera-side behaviour would be speculation and is confined to HYPOTHESIS tags.
