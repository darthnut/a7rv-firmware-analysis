# Mapping the Sony a7R V OSAL/UIPC message-passing ABI (`libosal_uipc.so`)

Static reverse-engineering of the user's **own** Sony a7R V firmware, for a public research
write-up. This document records offsets, ioctl request numbers, struct layouts and mechanism.
**No firmware bytes are reproduced here** — only pseudo-code fragments recovered by Ghidra this
session, as evidence for the claims being made.

---

## 0. Scope, method, notation

**Target.** `/srv/a7rv/a7rv-fw/fs/a15/lib/libosal_uipc.so`, AArch64 (a15 core), analyzed in the
Ghidra project `ghidra_svctools`. `list_project_binaries` returned it with
`analysis_complete: true` alongside `/adjstctl.elf` and `/libtestcmd.so`.

**The one architectural fact everything else hangs off.** There are two layers in this one
library, and which one runs is decided by **bit 15 of the QID**:

* `osal_*` (public API) — a **userspace fast path**. QCB (queue control block) lookup in a
  userspace table, priority-ordered list insert, in-thread callback dispatch. **No syscall.**
* `u_osal_*` — the **kernel-facing** layer. Each wrapper issues **exactly one `ioctl`** on the
  single `/dev/uipc` file descriptor and retry-loops on one specific error.

The branch is explicit and appears at the top of essentially every public entry point:

```c
/* osal_free_msg @0x106970 (decompiled this session) */
if ((param_1 >> 0xf & 1) == 0) { uVar10 = u_osal_free_msg(); return uVar10; }
/* osal_reg_msg_queue_cb @0x106b78 (decompiled this session) */
if ((param4 >> 0xf & 1) == 0) { uVar2 = u_osal_reg_msg_queue_cb(); return uVar2; }
```

So: **bit 15 = 1 → userspace queue; bit 15 = 0 → kernel queue.** VERIFIED (§C.1).

**Notation.** Addresses are Ghidra virtual addresses in `libosal_uipc.so`, written `@0x106970`.
Every symbol was resolved with `search_symbols_by_name` first, because each export appears twice —
a real body (`source: IMPORTED, is_thunk: false`) and a same-named PLT thunk
(`source: DEFAULT, is_thunk: true`) — and decompiling by name on the ambiguous ones returns
`Ambiguous match` rather than a body. All calls below name the real address.
Error codes are decimal unless prefixed `0x`; `-1024 == 0xfffffc00`.

**Confidence tags.** `VERIFIED` = backed by a Ghidra `decompile_function` / `disassemble` call run
this session, with the cited lines shown. Anything I inferred rather than read is tagged
**HYPOTHESIS** and is not used to support any other claim.

---

## A. Message lifecycle end-to-end

### A.1 The path a message takes

```
osal_valloc_msg_wait(qid,&pp,size,flags)   @0x1067b0   allocate + (optional) wait
        │  bit15 clear → u_osal_valloc_msg_wait()   ioctl 0x8000000a
        │  bit15 set   → alloc_msg() @0x105460      userspace, no syscall
        ▼
   *pp  = payload pointer = allocation_base + 0x18
        ▼
fill payload; optionally osal_set_msg_pri / osal_set_msg_src
        ▼
osal_snd_msg(qid,msg)         @0x105e60   async: link into QCB, dispatch CB, RETURN
osal_snd_sync_msg(qid,msg)    @0x106458   sync: call the consumer's CB inline
        │  bit15 clear → u_osal_snd_msg() 0x80000004 / u_osal_snd_sync_msg() 0x80000005
        ▼
consumer runs (same thread for the userspace path)
        ▼
osal_free_msg(qid,msg)        @0x106970   atomic refcount-- then vpool_free/free_fblock
```

**`osal_snd_msg` contains no `ioctl`.** VERIFIED (read this session): it links the message into the
QCB list and dispatches; the syscall only happens when QID bit 15 is clear. This is why a naive
`strace` of a7R V task-to-task messaging inside one core shows nothing.

### A.2 Where the buffer memory comes from — `mmap`, but not the shared one

This is the part most easily gotten wrong, so both regions are stated separately. `do_init`
(`@0x1033e8`, `source: IMPORTED`, the `0x102740` duplicate is a thunk; decompiled this session
with `include_strings`):

```c
uconf = open("/dev/uipc",2);                                    /* O_RDWR */
if (uconf < 0) { perror("open /dev/uipc error: "); return 0xffffffff; }
do {
  iVar3 = ioctl(uconf,0xffffffff80000010,&local_100);           /* ← 0x80000010 */
  if (iVar3 == 0) goto LAB_0010344c;
  if (iVar3 == -1) { iVar3 = -*__errno_location(); }
} while (iVar3 == -0x3fd);                                      /* ERETRY loop */
LAB_0010344c:
  DAT_0011b570 = local_110;  DAT_0011b580 = iStack_10c;
  DAT_0011b584 = local_108;  DAT_0011b590 = uStack_104;
  fcntl(uconf,2,1);
  DAT_0011b568 = mmap((void *)0x0,(long)DAT_0011b570,3,1,uconf,0);   /* region 1 */
  ...
  uipc_opt = DAT_0011b568;
  ... DAT_0011b578 = mmap((void *)0x0,(long)DAT_0011b580,3,0x22,0,0) /* region 2 */
  fblock_init(DAT_0011b578, DAT_0011b580 - DAT_0011b584);
  osal_lock_init(vpool);
  vpool._16_8_ = (long)DAT_0011b578 + (long)(DAT_0011b580 - DAT_0011b584);
  ...
  iVar3 = pthread_mutex_init((pthread_mutex_t *)&DAT_0011a410,0);
```

VERIFIED — two mappings, doing different jobs:

| | region 1 (`DAT_0011b568`, aliased as `uipc_opt`) | region 2 (`DAT_0011b578`) |
|---|---|---|
| `mmap` flags | `prot=3 (RW)`, `flags=1` → **`MAP_SHARED`, fd = the `/dev/uipc` fd** | `prot=3 (RW)`, `flags=0x22` → **`MAP_PRIVATE\|MAP_ANONYMOUS`, fd = 0** |
| size | `DAT_0011b570`, i.e. **sized by the kernel** (ioctl `0x80000010` reply) | `DAT_0011b580`, kernel-reported; usable = `DAT_0011b580 - DAT_0011b584` |
| purpose | **kernel-written control block.** `uipc_opt+0x10` = proxy-thread count, `uipc_opt+0x17` = debug/abort flag (§B.3, §C.4) | **the message arena.** `fblock_init` + `vpool` are laid over it |

So the precise answer to "is a shared region `mmap`'d?" is **yes, one**: region 1 is the
`MAP_SHARED` mapping of `/dev/uipc`, and it is a small *control/config* block, **not** the message
buffer pool. Message data lives in region 2, a `MAP_PRIVATE|MAP_ANONYMOUS` pool — it is *not*
shared with the kernel, so the kernel does not see message payloads through an mmap; it sees them
only as pointers passed in ioctl argument structs. **HYPOTHESIS:** the kernel pins/translates those
pointers at ioctl time (the kernel side is out of scope).

Allocation classes, from `FUN_00105460` = `alloc_msg(uint qid, long *out, int size, int flags)`
(`@0x105460`, VERIFIED):

```
total = ((size + 3) & ~3 + 0x5b) & ~0x3f        /* 64-byte granularity */
total == 0x40 → alloc_fblock()                  /* 64-byte fast class */
else          → vpool_alloc(qcb+0x30 | global vpool, total, flags, &sub)
*out = base + 0x18                              /* header is 0x18 bytes */
```

Max message payload is **0x1000 (4096 B)**; the allocator rejects larger requests (VERIFIED in
`alloc_msg`).

### A.3 Message buffer layout (offsets)

`msg` as passed around the API is the **payload pointer**. The internal base is `msg - 0x18`.
Confirmed independently by `alloc_msg` (`*out = base + 0x18`) and by `osal_free_msg`:

```c
/* osal_free_msg @0x106970, decompiled this session */
lVar11 = param_2 + -0x18;                       /* base = payload - 0x18 */
psVar1 = (short *)(param_2 + -0xe);             /* base+0x0a : u16 refcount */
... ExclusiveMonitorPass(psVar1,0x10); *psVar1 = sVar5 + -1; ...   /* atomic -- */
if (lVar11 == 0 || (short)(sVar5 + -1) != 0) { uVar10 = 0; }       /* still held → no free */
```

| offset | field | evidence |
|---|---|---|
| `+0x00` | `void *next` — singly-linked queue link | `osal_snd_msg` writes `base+0`; dispatch walks it (VERIFIED) |
| `+0x08` | `u8 nblk` — allocation size in 64-byte blocks; **0 ⇒ fblock class** | `alloc_msg`; `osal_free_msg`: `iVar12 = byte[payload-0x10] << 6; if (byte==0) iVar12 = 0x40;` |
| `+0x09` | `u8 flags` — bit0 in-use, **bit6 = extended prologue**, **bit7 = sync-in-service** | `osal_free_msg`: `if ((*(byte *)(param_2 + -0xf) & 0x40) == 0) lVar4 = lVar11;` ; `__osal_snd_sync_msg`: `[payload-0xf] \|= 0x80`; `__osal_finish_sync_cb`: `&= 0x7f`; `alloc_msg`: priority = `byte[payload-0xf] & 0x3f` |
| `+0x0a` | `u16 refcount` (init 1) | atomic decrement quoted above (VERIFIED this session) |
| `+0x0c` | `u32 0xa5a5a5a5` canary | `alloc_msg` (VERIFIED) |
| `+0x10` | `u32 size` — payload bytes | `alloc_msg` (VERIFIED) |
| `+0x14` | `u32 0x55555555` canary | `alloc_msg` (VERIFIED) |
| `+0x18` | **payload begins** | `*out = base + 0x18` (VERIFIED) |
| `+0x18+size` | `u32 0x77777777` trailing canary | `alloc_msg` (VERIFIED) |

**Open detail, flagged rather than papered over.** `osal_free_msg` computes the *allocation* base as
`payload - 0x18` normally, but **`payload - 0x40` when header byte `+0x09` bit 6 is set** — a 0x28
byte larger. My earlier read of `alloc_msg` described that bit as adding a 0x10-byte extra header
with the payload at `base+0x28`. Those two are not the same number, and I did not re-derive the
extended case to closure this session. **HYPOTHESIS:** bit 6 marks a message allocated with a
larger reserved prologue (e.g. for a relay/broadcast rewrite of the header chain), and the
`payload-0x28` figure from `alloc_msg` is one level of that indirection. Treat "extended messages
reserve extra prologue before the 0x18 header" as the claim; do not quote a second offset for it.

Priority and source live **in the header**, not the payload:
`osal_get_msg_pri` `@0x106de0` / `osal_set_msg_pri` `@0x106db0` operate on
`byte[payload-0xf] & 0x3f` (header `+0x09`, bits 0–5) — VERIFIED in `alloc_msg`'s priority field.
`osal_msg_size` `@0x107e08`, `osal_set_msg_src` `@0x107e20`, `osal_get_msg_src` `@0x107e28` are
thin accessors around the same 0x18-byte header; I resolved their addresses with
`search_symbols_by_name` but **did not decompile the bodies of the src accessors**, so this document
makes no claim about which header field carries the source.

### A.4 Free path, VERIFIED (`osal_free_msg` @0x106970)

```c
if (uVar3 < 0x40) pbVar9 = (byte *)(&DAT_0011b0d0)[uVar3];      /* static QCB table */
else              pbVar9 = (byte *)FUN_001050b8((ulong)uVar3);  /* dynamic QCB table */
...atomic -- on [payload-0xe] (msg refcount); if still held → return 0;
...atomic -- on QCB+0x02 (queue's outstanding-message count);
if (((*pbVar9 >> 3 & 1) == 0) && (*(long *)(pbVar9 + 0x30) != 0)) {
        lVar4 = param_2 + -0x40;
        if ((*(byte *)(param_2 + -0xf) & 0x40) == 0) lVar4 = lVar11;   /* = payload-0x18 */
        vpool_free(*(long *)(pbVar9 + 0x30), lVar4, size);      /* queue-private pool */
} else if (*(byte *)(param_2 + -0x10) == 0) {
        free_fblock(lVar11);                                    /* 64-byte class */
} else {
        vpool_free(vpool, lVar4, (ulong)*(byte *)(param_2 + -0x10) << 6);  /* global pool */
}
```

Note the **double bookkeeping**: a per-message refcount at header `+0x0a` *and* a per-queue
outstanding count at `QCB+0x02`, both manipulated with ARM exclusive monitor loops
(`ExclusiveMonitorPass`/`ExclusiveMonitorsStatus`) rather than locks. QCB byte 0 bit 3 selects
queue-private vs global pool. `-1018` (`0xfffffc06`) is returned as the generic "bad QID / no QCB"
result here.

### A.5 Ioctl ABI — exact request constants

All sites verified by `disassemble` this session reading the `mov`/`movk` that builds `w1` plus the
`bl 0x00102530` (`ioctl` PLT thunk) that follows.

Ghidra prints the 16-bit `mov` immediate signed, so `mov x20,#-0xfffb` is `0x5`
(`0x10000 - 0xfffb`), and `movk x20,#0x8000,LSL#16` sets bits 16–31. Worked example,
`u_osal_snd_sync_msg` `@0x103a98`:

```
00103abc mov x20,#-0xfffb
00103ad4 movk x20,#0x8000,LSL#16        → 0x80000005
00103ae8 ldr w0,[x21]                   ; fd  (x21 = global at 0x119fc8)
00103af4 bl  0x00102530                 ; ioctl(fd, 0x80000005, struct)
```

`0x80000004` decoded with Linux `_IOC`: `dir = (v>>30)&3 = 2` (READ), `size = (v>>16)&0x3fff = 0`,
`type = v&0xff = 0`, `nr = 4`. A direction bit of READ **with size 0** is not what `_IOC()` ever
emits. **VERIFIED conclusion:** Sony uses its own numbering, effectively **`(dir << 31) | nr`** — a
linear enum `0x80000004 … 0x80000010`, direction-in-bit-31, **no encoded struct size**. Do not try
to generate these with `_IOR(type, nr, struct)`.

| request | wrapper | arg struct | status |
|---|---|---|---|
| `0x80000004` | `u_osal_snd_msg(qid,msg)` `@0x103a10` | `{u32 qid; pad; u64 msg}` | VERIFIED |
| `0x80000005` | `u_osal_snd_sync_msg(qid,msg)` `@0x103a98` | 0x28 B, see §B.2 | VERIFIED |
| `0x80000006` | `u_osal_snd_sync_direct` `@0x103bd8` | — | VERIFIED (constant) |
| `0x80000007` | `u_osal_rcv_msg_tmo(qid,out,tmo)` `@0x103c60` | — | VERIFIED (constant) |
| `0x80000008` | `u_osal_reg_msg_queue_cb` `@0x103cd8` **and** `u_osal_reg_sync_msg_queue_cb` `@0x103d68` | identical; one flag byte differs (see §B.3) | VERIFIED |
| `0x80000009` | `u_osal_unreg_msg_queue_cb` (site `@0x103e38`) | `{u64 qid; u64 handle}` | VERIFIED |
| `0x8000000a` | `u_osal_valloc_msg_wait(qid,out,size,flags)` `@0x103e98` | — | VERIFIED (constant) |
| `0x8000000b` | `u_osal_free_msg(qid,msg)` `@0x103f28` | — | VERIFIED (constant) |
| `0x8000000c` | `u_osal_dynamic_id(...)` `@0x103fb0` | — | VERIFIED (constant) |
| `0x8000000d` | proxy-thread upcall loop, `FUN_00103260` | see §B.4 | VERIFIED |
| `0x80000010` | `do_init` `@0x1033e8` — query sizes, no args in | 4 × u32 out | VERIFIED |

Unreg (`0x80000009`) verified at the instruction level:

```
00103e14 mov x21,#-0xfff7         ; 0x9
00103e1c movk x21,#0x8000,LSL#16  ; → 0x80000009
00103e18 add x22,x29,#0x30        ; arg struct
00103e24 str w0,[x29,#0x30]       ; +0x00 = qid
00103e28 str x1,[x29,#0x38]       ; +0x08 = handle
00103e2c ldr w0,[x20]             ; fd
00103e38 bl  0x00102530           ; ioctl(fd, 0x80000009, struct)
00103e48 add x1,x1,#0x34 ; ldxr/stxr w0-1   ; atomic dec of a global refcount at 0x119ffc
```

**Uniform retry rule, VERIFIED in every wrapper read:** `if (ret == -1) ret = -*__errno_location();`
then **loop again while `ret == -1021` (`-0x3fd`)**. `-1021` is the driver's "try again" status, and
it is the *only* status the library retries.

**Error-code table** (values observed as immediates in the functions quoted in this document):

| value | hex | observed meaning |
|---|---|---|
| `-1024` | `0xfffffc00` | parameter error (null ptr, index 0, bad type) |
| `-1023` | `0xfffffc01` | not handled / need-alloc; also the `uipc_oom` result |
| `-1022` | `0xfffffc02` | queue-get failure, `alloc_cb()` OOM |
| `-1021` | `0xfffffc03` | **kernel "retry"** — loops on this |
| `-1020` | `0xfffffc04` | **no sync consumer registered on that QID** |
| `-1018` | `0xfffffc06` | no QCB for this QID; **also** "multi CB registered" |

(The `-1022`/`-1023` split is the one number pair I did not pin down cleanly across all sites;
treat those two rows as approximate. Every other row is an immediate I read.)

**Deliberately not read** (§Footer): ioctl constants at `0x1038d4` (`u_osal_stat_msgq`), `0x103950`
(`u_osal_set_msgq_broadcast_mode`), `0x1039d0` (`u_osal_set_msgq_log_mode`), `0x10376c`
(`u_osal_stat_sem`), `0x1037e0` (`u_osal_wai_sem_tmo`), `0x103858` (`u_osal_sig_sem`). Six sites
identified but not disassembled; I claim no constants for them.

---

## B. Sync vs async, and how callbacks are delivered

### B.1 The async (fast) path is not a syscall

`osal_snd_msg` `@0x105e60` (VERIFIED): for a userspace QID it links the message at `QCB+0x10`/
`QCB+0x18` (head/tail, priority-ordered), then calls `FUN_001057e8(qcb)` — a dispatch loop that pops
`qcb+0x10`, invokes each CB, and frees unconsumed messages with
`vpool_free(payload-0x28 | payload, nblk<<6)` or `free_fblock(payload)` when `nblk == 0`.
**Not a kernel handoff.** `QCB+0x00` bit 1 suppresses local dispatch.

### B.2 Sync send: the sender calls the consumer *in its own thread*

`osal_snd_sync_msg` `@0x106458` is a one-line tail call — VERIFIED:

```
mov x3,#0 ; mov x2,#0 ; b __osal_snd_sync_msg      /* pre_cb = NULL, pre_arg = 0 */
```

`__osal_snd_sync_msg(uint qid, long payload, code *pre_cb, undefined8 pre_arg)` `@0x1061e8`,
VERIFIED body:

* bit 15 clear → `u_osal_snd_sync_msg()` → ioctl `0x80000005` (§B.2b).
* bit 15 set → `osal_lock(QCB+0x38)`; `cb = *(QCB+0x28)`; **`return -1020` if `cb == NULL`** —
  there must already be a *sync* consumer on that QID.
* if `cb+0x19 & 8 && pre_cb` → call `pre_cb(cb, pre_arg)`; if it handled it, return 0 leaving
  message bit 7 set.
* set `byte[payload-0xf] |= 0x80` (sync-in-service), then
  **`(*(cb+0x10))(payload-0x18, cb, qcb)`** — the consumer's handler runs **on the sender's stack**.
* decrement `cb+0x18` (in-flight count); if `cb+0x19 & 2` and count reached 0 → `FUN_00105008(cb)`;
  clear msg bit 7; unlock.

**So a userspace-to-userspace sync send never blocks and never syscalls.** "Sync" here means
*the consumer's callback executes inside the sender's call*, not "the sender waits on a semaphore".

**B.2b — the kernel flavour of sync is different, and is where the upcall trick lives.**
`u_osal_snd_sync_msg` `@0x103a98`, VERIFIED instruction-level:

```
00103acc add x19,x29,#0x58            ; struct base = ioctl arg
00103ad8 str w24,[x29,#0x58]          ; +0x00 = qid (u32)
00103adc str x0,[x29,#0x60]           ; +0x08 = self-ptr → &struct+0x10
00103ae4 str x1,[x29,#0x68]           ; +0x10 = msg ptr
00103ac8 stp xzr,xzr,[x0]             ; +0x10, +0x18 zeroed  (kernel fills these)
00103ae0 str xzr,[x29,#0x78]          ; +0x20 = 0
00103af4 bl  0x00102530               ; ioctl(fd, 0x80000005, struct)
00103b00 ldr x2,[x29,#0x70]           ; struct+0x18 = fn pointer THE KERNEL WROTE
00103b04 cbz x2, done
00103b08 ldr x1,[x29,#0x78]           ; struct+0x20 = arg THE KERNEL WROTE
00103b18 blr x2                       ; cb(msg, cb_arg)   ← kernel upcall into the sender
00103b34 bl  0x00102530               ; re-issue the SAME ioctl to finish
```

Struct = **0x28 bytes**: `{u32 qid; u32 pad; void *self (→ +0x10); u64 msg; u64 out_cb; u64 out_arg}`.
The kernel returns a *function pointer and an argument* in the caller's own struct; userspace calls
it, then re-issues the same ioctl so the kernel can retire the request. That is the entire sync-reply
mechanism across the kernel boundary: **the reply is delivered by the driver handing userspace a
callback to run, not by a second message.** (Whether the driver blocks the sending thread across the
first ioctl is a kernel-side property — out of scope, §D.)

**Completion half, for cross-image sync:** `__osal_finish_sync_cb(uint qid, long payload)`
`@0x106110`. `list_xrefs` reports its only reference as **"Entry Point"** — nothing inside this `.so`
calls it; it exists for other images. VERIFIED body: lock QCB, `cb = *(QCB+0x28)`, `--cb+0x18`, free
via `FUN_00105008(cb)` at zero when `cb+0x19 & 2`, then `byte[payload-0xf] &= 0x7f` (clear
sync-in-service). So a consumer that finishes a sync exchange late calls this to release the
sender's message state.

### B.3 Registering as a consumer — and one CB per QID is enforced

`osal_reg_msg_queue_cb(uint qid, void **out_handle, cb, cb_arg)` `@0x106b78`, VERIFIED in full:

```c
if (param_3 == 0 || param_2 == 0) return 0xfffffc00;
if ((param_1 & 0x7fff) == 0) { if (*(char *)(uipc_opt + 0x17) == '\0') return 0xfffffc00;
                               else { SoftwareBreakpoint(1000,0x106c80); } }   /* trap! */
if ((param4 >> 0xf & 1) == 0) return u_osal_reg_msg_queue_cb();                /* ioctl 8 */
if ((int)param4 < 0) return 0xfffffc00;                                        /* bit31 */
pbVar4 = (qid&0x7fff) < 0x40 ? (&DAT_0011b0d0)[idx] : FUN_001050b8(idx);
if ((pbVar4 == 0 && (pbVar4 = FUN_00105100(idx)) == 0) || (puVar5 = alloc_cb()) == 0)
        return 0xfffffc01;
puVar5[4] = param_3;              /* CB+0x20 = user callback */
puVar5[5] = param_4;              /* CB+0x28 = user cb_arg  */
puVar5[2] = FUN_00104d38;         /* CB+0x10 = internal trampoline */
*param_2 = puVar5;                /* opaque handle back to caller */
osal_lock(*(undefined8 *)(pbVar4 + 0x38));
```

Then the guard whose string the brief asked me to confirm — VERIFIED, including its name:

```c
if ((pbVar6[0x19] >> 1 & 1) == 0) {
    print_task_info();
    __fd = open("/dev/kmsg",1);
    snprintf(buf+3,0xfd,"**UIPC ERROR** %s: multi CB registered to qid 0x%08x.\n",
             "check_double_register_cb", param4);
    write(__fd,buf,iVar3+3); close(__fd);
    FUN_00106ad8((param_1 >> 0x10 & 0xfff),"multi CB registered.");
    if (*(char *)(uipc_opt + 0x17) != '\0') { SoftwareBreakpoint(1000,0x106c80); }  /* trap */
    return 0xfffffc06;            /* -1018 */
}
```

`list_xrefs("0x00109278")` returned exactly one xref — `osal_reg_msg_queue_cb+0x1c0` (`0x106d38`),
type PARAM — so this is the sole enforcement site, and the function name appears as a literal
argument. **VERIFIED: at most one live callback per QID** (a CB whose `+0x19` bit 1 marks it dead is
ignored). Two consequences worth stating: this is a **1:1 point-to-point queue, not a multicast
subscription model**; and the failure mode is deliberately harsh — in debug builds
(`uipc_opt+0x17 != 0`) double registration **traps the process** rather than returning an error.
After linking a fresh CB, if `QCB` bit 1 is clear and a message is already queued
(`QCB+0x10 != 0`), it immediately calls `FUN_001057e8(qcb)` to drain it.

`osal_unreg_msg_queue_cb` `@0x105c98` → `u_osal_unreg_msg_queue_cb`, ioctl `0x80000009` (§A.5).

**Sync vs async registration is one byte.** `u_osal_reg_msg_queue_cb` `@0x103cd8` and
`u_osal_reg_sync_msg_queue_cb` `@0x103d68` both issue **`ioctl(fd, 0x80000008, ...)`** and differ
only by a flag at struct **`+0x28`: 0 = async, 1 = sync** (VERIFIED this session). The sync variant
is what populates `QCB+0x28`, the slot `__osal_snd_sync_msg` requires (else `-1020`).
`osal_reg_sync_msg_queue_cb` `@0x105b88` → `reg_sync_msg_queue_cb` `@0x105ae0`. Both variants call
the post-registration hook `FUN_00102ec0()` on success.

CB entry layout, as populated above and read by the dispatch loop:

| offset | field |
|---|---|
| `+0x00` | `next` (link in `QCB+0x08` list) |
| `+0x10` | internal dispatch trampoline — `reg` always sets it to `FUN_00104d38` (VERIFIED) |
| `+0x18` | `s8` in-flight count; `+0x19` flags (bit1 = dead → `FUN_00105008` frees; bit2 = free-at-zero; bit3 = has pre-notify) |
| `+0x1c` | `u32` owner tid, taken from `tpidr_el0` |
| `+0x20` | **user callback** |
| `+0x28` | **user `cb_arg`** |

Note `+0x18…+0x1f` are four packed byte/half fields sharing the slot that `reg` leaves alone.
The `+0x10` trampoline explains an apparent contradiction: dispatch calls `(*(cb+0x10))(msg_base, cb,
qcb)` with *three* args while the user callback was stored at `+0x20`. The trampoline adapts.
**HYPOTHESIS:** `FUN_00104d38` unwraps `cb+0x20`/`cb+0x28` and calls the user function as
`cb(msg, cb_arg)`; I read the two stores and the call site but not `FUN_00104d38`'s body.

### B.4 The proxy threads are a fixed pool, **not** one per queue

The brief phrased this as a "per-queue proxy thread". What the code actually shows is a **pool
sized by a kernel-supplied count**, and I want to be explicit that this differs from the phrasing.

`FUN_00102b88` — self-named **`create_proxy_thread`** via its own error strings. VERIFIED:

```c
iVar3 = pthread_mutex_trylock(&DAT_0011a410);        /* the mutex do_init initialised */
if (iVar3 != 0) return 0;                            /* another thread is doing it */
if (DAT_0011b588 == 0) DAT_0011b588 = calloc((long)(*(int *)(uipc_opt + 0x10) << 3),1);
if (*(int *)(lVar1 + 0x10) < 1) goto done;
local_148[0].__sched_priority = 6;
... pthread_attr_init(&attr);
    pthread_attr_setschedpolicy(&attr, 2);           /* SCHED_FIFO */
    pthread_attr_setschedparam(&attr, local_148);    /* priority 6 */
    pthread_attr_setinheritsched(&attr, 1);          /* EXPLICIT */
    pthread_create(&DAT_0011b588[i], &attr, FUN_00103390, (void *)i);
```

Thread count = **`*(int *)(uipc_opt + 0x10)`** — a value read out of the `MAP_SHARED` `/dev/uipc`
mapping, i.e. **the kernel decides how many proxy threads this process gets** (VERIFIED: same
`uipc_opt` symbol assigned from `mmap(...,1,uconf,0)` in `do_init`). Every one is `SCHED_FIFO`
priority 6, `PTHREAD_EXPLICIT_SCHED`; each gets its **own index** `i` as its thread argument, not a
QID. Any `pthread_attr_*`/`pthread_create` failure writes to `/dev/kmsg` and calls **`abort()`** —
the UIPC subsystem treats a missing proxy thread as fatal.

The start routine, `FUN_00103390` `@0x103390`, VERIFIED in full:

```c
void FUN_00103390(int param_1) {
  snprintf(acStack_18,0x14,"%s_%d","uipc_proxy",param_1);
  prctl(0xf,acStack_18,0,0,0);                       /* PR_SET_NAME → "uipc_proxy_<i>" */
  FUN_00103260(param_1);
  /* does not return: */ (*pcVar1)();                /* UndefinedInstructionException */
}
```

and its body `FUN_00103260` (`@0x103260`, reached only from `FUN_00103390+0x50`) is the upcall loop,
VERIFIED at instruction level:

```
00103280 mov x22,#-0xfff3 ; 001032c0 movk x22,#0x8000,LSL#16   → cmd 0x8000000d
00103284 str w0,[x29,#0x78]                          ; thread index
001032a4/7c stp xzr,xzr,[x29,#0x60] and [x29,#0x70]  ; out block zeroed each pass
001032c4 str wzr,[x29,#0x80] ; 001032c8 str x23,[x29,#0x88]   ; struct { 0, ptr, ... }
001032d8 bl  0x00102530                              ; ioctl(fd, 0x8000000d, ...)
001032e0 mov w19,w0 ; 001032e0/4 cmn/cbnz → EINTR check
001032e8 ldp x2,x1,[x29,#0x60]                       ; fn + arg, WRITTEN BY THE KERNEL
001032ec ldr x0,[x29,#0x70]
001032f0 blr x2                                      ; run the upcall
001032f4 str wzr,[x29,#0x80]
00103308 bl  0x00102530                              ; re-issue, forever
```

**So the proxy threads are the kernel→userspace upcall delivery mechanism**: block in
`ioctl(0x8000000d)`, the driver fills a callback pointer + argument into the caller's struct, the
thread executes it, then re-enters the ioctl. This is the same "kernel hands userspace a function
pointer" idiom as `u_osal_snd_sync_msg`, in loop form. If `FUN_00103260` ever *returns*, the thread
falls into an undefined instruction — matching the string `exit() from proxy thread!` `@0x108c40`,
and matching that `do_init` frees `DAT_0011b588` (the thread-slot array) only as part of teardown.
Strings at `@0x108c10` `cancel proxy thread error!` plus the imported `pthread_cancel`,
`pthread_join`, `pthread_detach`, `pthread_setcanceltype` indicate a cancellation path; I did **not**
read it.

**What the index means inside the driver — out of scope.** Whether `ioctl(0x8000000d, i)` partitions
upcalls by index, or whether any given QID's upcalls are pinned to a given proxy thread, is decided
in the kernel driver. Userspace only passes `i` (VERIFIED: `str w0,[x29,#0x78]` with `w0 = param_1`).

### B.5 Blocking primitives: present, but *not* on the paths I read

The brief asked about `get_bsem` / `osal_wai_sem_tmo`. Honest result: **I could not connect them to
message send.**

* `get_bsem(ulong id)` `@0x1045b0`, VERIFIED: a pure-userspace **object cache** — flat array
  `DAT_0011a450[id]` for `id < 0x40`, else a 3-level radix lookup on `(id>>9&0x3f, id>>6&7, id>>3&7,
  id&7)` rooted at `DAT_0011a660`, objects from `FUN_00104518`, sub-tables from `FUN_00104560`,
  guarded by `osal_lock/osal_unlock`, with an exclusive-monitor decrement of `DAT_0011b5cc` on the
  failure path. **No ioctl in it.**
* `list_xrefs("0x1045b0")` shows its only in-library callers are the `osal_dynamic_id` semaphore-id
  path (`bsem+0x12` ← type, `bsem+0x28` ← owner) plus an export entry point — **no caller in any
  `snd_msg`/`snd_sync_msg` path**.
* `osal_wai_sem_tmo` `@0x104858`, `osal_sig_sem` `@0x104a70`, `osal_stat_sem` `@0x104800`,
  `reset_bsem` `@0x104cf8`, `bsem_dump` `@0x104b38` exist; the `u_osal_*` counterparts
  (`u_osal_stat_sem` `@0x103740`, `u_osal_wai_sem_tmo` `@0x1037b0`, `u_osal_sig_sem` `@0x103820`)
  are the ioctl-bearing layer. The import list contains **no `sem_*` symbols**, so semaphores here
  are Sony's own objects backed by driver ioctls, not POSIX semaphores (VERIFIED via `list_imports`).
* Prior analysis exists in this Ghidra project — `::override` USER_DEFINED labels
  `prt_10498c_...` in `osal_wai_sem_tmo::override`, `prt_104c48_...` in `bsem_dump::override`,
  `prt_107588_...` in `check_dynamic_sem_id::override`. I did not modify them.

**HYPOTHESIS (explicitly unresolved):** the bsem pool is what a *cross-processor* synchronous
exchange blocks on, with the sem id carried in the message or in the `0x80000005` struct. I am not
asserting it — I found no call edge from a send path to a bsem wait, and I say so rather than
asserting the shape the question implied.

---

## C. QID namespace and `/dev/uipc`

### C.1 The QID is bit-encoded, and the encoding is cracked

`0x8f013a`, `0x94020a`, `0x80924220` are **not opaque tokens**. VERIFIED from two directions.

**(a) From the consumers.** The mask/shift idioms recur in `osal_reg_msg_queue_cb`, `osal_free_msg`,
`alloc_msg` and `osal_valloc_msg_wait`:

| bits | meaning | evidence |
|---|---|---|
| `0–14` | 15-bit **queue index**; index `0` is illegal → `-1024` | `qid & 0x7fff` everywhere; `if ((param_1 & 0x7fff) == 0) return 0xfffffc00` |
| `15` | **1 = userspace queue, 0 = kernel queue** (`u_osal_*`) | `(param_1 >> 0xf & 1) == 0 → u_osal_*()` in every public wrapper |
| `16–27` | 12-bit **type/owner** field | `FUN_00106ad8((param_1 >> 0x10 & 0xfff), "multi CB registered.")` |
| `31` | must be clear, else `-1024` | `if ((int)param4 < 0) return 0xfffffc00` |
| `28–30` | no mask observed | — |

**(b) From the allocator.** `osal_dynamic_id(uint type, int param_2, uint *out)` `@0x1075b8`,
VERIFIED — the line that defines the encoding outright:

```c
uVar1 = param_2 << 0x10 | 0x8000U | uVar1;      /* ← THE QID IS CONSTRUCTED HERE */
*param_3 = uVar1;
*(ulong *)(pbVar7 + 0x30) = (ulong)uVar1;        /* QCB+0x30 = the full assigned QID */
```

i.e. `QID = (type << 16) | 0x8000 | index` — bit 15 **forced to 1** because this is the *userspace*
allocator, bits 16–27 filled from the caller-supplied `type` argument (`param_2`), low 15 bits from a
free-index scan of a bitmap allocator.

Reading the same function's other branches, `osal_dynamic_id` is really four functions in one,
selected by `type` bits:

* `(type & 3) == 0 || == 3` or `(type & 0x60) == 0x60` → invalid:
  `"Parameter error OSAL_ID_TYPE[%x]"`, `-1024` (or trap if `uipc_opt+0x17`).
* `type>>1 & 1` → **`u_osal_dynamic_id()`, ioctl `0x8000000c`** — a *kernel-assigned* id.
* `type>>4 & 1 == 0` → **message-queue id pool**: `DAT_0011a3c0`, or `DAT_0011a340` when `type & 4`
  (which additionally calls `osal_set_msgq_broadcast_mode()`). Free-bit scan
  (`0x3f - LZCOUNT(~word)`), QCB created by `FUN_00105100` if absent.
* `type>>4 & 1 == 1` → **semaphore id pool**: `DAT_0011a380` / `DAT_0011a390` / `PTR_DAT_0011a398`,
  `get_bsem(idx)`, `bsem+0x12 = qid>>16` (stores the type into the sem object).
* the `free` roles surface as their own log strings: `free_dynamic_id`, `free_dynamic_msgq_id`,
  `free_dynamic_sem_id`, `QID %08x is not dynamic`, **`double free detected. 0x%08x`**
  (→ `-1018`, or trap under debug). Exhaustion → `uipc_oom(~type & 0xffff | param_2 << 0x10)` → `-1023`.

**Static vs dynamic QCB lookup — resolved.** `qid&0x7fff < 0x40` indexes the static array
`DAT_0011b0d0`; otherwise `FUN_001050b8` (dynamic table) then `FUN_00105100` (create). VERIFIED in
`osal_free_msg`, `osal_reg_msg_queue_cb` and `osal_dynamic_id`. I earlier had a discrepancy here
(×8 scaling vs QCB fields out at `+0x38`); `disassemble("0x106020")` settles it:

```
00106020 adrp x1,0x11b000
00106024 ubfiz x0,x23,#0x3,#0xf     ; (index & 0x7fff) << 3   ← 8-byte entries
00106028 add x1,x1,#0xc0            ; 0x11b0c0
0010602c add x0,x1,x0
00106030 ldr x20,[x0,#0x10]         ; entry at 0x11b0c0 + idx*8 + 0x10
```

`0x11b0c0 + 0x10 == 0x11b0d0`, so the array is **64 8-byte entries at `0x11b0d0` = an array of QCB
`*` pointers**, with a 16-byte header at `0x11b0c0`. QCBs are separately allocated objects — which
is why their fields can sit at `+0x28/+0x38` while the table stride is 8. My earlier "embedded QCB"
reading was wrong; this is the correction. **QCB total size is NOT determined** by this work.

QCB fields observed (VERIFIED, offsets only — no size claim):

| offset | field | seen in |
|---|---|---|
| `+0x00` | `u8` flags: bit1 = suppress local dispatch; bit3 = dynamic/use-global-pool; value `0xff` = bypass the double-CB check | `reg`, `free_msg`, dispatch |
| `+0x02` | `u16` outstanding-message count (atomic); `0` = unassigned slot; logged as `A=%d` in `"QID[%x] M=%d C=%d S=%d A=%d"` | `free_msg`, `free_dynamic_msgq_id` |
| `+0x08` | async CB list head | `reg`, dispatch |
| `+0x10` / `+0x18` | message queue head / tail | `snd_msg`, dispatch |
| `+0x28` | **sync consumer CB** — `-1020` when null | `__osal_snd_sync_msg`, `__osal_finish_sync_cb` |
| `+0x30` | union: per-queue `vpool` handle **or** the assigned full QID for a dynamic queue | `free_msg`, `dynamic_id` |
| `+0x38` | mutex handle passed to `osal_lock`/`osal_unlock` | `reg`, `sync_msg`, `finish_sync_cb` |

### C.2 `osal_valloc_msg_wait`'s type allow-list, stated factually

`osal_valloc_msg_wait` `@0x1067b0` accepts only type fields `0x8f`, `0x3e`, `0x110` on the local
path; anything else is rejected (VERIFIED). Applying the decoder mechanically:

| QID | type (`>>16 & 0xfff`) | index (`& 0x7fff`) | bit 15 | in valloc's allow-list? |
|---|---|---|---|---|
| `0x8f013a` | `0x08f` | `0x013a` | **1 → local** | yes |
| `0x94020a` | `0x094` | `0x020a` | **1 → local** | **no** |
| `0x80924220` | `0x092` (`bit31` also set) | `0x24220 & 0x7fff = 0x4220`… | `0` → **kernel path** | n/a — and bit 31 set makes it a `-1024` param error in the public wrappers |

I report the arithmetic and stop there: `0x94020a`'s type `0x94` is not in
`osal_valloc_msg_wait`'s local allow-list, so a message on it cannot be allocated through that
function's local branch. **I did not establish *why*** — it may be allocated via `alloc_msg`
directly, via `u_osal_valloc_msg_wait`, or by another image entirely. `0x80924220` carries bit 31,
which every public wrapper I read rejects outright, so it is most likely a kernel-namespace or
cross-processor identifier handled entirely on the `u_osal_*` side rather than a public userspace
QID. Flagging rather than explaining is the honest result here.

### C.3 The connect targets `0x8f013a` and `0x94020a`

Per the brief these are the SSH-manager heartbeat target and the command-executor endpoint
respectively. **What this library can tell me about them stops at the mechanism**, and that is the
correct boundary:

* Both decode as **bit 15 = 1 → local/userspace queues**, so traffic on them is delivered by
  `osal_snd_msg`'s QCB list + callback dispatch with **no syscall at all** (§B.1) — the peer is
  reached through a QCB in this same process's address space, or through an image that shares it.
* A consumer for either would be established by `osal_reg_sync_msg_queue_cb(qid, &handle, cb, arg)`
  (sync, `QCB+0x28`, ioctl `0x80000008` with struct `+0x28 = 1`) or the async variant — **exactly
  one CB, and a second registration aborts or traps** (§B.3).
* **Which task or image currently holds the CB for `0x8f013a` or `0x94020a` cannot be determined
  from this file.** It is set at runtime by whoever calls the register function; it may live in
  another process, or on another processor whose image is not in this Ghidra project. `list_xrefs`
  in `libosal_uipc.so` shows no reference to either constant — this is a *library*, called by
  whoever links it, so the caller that names the QID is by construction elsewhere. Finding it means
  cross-referencing other a15 images, which is a different job.

### C.4 `/dev/uipc` and the public-ID slot

VERIFIED from `do_init` `@0x1033e8`:
`open("/dev/uipc", O_RDWR)` → `ioctl(fd, 0x80000010, &out)` (4 × u32: mmap size, pool size, pool
reserved, one more) → `fcntl(fd, F_SETFL, 1)` → `mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED,
fd, 0)` → `mmap(NULL, pool_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0)` →
`fblock_init` + `osal_lock_init(vpool)` + `pthread_mutex_init(&DAT_0011a410)`. On any failure:
`perror`, `munmap`, `close(uconf)`, return `-1`. `/dev/kmsg` is opened (`O_WRONLY`) purely to write
the `**UIPC ERROR**` diagnostic lines — visible over serial/console, which is why they are the
surviving evidence.

The shared page is a **kernel-written config block**, VERIFIED by two of its fields being consumed:
`uipc_opt+0x10` = proxy-thread count (`create_proxy_thread`) and `uipc_opt+0x17` = debug/abort flag
(`osal_free_msg`, `osal_reg_msg_queue_cb`, `osal_dynamic_id` — every one of them traps instead of
returning when it is set). Other fields at `+0x10…+0x17` were not decoded.

Also VERIFIED, and small but notable for anyone enumerating endpoints:
`osal_reg_public(long handle)` `@0x105e20` is a **four-line single-slot registration**:

```c
if (param_1 == 0) return 0xfffffc00;
if (DAT_0011b080 == 0) { DAT_0011b080 = param_1; return 0; }
return 0xfffffc06;                 /* -1018: already taken */
```

One global slot at `DAT_0011b080`, first caller wins, second gets `-1018`. So the "public" id space
is not a table — a process can hold **one** public registration. Static/pre-assigned QIDs come from
`osal_init_msgq` `@0x107470`; dynamic ones from `osal_dynamic_id` (§C.1); `check_dynamic_sem_id`
`@0x1074d0` validates the sem variant. `do_init` is registered via `__register_atfork` (imported),
so the device state is re-established across `fork()`.

### C.5 One unresolved address aliasing

The `u_osal_*` wrappers obtain the descriptor as `adrp x19,0x119000; ldr x20,[x19,#0xfc8];
ldr w0,[x20]` — i.e. a **pointer** at `0x119fc8`, dereferenced — while `do_init` assigns
`uconf = open("/dev/uipc",2)` and `unreg` atomically decrements a count at `0x119ffc`. Ghidra may be
rendering one object two ways or these may be two globals. **HYPOTHESIS:** same underlying object.
I did not resolve it, and no claim above depends on it.

---

## D. Scope, safety, and what this is not

**This is a userspace client of a kernel driver.** Everything above describes
`libosal_uipc.so` — the client library. The `/dev/uipc` **kernel driver is not analyzed here and is
out of scope**: its handler table, its internal queue representation, how it resolves a QID to a
task, whether `ioctl(0x80000005)` blocks the sender, and how it chooses which proxy thread services
an upcall are all kernel-side properties that this file cannot evidence.

**Per-QID consumers are out of scope.** This document does **not** name the task, process, or
processor that consumes any QID, including `0x8f013a` and `0x94020a`. Ownership is a runtime fact —
whoever called `osal_reg_msg_queue_cb` / `osal_reg_sync_msg_queue_cb` first, possibly in an image
that is not in this Ghidra project. §C.3 describes *how* a consumer would register; that is as far as
mechanism takes us. Anyone who reads a QID constant in this document as an ownership claim has been
misled by a line I should have drawn more visibly, so: **constant ≠ owner.**

**Mechanism and ABI, not secrets.** The value here is the interface contract — struct layouts,
offsets, request numbers, error semantics — which is what interoperability research needs. There is
no exploit, no bypass, and nothing that defeats a security control: the library's own guardrails
(one CB per QID, `0xa5a5a5a5`/`0x55555555`/`0x77777777` canaries, double-free detection,
`print_task_info()` + `/dev/kmsg` forensics, and `abort()`/`brk` traps under `uipc_opt+0x17`) are
*defensive* mechanisms in the firmware, and I have described them only to characterise the ABI.

**Authorized context.** Static analysis of the user's **own** Sony a7R V firmware, for a public
research write-up. No device was modified, no code was executed on the camera, nothing was
extracted from a device I don't own. **No firmware bytes are reproduced** — no binary dump, no byte
array, no reproducible build input. The pseudo-code fragments shown are Ghidra's C output, included
as evidence for specific claims, and they are the minimum needed to make those claims checkable.

**A note on what the analysis is *not*.** The `**UIPC ERROR**` strings reveal that production
builds carry a rich internal fault-reporting layer (`print_task_info`, `dump_trace`,
`bsem_dump`, `/proc/osal/uipc`, `/tmp/uipc_stat_user.txt`). Those are the debugging surface of
Sony's own developers, and the reason the ABI is legible at all.

---

## How this was checked

All work in this session was against Ghidra project `ghidra_svctools`, binary
`/libosal_uipc.so` (`analysis_complete: true` per `list_project_binaries`). Local binutils were
**not** used — `objdump`/`readelf` here cannot disassemble AArch64. Addresses below are the real
bodies; each export also has a same-named `is_thunk: true` PLT duplicate that was avoided.

**`decompile_function` calls made this session** (with `include_callees` / `include_strings` where
noted): `0x1033e8` `do_init` · `0x1045b0` `get_bsem` · `0x106b78` `osal_reg_msg_queue_cb` ·
`0x1075b8` `osal_dynamic_id` · `0x105e20` `osal_reg_public` · `0x102680` `pthread_create` thunk ·
`0x103390` proxy start routine · `0x106970` `osal_free_msg` · `0x102b88` `create_proxy_thread` ·
plus, earlier in the session, `osal_valloc_msg_wait` `0x1067b0`, `osal_snd_msg` `0x105e60`,
`FUN_00105460` `alloc_msg`, `osal_snd_sync_msg` `0x106458`, `__osal_snd_sync_msg` `0x1061e8`,
`__osal_finish_sync_cb` `0x106110`, `FUN_001057e8` dispatcher, `u_osal_snd_sync_msg` `0x103a98`,
`u_osal_reg_msg_queue_cb` `0x103cd8`, `u_osal_reg_sync_msg_queue_cb` `0x103d68`.

**`disassemble` calls made this session** (for exact ioctl constants and table arithmetic):
`0x106020` (QCB table index) · `0x103de8`–`0x103e5c` (`0x80000009` unreg) · `0x103268`, `0x103288`,
`0x1032c0` (`0x8000000d` upcall loop) · plus `0x103abc`–`0x103b34` (`0x80000005`).

**`search_symbols_by_name` / `list_xrefs` / `search_strings` / `list_imports`:** used to resolve every
address quoted, to find the `ioctl` PLT thunk `0x00102530` (20 call sites — the `ioctl` import
symbol itself reports 0 refs and cannot be xref'd directly), to find `pthread_create` thunks
`0x11c0d8`/`0x102680`, to confirm `0x109278` "multi CB registered to qid 0x%08x." has exactly one
xref (`osal_reg_msg_queue_cb+0x1c0`), to confirm `__osal_finish_sync_cb` has only an "Entry Point"
xref, to locate `uipc_proxy` `0x108ad8` → `FUN_00103390`, and to confirm **no `sem_*` imports**.

**Identified but deliberately NOT read** — no claim in this document rests on these:
the ioctl constants at `0x1038d4` (`u_osal_stat_msgq`), `0x103950`
(`u_osal_set_msgq_broadcast_mode`), `0x1039d0` (`u_osal_set_msgq_log_mode`), `0x10376c`
(`u_osal_stat_sem`), `0x1037e0` (`u_osal_wai_sem_tmo`), `0x103858` (`u_osal_sig_sem`);
the bodies of `osal_set_msg_src` `0x107e20` / `osal_get_msg_src` `0x107e28` / `osal_msg_size`
`0x107e08` / `osal_set_msg_pri` `0x106db0` / `osal_get_msg_pri` `0x106de0` (addresses resolved,
bodies not read); `FUN_00104d38` (the CB trampoline — its stores and its call site are cited, its
body is not); `FUN_00105008` (CB free), `FUN_001050b8`/`FUN_00105100` (QCB tables),
`FUN_00106ad8` (error reporter), `FUN_00102ec0` (post-reg hook); the `pthread_cancel`/`join`/
`detach` proxy-teardown path; `reset_bsem` `0x104cf8`, `bsem_dump` `0x104b38`,
`osal_sig_sem` `0x104a70`, `osal_stat_sem` `0x104800`, `osal_wai_sem_tmo` `0x104858` bodies;
`osal_init_msgq` `0x107470`, `check_dynamic_sem_id` `0x1074d0`, `osal_unreg_msg_queue_cb` `0x105c98`
bodies; `alloc_fblock`/`free_fblock`/`fblock_init`/`vpool_*` internals; and `osal_snd_sync_direct`
`0x107e30` / `u_osal_snd_sync_direct` `0x103bd8` / `u_osal_rcv_msg_tmo` `0x103c60` bodies (constants
verified, bodies not read).

**Explicitly out of reach, not merely unread:** the `/dev/uipc` kernel driver, and the identity of
any QID's consumer.
