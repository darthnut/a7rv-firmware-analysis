# Factory adjustment message framing (`adjstctl` → `libtestcmd`)

**Summary.** How the adjustment CLI turns argv into an OSAL message: a `0x150`-byte buffer with a 0x28-byte
request header `{1, 1, step, length, 0x40, block@+0x24, code@+0x26}` and payload, sent synchronously; the
reply header carries `mode`/`res`/`step`/`addr`/`datasz`, and a non-zero `addr` makes the tool `mmap`
`/dev/mem` and dump that physical region.

**Where.** `fs/a15/lib/libtestcmd.so` (project `ghidra_svctools`; file vaddr = Ghidra addr − `0x100000`)
and `adjstctl.elf`. `testcmd_sndmsg` `0x101e3c`; request header builder `FUN_004014d0`; payload fill
`FUN_004018a8`; reply parse `FUN_00401644`; `cmdline_get_id` `0x1029f0`, `cmdline_get_sync` `0x102838`.

**Mechanism.**
- **Chain:** argv → `cmdline_get_opts` (getopt_long) → `cmdline_get_sync` (sets flags bit 0 = SYNC,
  **always on** for adjstctl) → `cmdline_get_id` ×2 (the two u16 positionals) → `FUN_00401474` (the table
  lookup → OSAL id) → `testcmd_sndmsg(osal_id, &sndstruct, sid=0xdc0000)`.
- **Send (`testcmd_sndmsg`):** `osal_valloc_msg_wait(id, &msg, 0x150, 1)` → `osal_set_msg_src(msg,
  0xdc0000)` → fill via `do_read` → **`osal_snd_sync_msg(id)`** → reply handled in-place via `do_write` →
  `osal_free_msg`. The async path (`osal_snd_msg`, `__rcvmsg`, `testcmd_cb`) is dead code for this tool.
- **Request header (`0x28` bytes):** `+0x00=1`, `+0x01=1`, `+0x02=step` (`--step`, default 1), `+0x04`
  total length, `+0x08=0x40`, `+0x24=adjust_block`, `+0x26=code`; payload starts at `+0x28` (argv
  `[size]:[data]` tokens, then `--ibfile`/`--ifile` bytes).
- **Reply header (`0x1c` bytes):** `+0x00 mode`, `+0x01 res`, `+0x02 step`, `+0x10 addr`, `+0x18 datasz`,
  `+0x1c` inline payload (when `addr==0`). **If `addr != 0`** the tool `open("/dev/mem")` + `mmap(…,
  PROT_READ, MAP_SHARED, fd, addr & ~0xfff)` and dumps `datasz` bytes — a host-side physical-memory read
  on the reply.

**Verification.** *deep (framing decompiled).* `testcmd_sndmsg`, the header builder, the fill and reply
callbacks, and the lookup are decompiled verbatim; the sync-only selection proven two ways
(`cmdline_get_sync` is unconditional and `main` calls it unconditionally); the reply header labels taken
from the tool's own `printf` strings; `main`'s positional handling disassembled verbatim.

**Boundary / open.** **Camera-side handling is out of scope** — the actual adjust semantics, validation,
and any auth checks live past `osal_snd_*` in `libosal_uipc.so`/the device and were not examined. The
request constants (`1`,`1` at +0x00/+0x01, `0x40` at +0x08) are counterpart-of-the-reply inference
(**HYPOTHESIS**). The `osal_snd_sync_msg` exact ABI (whether the msg handle travels in an unmodelled
argument) needs `libosal_uipc.so` ([osal-uipc](../transport/osal-uipc.md)). The `/dev/mem` dump is the
host tool's output path, not the camera touching `/dev/mem`.

**Source.** [framework-runs/service-adjust-map.md](../../framework-runs/service-adjust-map.md)
