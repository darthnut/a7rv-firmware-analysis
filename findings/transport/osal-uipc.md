# OSAL / UIPC — the message fabric (`libosal_uipc.so`)

**Summary.** The message bus under every service command: a userspace client of a `/dev/uipc` kernel
driver, with two layers chosen by QID bit 15 (a syscall-free userspace fast path, or exactly one
`ioctl`), a byte-verified ioctl ABI, and a one-callback-per-QID point-to-point model.

**Where.** `fs/a15/lib/libosal_uipc.so` (project `ghidra_svctools`, Ghidra VAs; real bodies, not thunks).
`do_init` `0x1033e8`, `osal_snd_msg` `0x105e60`, `osal_snd_sync_msg` `0x106458`,
`__osal_snd_sync_msg` `0x1061e8`, `osal_reg_msg_queue_cb` `0x106b78`, `osal_free_msg` `0x106970`,
`osal_dynamic_id` `0x1075b8`, the `u_osal_*` ioctl wrappers `0x103a10`–`0x103fb0`, the proxy-thread loop
`FUN_00103260`.

**Mechanism.**
- **Two layers by QID bit 15.** Set → a pure-userspace fast path (callback runs in the sender's thread,
  zero syscalls). Clear → exactly one `ioctl` on the single `/dev/uipc` fd, retry-looping only on status
  `-1021`.
- **ioctl ABI (decompile-verified):** Sony's own numbering `(dir<<31)|nr`, **no encoded struct size** —
  `0x80000004` send, `0x80000005` sync-send (issued twice: request then retire), `0x80000008`
  register-callback (one flag byte selects async=0/sync=1), `0x80000009` unreg, `0x8000000a/b`
  alloc/free, `0x8000000d` the proxy-thread upcall loop, `0x80000010` init/size-query.
- **Message buffer:** `0x18`-byte header (`+0x00 next`, `+0x08 nblk`, `+0x09 flags`, `+0x0a refcount`,
  canaries `0xa5a5a5a5`/`0x55555555`/`0x77777777`, `+0x10 size`), payload at `base+0x18`, max payload
  `0x1000`.
- **Sync reply is a callback, not a message.** The kernel writes a function pointer + argument back into
  the request struct and userspace calls it, then re-issues the ioctl to retire. The proxy threads are a
  kernel-sized pool delivering the same upcall idiom in loop form.
- **QID encoding:** bits 0–14 queue index (0 illegal), bit 15 userspace/kernel, bits 16–27 type/owner,
  bit 31 must be clear. `osal_dynamic_id` builds `QID = (type<<16)|0x8000|index`.
- **One callback per QID.** A second registration writes a `**UIPC ERROR** multi CB registered` line to
  `/dev/kmsg` and, under debug builds, traps the process — a 1:1 point-to-point model, not multicast.

**Verification.** *deep — ioctl numbers decompile-verified.* Every ioctl request constant was read from
the `mov`/`movk` immediates in the real `u_osal_*` bodies (by address, avoiding the PLT thunks); the
two-layer branch, the buffer layout with its canaries, the sync-reply-as-callback mechanism, the
one-CB-per-QID enforcement site, and the QID bit-encoding (confirmed from both consumers and the
allocator) are all decompile-backed.

**Boundary / open.** The `/dev/uipc` **kernel driver is out of scope** — its handler table, internal
queue representation, QID→task resolution, whether `0x80000005` blocks the sender, and how it picks a
proxy thread are all kernel-side. **Per-QID consumers are a runtime fact** (whoever registered first,
possibly in an image not in this project) — a QID constant in a binary is **not** an ownership claim.
This is the mechanism every other finding's queue traffic rides on (QIDs `0x25906be`, `0x82cd08e0`,
`0x3d032e`, `0x8f013a`, `0x94020a`).

**Source.** [framework-runs/osal-uipc-map.md](../../framework-runs/osal-uipc-map.md)
