# cpapp FW command handlers: the exposure / metering / white-balance family (Sony a7R V)

Static reverse-engineering of the user's **own** a7R V firmware image `cpapp-b.bin`, Ghidra project
`ghidra_cpapp`. This document maps the exposure/metering/WB command family from the FW command-dispatch
table and records what each handler actually *does* — the settings a photographer changes. Offsets and
derived labels only; **no firmware bytes are reproduced**.

Conventions: the catalog lists **file offsets**; Ghidra load base is 0x108000, so **VA = file offset +
0x108000**. All Ghidra evidence below is `decompile_function` **by address** on binary `cpapp-b.bin`,
run this session. Evidence tags: *observed* = returned by Ghidra this session; *HYPOTHESIS* = inference.

## A. The family

Selected from `docs/command-table.txt` (TABLE A, the 306-entry FW `SET_` dispatcher table at cpapp file
`0xFF6E4C`–`0xFF8FE4`, stride 0x14, entries `{u16 id, handler|1, flags, 0, checker|1}`): the
**exposure / metering / white-balance family** — the exposure-triangle setters (ISO, iris/aperture),
the spot-metering verbs, and the white-balance verbs. All offsets below are **file offsets** as listed
in the catalog; VA = +0x108000. Names are the handler's own log format string, i.e. the FW's internal
name for the verb.

| id | internal name (from handler log string) | handler off → VA | checker off → VA | decompiled this session |
|----|------------------------------------------|------------------|------------------|----|
| 0x4006 | `SET_WB_MODE[%d: %d: %d: %d: %d: %d: %x: %x]` | 0x235a5c → 0x33da5c | 0x23e180 → 0x346180 | ✓ both |
| 0x4028 | `SET_IRIS_DRIVE[%d:%d:%d:%d:%d:%ld:%lu]` | 0x236c00 → 0x33ec00 | 0x23f8f0 → 0x3478f0 | handler |
| 0x4029 | `SET_ISO_SPEED_RATE[%d: %d: %d]` + `MULTI_SHOT_NR_LEVEL[%d]` | 0x236d58 → 0x33ed58 | 0x23fa80 → 0x347a80 | ✓ both |
| 0x402C | `SET_CUSTOM_WB_SAVE[%d %d]` | 0x2370f0 → 0x33f0f0 | 0x23ffe4 → 0x347fe4 | handler |
| 0x4045 | `SET_REQ_CUSTOM_WB_DATA[%d %d]` | 0x237934 → 0x33f934 | 0x24095c → 0x34895c | handler |
| 0x4046 | `SET_SPOT_METER_FOCUS[%d, %d, %d]` | 0x235728 → 0x33d728 | 0x23de8c → 0x345e8c | handler |
| 0x4054 | `SET_TOUCH_SPOT_METER[%d, %d, %d, %x]` | 0x236448 → 0x33e448 | 0x23efe8 → 0x346fe8 | handler |
| 0x4063 | `SET_WB_MODE[%d: %d: %d: %d: %d: %d]` (2nd verb, same name) | 0x23da48 → 0x345a48 | 0x790e2e → 0x898e2e | handler |
| 0x40DB | `SET_SET_STANDARD_EXPOSURE_STEP[%d]` | 0x23ab34 → 0x342b34 | 0x244b04 → 0x34cb04 | handler |
| 0x415A | `SET_EXPOSURE_CANCEL` | 0x23d8e0 → 0x3458e0 | 0x790e2e → 0x898e2e | handler |
| 0x409E | `SET_TOUCH_SPOT_COLOR[%d %d %d]` | 0x2371dc → 0x33f1dc | 0x240064 → 0x348064 | — listed only |
| 0x40FA | `SET_INTERVAL_REC_AE_SMOOTHING_END` | 0x23b2a4 → 0x3432a4 | 0x790e2e → 0x898e2e | — listed only |

Three observations from the catalog rows themselves, before any decompilation:

- The family reuses the **universal checker stub** `0x790e2e → 0x898e2e` for the parameterless verbs
  (`SET_EXPOSURE_CANCEL`, `SET_INTERVAL_REC_AE_SMOOTHING_END`) and for the second `SET_WB_MODE`
  (0x4063) — i.e. verbs that carry no checkable payload get the stub, verbs with payload get a
  hand-written field-by-field checker. See §C.
- There are **two ids for `SET_WB_MODE`** (0x4006 and 0x4063) with different handlers *and* different
  checker kinds; 0x4006 is the payload store, 0x4063 turns out to be a bulk re-apply (§B.9).
- `SET_ISO_SPEED_RATE`'s log string carries a second format, `MULTI_SHOT_NR_LEVEL[%d]`, which is
  visible as a second log call in the handler (§B.3) — the ISO verb also latches the multi-shot
  noise-reduction level.

## B. Handler semantics

**Calling convention (observed, common to every handler decompiled here).** Each handler is entered as
`code *handler(message *)` from the dispatcher, with the message pointer in `param_1`. The message has a
header *before* the pointer: a u16 command id at `[p+2]`, a u32 sequence/tag at `[p+4]`, and another u32
at `[p-0xc]` which the handlers read only through the accessor `FUN_00baaaa6` (decompiled: literally
`return *(undefined4 *)(param_1 + -0xc);`). The payload starts at `[p+8]`. Every handler ends
`return 1` (a bool "handled"), and every one of them that logs does so under
`if ((DAT_01915dc6 & 1) != 0) FUN_00b0de92(<that FW: string>)`.

**Where the values go.** The setters write into one contiguous `.bss` latch block whose base is
`0x0157aa10` — that is the pointer `FUN_008989ac()` returns (decompiled: `return &DAT_0157aa10;`) and it
is the block §C's checkers read back. WB mode lands at base+0xa10..0xa1f, ISO at base+0x2ec..0x304 and
base+0x42c, spot metering at base+0x634.., exposure step at base+0x3a2... i.e. **the handlers and the
checkers address the same bytes, the handlers through absolute `DAT_` symbols and the checkers through
`FUN_008989ac() + offset`** (arithmetic checked against the decompiled field lists in §C).

### B.1 `SET_WB_MODE` 0x4006 — handler VA 0x33da5c (`hint_235a5c`) — local store

Pure unpack: copies `p[8], p[9], p[10]` → `_DAT_0157b420 / DAT_0157b424 / DAT_0157b425`, two u16s at
`p+0xc, p+0xe` → `_DAT_0157b426 / _DAT_0157b428`, three more bytes `p+0x10..0x12` →
`DAT_0157b42c/2e/2f`, then eight u32s from `p+0x14 … p+0x30` → `_DAT_0157b430 … _DAT_0157b44c`, and
finally the odd one out, the u8 at `p+0x34` → `DAT_0157b42d` (sits *inside* the u32 run in the latch,
which is why the checker's field order and the payload order disagree — §C). Its **only** callee is the
log sink `FUN_00b0de92`, so this verb does nothing but publish settings — no IPC, no queue.

The latch is *not* consumed inside cpapp: `list_xrefs` on `0x0157b420` returns exactly two references —
one WRITE at `0x33da78` (this handler) and one READ at `0x345aac` (B.9's re-apply log).
*HYPOTHESIS:* the WB consumer is on the other processor; cpapp only mirrors the value.

### B.2 `SET_IRIS_DRIVE` 0x4028 — handler VA 0x33ec00 (`hint_236c00`) — mode-gated, accumulating

The only setter in the family that does arithmetic. First it asks for a mode:
`iVar2 = hint_915082(); if (*(char *)(iVar2 + 8) != 1) { … }` — i.e. the whole update is **skipped** in
one mode (`hint_915082`, VA 0xa1d082, derives `DAT_018b3cf0` ∈ {1,2,0} from
`thunk_FUN_00a608f8()` cross-checked with `FUN_00a6aac8()`, saves/restores it across calls, and returns
`&DAT_018b3ce8`; the byte at +8 is one of those three values). Inside the gate:

- `p[8]` is **added** to `_DAT_0157acd0` (delta/relative accumulation, not a set) — this matches the verb
  being an iris *drive* rather than an iris value.
- `p[9]` → `_DAT_0157acd8`, and `if ((_DAT_0157acd8 - 1 & 0xff) < 2) DAT_0157aeb0++;` — a counter that
  ticks for values 1 and 2 (HYPOTHESIS: an "open/closing direction" tally).
- u16s `p+0xa`, `p+0xc` → `_DAT_0157acdc`, `_DAT_0157acde`.
- If `p+0x10`, `p+0x14` and `p+0x18` are non-zero, it appends a 16-byte record `{p+0x10, p+0x14, p+0x18,
  0}` at `_DAT_0157aec0 * 0x10 + 0x157aec8` (a **ring buffer**: index `_DAT_0157aec0`, capacity
  `_DAT_0157aec2`, and on wrap `DAT_0157aebe++; _DAT_0157aec0 = 0;` — a dropped/overflowed-record
  counter).

Callees: `hint_915082`, log sink only → still local, but it is a *telemetry/history* recorder as well as
a setter.

### B.3 `SET_ISO_SPEED_RATE` 0x4029 — handler VA 0x33ed58 (`hint_236d58`) — local store, two latches

Latches `p[8]…p[0xf]` into `_DAT_0157acfc/ad00/ad04/ad08/ad0c/ad10`, plus `p[0xe]` → `_DAT_0157ae3c` and
`p[0xf]` → `_DAT_0157ad14` (the ISO value is stored twice, once in the ISO run and once as a standalone
"base sensitivity"). Two conditional logs, and the second one is what explains the second format in the
catalog string: `s_FW__…BaseSens_0033ee10` prints `_DAT_0157ae3c, _DAT_0157ad14`, i.e. the ISO verb also
latches the `MULTI_SHOT_NR_LEVEL` byte. Only callee is the log sink → local.

### B.4 `SET_SPOT_METER_FOCUS` 0x4046 — handler VA 0x33d728 (`hint_235728`) — latch, then hand off

Writes `_DAT_0157b198 = 3` (a bare mode literal — "spot/meter-with-focus", HYPOTHESIS), the two u16
meter coordinates at `p+0xa`… as `_DAT_0157b044 / _DAT_0157b046`, bumps a request counter
`DAT_0157b03c++`, stores the header u32 as `_DAT_0157b040`, and **mirrors** the coordinates to a second
pair `_DAT_0157b288 / _DAT_0157b28a`. Then it hands off:

```
uVar1 = u16[p+2];  uVar2 = FUN_00baaaa6(param_1);
hint_2355e8(uVar1, [p+4], uVar2, &LAB_0033d7e8_1);
FUN_00897862(0x2001);
DAT_0157b287++; DAT_0157b296++;
```

`FUN_00897862` (VA 0x897862) walks a **150-record property table** (`&DAT_010fee54`, stride 0xc, keyed by
a u16 id at record−8) and sets a "changed" byte on the matching record; `0x2001` is one of those TABLE B
(GET/notify) property ids. So this verb marks a *property* dirty so the GET/notify layer will report it —
that is cpapp-internal, not an IPC send. The real hand-off is `hint_2355e8` (B.10).

### B.5 `SET_TOUCH_SPOT_METER` 0x4054 — handler VA 0x33e448 (`hint_236448`) — local store

Smallest handler in the family: `_DAT_0157aca8 = u16[p+8]; _DAT_0157acaa = u16[p+10];` (touch x/y),
`DAT_0157acb0++` (counter), `_DAT_0157acac = [p+4]` (the header tag, echoed into the latch), one
conditional log, `return 1`. Local only — notably, the *touch* variant does **not** use the pending
latch that the focus-spot variant does.

### B.6 `SET_CUSTOM_WB_SAVE` 0x402C (VA 0x33f0f0) and `SET_REQ_CUSTOM_WB_DATA` 0x4045 (VA 0x33f934) — latch + hand off

Both are "do this thing with the sensor" verbs, and both take the same shape: set a trigger byte, latch
the argument, then `hint_2355e8(id, [p+4], FUN_00baaaa6(p), &<their own LAB/string>)`.
- 0x402C: `DAT_0157b493 = 1; _DAT_0157b494 = p[8];` then the latch.
- 0x4045: `DAT_0157b4a0 = 1; _DAT_0157b49c = p[8];` and additionally **stamps a global request sequence**:
  `DAT_0157b4a1 = DAT_019c2514;` before the latch, then `DAT_019c2514++;` after — so the requester can
  later match a reply to this request by sequence number. (One of only two writes to `DAT_019c2514`'s
  family in this handler; treat the matching semantics as HYPOTHESIS.)

### B.7 `SET_SET_STANDARD_EXPOSURE_STEP` 0x40DB — handler VA 0x342b34 (`hint_23ab34`) — local store

Stores six bytes `p[8]…p[0xd]` → `DAT_0157adb2 … DAT_0157adb7`, then emits **six** separate conditional
logs, one per stored byte (`…_ST_00342bec` plus `…_SH_…` at 0x00342c14, 0x00342c44, 0x00f3ce78,
0x00f3cea5, 0x00f3ced7). The catalog name says "standard exposure step" but the verb carries six step
values (HYPOTHESIS: one per dial/step domain — still/still-Hi/lo/video…, not resolved).

### B.8 `SET_EXPOSURE_CANCEL` 0x415A — handler VA 0x3458e0 (`hint_23d8e0`) — the one real queue forward

This is the only handler here that leaves the settings store. It resolves a task/event object
(`uVar1 = FUN_00adeb14();` → `return &DAT_018fff6c;`), then builds a **5-word callback descriptor on the
stack** (`local_24 = &LAB_0082e71a_1; uStack_20 = 0; local_1c = &LAB_00adebf8_1; local_18 = 0;
uStack_14 = 0;`) — two function pointers with their contexts — and posts it:
`FUN_004e8a90(uVar1, &local_24, 0, 0); return 1;`.

`FUN_004e8a90` (VA 0x4e8a90) copies that descriptor plus its two scalar args into a 0x1c-byte frame and
calls `FUN_005c353c(*(handle + 0x18), &frame, 0x1c)`; on failure it logs
`s_EvtDrvnTsk__Send_Err_tid__d_>_d__004e8b28`. `FUN_005c353c` (decompiled, VA 0x5c353c) is a genuine
**RTOS message-queue post**: a per-queue control block indexed from `&DAT_019e2b58` (stride 0x28) chosen
by the id in `handle + 0x18`, a spin lock taken via `hasExclusiveAccess(0x1a38ec8)`, a ring-buffer copy
plus `*(count+0x7c)++`, and a `SendEvent()` wakeup; its assert path carries the build string
`s__home_jp10239_git_work_build_git_00fba220` with `s_p_queue_>p_prev____p_queue_00fba28c`.

So: **exposure cancel is forwarded by value into an RTOS queue** (`EvtDrvnTsk::Send`-style, event id 1 +
callback pair), unlike the rest of the family. Note the difference from the sibling map's
`SET_DRIVE_MODE` finding: that one reaches the *OSAL* sender and a statically visible port
(queue/msg-id `0x90040193`, dest `0x90030001`). Nothing in this exposure family reaches those senders —
`FUN_005c353c`'s queue index is read from a runtime handle (`&DAT_018fff6c + 0x18`), so there is **no
static port number to cite** for exposure cancel. Cite the mechanism, not a port.

### B.9 `SET_WB_MODE` (2nd verb) 0x4063 — handler VA 0x345a48 (`hint_23da48`) — bulk re-apply, not a setter

Does not take a payload at all. It calls `FUN_00897918()` and bumps `_DAT_0157b7c4`, then emits three
conditional logs: `s_FW__CNT__d_00345ac8` (the counter), `s_FW__SET_AF_LIGHT__d_00f3cc92` with
`_DAT_0157b180`, and `s_FW__SET_WB_MODE__d___d___d___d____00345ad4` which **reads back** the WB latch
written by 0x4006 (`_DAT_0157b420, DAT_0157b424, DAT_0157b425, DAT_0157b42c, DAT_0157b42d,
DAT_0157b42e`) — the READ at 0x345aac from B.1. Hence the duplicate name: 0x4006 *sets* WB mode, 0x4063
*re-pushes the whole settings snapshot* and logs what WB is currently latched as.

`FUN_00897918` (VA 0x897918, ~170 calls) is the replay driver: it calls `hint_23dafc(<cmd id>, param_1 +
<offset>)` for a long ascending id list (0x4002, 0x4006@+0x14, 0x4007, 0x4008 … 0x4029@+0x198 …
0x40db@+0x648 … 0x4164@+0x954; field stride mostly 0xc) — one settings struct, one command per field.

`hint_23dafc` (VA 0x345afc) is a second dispatcher over a **333-entry, stride-0x14 table** at VA
0x010ff600. `read_bytes` at VA 0x010ff5f4 and 0x010ff630 pins the entry layout exactly (the walk starts
mid-entry, so entry base = `DAT_010ff600 − 0xc`):

| field | meaning (verified) |
|-------|--------------------|
| +0x00 | u32 command id (low half compared; ids 0x4000, 0x4001, 0x4003, 0x4006, 0x4007, 0x4008, 0x4009 seen in order) |
| +0x04 | `(handler\|1)` — called as `fn(settings_ptr)` |
| +0x08 | u32 flag, 0 for id 0x4000 and 1 for 0x4001…0x4009 (never read by `hint_23dafc`) |
| +0x0c | u32 context slot — all zeros in the image; passed to the second fn and cleared after |
| +0x10 | `(checker\|1)` — called as `fn(settings_ptr, slot)`, **only when `_DAT_0172e1c0 == 0x80020002`** |

The decisive part: for ids 0x4000, 0x4001, 0x4006, 0x4007, 0x4008, 0x4009 the +0x04 and +0x10 words are
*byte-for-byte the handler and the checker* that `docs/command-table.txt` lists for those same ids
(lines 22–34; e.g. id 0x4006 → +0x04 = `0x0033da5d` → VA 0x33da5c = handler 0x235a5c, +0x10 =
`0x00346181` → VA 0x346180 = checker 0x23e180). So the "checker" column is not a message-validation-only
hook: **the same function object is the second callback on the bulk-replay path**. See §C.

### B.10 The hand-off target: `hint_2355e8` (VA 0x33d5e8) — a one-deep pending-request latch

Used by 0x4046, 0x402C, 0x4045 (and, per the sibling map, by other families). Signature
`hint_2355e8(u32 id, u32 tag, u32 seq, int cb)`. If the slot is free (`_DAT_0157b7ec == 0`) it latches:
`DAT_0157b7e0 = 1; _DAT_0157b7e2 = (u16)id; _DAT_0157b7e4 = tag; _DAT_0157b7e8 = seq; _DAT_0157b7ec = cb;`
— a **single slot**. If it is already occupied it does not queue; it logs
`s_FW__receive_0x_x_0x_x__before_co_0033d670` ("receive … before complete") naming the previously latched
id/tag. There is **no IPC send anywhere in this function**; the consumer of the slot is outside cpapp
(sibling map reached the same conclusion). Practical consequence for this family: a second
spot-meter/custom-WB request arriving before the first completes is *dropped and logged*, not queued.

### B.11 Local vs forwarded, and the logging flag

| id | verb | effect |
|----|------|--------|
| 0x4006, 0x4029, 0x4054, 0x40DB | WB mode, ISO, touch spot meter, exposure step | **local**: latch store + counters only |
| 0x4028 | IRIS drive | **local**, but mode-gated, delta-accumulating, writes a bounded ring |
| 0x4046, 0x402C, 0x4045 | spot meter focus, custom WB save/req | latch + `hint_2355e8` pending slot; 0x4046 additionally dirties TABLE B property `0x2001` via `FUN_00897862` |
| 0x415A | exposure cancel | **forwards** to an RTOS queue via `FUN_004e8a90` → `FUN_005c353c` (runtime queue id, no static port) |
| 0x4063 | WB mode (re-apply) | **replays** ~170 commands through `hint_23dafc`'s 333-entry table |

No handler in this family calls an OSAL IPC sender, so none of them cite ports `0x90040193` /
`0x90030001`; the closest thing to a cross-task forward is B.8's RTOS queue post.

The `DAT_01915dc6 & 1` log guard is worth one note: `list_xrefs` on `0x01915dc6` returned ~90
references, **all READ** — every handler in the 0x235xxx–0x23dxxx command block plus the shared
0x898xxx helper region, and **not one WRITE** inside cpapp. So the "FW: …" traces are compiled in and
enabled by a flag this binary never writes (HYPOTHESIS: initialised elsewhere in the image or fixed),
which is why the catalog's format strings are visible at all.

## C. The checkers

Two family checkers decompiled: `hint_23e180` (VA 0x346180, for 0x4006 WB mode) and `hint_23fa80`
(VA 0x347a80, for 0x4029 ISO). They share one shape:

```c
void hint_23e180(int payload, int param_2)
{
  iVar1 = FUN_008989ac();                 /* -> &DAT_0157aa10  (the same latch block §B writes) */
  if (param_2 == 1) {
     if (*(uint *)(iVar1 + 0xa10) != *(byte *)(payload + 8)) {
        /* Subroutine does not return */
        FUN_00b0de92(s_FW__LiroSeq_ParamCheckErr__s_wb__<n>, s_CheckSetWBMode_003462bc, live, incoming);
     }
     … eight more fields …
  }
}
```

**What it gates.** Two things, and neither is a mode/permission guard:

1. `param_2 == 1` — a caller-supplied mode word. The function returns `undefined` (void) and its only
   effect is logging: there is no error code, no early return that could suppress the handler, and the
   dispatcher calls handler and checker as two separate table entries. So a "failing" checker cannot stop
   the command; it only makes noise.
2. Field-by-field equality between the **incoming payload** and the **live latch**. For 0x4006 the nine
   compares are (checker offset → absolute latch → payload field the handler at 0x33da5c writes there):

   | `FUN_008989ac()+` | absolute | payload |
   |---|---|---|
   | 0xa10 | 0x0157b420 | `p[8]` |
   | 0xa14 | 0x0157b424 | `p[9]` |
   | 0xa15 | 0x0157b425 | `p[10]` |
   | 0xa16 (u16) | 0x0157b426 | `p+0xc` |
   | 0xa18 (u16) | 0x0157b428 | `p+0xe` |
   | 0xa1c | 0x0157b42c | `p[0x10]` |
   | **0xa1d** | 0x0157b42d | **`p[0x34]`** |
   | 0xa1e | 0x0157b42e | `p[0x11]` |
   | 0xa1f | 0x0157b42f | `p[0x12]` |

   The checker's offsets run **monotonically** 0xa10→0xa1f while the payload offsets do not — the odd byte
   `p[0x34]` maps into the middle of the latch run. That asymmetry is exactly what §B.1 shows the *handler*
   doing (`p[0x34] → DAT_0157b42d`), so it is a payload-layout quirk, not a checker bug, and it is
   independent confirmation that the checker's base really is the handler's latch block.

   For 0x4029 the eight compares read `+0x2ec, +0x2f0, +0x2f4, +0x2f8, +0x2fc, +0x300, +0x304, +0x42c` →
   0x0157acfc, ad00, ad04, ad08, ad0c, ad10, ad14, 0x0157ae3c — i.e. **byte-for-byte the set of globals
   `hint_236d58` writes**, including the separate `+0x42c` "BaseSens" copy. The three log tags inside that
   checker split the same way the handler's two logs do: the `+0x2ec…+0x304` group logs as `s_Mul…`
   (multi-shot NR), `+0x42c` as `s_bas…` (base sensitivity), `+0x304` as `s_EIV…` (exposure index value),
   all naming `s_CheckSetIsoSpeedRate_00347b94`.

**Reading of the mechanism (HYPOTHESIS, but the code supports it well):** `FW: LiroSeq_ParamCheckErr` + a
`CheckSet<Name>` string + (live, incoming) = a **state-drift assertion between the host's view and the
FW's latched view** of a setting, emitted when they disagree — not a precondition on whether the command
is allowed. The name "LiroSeq" suggests a sequence/consistency checker (unresolved).

**The "universal checker" is not a checker.** Every parameterless verb in this family (0x4063, 0x415A,
0x40FA) lists checker `0x790e2e` → VA 0x898e2e. `decompile_function` on that address reports it is not a
function, so it was inspected with `disassemble` at 0x898e2e (note: the returned listing *starts* at
0x898e30 — the Thumb entry point is a byte or two before the requested address, so read the offsets, not
the label). What it shows is `push {r4,r5,r6,r7,lr}; add r7,sp,#0xc; push.w r11; mov r4,r0; movs r5,#0;
movs r1,#0x4b; add.w r0,r4,#0x68; strd r5,r5,[r4,#0x154]; str.w r5,[r4,#0x15c]; str r5,[r4,#0x50];
str r5,[r4,#0x58]; blx 0x005f58b0` — zero-filling fields of its argument struct and then **tail-calling
0x5f58b0 with `r0 = arg + 0x68, r1 = 0x4b`**, i.e. zero 0x4b bytes at arg+0x68. That is a
struct-initialiser / shared default handler, not a per-command gate (meaning of the cleared block =
HYPOTHESIS; the instructions above are observed).

**Open point on the replay path.** §B.9 showed the same checker object is the `+0x10` callback of the
333-entry replay table and is invoked as `checker(settings_ptr, slot)` where every `slot` word in the
table image is **zero** — under that path a `param_2 == 1`-gated checker would do nothing at all. Either
something writes those slots at runtime (none seen), or the replay path's second callback is a different
role that happens to share the function. Unresolved; flagged rather than asserted.


## D. Scope and safety

Static analysis only, on the user's **own** Sony a7R V (ILCE-7RM5) firmware image `cpapp-b.bin`, for a
public write-up. Everything here is derived from read-only Ghidra queries (`decompile_function` by
address, `disassemble`, `list_xrefs`, `read_bytes`, symbol/string search) against the existing
`ghidra_cpapp` project. No AArch64 binutils were used or needed.

Out of scope by design: the **cross-processor side**. The handlers here are the host-side (AP-app) end of
the command layer — they latch settings into `0x0157aa10`-based state, and where they hand work off
(`hint_2355e8` pending slot, `FUN_004e8a90`/`FUN_005c353c` RTOS queue post) the consumer lives outside
cpapp and was not followed. So this document says what cpapp *records and forwards*, not what the sensor
or the imaging processor does with it.

Safety: no firmware bytes are reproduced in this document — only offsets, addresses, Ghidra-generated
identifiers, short pseudocode fragments and the FW's own log strings, which is what makes the mechanism
describable without redistributing the image. Nothing here was executed, patched, or run against the
camera; there is no hardware verification behind any claim, and none should be read into the word
"observed" (it means "returned by Ghidra in this session", never "confirmed on device"). Where the code
does not settle a question it is marked HYPOTHESIS or flagged unresolved rather than dressed up as fact.
No credentials, keys, signatures, or exploit paths are involved or described.


## How this was checked

Every claim above traces to a read-only Ghidra call on `cpapp-b.bin` in project `ghidra_cpapp`, made in
this session. Ghidra addresses are **virtual**: VA = file offset + 0x108000; the catalog stores file
offsets, so each address below was converted and then resolved by Ghidra itself (a decompile that returns
a function body is the confirmation that the conversion was right).

**Handlers decompiled by address** (`decompile_function`, 10 of the 12 family members):

| VA | file off | command |
|----|----------|---------|
| 0x33da5c | 0x235a5c | 0x4006 `SET_WB_MODE` |
| 0x33ec00 | 0x236c00 | 0x4028 `SET_IRIS_DRIVE` |
| 0x33ed58 | 0x236d58 | 0x4029 `SET_ISO_SPEED_RATE` |
| 0x33f0f0 | 0x2370f0 | 0x402C `SET_CUSTOM_WB_SAVE` |
| 0x33f934 | 0x237934 | 0x4045 `SET_REQ_CUSTOM_WB_DATA` |
| 0x33d728 | 0x235728 | 0x4046 `SET_SPOT_METER_FOCUS` |
| 0x33e448 | 0x236448 | 0x4054 `SET_TOUCH_SPOT_METER` |
| 0x342b34 | 0x23ab34 | 0x40DB `SET_SET_STANDARD_EXPOSURE_STEP` |
| 0x345a48 | 0x23da48 | 0x4063 `SET_WB_MODE` (re-apply) |
| 0x3458e0 | 0x23d8e0 | 0x415A `SET_EXPOSURE_CANCEL` |

Not decompiled (listed for completeness of the family only): 0x33f1dc (0x409E), 0x3432a4 (0x40FA).

**Checkers decompiled:** 0x346180 (0x4006), 0x347a80 (0x4029).

**Supporting callees / helpers decompiled:** 0x33d5e8 (`hint_2355e8` pending latch) · 0x897862 (property
dirty, 150-record table) · 0x897918 (bulk replay driver) · 0x345afc (`hint_23dafc`, 333-entry replay
dispatcher) · 0xa1d082 (`hint_915082`, mode source for IRIS) · 0x8989ac (`&DAT_0157aa10` latch-block
accessor) · 0xbaaaa6 (`*(u32*)(p-0xc)` header accessor) · 0xadeb14 (`&DAT_018fff6c` event object) ·
0x4e8a90 (`EvtDrvnTsk` send wrapper) · 0x5c353c (RTOS message-queue post).

**Non-decompile evidence:** `list_project_binaries` (confirmed `/cpapp-b.bin` in the project).
`disassemble` at 0x898e2e (universal checker stub). `list_xrefs` on 0x0157b420 (1 WRITE / 1 READ → latch
has no in-cpapp consumer) and on 0x01915dc6 (~90 refs, all READ → log flag never written here).
`read_bytes` at VA 0x010ff5f4 (56 B) and 0x010ff630 (80 B) to pin the replay-table entry layout, checked
against `docs/command-table.txt` lines 22–34. Symbol/string searches were used only to locate names.

**Accuracy notes, stated rather than hidden:**
- One VA conversion slip: I first computed file 0x237934 → 0x345934 and asked Ghidra for that address,
  which answered `Function or symbol '0x345934' not found`. The correct VA is **0x33f934**. What made the
  wrong address look plausible is that 0x34593x *is* live memory — it is rodata: `search_strings` reports
  `FW: SET_EXPOSURE_CANCEL` at VA 0x345930 (0x50 past the 0x415A handler), i.e. data, not code. Every
  conversion cited above was recomputed and each one is backed by a successful decompile or a matching
  catalog row.
- `disassemble` at 0x898e2e returns its first instruction at **0x898e30** (Thumb entry lies at/before
  0x898e2d), so §C describes the listing it returned and does not claim the exact byte 0x898e2e was
  decoded.
- `hint_23da48` (0x4063) decompiled as `(void)` with a bare `FUN_00897918()` call, i.e. Ghidra recovered
  no argument for it although `FUN_00897918` clearly indexes `param_1`. The call almost certainly
  inherits `r0` (the message pointer) from the dispatcher, but that is **not** established by the
  decompiler output — treat the "settings struct base" in §B.9 as unresolved.
- `hint_23dafc`'s callee list attributed one indirect call to `hint_23dfb4`; the `read_bytes` dump shows
  the table really does hold that address at entry+0x10, so it is a data-table value, not a static
  call edge. Don't read it as a call graph link.
- The requested `TodoWrite` list could not be kept: that tool is not available in this harness (it was
  requested and never offered). Tracking was done inline instead; no analysis step was skipped as a
  result.
- Ghidra annotates the log sink `FUN_00b0de92` with "Subroutine does not return" and several handlers show
  that comment mid-body. Per the sibling map this is a **log sink**, not a panic, and the handlers'
  `return 1` paths are reachable; the warning was not treated as evidence of an abort.

Cross-references: `gptoss-out/cpappcmd-map.md` (same firmware, other command families — TABLE A geometry,
OSAL senders and queue `0x90040193` / dest `0x90030001`, `SET_DRIVE_MODE` as the one OSAL-forwarding
verb, and the prior `0x898e2e` "not a function" finding) and
`a7rv-firmware-analysis/docs/command-table.txt` (the id → handler → checker catalog this family was
selected from).

