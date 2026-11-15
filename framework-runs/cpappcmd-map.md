# cpapp FW command handlers: the focus/drive family (Sony a7R V)

Static reverse-engineering of the user's own a7R V firmware image `cpapp-b.bin`, Ghidra project
`ghidra_cpapp`. This document maps one coherent command family from the FW command-dispatch table
and records what each handler actually *does*, recovering the verb semantics that Investigation 1
left open. Offsets and derived labels only — no firmware bytes are reproduced.

Conventions: table lists file offsets; Ghidra load base is 0x108000, so **VA = file offset + 0x108000**.
All Ghidra calls below are `decompile_function` **by address** on binary `cpapp-b.bin`, run this session.
Evidence tags: *observed* = returned by Ghidra this session; *HYPOTHESIS* = inference.

## A. The family

Selected from `docs/command-table.txt` (TABLE A, the 306-entry FW `SET_` dispatcher table at cpapp
file `0xFF6E4C`–`0xFF8FE4`, 20-byte entries `{u16 id, handler fn, flags, checker fn}`): the **focus &
drive family** — the commands that set how the camera captures (drive/bracket/self-timer) plus the
focus-bracket execution state and the focus/zoom-drive verbs. All offsets below are **file offsets**
as listed in the table; VA = +0x108000.

| id | internal name (from handler log string) | handler off → VA | checker off → VA |
|----|------------------------------------------|------------------|------------------|
| 0x4001 | `SET_ZM_DRIVE[%d: %d: %d: %d]` | 0x2358c4 → 0x33d8c4 | 0x23dfb4 → 0x345fb4 |
| 0x4008 | `SET_DRIVE_MODE[%d: %d: %d]` | 0x235bc4 → 0x33dbc4 | 0x23e40c → 0x34640c |
| 0x4009 | `SET_SELF_TIMER[%d]` | 0x235c2c → 0x33dc2c | 0x23e4c0 → 0x3464c0 |
| 0x4015 | `SET_BRACKET_MODE[%d: %d: ... x8]` | 0x2369b0 → 0x33e9b0 | 0x23f5b8 → 0x3475b8 |
| 0x401B | `SET_P_SHIFT_DRIVE[%d:%d:%d]` | 0x2360d0 → 0x33e0d0 | 0x23eb28 → 0x346b28 |
| **0x4152** | `SET_FOCUS_BRK_EXEC_STATE[%d]` ("AR") | **0x23d3bc → 0x3453bc** | **0x2470f8 → 0x34f0f8** |
| 0x4165 | `SET_FOLLOW_FOCUS[%d, %d]` | 0x23d158 → 0x345158 | 0x790e2e → 0x898e2e |
| 0x4166 | `SET_PRESET_FOCUS_ZOOM_COMMAND[%d x7]` | 0x23d1c0 → 0x3451c0 | 0x790e2e → 0x898e2e |

**Entry geometry, re-derived this session by reading table bytes** (`read_bytes` on `cpapp-b.bin`).
Investigation 1's header says 20-byte entries `{u16 id, handler fn, flags, checker fn}`. The size is
right; the field order is not. Sampled `0x10ff7e4`–`0x10ff83f` (two `read_bytes` calls), which decodes
as three complete entries plus the neighbouring id, stride 0x14, all u32 little-endian:

```
+0x00  id                       e.g. 0x00004015
+0x04  handler | 1              0x0033e9b1  → 0x33e9b0 = 0x4015's handler (catalog 0x2369b0 + 0x108000) ✓
+0x08  flags                    0x00000001
+0x0c  reserved, 0 observed     0x00000000
+0x10  checker | 1              0x003475b9  → 0x3475b8 = 0x4015's checker (catalog 0x23f5b8 + 0x108000) ✓
```

Four further entries in the same sample repeat the pattern (second `read_bytes`, 0x10ff7e4 + 96 B):

| id | handler word → VA | `+0x08` | `+0x0c` | checker word → VA |
|---|---|---|---|---|
| 0x4014 | `0x0033e7b9` → 0x33e7b8 | 0x00000001 | 0 | `0x0034742d` → 0x34742c |
| 0x4015 | `0x0033e9b1` → 0x33e9b0 | 0x00000001 | 0 | `0x003475b9` → 0x3475b8 |
| 0x402a | `0x0033ea59` → 0x33ea58 | 0x00000001 | 0 | `0x003476a1` → 0x3476a0 |
| 0x4024 | `0x0033eaa5` → 0x33eaa4 | **0x00000000** | 0 | `0x0034771d` → 0x34771c |
| 0x4025 | `0x0033eb09` → 0x33eb08 | **0x00000000** | 0 | `0x00347771` → 0x347770 |

(0x4025's checker sits at 0x10ff848, captured by a third 16-byte read.) **All five rows match the
catalog independently**, which is what fixes the field order: 0x4014 (`0x2367b8`/`0x23f42c`), 0x4015
(`0x2369b8`/`0x23f5b8`), 0x402A (`0x236a58`/`0x23f6a0`), 0x4024 (`0x236aa4`/`0x23f71c`), 0x4025
(`0x236b08`/`0x23f770`) — ten of ten words equal catalog value + 0x108000. Two things follow, both
*observed*:

- The `+0x08` word is **not constant** — 1 for 0x4014/0x4015/0x402a, **0** for 0x4024/0x4025 — so it is
  a per-entry flag whose meaning is unknown (open item 3). `+0x0c` is 0 in all five entries.
- **Ids do not ascend here**: the window reads 0x4014, 0x4015, **0x402A**, 0x4024, 0x4025, 0x4026 (the
  last id appearing at 0x10ff84c). The table is in *registration* order, not id order — and see the
  catalog-order point below: this window's order is the catalog's own line order (0x402A on line 48,
  0x4024 on 49, 0x4025 on 50), which is the first hard evidence that the catalog mirrors the binary.

Two further consequences, both *observed*:

- Both function pointers are stored **with the ARM/Thumb LSB set**. That is why `list_xrefs` on the
  even handler/checker addresses (0x33dbc4, 0x34f0f8) returns **zero** cross-references: the dispatcher
  reaches them through these masked-away table values, so Ghidra never creates a reference. Any
  "who calls this handler?" question in cpapp has to be answered by byte-scanning the table, not by
  xrefs.
- The region Investigation 1 names as the FW table **starts with a different table**. Bytes at the
  stated base 0x10fee4c (file 0xFF6E4C) decode as `{u16 id, u16 0, u32 handler|1, u32 0}`, stride
  **0xc**, ids running 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005… with pointers in the 0x89xxxx
  range — i.e. the property-handler range of TABLE B, not the 0x33xxxx FW handler range. Both literal
  consumers of that base agree with a 12-byte geometry: `FUN_00897862` walks 0x96 = 150 entries at
  stride 0xc setting a flag, and `hint_234d7c` loops while `i + 0xc != 0x708` (= 150 × 12) calling the
  +4 pointer. So the FW command table begins somewhere after file 0xFF7554, and where exactly is **an
  open item** (D) — it is not needed for handler semantics, since every catalog handler offset I tested
  decompiles to the very function whose log string matches its own name.

Two further facts from the catalog itself:

- **The catalog's line order mirrors the table's registration order.** The catalog is unsorted — line
  234 lists `0x4146` between 0x4101 and 0x4102, and lines 240–244 list 0x40F1, 0x40F3–0x40F5 after
  0x4105 (verified by reading those lines) — and where I could compare directly, the binary agrees:
  entries 0x402A, 0x4024, 0x4025 lie in the table in exactly the catalog's line order (48, 49, 50), not
  in id order. So the catalog reads as a dump taken **in table order** rather than a sorted export, and
  its ordering anomalies are properties of the firmware's table, not of the export. Caveat: that
  agreement rests on three consecutive entries in one window; the `0x4146` case is untested against
  the binary because that segment's location is unknown (open item 1).
- The checker column collapses onto a few shared values. `checker=0x790e2e` appears on **59** lines of
  the catalog (`grep -c "checker=0x790e2e" docs/command-table.txt` → `59`, run this session) — it is not
  a checker at all, see C — while the focus/drive commands that carry a real check each point at a
  distinct one (`0x2470f8` for 0x4152, `0x23e40c` for 0x4008, `0x23eb28` for 0x401B).

Handlers decompiled this session for this family: 0x4152, 0x4008, 0x4015, 0x401B, 0x4165, 0x4166
(6 of 8) — see B.

## B. Handler semantics

All six handlers decompiled this session share one shape (observed identically in 0x4152, 0x4008,
0x4015, 0x401B, 0x4165, 0x4166):

```
undefined4 handler(int param_1)              /* param_1 = pointer to the request PAYLOAD */
{   ... latch payload bytes at param_1+8, +9, +10, … into dedicated globals in the
        settings block at 0x0157abxx / 0x0157b2xx / 0x0157b4xx ...
    if ((DAT_01915dc6 & 1) != 0)             /* trace-enable bit in a global mask */
        FUN_00b0de92(s_FW__SET_<NAME>_fmt, ...);
    return 1;                                 /* always success */
}
```

Mechanism facts, each from a Ghidra decompile this session:

- **Request header sits at negative offsets.** `FUN_00baaaa6` (VA 0xbaaaa6) is literally
  `return *(u32 *)(param_1 + -0xc);` — the handlers that need the message header read a u32 12 bytes
  *before* the payload pointer. Only 0x4152 does this.
- **`FUN_00b0de92` is a log sink, not a panic** (VA 0xb0de92): it zeroes a 129-byte stack buffer
  (`FUN_005f58b0(buf,0x81)` = memset), formats via `hint_4f655c(buf, 0x81, fmt)` (vsnprintf-shaped),
  clamps to 0x80, and emits through `FUN_00b0cb7c(1, buf, len)` and `FUN_00b0cb7c(3, buf, len)`
  (two log channels) guarded by a log-buffer cursor `_DAT_0192dca0`. Its body ends in `return;` —
  the *"Subroutine does not return"* comments Ghidra attaches at the call sites are artifacts and must
  not be read as "the log call aborts".
- **No handler validates or rejects.** All six return 1 unconditionally; none call its table checker.
  Precondition logic lives in the checker column (C) or, in one case, inline (0x401B below).
- **`DAT_01915dc6`** is a global trace-level mask tested identically by every handler in the family.

### Per-command

**0x4008 `SET_DRIVE_MODE`** — handler VA 0x33dbc4. *The only handler in the family that leaves cpapp.*
First calls `FUN_00899106(prev=_DAT_0157ab30, new=byte[p+8], arg=u32[p+0xc])`, then latches
`_DAT_0157ab20 = byte[p+8]`, `_DAT_0157ab24 = byte[p+9]`, `_DAT_0157ab1c = u32[p+0xc]`
(the 3 args of the log string). `FUN_00899106` (VA 0x899106) branches on the **old→new** transition:
`prev==1 && new==9` → `FUN_00ab416c(arg)` + `FUN_00ab3e30(0x4000000)`; `prev==0x19` →
`FUN_00ab416c(0)` + `FUN_00ab3dd8(0x4000000)`; otherwise forces arg=1 and takes the first path.
Each of those three helpers (VA 0xab416c / 0xab3dd8 / 0xab3e30) is an **OSAL IPC sender**:
`hint_506baa(&ctx, 0x90030001, 0x90040193, len)` allocates a 0xc–0x10-byte message, the caller fills
`msg[0]=5` (type), `msg[2] (u16) = 0xd003` or `0xd006` (opcode), `msg[8] = value (0x4000000 bit
mask)`, `msg[0xc] = 1/0` (assert/clear — the only difference between 0xab3dd8 and 0xab3e30), then
`FUN_0053bb54(msgid, msg)` sends and `hint_506bee(&ctx)` frees. `FUN_0053bb54` (VA 0x53bb54) is
`osal_snd_msg`: it carries the literal strings `osal_snd_msg` and `*** UIPC_ERROR ***: No snd msg
receiver` / `Dynamic QID` / `snd to invalid`, extracts the queue id from the low 16 bits, resolves
the queue with `FUN_00baa416(qid)`, and priority-inserts the message by
`*(byte *)(msg - 0xf) & 0x3f`.
→ **Dispatches onward via OSAL IPC: queue/msg-id 0x90040193, destination id 0x90030001, opcode
0xd006 (assert/clear bit 0x4000000) and 0xd003 (value).** *HYPOTHESIS*: that bit gates a capture-pipeline
feature in the other processor, since only drive-mode transitions touch it.

**0x4015 `SET_BRACKET_MODE`** — VA 0x33e9b0. Pure latch: 8 payload fields from `p+8 … p+0x13` into
consecutive globals `_DAT_0157ab38, _DAT_0157ab3c, DAT_0157ab40, _DAT_0157ab44, _DAT_0157ab48,
DAT_0157ab4c, _DAT_0157ab50, _DAT_0157ab54` — matching the 8 `%d`s of its log format. No mode
precondition, no IPC. *Acts locally.*

**0x401B `SET_P_SHIFT_DRIVE`** — VA 0x33e0d0. The one handler with an **inline precondition**: it calls
`hint_915082()` (VA 0xa1d082) and latches only `if (*(char *)(result + 8) != 1)`. `hint_915082` is a
state resolver: it maps `thunk_FUN_00a608f8()` ∈ {1, 2, other} cross-checked against `FUN_00a6aac8()`
into `DAT_018b3cf0` ∈ {0,1,2}, with a save/restore latch on `DAT_019cbc79` / `DAT_019cbc9a`, and
returns `&DAT_018b3ce8`. When latching: `DAT_0157acb3 = byte[p+8]`, `DAT_0157acb6 = byte[p+9]`,
`DAT_0157acb4++` (a change counter), `DAT_0157acb5 = 0`. *Acts locally.*

**0x4152 `SET_FOCUS_BRK_EXEC_STATE`** — VA 0x3453bc, the Investigation-1 anchor.
Latches `_DAT_0157b418 = (uint)byte[p+8]` (the exec state), `_DAT_0157b41c = (state == 1)`,
`DAT_0157b41e = 0`; then reads the header (`u16 [p+2]`, `u32 [p+4]`, `u32 [p-0xc]` via `FUN_00baaaa6`)
and calls `hint_2355e8(id16, u32, seq, &DAT_00345445)`. `hint_2355e8` (VA 0x33d5e8) is a
**completion-sequencing guard, not a send**: if the pending slot `_DAT_0157b7ec` is empty it stores
`(_DAT_0157b7e0=1, _DAT_0157b7e2=id, _DAT_0157b7e4, _DAT_0157b7e8, _DAT_0157b7ec=&DAT_00345445)`;
if it is *not* empty it logs `"FW: receive 0x%x 0x%x before co…"` with the new and the still-pending
identifiers — i.e. a second focus-bracket exec request arrived before the first completed. It sends
nothing. → **local**, and the only family member that consults the request header or the in-flight slot.

`list_xrefs` on the exec-state global **0x0157b418 returns exactly one cross-reference**: the WRITE from
`hint_23d3bc` at 0x3453d4. **Nothing in `cpapp-b.bin` reads this global back.** *HYPOTHESIS*: the latch
plus the pending slot in `hint_2355e8` is the whole handoff, and the consumer lives outside this binary
— which fits 0x4152 being the focus-bracket trigger Investigation 1 flagged. Same shape as the other
five handlers: cpapp records the verb, something else acts on it.

**0x4165 `SET_FOLLOW_FOCUS`** — VA 0x345158. `u16 = [p+8] → _DAT_0157b284`; increments
`DAT_0157b286` and `DAT_0157b296`, clears `DAT_0157acb2`. Two monotonic counters bumped per command —
*HYPOTHESIS*: a "value changed" pulse consumed by a capture/focus task rather than a direct call.

**0x4166 `SET_PRESET_FOCUS_ZOOM_COMMAND`** — VA 0x3451c0. Seven fields from `p+8 (u8), p+10 (u16),
p+0xc (u16), p+0x10 (u32), p+0x14 (u32), p+0x18 (u32)` into `_DAT_0157b2a8 … _DAT_0157b2bc`, plus
`_DAT_0157b2b0++`. Matches its 7-`%d` format. *Acts locally.*

Summary: five of six handlers are **state latches** on the shared settings block in RAM
(0x0157aa10–0x0157b8xx), not actors — they park arguments plus a change counter for another task to
consume. Only `SET_DRIVE_MODE` reaches a cross-processor queue (OSAL 0x90040193). None of the six
touches a peripheral register directly.

## C. The checker functions

Signature, observed: `void checker(int request, int phase)` — same first argument as the handler
(payload pointer), plus a second argument that the checker branches on.

**Per-command checker — 0x4152's, VA 0x34f0f8** (table value 0x2470f8):

```
iVar1 = FUN_008989ac();                        /* → &DAT_0157aa10: the settings state block */
if (param_2 == 1) {                            /* only "phase 1" validates */
  if (*(uint *)(iVar1 + 0xa08) != (uint)*(byte *)(param_1 + 8))
      FUN_00b0de92("FW: LiroSeq_ParamCheckErr: s_fcb…", "CheckSetFocusBrkExecState", …);
}
return;                                        /* returns void: no status to the dispatcher */
```

So the gate is: *compare the incoming focus-bracket exec-state byte (payload +8) against the state
block's live field at `state+0xa08`, and if they disagree emit a `LiroSeq_ParamCheckErr` diagnostic
naming the check function `CheckSetFocusBrkExecState`.* It is a **phase-gated consistency assertion,
not a permission gate** — it returns void, logs via the same sink as the handlers (which returns, per
B), and the handler itself neither calls it nor inspects its result. Enforcement is therefore
diagnostic: a rejected command would have to be dropped by the dispatcher, not by this function.
*HYPOTHESIS*: the dispatcher calls `checker(request, 1)` before `handler(request)` — I could not
observe the call site. `list_xrefs` on 0x34f0f8 returns **zero** cross-references, and A's byte dump
explains why without guesswork: sampled entries store the checker word with the Thumb LSB set
(0x4015's → `0x003475b9`), so 0x4152's checker is held as `0x0034f0f9` (*inference* from that pattern)
and can never match an even-address symbol reference.

**The shared value `0x790e2e` is not a checker at all.** It is reused by **59** catalog lines
(`grep -c "checker=0x790e2e" docs/command-table.txt` → `59`, run this session), including 0x4165 and
0x4166 above. Decompiling at its VA 0x898e2e yields no function;
code starts two bytes later and Ghidra's function there is `FUN_00898e30` — a ~150-line **reset of the
settings state block**: it zeroes ~120 scalar fields spread over offsets +4 … +0xda9, sets non-zero
defaults (1, 2, 3, 5, 8, 10, 100, 0x10), calls `FUN_005f58b0` (memset) on seven sub-ranges
(+0x68 len 0x4b, +4 len 0x24, +0x298 len 0xf, +0x6b0 len 0x2c, +0x808 len 0x24, +0x4b8 len 0x100, …),
clears exactly the fields the checkers read (`+0xa04/+0xa08/+0xa0c`), and finishes by replaying the
drive-mode handshake
drive-mode handshake: `FUN_00899106(*(p+0x120), *(p+0x110), *(p+0x10c))`. `list_xrefs` on 0x898e30 shows
one call site, `FUN_00899e32` (unconditional call at 0x899e3a) — a code path, not the table (a
table-reached call would be invisible to xrefs anyway, see A).

Two readings, both tagged *HYPOTHESIS* — the table alone cannot separate them:
1. The 4th column is polymorphic: phase 0 = reset state, phase 1 = validate. `FUN_00898e30` would be
   the "no per-command check" filler that only does something at phase 0. Weakness: it never looks at
   `param_2`, so a phase-1 call would wipe the whole settings block.
2. `0x790e2e` is a sentinel meaning "no check for this verb" and the dispatcher skips it; the value is
   simply the address of the settings-initializer because that is what the slot was filled with.
   Why (2) is the better reading, and it rests on observed shape rather than opinion: `FUN_00898e30` takes
**one** parameter (the state-struct pointer) and never inspects a second argument, whereas the real
checker above branches on `param_2`; and its only observed caller is `FUN_00899e32` (unconditional call
at 0x899e3a) — reached from an init path, not from a table walk. So it was written as an initializer. Under reading (1) it would be a checker that resets
the entire settings block on every command of those 59 verbs — *HYPOTHESIS* that this is not what
happens, unproven from static evidence alone.

The *interesting* asymmetry, observed: the commands with real names in the family (0x4008, 0x4015,
0x401B, 0x4152) each have their own distinct checker offset, while the focus commands 0x4165/0x4166 —
which latch the most arguments — share the sentinel. So checking correlates with *state-machine
verbs*, not with parameter count.

## D. Scope and safety

**What this document is.** A static, offset-level map of the *host-side* (cpapp) half of one command
family in the user's **own** Sony a7R V firmware. Everything asserted here came from read-only Ghidra
queries (`decompile_function`, `disassemble`, `list_xrefs`, `read_bytes`) against an already-imported
`cpapp-b.bin`, plus offsets already published in this repo's `docs/command-table.txt`.

**What it is not, deliberately.**

- *Not a binary dump.* No firmware bytes, no hex runs, no extracted blobs, no base64 — the byte reads
  in A are used only to establish entry geometry and are reported as decoded fields, which is the same
  class of information the catalog already publishes. This keeps the repo's no-redistribution line.
- *Not an attack path.* Nothing here was executed on hardware, written to a card, or sent to a camera:
  no patched image, no signature or verification bypass, no memory-corruption primitive, no fuzzing.
  The one IPC handoff documented (OSAL queue 0x90040193) is described only as "cpapp posts a formatted
  message"; the receive side, the peer processor, and anything `0x4000000` eventually actuates are
  **out of scope and unverified** — the doc says so rather than implying a shutter/actuator claim.
- *Not verified behaviour.* Static analysis only: every handler returns 1, so the observed code does
  not reject anything, but what a real camera does with these commands was not observed and is not
  claimed. Statements about *why* a value exists are tagged *HYPOTHESIS* inline; the tags are load-
  bearing, so read them as part of the claims.

**Boundary of the analysis, precisely.** In scope: the 20-byte table entry geometry, eight family
commands, six handlers, one checker, the settings-state block they latch into, and the `osal_snd_msg`
call boundary. Out of scope: TABLE B (the 102 `0x78xxxx` property/GET handlers, untouched this
session), everything downstream of OSAL queue 0x90040193, the other processors' firmware images, and
the property/notification table at file 0xFF6E4C.

**Open items, in rough order of interest:**

1. **True base and segmentation of the FW table.** Confirmed contiguous at **0x10ff7d4–0x10ff850**
   (VA): entries 0x4013, 0x4014, 0x4015, 0x402A, 0x4024, 0x4025, 0x4026 at stride 0x14, with 0x4013's
   position inferred from its checker word at 0x10ff7e4 (0x3473b8 = catalog `0x23f3b8` + 0x108000 ✓).
   The region Investigation 1 attributes to the table starts 0x708 bytes earlier with the 0x20xx
   property table. Someone should byte-scan for the `id` word pattern to pin the base and count entries
   against the catalog's 306.
2. **Whether the dispatcher calls the checker at all**, and what the `param_2` phase argument means.
   No call site is reachable by xref (A). Resolving it needs a byte-scan for the checker pointer value,
   or dynamic tracing.
3. **The `+0x08` flags word.** Values 0 and 1 observed on sampled entries; semantics unknown. Plausibly
   "enabled" — `FUN_00897862` writes a 1 into an adjacent-table slot per matched id — but that function
   works on the 12-byte property table, so the analogy is not established.
4. **Who consumes the latched globals.** `0x0157b418` has one xref (a write) and no reader in this
   binary; the other family globals are untested. The "parked for another task" model in B is inferred
   from the missing readers and the change counters, not from a consumer.
5. **`hint_915082`'s mode semantics** — 0x401B's inline precondition depends on `*(state+8) != 1`, and I
   characterised the resolver's output but not the meaning of its inputs (`thunk_FUN_00a608f8`,
   `FUN_00a6aac8`).
6. **TABLE B / the 0x2000-series property table** — a 150-entry stride-0xc table with its own consumers
   (`hint_234d7c` boot-notify sweep, `FUN_00897862` flag setter) that looks like a useful next
   investigation and is adjacent to what was done here.

## How this was checked

All Ghidra calls used binary name `cpapp-b.bin` in project `ghidra_cpapp`, and were **by address**
(not by name — name lookups resolve thunks). VA = file offset + 0x108000. Every item below was run this
session; nothing here carries a VERIFIED label for work that was not.

Gate: `list_project_binaries` (project reachable, `cpapp-b.bin` analyzed), then `decompile_function` at
0x3453bc (0x4152's handler) → real decompilable C, so the job proceeded rather than stopping.

Handlers decompiled (6 of the 8 family commands): `0x3453bc`, `0x33dbc4`, `0x33e9b0`, `0x33e0d0`,
`0x345158`, `0x3451c0`.

Supporting functions decompiled: `0x899106` (drive-mode → IPC transition), `0xab416c`, `0xab3dd8`,
`0xab3e30` (OSAL message builders), `0x53bb54` (`osal_snd_msg`), `0xbaaaa6` (header accessor),
`0xb0de92` (log sink), `0x33d5e8` (`hint_2355e8`, pending-request slot), `0xa1d082` (`hint_915082`,
mode resolver), `0x33cd7c` (`hint_234d7c`, boot-notify sweep), `0x897862` (per-id flag setter).

Checker / init: `0x34f0f8` (0x4152's checker), `0x898e30` (the routine the `0x790e2e` column actually
points at — see the offset note below).

`disassemble`: `0x898e2e` — needed because `decompile_function` at that address reports *"Function or
symbol not found"*; code begins at 0x898e30. Same class of problem as the `hint_XXXXXX` naming gotcha:
`hint_915082` / `hint_23d3bc` embed **file** offsets while `FUN_00XXXXXX` embeds **VAs**, so
`decompile_function("0x915082")` fails but 0xa1d082 works.

`list_xrefs`: `0x34f0f8` → **none**; `0x33dbc4` → **none**; `0x157b418` → one WRITE (0x3453d4);
`0x898e30` → one caller (`FUN_00899e32`); `0x10fee4c` → two consumers (`hint_234d7c`, `FUN_00897862`);
`0xb0de92` → **not analysed**: the response was 679,923 characters and exceeded the tool's output limit,
so this document makes no claim based on that xref set.

`read_bytes` (5 calls, all in the claimed table region): `0x10fee4c` (64 B — the 12-byte 0x2000-series
table), `0x10ff554` (80 B — not a pointer table, rules out a start there), `0x10ff800` (64 B),
`0x10ff7e4` (96 B), `0x10ff844` (16 B). The last three pin the 20-byte entry layout in A and yield the
five-entry cross-check table (0x4014, 0x4015, 0x402A, 0x4024, 0x4025). No byte string from the firmware
is reproduced anywhere in this document; only decoded field values and the addresses they came from.

Shell, against the read-only catalog `docs/command-table.txt`:

- `grep -c "checker=0x790e2e" docs/command-table.txt` → `59`
- `grep -E "^0x(4014|4015|402a) " …` → rows for 0x4014 and 0x4015 (0x402a missed — see next)
- `grep -nE "^0x(4024|4025|402a|4013) " …` → 0x4013 (line 45), 0x4024 (49), 0x4025 (50)
- `grep -icE "^0x402a " …` → `1`; `grep -inE "^0x402a " …` → line 48, id spelled `0x402A`

That last pair is why the catalog's id column must be grepped case-insensitively: **every** hex letter
in it is uppercase — `grep -cE "^0x[0-9a-f]*[a-f][0-9a-f]* "` → `0` rows out of 429 — so `0x401B`,
`0x402A`, `0x40F1`, and a case-sensitive pattern silently drops them.

Function-length rule: no function was read whole beyond ~300 lines; `FUN_00898e30` (~150 lines) was the
largest, and the oversized xref response was left unread rather than truncated into a conclusion.

Tooling note: this build exposes no `TodoWrite` tool (the task list tools here are `TaskCreate` /
`TaskUpdate` / `TaskList`), so progress was tracked in prose against the A–D checklist instead.
