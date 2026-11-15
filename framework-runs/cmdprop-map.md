# cpapp property GET layer — the `0x78xxxx` property handlers (Sony a7R V)

Static reverse-engineering of the user's own Sony a7R V (ILCE-7RM5) firmware image
`cpapp-b.bin`, loaded read-only in Ghidra as **`ghidra_cpapp`** (project program
`/cpapp-b.bin`, `analysis_complete: true`). ARM32 / ARMv7 **Thumb**, load base **0x108000**, so
**VA = file offset + 0x108000**; pointers in the dispatch tables carry the Thumb LSB
(entry address = `ptr & ~1`). No firmware bytes are reproduced — offsets, pseudo-C shapes,
and derived labels only.

**Scope:** the host-side (cpapp) property/query layer only. Cross-processor (other CPU)
handlers are out of scope. See §C.

> **Headline finding.** The `0x78xxxx` layer is **not a request/response GET**. There is no
> per-id lookup, no checker invocation, and no query path in this image at all. It is a
> **change-driven producer**: a single walk over a 150-entry table emits a record for each
> property whose value changed, and `SET_` command handlers are the only thing that marks a
> property dirty. §A.2.

> **Two corrections to `docs/command-table.txt` / `README.md`** (evidence in §A.1): the
> `0x78xxxx` numbers are **handler file offsets, not property ids** (real ids are 16-bit
> `0x20xx`), and the family has **150 entries, not 102**. The table's `checker=` column is a
> parse artifact — it holds the *next* entry's handler.

---

## A. The property dispatch

### A.0 What the dispatch looks like

```
 SET_ command handler (0x40xx/0x41xx path, FW region file 0x235–0x239)
        │  FUN_00897862(id)                       ← the only writer of the dirty flag
        ▼
 ┌───────────────────────────────────────────────┐
 │ property table, VA 0x010FEE4C, 150 × 12 bytes  │  {u16 id, u16 0, u32 handler|1, u8 dirty, u8[3]}
 └───────────────────────────────────────────────┘
        │ walk: hint_234d7c @ VA 0x0033CD7C
        │   per entry: handler(ctx, record_buf, dirty)
        │   non-zero return ⇒ stamp {u8 6, u8 ?, u16 id} + append via 0x00AEF4BC, clear dirty
        ▼
   property record stream (to the host link)
```

### A.1 The id space

* **Table location and size.** `movw r10,#0xee4c ; movt r10,#0x10f` at `0x0033cda2`/`0x0033cdb4`
  puts the table base at **VA `0x010FEE4C`**. The walk bounds are `adds r5,#0xc` /
  `cmp.w r5,#0x708` (`0x0033cddc`/`0x0033cde2`) — a **0x708 = 1800 byte** table at **12-byte
  stride ⇒ exactly 150 entries**. Independently corroborated by the dirty-marker
  `FUN_00897862` (`decompile_function("0x897862")`), which scans the same array
  (`&DAT_010fee54`) with stride `0xc` and bound `0x96` = **150**.
* **Entry layout** (from the access pattern, not from a declared struct):

  | off | width | role | evidence |
  |---|---|---|---|
  | 0x00 | u16 | property id | `ldrh.w r0,[r10,r5]` @ `0x0033cdca`; `*(ushort*)(puVar1+-8)==param_1` in `FUN_00897862` |
  | 0x02 | u16 | 0 in every entry | read of the raw table bytes |
  | 0x04 | u32 | handler pointer, Thumb LSB set | `ldr r4,[r6,#4]` @ `0x0033cdbc`, then `blx r4` |
  | 0x08 | u8 | dirty flag | `ldrb r2,[r6,#8]` @ `0x0033cdc2`; cleared by `strb.w r8,[r6,#8]` (r8=0) @ `0x0033cdde`; set to 1 in `FUN_00897862` |
  | 0x09 | u8[3] | 0 in every entry | read of the raw table bytes |

  All 150 flag/pad bytes are `0` in the shipped image — the dirty flags are **runtime state**
  in the RAM copy of the table, never pre-set at build time.
* **Id range and gaps.** Ids run **`0x2000` … `0x20b2`** (span 0xb3 = 179 slots) with
  **150 present ⇒ 29 absent**. Absent: `0x2007 0x200A 0x200C 0x200F 0x2010 0x2011 0x201C 0x201F
  0x2021` and the ten consecutive `0x2023`–`0x202C`, plus `0x202E 0x203B 0x2040 0x204B 0x2056
  0x205B 0x20A3 0x20A9 0x20AB 0x20AF`. The gaps are holes in the *published* id space
  (reserved/removed properties) — HYPOTHESIS, since nothing in the image explains them.
* **`0x78xxxx` is not an id.** Handler pointers span VA `0x891ff0`–`0x897777`; minus the
  0x108000 load base that is **file offset `0x789ff0`–`0x78f776`**. That is where the
  "0x78xxxx property" label comes from — it names the *handler code region*, while the actual
  16-bit property ids are `0x20xx`.
* **`0x2040` is absent because it is the container id.** The forced bulk pass emits its whole
  packed blob under a single record header with id **`0x2040`** (`mov.w r0,#0x2040` /
  `strh.w r0,[sp,#6]` @ `0x0033ce56`/`0x0033ce5a`) — see §A.2. A queryable id that is a frame,
  not a property, is a coherent explanation for that specific gap. HYPOTHESIS.
* **One handler leaves the property region.** Id **`0x2018` → `0x0033CC31`** (function
  `hint_234c30` @ `0x0033cc30`, `refcount: 0`), i.e. in the FW command region rather than the
  `0x89xxxx` property region — and it sits in the same code cluster as the property walk
  itself (`hint_234d7c` @ `0x0033cd7c`). HYPOTHESIS: a property whose value is served by
  FW-command-side code sharing that context. Untested.
* **Second copy of the table.** A byte-identical mirror exists at **VA `0x00D526EC`**
  (`movw r11,#0x26ec ; movt r11,#0xd5` @ `0x0033cdf0`/`0x0033ce02`); the forced pass reads its
  handler pointers from there with the same 12-byte layout.

### A.2 How a property read is routed

The whole mechanism is one function, **`hint_234d7c` @ VA `0x0033CD7C`**
(`disassemble("0x33cd6c", 60)` + `disassemble("0x33ce34", 40)`). It has **no incoming
references** (`list_xrefs("0x33cd7c")` → empty, symbol `refcount: 0`), so it is entered through
a function pointer / table dispatch — the trigger (timer, task tick, or link worker) is
**not statically resolvable here**.

**Entry gate.** It reads a saved sequence value from RAM global `DAT_0172daa8`
(`movw r4,#0xdaa8 ; movt r4,#0x172`, `0x0033cd8a`–`0x0033cd92`) and compares it against a live
field at offset `0xdb4` of a context object obtained via `bl 0x00afc7ca`
(`0x0033cd94`–`0x0033cda0`). Equal ⇒ incremental pass; unequal ⇒ forced pass, which first
writes the new value back (`str r0,[r4,#0x0]` @ `0x0033ce0a`).

**Pass 1 — incremental drain** (`0x0033cdb8`–`0x0033cde6`), all 150 entries:

```
add  r6, r10, r5          ; entry = table + i*0xc
ldr  r4, [r6,#4]          ; handler
ldrb r2, [r6,#8]          ; dirty flag  → 3rd argument ("force")
mov  r1, r11              ; record buffer (sp+4)
blx  r4                   ; handler(ctx, record, dirty)
mov  r1, r0               ; r0 = low word of return = record LENGTH (0 ⇒ nothing to emit)
ldrh r0, [r10,r5]         ; id
strb r9, [sp,#4]          ; record[0] = 6      (r9 = 6)
strh r0, [sp,#6]          ; record[2] = id
mov  r0, r11
bl   0x00aef4bc           ; append(record, length)  ← shared record sink
strb r8, [r6,#8]          ; clear dirty        (r8 = 0)
```

So: **one record per changed property**, header stamped *after* the handler filled the buffer,
then handed to the common append routine at **VA `0x00AEF4BC`**.

**Pass 2 — forced bulk report** (`0x0033ce10`–`0x0033ce36`), entered on state change: same
walk shape over the mirror table at `0x00D526EC`, but only the **first 75 entries**
(`adds r6,#0xc ; cmp.w r6,#0x384`, 0x384 = 75 × 12) and with the 3rd argument hard-wired to
**1** (`movs r2,#1` @ `0x0033ce1c`) — i.e. `force = true`, which is what makes a handler emit
unconditionally. Each handler is called with the *running* buffer cursor and the cursor is
advanced by the returned length (`add r4,r0` @ `0x0033ce34`), so the 75 sub-records are packed
contiguously; each sub-record gets its own `{u8 6, u8 ?, u16 id, u32 0}` header
(`strb.w r10,[r4,#0]` / `strh r1,[r4,#2]` / `str.w r9,[r4,#4]`, `0x0033ce26`–`0x0033ce30`).
The packed total is then **asserted to be exactly 0x6c8 bytes** (`sub.w r1,r4,r8 ; cmp r1,#0x6c8`,
`0x0033ce38`–`0x0033ce40`, else logged/asserted through `bl 0x00b0de92` with a message at
`0x33ce74`), and the whole 0x6c8-byte blob is appended as **one record with id `0x2040`**
(`0x0033ce4c`–`0x0033ce64`).

Consequence worth stating plainly: **ids `0x2000`–`0x2063`** (the first 75 table entries)
are re-sent in full on every state change, while **ids `0x2064`–`0x20b2`** are only ever
emitted incrementally through dirty flags.

**Record framing.** A record is `u8 6` (record type), one byte left at whatever the handler
wrote there (see below), `u16 id`, then payload. The handler signature Ghidra recovers is

```c
undefined8 handler(int ctx, undefined4 *record, int force);   /* (endptr << 32) | length */
```

and **both passes use only the low word (the length)** — `mov r1,r0` before the append in pass 1,
`add r4,r0` to advance the cursor in pass 2. The high word (write-end pointer, visible in the
pseudo-C as `CONCAT44(param_2+N, len)`) is redundant and ignored.
Handlers uniformly write two constant dwords at `record[0..1]` before their payload; the
dispatcher then overwrites `record[0]`/`record[2..3]` with `{6, id}` and leaves `record[1]` —
so the per-property constants live in RAM at `0x0157_9xxx`, which is **not present in the
image** (`read_bytes("0x1579950")` → *"Address 0x1579950 is not in mapped memory"*). Pass 1
preserves the handler's `record[1]` constant; pass 2 zeroes it (`str.w r9,[r4,#4]`, r9 = 0).
HYPOTHESIS: that dword is a per-property sub-header (element count / sub-type), populated only
on the incremental path. Unresolved.

**The only other consumer of the table** is the dirty-marker
**`FUN_00897862(int id)`** @ `0x00897862`:

```c
/* linear scan, stride 0xc, bound 0x96 */
if (*(ushort *)(p - 8) == id) { *p = 1; return; }
```

`list_xrefs("0x10fee4c")` returns **only** `hint_234d7c`@`0x33cdca` (READ) and
`FUN_00897862`@`0x89786b`/`0x89786e` (READ/DATA). Therefore: **there is no by-id read path in
this image** — no code that looks a property up and answers a single-property query. §A.3.

### A.3 Relation to the `0x40xx` / `0x41xx` SET-command path

**Same firmware, same subsystem, different table and different id family — coupled one-way.**

* **Different table, different entry size.** The property table is 12-byte entries at
  `0x010FEE4C` with a *dirty flag*. The command table described in `command-table.txt` is
  20-byte entries `{u16 id, handler, flags, checker}`. The property table has **no checker
  slot**; nothing in the walk calls a checker. (The README's claimed command-table VA
  `0x10FF6E4C` is *not in mapped memory* in this Ghidra project, so the command table itself
  could not be re-read here — the entry-shape comparison rests on the in-image `movw/movt`
  evidence for the property table plus the documented command shape.)
* **Different id family.** Commands are `0x40xx`/`0x41xx`; properties are `0x20xx`. Nothing
  overlaps; the walk never inspects a command id and the command path never indexes the
  property array.
* **The only coupling is dirty-marking.** `FUN_00897862(id)` is called from four functions in
  the FW `SET_` handler region — `hint_235728`@`0x33d7a0`, `hint_238b18`@`0x340b72`,
  `hint_2391c8`@`0x3411fa`, `hint_2394a0`@`0x3414e8` (`list_xrefs("0x897862")`) — plus a
  thin wrapper `FUN_00af2110`@`0xaf2114`, itself called from `0x4969a0` and `0x497020`.
  So a host `SET_` command changes state and marks the corresponding property dirty; the next
  walk emits the new value. The property layer never services the command that changed it.
* **Answer to the brief's question — "same table, different family? a distinct GET
  dispatcher?"** Neither framing fits: it is **not a GET dispatcher at all**. It is a distinct
  *publish* dispatcher (one function, one table) driven by state change. A `0x78xxxx`-labelled
  "query" does not reach a handler by id in this image.

---

## B. Representative handlers

Eight handlers decompiled by address (batch `decompile_function`, `include_callees`/
`include_strings` = true). Handler symbols with **`refcount: 0`** are reachable only through the
table's `blx r4` — a reliable way to confirm a function *is* a property handler.

| id | handler (VA / file) | gate | state read | payload |
|---|---|---|---|---|
| `0x2000` | `0x891FF0` / `0x789ff0` | `**(ctx+4) & 0x1f == 0` or force | 2 bytes @ `**(ctx+0x50)` | 3 dwords, len **0xc** |
| `0x2001` | `0x892040` / `0x78a040` | `**(ctx+4) & 0x1f == 5` or stale-ctr or force | 1 byte @ `**(ctx+0x10)+0xd7` | 3 dwords, len **0xc** |
| `0x200B` | `0x892EE6` / `0x78aee6` | value-dedup only | 1 byte @ `**(ctx+0x20)+4` | 3 dwords, len **0xc** |
| `0x2014` | `0x89346E` / `0x78b46e` | `*(char*)(s+0x15f) ∈ {0,6}` else `*(char*)(s+0x306)` | `ctx+0x30` struct: `+0x1a4`, `+0x1a8`, `+0x15f`/`+0x306` | 4 dwords, len **0x10** |
| `0x2073` | `0x8955D2` / `0x78d5d2` | value-dedup only | bytes @ `**(ctx+0x10)+0x29e` and `+0x2a0` | packed u16, len **0xc** |
| `0x2091` | `0x895F38` / `0x78df38` | 9-way byte/word dedup | 9 fields @ `**(ctx+0x10)+0x398…0x3bc` | 3 dwords, len **0x14** |
| `0x20A0` | `0x89699E` / `0x78e99e` | change of `**(ctx+0x10)+0x291` or force | ~40 fields **+ 3 sub-handlers** | flat **0x9c** (156 B) |
| `0x20A6` | `0x8970DA` / `0x78f0da` | 2-value dedup | u32 @ `**(ctx+0x10)+0x158`, u16 @ `+0x15c` | 4 dwords, len **0x10** |

### Group 1 — mode-gated scalar state (`0x2000`, `0x2001`)

Both read a **mode/state word at `**(ctx+4)`** and mask it with `0x1f`; `0x2000` emits only in
mode `0`, `0x2001` only when the same field equals **5** (or when its stale-counter check
against RAM `_DAT_0172da68` trips, or `force`). `0x2000` reads a 2-byte value through the
`***(ctx+0x50)*** sub-struct; `0x2001` reads a single byte at offset `+0xd7` of the `**(ctx+0x10)`
sub-struct. Both cache the last emitted value in dedicated RAM globals
(`DAT_01579010/_01579014/_01579018`; `_DAT_01579028`) and emit 12 bytes — two constant header
words plus the cached value — so the host sees the property only in the modes where it is
meaningful.

### Group 2 — ungated scalar with pure value-dedup (`0x200B`)

The simplest shape: no mode test at all. Reads one byte at `***(ctx+0x20)***+4`, compares against
`_DAT_01579290`, and returns `0` when unchanged and `force == 0`; otherwise writes the cached
byte into the third dword and returns 12. This is the canonical "publish on change" handler,
and it shows that the deduplication is *per property*, held in RAM, independent of the table's
dirty flag — the flag only says "look at me", the handler decides whether the value moved.

### Group 3 — multi-field record (`0x2014`, `0x20A6`)

`0x2014` is the only sampled handler using the **`ctx+0x30`** sub-struct. It computes a
condition value (byte `+0x15f` — if it is `6` or `0` a fixed `1` is used, otherwise byte
`+0x306`), and on any change caches `+0x1a8` → `DAT_01579264`, `+0x1a4` → `_DAT_01579260` and
the condition → `DAT_019c2506`, then emits **four dwords (0x10)**: two header words, a u32 read
from `+0x1a4`, and a byte from `+0x1a8`. `0x20A6` is the same shape on the `ctx+0x10`
sub-struct: u32 `+0x158` and u16 `+0x15c`, deduped against `_DAT_01579958`/`_DAT_0157995c`,
emitted as 4 dwords / length 0x10. Both return the length directly (`return 0x10;`) rather than
the `CONCAT44(ptr, len)` packing — the dispatcher only reads the low word, so both work.

### Group 4 — packed pair (`0x2073`)

Reads two bytes at `**(ctx+0x10)+0x29e` (low) and `+0x2a0` (high), packs them into one word in
`_DAT_01579658`, and returns 0 only if **both** halves are unchanged and `force == 0`. Payload
12 bytes. It is the scalar case of the fields later re-read individually by the composite in
Group 5 — same offsets, same sub-struct.

### Group 5 — composite / aggregate property (`0x20A0`), with sub-blocks

`FUN_0089699E` (id `0x20a0`) is by far the largest handler sampled (~300 lines; read in
sections). Gate: change of a byte at `**(ctx+0x10)+0x291`, or `force`. Its 156-byte payload is
**assembled, not read**: ~40 individual byte/word fields are copied out of the `ctx+0x10`
sub-struct (offsets `0x29e`, `0x2a0`, `0x2a4`, `0x2ac` … `0x426`, plus u32s at `0x410`/`0x418`)
into `record+8 … +0x66`, and three **other table handlers are called inline with `force = 1`**
into scratch and spliced at `record+0x3b`, `+0x6d`, `+0x88`:

| callee | its own table id | splices |
|---|---|---|
| `FUN_00895F38` | **`0x2091`** | 0x14-byte block |
| `FUN_00895CD4` | **`0x208d`** | 0x16-byte block |
| `FUN_0089606C` | **`0x2093`** | 0x10-byte block |

All three callees are themselves entries in the same table (`0x208d → 0x895cd5`,
`0x2091 → 0x895f39`, `0x2093 → 0x89606d`), so **properties can be both published standalone and
embedded in a larger aggregate** — the aggregate is a materialized snapshot of its siblings,
which is why it forces them instead of reading their caches. Two fields get a
`0 → 3` default fix-up (`DAT_01579860`, `DAT_01579888`) applied both to its own fields and to
the spliced blocks. `FUN_0089699E` has **no xrefs at all** (`refcount: 0`) — table-only.
`FUN_00895F38` is the cleanest sub-block (`decompile_function("0x895f38")`): a nine-way
byte/word comparison of `**(ctx+0x10)+0x398…0x3bc` against three packed cache words
`_DAT_01579848/_DAT_0157984c/_DAT_01579850`, re-packed on change, 20-byte payload.

### Why these are grouped by mechanism, not by "exposure / AF / media"

The brief's suggested subsystem grouping is **not statically supportable here and I have not
guessed at it.** None of the sampled handlers contains a single string reference
(`referenced_strings: null` for all of them), and the values come from an opaque shadow-state
struct reached via `**(ctx+K)` (`ctx+0x10`, `+0x20`, `+0x30`, `+0x50`) whose layout is defined
by the producing side, not by this layer. Offsets like `+0x29e` carry no name, and the
`command-table.txt` header itself concedes that "verb *semantics* beyond the log strings are
NOT recoverable statically". Naming any of these ids "exposure state" or "battery" would be a
fabrication, so the table above records **what each handler reads and returns** and leaves the
semantics to runtime observation.

---

## C. Scope, safety, and confidence

**Scope / safety.** Static analysis only, of a firmware dump of the user's own Sony a7R V, for
a public write-up. Only read-only Ghidra queries were used (`list_project_binaries`,
`decompile_function`, `disassemble`, `read_bytes`, `list_xrefs`, `search_symbols_by_name`);
nothing in the Ghidra project was renamed, retyped, commented, or saved, and the image was
never patched or executed. **No firmware bytes are reproduced in this document** — only
addresses, pseudo-C shapes derived by decompilation, and labels I derived. The **cross-processor
side is out of scope**: these handlers format records for a link, and the peer that consumes
them (and the code that fills the `**(ctx+K)` shadow structs) lives elsewhere; the record stream's
transport framing was not traced. No device interaction, no exploit development, no
capability-testing tooling.

**What is directly evidenced** (disassembly of the walk, table bytes, xref counts): table base
`0x010FEE4C`, 150 × 12-byte entries, dirty-flag byte, `{6, id}` header stamping, append via
`0x00AEF4BC`, the forced pass over `0x00D526EC` with `force = 1` over the first 75 entries, the
`0x6c8` size assertion and the `0x2040` container id, `FUN_00897862`'s scan bounds and its six
call sites, and the eight handler bodies in §B.

**Tagged HYPOTHESIS (not verified):** the meaning of the record type byte `6`; the meaning of
the per-property constant dword at `record[4..7]` and why pass 2 zeroes it; whether `0x2040` is
missing from the table *because* it is the container id; whether `0x2018 → 0x0033CC31` is a
command-backed getter; why the 29 id gaps exist; the identity of `0x00AFC7CA` (called once
before the walk and once per entry, with its return value discarded at the in-loop site —
plausibly a lock or keepalive hook, unverified).

**Known limits / deviations.**
1. The walk `hint_234d7c` has **no incoming xref**, so the trigger cadence is unknown.
2. Cache globals at `0x0157_9xxx` are RAM/BSS — `read_bytes("0x1579950")` returned *"not in
   mapped memory"*, so per-property constant values are not statically recoverable.
3. The README's command-table VA `0x10FF6E4C` (also `0x10ff5500`, `0xff00000`) is not mapped in
   this project, so the command table's 20-byte entries could not be re-verified in-image; §A.3
   compares the documented command shape against the directly-evidenced property shape.
4. `docs/command-table.txt` **TABLE B needs correcting** (see below) — I did not edit it, as
   `/srv/a7rv/gptoss-out/cmdprop-map.md` is the only path this run may write.
5. The brief asked for a `TodoWrite` task list; **no such tool exists in this harness**
   (`TaskCreate`/`TaskList` are available but deferred). Progress was tracked in-conversation
   instead — a deliberate deviation, recorded here.

**Corrections to `docs/command-table.txt` TABLE B** (lines 328–401) and to `README.md` lines
311 and 465 ("102 property handlers"):
* **Family size is 150, not 102** (`cmp.w r5,#0x708` ⇒ 0x708/12 = 150; `FUN_00897862` bound
  `0x96` = 150).
* **TABLE B was parsed with roughly a 24-byte stride** over a 12-byte table, so every
  `checker=` value is the **next** entry's handler. Three rows prove it: row `0x2000
  handler=0x789ff0 checker=0x78a040` is really entries `0x2000 → 0x891ff0` and
  `0x2001 → 0x892041`; the README's FW-section row `0x2018 handler=0x234c30 checker=0x78b5d2`
  mixes real entry `0x2018 → 0x0033cc31` with entry `0x2019 → 0x8935d3` (file `0x78b5d2`);
  and the last row's `checker=0x78f776` is real entry `0x20b2 → 0x897777`.
* **There is no checker column in the property table** — entries are 12 bytes with a dirty flag
  (§A.1), so `0x78xxxx` "checkers" do not exist.
* **`0x78xxxx` are handler file offsets, not ids**; ids are `0x2000`–`0x20b2`.

**Open items.** (a) Semantics of individual ids — needs runtime observation, not static work.
(b) The caller/timer that drives `hint_234d7c`. (c) Callers of `FUN_00af2110` beyond
`0x4969a0`/`0x497020` — what subsystem marks properties dirty from the other region.
(d) Whether the record sink at `0x00AEF4BC` is shared with the `0x40xx` command replies (which
would make the two families siblings at the transport layer only).

---

## How this was checked

All queries were read-only Ghidra MCP calls against `ghidra_cpapp` / `/cpapp-b.bin`.

**Project / setup**
* `list_project_binaries()` — confirmed the `cpapp-b.bin` program and `analysis_complete`.
* `list_project_binary_metadata`, `search_symbols_by_name("hint_78")` — no labels exist for the
  handler region, so handlers could not be enumerated by name.
* `search_symbols_by_name("FUN_0089[0-4]", functions_only=true)` and
  `("FUN_0089[5-7]", functions_only=true)` — enumerated Ghidra function symbols in the handler
  region and intersected them with the table's handler pointers to find decompilable handlers
  (`refcount: 0` ⇒ table-only reachability).

**Table and dispatch**
* `read_bytes` on VA `0x010FEE4C` in chunks (512/512/512/264) — hand-parsed all 150 entries
  (a scratch Python parser was denied by permissions, so the parse was done by hand);
  `0x00D526EC` compared against it.
* `disassemble("0x33cd90", 50)`, `disassemble("0x33cd6c", 60)`, `disassemble("0x33ce34", 40)` —
  the walk: table base construction, both loops, header stamping, append calls, forced pass,
  `0x6c8` assertion, `0x2040` container record.
* `decompile_function("0x891ff0")` — first gate handler (id `0x2000`); first-pass gate check.
* `decompile_function("0x897862")` — the dirty-marker; 150-entry bounds.
* `list_xrefs("0x10fee4c")` — only the walk and the dirty marker (⇒ no by-id read path).
* `list_xrefs("0x897862")` — the four `SET_`-region callers + wrapper `FUN_00AF2110`.
* `list_xrefs("0xaf2110")` — callers `0x4969a0`, `0x497020`.
* `list_xrefs("0x33cd7c")` / `("0x33cd90")` — empty (walk has no static caller).
* `list_xrefs("0x895f38")` / `("0x89699e")` — `0x895f38` called only from `FUN_0089699E`@`0x896c72`
  (besides its table entry); `0x89699e` has no xrefs.
* `read_bytes("0x1579950", 48)` — failed, *"not in mapped memory"* (RAM cache globals).

**Handlers decompiled by address** (§B set; batch `decompile_function` with
`include_callees=true`, `include_strings=true`)
* `0x891FF0` — id `0x2000`
* `0x892040` — id `0x2001`
* `0x892EE6` — id `0x200B`
* `0x89346E` — id `0x2014`
* `0x8955D2` — id `0x2073`
* `0x895F38` — id `0x2091` (also a sub-block of `0x20a0`)
* `0x89699E` — id `0x20A0` (composite; read in sections, ~300 lines)
* `0x8970DA` — id `0x20A6`

Addresses that produced *"Function or symbol not found"* (no Ghidra function symbol; recorded so
the next pass does not re-try them): `0x8920a2`, `0x894306`, `0x894b60`, `0x897012`, `0x897776`.
Table-derived handler addresses are odd (Thumb LSB) — subtract 1, or use the even function
address, when decompiling.
