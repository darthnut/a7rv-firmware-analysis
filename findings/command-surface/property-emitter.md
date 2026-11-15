# Property emitter — the `0x78xxxx` / `0x20xx` layer is not a GET

**Summary.** The `0x78xxxx` "property GET" layer is not a request/response query at all: it is a single
change-driven *publish* walk over a 150-entry table that emits a record for each property whose value
changed, and `SET_` command handlers are the only thing that marks a property dirty.

**Where.** `cpapp-b.bin` (project `ghidra_cpapp`; VA = file offset + `0x108000`, Thumb). The walk
`hint_234d7c` @ VA `0x0033CD7C`; the table at **VA `0x010FEE4C`** (150 × 12 bytes), mirror at
`0x00D526EC`; the dirty-marker `FUN_00897862` @ `0x00897862`; the shared append sink at `0x00AEF4BC`.

**Mechanism.**
- **Two corrections to the catalog:** the `0x78xxxx` numbers are **handler file offsets, not property
  ids** (real ids are 16-bit `0x20xx`), the family has **150 entries, not 102**, and the catalog's
  `checker=` column is a parse artifact (the *next* entry's handler).
- **Entry (12 bytes):** `{u16 id, u16 0, u32 handler|1, u8 dirty, u8[3]}`. Ids run `0x2000`–`0x20b2` with
  29 gaps. No checker slot.
- **The walk:** `hint_234d7c` reads a sequence value and, per entry, calls `handler(ctx, record, dirty)`;
  a non-zero return (the record length) → stamp `{u8 6, id}` header and append, then clear the dirty flag.
  A **forced bulk pass** on state change re-sends the first 75 entries (ids `0x2000`–`0x2063`) packed into
  one `0x6c8`-byte record under container id `0x2040`.
- **Handlers publish-on-change:** each reads a shadow-state field via `**(ctx+K)`, dedups against a
  per-property RAM cache, and emits only on change (or `force`). Composite properties (e.g. `0x20a0`)
  force-call sibling handlers inline and splice their blocks.
- **Coupling to commands:** `FUN_00897862(id)` (the only dirty-writer) is called from four `SET_` handlers
  in the FW region — so a host `SET_` changes state and marks the property dirty; **the property layer
  never services the command that changed it**. There is no by-id read path in this image.

**Verification.** *light (bounds proven two ways).* The table base/size proven two independent ways
(`cmp.w r5,#0x708` ⇒ 0x708/12 = 150, and `FUN_00897862`'s `0x96` bound); entry layout, header stamping,
append sink, the forced pass, the `0x6c8` assertion and the `0x2040` container id all disassembled; eight
representative handlers decompiled; `list_xrefs` on the table shows only the walk + the dirty-marker.

**Boundary / open.** The **cross-processor side is out of scope** — these handlers format records for a
link; the peer that consumes them and the code that fills the `**(ctx+K)` shadow structs live elsewhere.
The record type byte `6`, the per-property constant dword, the trigger cadence of the walk (it has **no
incoming xref**), and the per-id *semantics* (no string references; naming them would be fabrication) are
all open. RAM cache globals at `0x0157_9xxx` are not in the mapped image.

**Source.** [framework-runs/cmdprop-map.md](../../framework-runs/cmdprop-map.md)
