# Method & tooling

## Target

- `cpapp-b.bin` — the camera-application image, a flat ARM/Thumb-2 binary.
- Ghidra load base `0x00108000`. Throughout this repo: **VA = file offset +
  0x108000** (and file offset = VA − 0x108000).
- The firmware image itself is **not** in this repo and is not ours to redistribute.

## Disassembly

- Ghidra 12.2 headless with Temurin JDK 25.
- Helper scripts: force Thumb mode over the code ranges, dump xrefs and callers,
  dump references to specific RAM addresses, and resolve `movw`/`movt` immediate
  pairs into target addresses.

### The `movw`/`movt` trap

This firmware constructs 32-bit RAM addresses from **`movw` + `movt` immediate
pairs**, not from literal pools. A naïve "scan the image for the 4-byte address"
approach therefore finds **zero** references to known-live addresses and will fool
you into thinking a counter is unused. Ghidra (which resolves the immediate pairs —
~95k of them here) is the right instrument; a literal-word scan is not.

## Byte verification

A standalone Python script reads the shipping binary and asserts the exact bytes at
each offset of interest (pool init, the gate's `movs`/`add.w`/`mvn` instructions).
Run any such script in isolated mode so it can't import code sitting next to the
untrusted binary:

```
python -I verify_gate.py
```

## Key addresses (quick reference)

| thing | file offset | VA | notes |
|---|---|---|---|
| gate function | `0x4196B4` | `0x5216B4` | STP buffer-full interlock |
| `movs r1,#0x28` | `0x41973E` | `0x52173E` | headroom constant |
| `add.w r2,r1,r0,lsl#1` | `0x419744` | `0x521744` | the `×2` (shift byte at `0x419746`) |
| `mvn r2,#0x13` | `0x41975E` | `0x52175E` | consume = −(0x13+1) = −0x14 |
| pool init literal (16364) | `0x1056994` | — | `ec 3f 00 00` |
| pool counter | — | RAM `0x0115E994` | advisory; only the gate touches it |
| mailbox send fn | `0xA642F2` | `0xB6C2F2` | `FUN_00B6C2F2`, msg bytes = r+0x14 |
| focus step-size calc | `0x27D2F0` | `0x3852F0` | per-frame lens target = pos ± step (Inv. 1) |
| step-width table (10×u16) | `0x27D384` | `0x385384` | `{32,42,53,64,74,85,96,106,117,128}` — distance, not a timer |
| bracket FSM body (`FocusBrk.cpp`) | `0x27D398` | `0x385398` | states 0–4, TBB dispatch; kick from capture-init (see below) |
| **settle counter cmp `r0,#4`** | `0x27D4B4` | `0x3854B4` | bytes `04 28` — the hard 4-field settle (state 2) |
| move timeout cmp `r0,#0x3C` | `0x27D48C` | `0x38548C` | bytes `3c 28` — 60-field abort cap (state 1) |
| window-retry cap cmp `r0,#0xB` | `0x27D55A` | `0x38555A` | bytes `0b 28` — ≤12 settle-validation attempts |
| bracket frame trigger | `0x85BA62` | `0x963A62` | request+kick+event; called from capture-init stages `Stg>CapInit` / `Stg>CapInitLv` (call sites VA `0x47EED2` / `0x473E52`) |
| trigger's event flag handler | `0x89914A` | `0x9A814A` | sets byte `0x0158829A`; reader `FUN` at file `0x8A05D8` |
| move-done poll (shared w/ AF) | `0x9160FA` | `0xA1E0FA` | 4 sub-checks; cmd-0x1D table at RAM `0x01109114` |

A machine-readable version of the frame-cycle timeline (for the planned
visualization) is at [frame-cycle-data.json](frame-cycle-data.json).
| bracket engine states | `0x27D1C4` | `0x3851C4` | RAM `0x01775864`; stored per-state lens positions |
| SDF resource-acquire retry | `0x3484F0` | `0x4504F0` | `ExecRcAcquire`; the >44-frame write-cliff wait shape |
| PowerSave handler | `0x27C144` | `0x384144` | imager power sequencing (not thermal) |
| ImagerSeqLog gate fn | `0x278B8C` | — | trace-category enable, channel `0x1C` → selector/dispatcher `0x4C1034` → category registry `0x4BCF58`/`0x4BCE08` |
