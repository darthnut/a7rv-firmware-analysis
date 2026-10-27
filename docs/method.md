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
