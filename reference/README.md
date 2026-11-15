# Reference — raw data to reuse

Machine- or grep-friendly data others can build on. These are the underlying artifacts the curated
[findings](../findings/) summarise; no key material or firmware bytes appear in them.

| File | What it is |
|---|---|
| [command-table.txt](command-table.txt) | The `cpapp` FW command-dispatch catalog: 306 `SET_` commands (`0x40xx`/`0x41xx`) + 150 property handlers (`0x78xxxx` → `0x20xx`), each with its id, handler offset, checker offset, and internal name (offsets only, no firmware bytes). Source for the [command-surface](../findings/command-surface/) findings. Two known corrections: the property family has **150** entries (not 102), and the `0x78xxxx` numbers are handler **file offsets**, not property ids — see [property-emitter](../findings/command-surface/property-emitter.md). |
| [frame-cycle-data.json](frame-cycle-data.json) | The machine-readable per-frame bracket-timing timeline behind [Investigation 1](../investigations/01-focus-bracket-cadence.md) and the [interactive page](https://darthnut.github.io/a7rv-firmware-analysis/docs/frame-cycle.html). |

The interactive frame-cycle visualization itself is published via GitHub Pages at
[docs/frame-cycle.html](../docs/frame-cycle.html) (it has its timeline data inlined, so it does not
depend on the JSON above).
