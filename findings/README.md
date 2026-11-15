# Findings — the subsystem reference

One curated page per subsystem, grouped by domain. Each page is a uniform summary of a raw study in
[framework-runs/](../framework-runs/) and carries the same header:

- **Summary** — one line.
- **Where** — binary, key offsets / VAs, Ghidra project.
- **Mechanism** — how it works.
- **Verification** — deep / light / hypothesis, plus what was checked (the terms are defined in
  [method/](../method/README.md#the-verification-policy)).
- **Boundary / open** — where the trail ends and why.
- **Source** — link to the raw `framework-runs/<x>-map.md`.

The **Verification** label is the point: it lets you tell *solid* from *inferred* from *out-of-image* at
a glance. The authoritative verification index is the appendix in
[framework-runs/CONSOLIDATED.md](../framework-runs/CONSOLIDATED.md).

All offsets are Ghidra virtual addresses unless a page says "file offset". For `cpapp-b.bin`,
VA = file offset + `0x108000`.

---

## crypto-keystore/ — data at rest

The headline structure: SecVault (AES-256-GCM) → Backup → key service, with the master key out of image.
See [Investigation 4](../investigations/04-security-architecture.md) for the synthesis.

| Subsystem | Verification | Page |
|---|---|---|
| SecVault secure store | light (8 exports decompiled; GCM + per-record DEK) | [crypto-keystore/secvault.md](crypto-keystore/secvault.md) |
| SecVault slot contents | light (table byte-verified; payloads HYPOTHESIS) | [crypto-keystore/secvault-slots.md](crypto-keystore/secvault-slots.md) |
| Key service (QID `0x25906be`) | light (protocol decompiled; provider out of image) | [crypto-keystore/key-service.md](crypto-keystore/key-service.md) |
| Key-wrapping root (the KEK) | light (boundary pinned) | [crypto-keystore/key-wrapping-root.md](crypto-keystore/key-wrapping-root.md) |
| `crypter.elf` crypt-file tool | light (import boundary proven) | [crypto-keystore/crypter-elf.md](crypto-keystore/crypter-elf.md) |

## service-mode/ — the factory / maintenance channel

Auth → verb dispatcher → SSH; plus the factory adjustment vocabulary and the HASP check-in log. See
[Investigation 2](../investigations/02-service-mode-and-auth.md).

| Subsystem | Verification | Page |
|---|---|---|
| SENSER verb dispatch | light (dispatch chain decompiled) | [service-mode/senser-verb-dispatch.md](service-mode/senser-verb-dispatch.md) |
| SENSER power daemon (`sen.elf`) | light (negative / redirect) | [service-mode/senser-power-daemon.md](service-mode/senser-power-daemon.md) |
| SSH provisioning | light (strings/imports; many bodies decompiled) | [service-mode/ssh-provisioning.md](service-mode/ssh-provisioning.md) |
| Adjustment command table (1,779 verbs) | deep (byte-verified table) | [service-mode/adjustment-command-table.md](service-mode/adjustment-command-table.md) |
| Adjustment message framing | deep (framing decompiled) | [service-mode/adjustment-message-framing.md](service-mode/adjustment-message-framing.md) |
| Plugin verbs (`libpro00.so`) | deep (bytes + decompile) | [service-mode/plugin-verbs.md](service-mode/plugin-verbs.md) |
| HASP store | light (accessors decompiled) | [service-mode/hasp-store.md](service-mode/hasp-store.md) |
| HASP id → feature gates | deep (negative, ~65k funcs) | [service-mode/hasp-id-gates.md](service-mode/hasp-id-gates.md) |

## transport/ — the message fabric

| Subsystem | Verification | Page |
|---|---|---|
| OSAL / UIPC (`/dev/uipc`) | **deep — ioctl numbers decompile-verified** | [transport/osal-uipc.md](transport/osal-uipc.md) |

## command-surface/ — internal & external commands

| Subsystem | Verification | Page |
|---|---|---|
| FW command table — focus/drive family | light (ids vs catalog) | [command-surface/fw-command-table-focus-drive.md](command-surface/fw-command-table-focus-drive.md) |
| FW command table — exposure/metering/WB | light (ids vs catalog) | [command-surface/fw-command-table-exposure.md](command-surface/fw-command-table-exposure.md) |
| Property emitter (`0x78xxxx`/`0x20xx`) | light (bounds proven two ways) | [command-surface/property-emitter.md](command-surface/property-emitter.md) |
| USB / PC-Remote (PTP) surface | light (boundary recorded) | [command-surface/usb-ptp-surface.md](command-surface/usb-ptp-surface.md) |

## persistence/ — the Backup store

| Subsystem | Verification | Page |
|---|---|---|
| Backup store model & cipher | light | [persistence/backup-store.md](persistence/backup-store.md) |
| Backup id registry | light (scheme proven; payloads OPEN) | [persistence/backup-registry.md](persistence/backup-registry.md) |

## behavior/ — measured behaviour, explained in the binary

| Subsystem | Verification | Page |
|---|---|---|
| Develop-resource acquire (write cliff) | light | [behavior/develop-resource-acquire.md](behavior/develop-resource-acquire.md) |
