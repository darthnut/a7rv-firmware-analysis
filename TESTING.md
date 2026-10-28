# Focus-bracket cadence test protocol

**Goal:** find what actually paces the *slow* focus-bracket stacks (≈0.60 s/frame =
36 VD fields) vs the *fast* ones (≈0.43 s/frame = 26 fields) — a settings/flash
effect that's fixable today, or something inherent — **before** anyone considers a
firmware patch (which is low-risk but of unproven benefit, and can't lower the
26-field floor anyway).

> **Note (post-test).** This is the original *pre-test* protocol, written around the old
> card-only figures (26-field fast / 36-field slow). The bench test has since run — see
> [RESULTS.md](RESULTS.md) — and on firmware 4.00 the fast zone actually measured
> **20 fields**, with the slowdown identified as a write-pipeline cliff rather than a
> flash/settings effect. The 26/36 framing below is kept as written for provenance; the
> measured story is in [RESULTS.md](RESULTS.md).

Cadence is read from each frame's EXIF capture clock (`DateTimeOriginal` +
`SubSecTimeOriginal`), so the numbers come from the camera itself and a USB tether
can't make them better or worse.

---

## Fixed setup — hold ALL of this constant for every stack

Match the original slow data so "slow" is reproducible, then change one thing at a
time.

- **Tripod**, static rigid subject (a ruler/coin). No handheld — we're measuring the
  camera's timing, not steadiness.
- **M mode:** 1/80 s, f/8, ISO 200 (these match the known slow stacks).
- **Lens:** the 100 mm macro.
- **Drive:** Focus Bracket, same shot count (**~40**) and same focus step every time.
- **Shooting Interval:** Shortest.
- **Card:** same card, started mostly empty (unless a test says otherwise).
- **Batteries:** camera + flash fresh. Same room temperature.
- A few seconds between stacks so each is a clean run.

For each stack, record: **test number, condition, and the order shot** (1st, 2nd…).
Keep each test's frames together (a folder per test is ideal; one big folder is fine
— segment by time gaps). Shot order matters (see Test 2).

Also record the **camera firmware version** — Sony's a7R V 4.00 (Nov 2025) touched
focus bracketing, so an out-of-date body may behave differently than the analysis
assumed.

---

## PHASE 1 — the two tests most likely to settle it. Do these first.

### Test 1 — Flash on vs off  ← prime suspect
The flash (Godox V1) fired on **every** frame of the slow stacks, and "camera waits
for the flash to recycle" is the single most common cause of exactly this symptom.

- **1A:** full baseline, **flash ON** (same power/TTL as normal). 3 stacks.
- **1B:** identical, **flash OFF**. 3 stacks.

**If 1B is consistently fast and 1A slow → the flash is the pacer.** That's the whole
answer; the fix is flash settings (lower manual power = faster recycle, fresh
batteries, or HSS), no firmware involved. If so, stop here.

### Test 2 — Warm-up / stack order
The slow stacks were the *first* ones shot that day, and one run showed a slow→fast
transition *within* a single stack — which smells like the pipeline priming on the
first stack, then clearing.

- **2:** flash **OFF**, else fixed. **5 stacks back-to-back**, changing nothing.

**Answers:** does stack #1 run slow and #2–5 fast? If yes, the slowdown is a
transient warm-up (a patch might shave the first stack, marginally). If all 5 match,
warm-up is ruled out.

---

## PHASE 2 — only if Phase 1 doesn't cleanly explain it

### Test 3 — Shutter mode
The slow stacks were recalled as **mechanical** shutter.
- **3A** mechanical, **3B** EFCS, **3C** electronic. Flash OFF, else fixed, 2 stacks each.
- **Tells us:** whether mechanical shutter rearm adds the delay (→ use EFCS/electronic).

### Test 4 — Write-pipeline pressure  ← the one that would implicate the gate
- **4A** compressed/lossy RAW, **4B** uncompressed/lossless RAW, **4C** repeat 4B with
  the **card nearly full**. Flash OFF, else fixed, 2 stacks each.
- **Tells us:** whether heavier write/request backlog slows cadence (→ compressed RAW,
  empty fast card). **This is the result that would make the firmware gate worth a
  hardware trial.**

### Test 5 — Interval setting sanity check
- **5:** one stack at Shooting Interval = **Mid** vs the Shortest baseline.
- **Tells us:** confirms Shortest is the floor and Mid only adds delay (expected).

---

## What the outcomes mean

| Result | Interpretation | Action |
|---|---|---|
| Always 26 fields now (can't reproduce slow) | The +10 was situational/transient | Likely nothing to fix |
| Flash OFF fast, ON slow | **Flash recycle paces it** | Flash settings — no firmware |
| 1st stack slow, rest fast | Pipeline warm-up | Inherent; patch marginal |
| Mechanical slow, EFCS/elec fast | Shutter rearm | Switch shutter mode |
| Uncompressed / full card slower | Write-pipeline backlog (→ the gate) | Compressed RAW, empty fast card; gate now worth testing |
| Nothing changes it; always slow at 1/80+flash | Inherent to that config | Firmware the only lever, benefit still unproven |

---

## Tether (optional) — live feedback loop

Tethering (Sony Imaging Edge → Remote, over USB) **does not** change the camera's
internal cadence or make the measurement more precise. What it buys: **auto-download
to a watched folder**, so each stack can be analyzed the instant it lands — confirm
or kill the flash hypothesis in ~2 stacks instead of shooting the whole matrix
blind. Flash/shutter/interval tests still need the physical flash and the menu.
