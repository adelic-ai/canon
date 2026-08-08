# forge-core

An agnostic signal-analysis substrate. No domain assumptions are baked in —
cyber, EEG, and other domains live in sibling packages or as consumers.

Built on five design decisions (see the `forge-core-scoping` memory and
`design/forge_core_step0_audit.md`):

1. **No horizon** — the SignalForge horizon concept is dropped.
2. **Hops-back lattice** — scale selection walks the divisibility lattice by
   covering-edge hops instead of a multiplicative horizon.
3. **Real/Complex/Cyclic type-gating** — operations are gated by `SignalKind`;
   the kind is the contract an Op consults before operating.
4. **EEG-first** — developed against EEG as the first real domain.
5. **EDA entry** — exploratory data analysis as a first-class entry point
   (design intent; not yet built).

## Layout

Flat module layout under `src/forge_core/` — 17 modules, 207 tests. Grouped here
by role in the detection battery (`web/detection/detection_battery.html`): a **measurement
axis** feeds a **decision axis** over a shared **foundation**, alongside a small
set of **classical detectors** that bundle feature and test.

**Foundation** — the substrate every Op runs on
- `signal` — the Signal container (the atom) + the `SignalKind` gate
- `ops` — Op protocol and registry (the provenance seam)
- `lattice` — the divisibility lattice and the hops-back walk
- `ingest` — the ingest boundary (a real decode joint, honest about its tier)
- `verdict` — DetectionVerdict, the canonical unit assembled from the five folds

**Axis A — measurement** (the features you compute)
- `information` — information-theoretic features: entropy / KL / mutual information
- `spectral` — Welch power spectral density
- `circular` — circular statistics (what a cyclic signal is actually consumed by)

**Axis B — decision** (the tests, with false-alarm control)
- `detection` — CFAR: adaptive-threshold over a test statistic
- `changepoint` — CUSUM sequential change detection
- `conformal` — conformal anomaly detection (distribution-free FP control)
- `fdr` — false-discovery-rate control (multiplicity, batch level)

**Classical detectors** (feature × test bundled — radar/sonar physics)
- `matched_filter` — the optimal known-template detector
- `energy` — the energy detector / radiometer (unknown-signal)
- `goertzel` — single-frequency power (known-frequency)
- `lock_in` — synchronous detection (pull a known tone below the noise floor)

**DSP support**
- `filters` — Butterworth IIR, line-noise notch, band-power filter bank

**Not yet built:** `wavelet` (a multi-resolution transform) and the EDA /
`analyze` entry (design decision 5).

> The layout is **flat, not a `transforms/` subpackage** — an earlier plan the
> build bypassed. Files stay flat; the grouping above is conceptual only.

## Status

Implemented and tested — **17 modules, 207 passing tests**, ported from the pre-canon
`forge` prototype (the quarry, a separate unpublished repo) via the Step-0 audit
(`design/forge_core_step0_audit.md`).

**The vertical slice is proven, not just designed.** `test_verdict.py` wires a growing
set of producers end-to-end, spanning the **feature** axis (`count`, `entropy`, `KL`,
`MI`, `distinct-count`, `HHI`) and the **test** axis (`CFAR`, `conformal`) — each
producing a `DetectionVerdict` that validates against the PINNED
`contracts/detection_verdict.schema.json`. Feature → test → five-fold provenance
assembly → contract holds across *both* axes, which is what makes the producer pattern
general. (`distinct-count` and `HHI` are the descriptive-stats features below, the first
non-IT features wired into cells.)

The real gap is **Axis-A breadth, and it is descriptive statistics — not IT**: the
IT trio (entropy / KL / MI, with windowed variants and an MI shuffle-null) is
present, but concentration (Gini, Herfindahl), cardinality / novelty
(distinct-count, first-seen, rare-value rank) and spread (MAD, CoV) are absent.
Adding those as ops — and wiring a cell or two — is the next step. One logged TODO
from the entropy cell: CFAR's closed-form Pfa is calibrated for power statistics,
so a bounded statistic like entropy wants its own threshold calibration. See
`design/through_line.md`.
