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
5. **EDA module** — exploratory data analysis as a first-class entry point.

## Layout (in progress)

    src/forge_core/
    ├── signal.py     # Signal dataclass + SignalKind gate            [done]
    ├── ops.py        # Op protocol + registry                        [done]
    ├── lattice.py    # divisibility lattice + hops_back_walk         [done]
    └── transforms/   # autocorr, spectral, wavelet, entropy, stats   [todo]
        + analyze/EDA entry                                           [todo]

Step-0 (the port/fix/drop audit of `~/dev/forge`) is committed; this package is
the foundation layer ported from those verdicts.
