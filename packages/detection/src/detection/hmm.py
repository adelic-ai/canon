"""HMM over the kill chain — infer the HIDDEN tactic path from observed detector findings.

The Markov model (:mod:`detection.killchain`) treats tactics as OBSERVED: a detector fires ⇒ the
tactic is known 1:1 via the technique (the orchestrator's `TECH_TACTIC`). But techniques are
ambiguous — `T1098` is BOTH persistence and priv-esc; `T1078` spans initial-access / lateral-movement
/ priv-esc. The HMM treats tactics as HIDDEN and detector findings (techniques) as EMISSIONS:

    transitions  A = P(next tactic | current)   — :func:`detection.killchain.build_model` (the Markov half)
    emissions    B = P(technique | tactic)       — :func:`emission_model`, learned from the same corpus;
                                                   multi-tactic techniques emit ambiguously (the point)
    initial      π = P(start tactic)             — the corpus start counts (indicative; see killchain)

:func:`viterbi` then decodes the most-likely HIDDEN tactic sequence from a time-ordered observation
(technique) sequence — resolving an ambiguous finding by transition+emission context, which the 1:1
mapping cannot do (it just hardcodes one tactic). This is the abductive step: infer the unobserved
milestone that best explains the observations.

FINDING / honest limitation (2026-06-14, verified). Viterbi only helps where the corpus has EMISSIONS
for the observed technique:
  * Demonstrated value (in-corpus): the SAME ambiguous T1098 decodes to *persistence* in
    ``execution → T1098 → impact`` but *priv-esc* in ``credential-access → T1098 → lateral-movement`` —
    context-disambiguation the 1:1 ``TECH_TACTIC`` map cannot do.
  * Limitation (out-of-corpus): cloud techniques like T1580 are ABSENT from the host-biased Attack-Flow
    corpus ⇒ no emission ⇒ Viterbi falls back to the transition prior and guesses (T1580 → execution,
    wrong — worse than the 1:1 map there).
So: use Viterbi where the corpus covers the technique; fall back to the 1:1 map otherwise. It is
therefore deliberately NOT wired into the orchestrator as a blanket replacement (that would regress
cloud) — a standalone capability pending a corpus-coverage gate (and, for cloud, a cloud-incident
corpus — the same gap as the cloud transition model).
"""

from __future__ import annotations

import json
import math
from collections import Counter, defaultdict
from pathlib import Path

from detection.killchain import TACTIC, _tactic, build_model

KNOWN_TACTICS = frozenset(TACTIC.values())  # restrict hidden states to the 14 canonical tactics (drop corpus noise)


def emission_model(corpus: str | Path) -> dict[str, dict[str, float]]:
    """``P(technique | tactic)`` learned from the Attack-Flow corpus — ``{tactic: {technique: prob}}``.
    Multi-tactic techniques (T1098 = persistence+priv-esc, T1078 = initial-access+lateral-movement+
    priv-esc) appear under several tactics ⇒ several tactics can emit them ⇒ the ambiguity Viterbi
    resolves by transition context."""
    counts: dict[str, Counter] = defaultdict(Counter)
    for f in sorted(Path(corpus).rglob("*.json")):
        if f.name == "manifest.json":
            continue
        try:
            objs = json.loads(f.read_text()).get("objects", [])
        except (json.JSONDecodeError, AttributeError):
            continue
        for o in objs:
            if o.get("type") == "attack-action":
                ta, tech = _tactic(o), o.get("technique_id")
                if ta in KNOWN_TACTICS and tech:
                    counts[ta][tech] += 1
    return {ta: {tech: n / sum(c.values()) for tech, n in c.items()} for ta, c in counts.items()}


def viterbi(
    observations: list[str],
    transitions: Counter,
    emissions: dict[str, dict[str, float]],
    starts: Counter,
    *,
    eps: float = 1e-9,
) -> list[str]:
    """Most-likely hidden TACTIC sequence for an observed TECHNIQUE sequence (log-space Viterbi).

    ``transitions`` = ``Counter{(from,to): n}`` (killchain), ``emissions`` = ``{tactic: {tech: prob}}``,
    ``starts`` = ``Counter{tactic: n}``. Unseen emissions fall back to ``eps`` (smoothing)."""
    states = sorted(emissions)
    nxt: dict[str, Counter] = defaultdict(Counter)
    for (a, b), n in transitions.items():
        if a in emissions and b in emissions:
            nxt[a][b] += n

    def lp(x: float) -> float:
        return math.log(x if x > 0 else eps)

    def trans(a: str, b: str) -> float:
        tot = sum(nxt[a].values())
        return nxt[a][b] / tot if tot else eps

    s_tot = sum(starts.values()) or 1

    def emit(t: str, o: str) -> float:
        return emissions.get(t, {}).get(o, eps)

    V = [{s: lp((starts.get(s, 0) / s_tot) or eps) + lp(emit(s, observations[0])) for s in states}]
    back: list[dict[str, str | None]] = [{s: None for s in states}]
    for o in observations[1:]:
        prev = V[-1]
        col, bk = {}, {}
        for s in states:
            p = max(states, key=lambda q: prev[q] + lp(trans(q, s)))
            col[s] = prev[p] + lp(trans(p, s)) + lp(emit(s, o))
            bk[s] = p
        V.append(col)
        back.append(bk)

    last = max(states, key=lambda s: V[-1][s])
    path = [last]
    for i in range(len(observations) - 1, 0, -1):
        last = back[i][last]
        path.append(last)
    return path[::-1]


def decode(observations: list[str], corpus: str | Path) -> list[str]:
    """Build A + π (``build_model``) and B (``emission_model``) from ``corpus``, then Viterbi-decode the
    most-likely hidden tactic path for ``observations`` (a time-ordered technique sequence)."""
    transitions, starts, *_ = build_model(corpus)
    return viterbi(observations, transitions, emission_model(corpus), starts)
