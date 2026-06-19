"""Real-data grounding — make synthetic scenarios PLAUSIBLE by deriving them from real open-source logs,
instead of inventing event fields. The fix for hand-authoring's realism ceiling: the label stays
correct-by-construction, but the *realism* comes from real data.

Two uses of a real corpus:
  1. a real **benign background** the labeled attack is injected into (the normal population an anomaly is
     relative to);
  2. a **field profile** — real fields + value distributions — that INFORMS plausible attack-event values.

Dependency-free (stdlib) — the generator stays canon-free. ML is a LATER, proposer-side amplifier *on top of*
this grounding (generative realism / adversarial cases / campaign sequences, see the design doc); grounding
itself needs no ML — it is sampling + empirical statistics.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


def load_events(path) -> list[dict]:
    """Read real events from a log file — a JSON array, or JSON-lines (one object per line). Generic log
    reading, no schema assumptions (so the generator can ground in any open-source corpus we have)."""
    text = Path(path).read_text()
    if text.lstrip().startswith("["):
        return [e for e in json.loads(text) if isinstance(e, dict)]
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(e, dict):
            out.append(e)
    return out


def field_profile(events: list[dict], *, top: int = 5) -> dict:
    """Empirical profile of real events: per field, how often it appears and its most common values — the
    'what's realistic' summary that informs plausible scenario values (and, later, an ML generative model)."""
    present: Counter = Counter()
    values: dict[str, Counter] = {}
    for e in events:
        for k, v in e.items():
            present[k] += 1
            values.setdefault(k, Counter())[str(v)] += 1
    n = len(events) or 1
    return {k: {"present_frac": round(present[k] / n, 3),
                "top_values": [v for v, _ in values[k].most_common(top)]}
            for k in present}


def plausible_fill(attack_event: dict, profile: dict, fields) -> dict:
    """A copy of an attack event with ``fields`` filled from the real profile's most common value
    (deterministic → reproducible, no randomness), so non-signature fields look like the real environment.
    Signature fields the scenario already set are left untouched — realism must never overwrite the attack."""
    out = dict(attack_event)
    for f in fields:
        top = (profile.get(f) or {}).get("top_values") or []
        if top and f not in out:
            out[f] = top[0]
    return out


def ground(attack_events: list[dict], background: list[dict]) -> dict:
    """Inject correct-by-construction attack events into a real benign background → a labeled corpus. The
    label is *by construction*: the injected events are malicious, the background is benign. Returns
    ``{events, labels (bool per event), n_background, n_attack}``."""
    events = list(background) + list(attack_events)
    labels = [False] * len(background) + [True] * len(attack_events)
    return {"events": events, "labels": labels,
            "n_background": len(background), "n_attack": len(attack_events)}


def grounded_scenario_corpus(scenarios, background: list[dict], *, min_present: float = 0.5) -> dict:
    """Wire grounding into the scenario builder: ground a scenario set in a real benign ``background``. Each
    attack event's MISSING contextual fields are filled from the background's real field profile (the common
    fields that aren't part of the attack signature), then the filled attack events are injected into the
    background → a realistic labeled corpus.

    The signature fields the scenario set are preserved (so detection still fires); only contextual fields
    (Computer, User, …) are added, so the attack looks like it came from the same environment as the
    background. Returns ``ground``'s corpus plus ``attack_meta`` — ``attack_meta[i] = {technique, variant,
    channel}`` for the i-th injected (malicious) event, so a consumer can score fidelity per variant/channel.
    ``scenarios`` is duck-typed (any object with ``.events/.technique/.variant/.channel``)."""
    profile = field_profile(background)
    common = [f for f, p in profile.items() if p["present_frac"] >= min_present]
    attack_events, attack_meta = [], []
    for s in scenarios:
        for e in s.events:
            attack_events.append(plausible_fill(e, profile, common))
            attack_meta.append({"technique": s.technique, "variant": s.variant, "channel": s.channel})
    corpus = ground(attack_events, background)
    corpus["attack_meta"] = attack_meta
    return corpus
