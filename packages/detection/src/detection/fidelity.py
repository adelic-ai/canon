"""Fidelity attestation — a justified, reproducible claim about what a detection RULE *covers*.

The justified-verdict substrate applied to a **rule** instead of an event (the detection inversion). Where
a Sigma rule's `attack.tXXXX` tag is the AUTHOR'S intent (an assertion), this evaluates the rule's own
condition on the labeled ground-truth instances of a technique in a named corpus and emits a
content-addressed, reproducible claim: **what the rule catches, what it structurally MISSES, and why** —
the machine-checkable version of Sigma/CAR's free-text `falsepositives:` note. This is the *warranted*
placement of a rule in the rule-graph (vs the author tag's *claimed* placement); the misses + their cause
are what locate a rule's adjacencies (which neighbor covers its gap).

Two carriers, both honest:
  ``coverage``  — a Belnap Four (`carrier.md`): ``true`` caught all ground-truth instances · ``false`` silent
                  on known instances (missed) · ``both`` caught some, missed some (a soundness alarm) ·
                  ``none`` no ground truth / not evaluated (NEVER a faked ``false`` — absence ≠ absence-of).
  ``evaluation.tier`` — the attestation's OWN ladder (`reproducible`/`asserted`/`absent`), parallel to the
                  verdict guarantee tier but rating the *rule-claim*, not a detection result.

Conforms to ``contracts/fidelity_attestation.schema.json``. Generalized from the LSASS experiment to any
``(rule, positives, technique)``; reuses the proper Sigma evaluator (:mod:`detection.sigma_eval`).
"""

from __future__ import annotations

import json

from provenance import evidence_digest

from detection.sigma_eval import evaluate_rule


def _cid(obj) -> str:
    """Content address of an object: sha2-256 over its canonical JSON (one-hash-three-roles). Same bytes
    → same CID, so the evidence re-derives — which is what earns the ``reproducible`` tier."""
    return evidence_digest(json.dumps(obj, sort_keys=True, separators=(",", ":")))


def _referenced_fields(rule: dict) -> set[str]:
    """The event field names a rule's detection blocks key on (the bit before any ``|`` modifier)."""
    det = rule.get("detection", {})
    fields: set[str] = set()
    for name, block in det.items():
        if name == "condition":
            continue
        for m in (block if isinstance(block, list) else [block]):
            if isinstance(m, dict):
                fields.update(str(k).split("|")[0] for k in m)
    return fields


def attest_fidelity(
    rule: dict,
    positives: list[dict],
    technique: str,
    *,
    rule_bytes: bytes,
    corpus_id: str,
    corpus_cid: str,
    event_count: int | None = None,
    not_claimed: list[str] | None = None,
    rules_not_evaluated: list[str] | None = None,
) -> dict:
    """Attest what ``rule`` covers w.r.t. ``technique`` on a corpus, given that corpus's labeled
    ground-truth instances (``positives``). Returns a schema-conforming attestation. ``coverage`` is the
    Belnap fold over the per-instance fire/miss; a miss carries a derived ``cause`` (which filter suppressed
    a matched instance, or a selection mismatch). ``positives=[]`` → ``coverage='none'`` (ground truth
    unknown), never a faked ``false``."""
    results = [(e, evaluate_rule(rule, e)) for e in positives]
    fired = [(e, r) for e, r in results if r["fires"]]
    missed = [(e, r) for e, r in results if not r["fires"]]

    if not positives:
        coverage = "none"                       # no ground truth — unknown, never faked false
    elif not missed:
        coverage = "true"                       # caught every known instance
    elif not fired:
        coverage = "false"                      # silent on known instances of T → missed
    else:
        coverage = "both"                       # caught some, missed others — a soundness alarm

    suppressed = sorted({f for _, r in missed for f in r["suppressed_by"]})
    evidence_body = {
        "fired_on": sorted(_cid(e) for e, _ in fired),
        "missed_on": sorted(_cid(e) for e, _ in missed),
        "suppressed_by": suppressed,
    }
    evidence_cid = _cid(evidence_body)

    att: dict = {
        "rule": {"id": rule.get("id", "?"), "source": "vendored Sigma",
                 "version_cid": evidence_digest(rule_bytes)},
        "corpus": {"id": corpus_id, "cid": corpus_cid,
                   **({"event_count": event_count} if event_count is not None else {})},
        "technique": technique,
        "coverage": coverage,
        "evidence": {
            "method": ("evaluated the rule's condition (`selection and not 1 of filter*`) on the labeled "
                       "ground-truth instances of the technique in the corpus, via the minimal Sigma-subset "
                       "evaluator (detection.sigma_eval)"),
            "flagged": [str(e.get("SourceImage") or e.get("Image") or _cid(e)) for e, _ in fired],
            "cid": evidence_cid,
        },
        "scope": {
            "claim": f"rule {rule.get('id', '?')}, on corpus {corpus_id}, w.r.t. technique {technique}",
            "not_claimed": (not_claimed or []) + [
                f"scoped to corpus {corpus_id} — says nothing about other corpora",
                "evaluates THIS rule only — not other rules tagged the same technique",
            ],
            "rules_not_evaluated": rules_not_evaluated or [],
        },
        "evaluation": {
            "tier": "reproducible" if positives else "absent",  # corpus-grounded + the evidence CID re-derives
            "custody": "none",                                   # unsigned corpus + unsigned rule snapshot
        },
    }
    if coverage in ("false", "both"):                            # a miss owes a structural cause
        referenced = _referenced_fields(rule)
        missed_events = [e for e, _ in missed]
        if suppressed:                                            # matched, then a filter excluded it
            kind = "allowlist"
            detail = f"real instances matched `selection` but were suppressed by {suppressed}"
        elif missed_events and all(not (referenced & set(e.keys())) for e in missed_events):
            kind = "missing-telemetry"                           # the rule's fields aren't in these events (wrong channel)
            detail = ("the rule keys on fields absent from these instances — wrong observation channel, not a "
                      f"logic gap (rule fields: {sorted(referenced)[:6]})")
        else:
            kind = "logic-gap"                                   # fields present, values don't match
            detail = "the rule's `selection` fields are present but its values did not match these instances"
        att["cause"] = {"kind": kind, "detail": detail,
                        **({"locus": suppressed[0]} if suppressed else {})}
    att["provenance"] = _cid({"attestation": rule.get("id"), "corpus": corpus_cid, "evidence": evidence_cid})
    return att
