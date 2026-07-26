"""Partial-kill-chain composition — mechanical tests on a synthetic HMM model.

The composition adds no algorithm; these assert it wires the four tested modules
together correctly (decode → completeness → frontier prob → optional motif GAP) on
a hand-built model with known answers — no corpus dependency.
"""

from collections import Counter

from detection.entailment_gap import EntailedMotif, Entailment
from detection.partial_chain import PartialChain, compose_partial_chain

# A 4-stage path A→B→C→D. Each tactic emits its own technique deterministically, and
# the transition matrix is DENSE (chain edges dominant at 8, every other pair 1) so no
# transition is eps — that makes the emission the deciding evidence, so the decode
# follows emissions (a skipped stage decodes to its true tactic, no wrong-way tie).
PATH = ["A", "B", "C", "D"]
TRANSITIONS = Counter({
    ("A", "B"): 8, ("A", "C"): 1, ("A", "D"): 1,
    ("B", "C"): 8, ("B", "A"): 1, ("B", "D"): 1,
    ("C", "D"): 8, ("C", "A"): 1, ("C", "B"): 1,
})
STARTS = Counter({"A": 5})
EMISSIONS = {"A": {"t_a": 1.0}, "B": {"t_b": 1.0}, "C": {"t_c": 1.0}, "D": {"t_d": 1.0}}
FALLBACK = {"t_a": "A", "t_b": "B", "t_c": "C", "t_d": "D"}


def _compose(obs, **kw):
    return compose_partial_chain(obs, PATH, transitions=TRANSITIONS, starts=STARTS,
                                 emissions=EMISSIONS, fallback=FALLBACK, **kw)


def test_full_chain():
    h = _compose(["t_a", "t_b", "t_c", "t_d"])
    assert isinstance(h, PartialChain)
    assert h.decoded == ("A", "B", "C", "D")
    assert h.completeness.completeness == 1.0 and h.completeness.reach == 1.0
    assert h.completeness.complete is True
    assert h.completeness.frontier is None
    assert h.frontier_prob is None                       # nothing ahead


def test_prefix_has_frontier_and_its_transition_prob():
    h = _compose(["t_a", "t_b"])
    assert h.observed_tactics == ("A", "B")
    assert h.completeness.completeness == 0.5 and h.completeness.reach == 0.5
    assert h.completeness.frontier == "C"                # next milestone
    assert h.frontier_prob == 0.8                        # P(C | B) = 8/(8+1+1) in this model
    assert h.completeness.internal_gaps == ()


def test_gappy_chain_surfaces_internal_gap():
    # jumped to D (terminal) without C — emission dominates, so t_d decodes to D even
    # though B→C is the likelier transition; C is the observed gap, not a decode error
    h = _compose(["t_a", "t_b", "t_d"])
    assert h.decoded == ("A", "B", "D")
    assert h.completeness.completeness == 0.75           # 3 of 4
    assert h.completeness.reach == 1.0                   # deepest = D (terminal)
    assert h.completeness.complete is True
    assert h.completeness.internal_gaps == ("C",)        # entailed-but-missing
    assert h.completeness.frontier is None and h.frontier_prob is None


def test_empty_observations():
    h = _compose([])
    assert h.decoded == ()
    assert h.completeness.completeness == 0.0
    assert h.completeness.frontier == "A"                # look for the entry first
    assert h.frontier_prob is None                       # no assembled stage to transition from
    assert h.gap_findings == {}


def test_motif_gap_refinement_wires_the_fourth_module():
    # refine the internal gap C to motif grain: an anchor entails a read; the read's
    # channel IS collected but the record is absent → GAP (not NONE).
    ent_C = Entailment(
        rationale="stage-C anchor entails a read",
        anchor=EntailedMotif(pred=lambda e: e.get("kind") == "anchor", join=lambda e: e.get("id")),
        expected=EntailedMotif(
            pred=lambda e: e.get("kind") == "read" and e.get("target") == "x",
            join=lambda e: e.get("id"),
            channel=lambda e: e.get("kind") == "read",
        ),
    )
    events = [{"kind": "anchor", "id": "1"}, {"kind": "read", "id": "2", "target": "other"}]
    h = _compose(["t_a", "t_b", "t_d"], gap_entailments={"C": ent_C}, events=events)
    assert "C" in h.gap_findings
    assert h.gap_findings["C"]["channel_collected"] is True
    assert h.gap_findings["C"]["counts"]["GAP"] == 1     # entailed, channel collected, record absent


def test_no_refinement_without_events():
    h = _compose(["t_a", "t_b", "t_d"], gap_entailments={"C": None})
    assert h.gap_findings == {}                          # skipped when events is None
