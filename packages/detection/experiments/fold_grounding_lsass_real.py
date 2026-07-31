"""First real-data grounding of the partial-kill-chain FOLD (not just an atom).

Everything upstream validated *atoms* on real data (the Kerberos ticket-hash golden,
the comsvcs+lsass subgraph in ``lsass_subgraph_detection.py``). This grounds the
COMPOSITION layer — ``compose_partial_chain`` + ``AnchorPosterior`` — on a real
capture: does the fold escalate, predict the frontier, decay, and expose GAPs when
driven by real, linked atom firings?

Data: OTRF Security-Datasets ``LSASS_campaign_03`` (real Sysmon, staged locally,
41,954 events, host PRD01.pandalab.com). Three atoms, ONE actor / ONE host / ONE
``ProcessGuid`` — coreference solved by ProcessGuid, so this isolates the FOLD and
does NOT stress the identity mystery (that is the cross-host frontier, deliberately
out of scope here):

  A1 execution         winx64_payload.exe spawned (Pupy RAT)   Sysmon EID 1   T1204
  A2 command-control   drops qfhaer.dll (tooling stage)        Sysmon EID 11  T1105
  A3 credential-access LSASS read GrantedAccess 0x1410          Sysmon EID 10  T1003.001  <- crown jewel

Crown jewel = LSASS credential material on PRD01; anchor = PRD01. The tactic path is
decoded by the HMM against the REAL Attack-Flow corpus (``build_model`` /
``emission_model``) — nothing synthetic except the analyst naming the crown jewel.
The corpus decode is load-bearing: it OVERRODE a hand-label (T1105 -> command-control,
where ATT&CK actually places Ingress Tool Transfer), so the model is not decoration.

What this grounds: the fold MECHANICS on real linked atoms. What it does NOT:
cross-host / identity-fragmented chains (needs a real multi-stage capture; the local
APT sims are empty placeholders), a CALIBRATED probability (the AnchorPosterior LLR-sum
is an independence-assuming UPPER BOUND, and abnormality is stubbed at 1.0).

Run:  .venv/bin/python packages/detection/experiments/fold_grounding_lsass_real.py
See:  design/fold_grounding_lsass_real.md
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from detection.killchain import build_model
from detection.hmm import emission_model
from detection.partial_chain import compose_partial_chain
from detection.anchor_posterior import AnchorPosterior, chain_evidence

DATA = Path.home() / "data/otrf-security-datasets/LSASS_campaign_03/lsass_campaign_03.json"
CORPUS = Path.home() / "data/attack-flow-corpus"
GUID = "{57be2c82-94c1-64df-3409-000000000600}"   # winx64_payload chain on PRD01
TARGET_PATH = ("execution", "command-control", "credential-access")  # crown jewel = LSASS creds (terminal)
ANCHOR = "PRD01.pandalab.com"


def epoch(utc: str) -> float:  # "2023-08-18 15:56:49.752" -> epoch seconds
    return dt.datetime.strptime(utc, "%Y-%m-%d %H:%M:%S.%f").replace(
        tzinfo=dt.timezone.utc).timestamp()


def main() -> None:
    recs = [json.loads(line) for line in open(DATA) if line.strip()]
    eid = lambda r: str(r.get("EventID"))

    spawn = next(r for r in recs if eid(r) == "1" and r.get("ProcessGuid") == GUID)
    drop = next(r for r in recs if eid(r) == "11" and r.get("ProcessGuid") == GUID)
    read = next(r for r in recs if eid(r) == "10" and r.get("SourceProcessGUID") == GUID
                and "lsass" in str(r.get("TargetImage", "")).lower())

    # (technique, real event time, description) — tactic labels come from the corpus decode
    atoms = [
        ("T1204", epoch(spawn["UtcTime"]), "spawn winx64_payload.exe"),
        ("T1105", epoch(drop["UtcTime"]), f'drop {Path(drop["TargetFilename"]).name}'),
        ("T1003.001", epoch(read["UtcTime"]), f'LSASS read {read["GrantedAccess"]}'),
    ]
    atoms.sort(key=lambda a: a[1])
    print("=== REAL atoms (ProcessGuid-linked, host PRD01) ===")
    for tech, t, desc in atoms:
        print(f"  {dt.datetime.fromtimestamp(t, dt.timezone.utc):%H:%M:%S}  {tech:<10} {desc}")

    transitions, starts, flows, nfiles = build_model(CORPUS)
    emissions = emission_model(CORPUS)
    print(f"\n=== model from real Attack-Flow corpus: {flows} flows / {nfiles} files, "
          f"{len(transitions)} transitions ===")

    # 1. the fold escalates as atoms land: run each time-prefix
    print("\n=== FOLD: completeness/reach per prefix, + anchor posterior ===")
    ap = AnchorPosterior(base_rate=0.01, decay_tau_sec=6 * 3600)
    for k in (1, 2, 3):
        obs = [a[0] for a in atoms[:k]]
        t_k = atoms[k - 1][1]
        pc = compose_partial_chain(obs, TARGET_PATH, transitions=transitions,
                                   starts=starts, emissions=emissions, fallback={})
        ap.observe(ANCHOR, chain_evidence(pc, abnormality=1.0, scale=6.0), t_k)
        c = pc.completeness
        print(f"  after A{k} ({pc.observed_tactics[-1]:<17}): "
              f"completeness={c.completeness:.2f} reach={c.reach:.2f} "
              f"complete={c.complete!s:<5} frontier={c.frontier} "
              f"| P(anchor)={ap.probability(ANCHOR, t_k):.3f}")

    later = atoms[-1][1] + 12 * 3600  # decay: 12h later, no fresh evidence
    print(f"  12h later, no new evidence:        P(anchor)={ap.probability(ANCHOR, later):.3f}  "
          f"(decays toward base rate)")

    # 2. the GAP signature: drop the middle atom (telemetry gap)
    print("\n=== GAP: middle atom (command-control) unobserved — jewel still reached ===")
    pc = compose_partial_chain(["T1204", "T1003.001"], TARGET_PATH, transitions=transitions,
                               starts=starts, emissions=emissions, fallback={})
    c = pc.completeness
    print(f"  completeness={c.completeness:.2f}  reach={c.reach:.2f}  "
          f"internal_gaps={c.internal_gaps}")
    print(f"  -> reach({c.reach:.2f}) > completeness({c.completeness:.2f}): the jewel was reached but a "
          f"lead-up step is entailed-but-missing = a GAP to hunt, not a NONE.")


if __name__ == "__main__":
    main()
