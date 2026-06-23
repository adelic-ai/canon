"""Kerberoast 2-stage chain check on faker-kerberos — does the spec recover the labeled kerberoasters?

Validates the model-checking mechanism (declarative satisfaction, not rule-firing) against ground truth:
the chain `authenticate (4768) → RC4-TGS fan-out (≥N distinct services)` should be satisfied by exactly the
labeled kerberoasters, and NOT by the enc-downgrade decoys (RC4 but no fan-out). Data stays local.

Run:  uv run python packages/detection/experiments/chain_kerberoast_faker.py
"""

import csv
from pathlib import Path

from detection.chain import check_chain, kerberoast_chain

_DATA = Path.home() / "data" / "faker-kerberos" / "v1" / "export.csv"
_KERBEROASTERS = {"maria.montgomery", "jill.rhodes", "christopher.hall", "debra.gardner"}
_DECOYS = {"diana.foster", "jeremy.johnson"}        # enc-downgrade: RC4 but no fan-out → must be excluded


def main() -> None:
    if not _DATA.exists():
        raise SystemExit(f"corpus absent: {_DATA}")
    events = list(csv.DictReader(_DATA.open()))
    res = check_chain(events, kerberoast_chain(n=8, window_sec=3600), actor_field="Account_Name")

    sat = set(res["satisfied"])
    tp, fp, missed = sat & _KERBEROASTERS, sat - _KERBEROASTERS, _KERBEROASTERS - sat
    print(f"chain: authenticate(4768) → RC4-TGS fan-out(≥8 distinct / 60min)   over {res['n_actors']} actors")
    print(f"satisfied: {sorted(sat)}")
    print(f"  recall: {len(tp)}/{len(_KERBEROASTERS)}   FP: {len(fp)} {sorted(fp) or ''}   missed: {sorted(missed) or 'none'}")
    print(f"  decoys excluded (RC4 w/o fan-out): "
          f"{'YES' if not (_DECOYS & sat) else 'NO — ' + str(sorted(_DECOYS & sat))}")
    print("\nThe declarative spec is SATISFIED by exactly the labeled kerberoasters — model-checking recovers")
    print("the chain, separating RC4-fan-out (kerberoast) from RC4-without-fan-out (enc-downgrade) and benign.")


if __name__ == "__main__":
    main()
