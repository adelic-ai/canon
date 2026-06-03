"""flaws.cloud — does the entropy feature / conformal calibration earn its keep on a large REAL corpus?

A reproducible experiment, NOT a pytest test (it loads ~2M records from ~/dev/csat/data/flaws, which is
not canon's data home). It answers two questions kept deliberately separate (so conformal is not credited
for what entropy does):

  Q1 (feature):     does region-ENTROPY beat distinct-region-COUNT at separating the compromised
                    identities (backup/Level6) from the legitimate ones (piper/flaws/SecurityMonkey/Root)?
  Q2 (calibration): does CONFORMAL beat a FIXED entropy threshold?

WEAK LABELS (stated explicitly): positives are the *documented compromised credentials* (backup, Level6),
negatives the *documented legit* identities. This is noisy — the leaked creds were also used by thousands
of legit challenge players, so most backup/Level6 cells are NOT the cryptojacking. Read results as
indicative, not authoritative.

RESULT (2026-06-03): the lead from the per-identity *max* view did NOT survive the cell-level analysis.
At the cell level, region-entropy ≈ distinct-count at every grain (AUC within ~0.02), best AUC ~0.76 at
day grain and degrading with finer grain. The 0.16-bit "entropy separates, count doesn't" was a
max-aggregation artifact. Entropy provides no feature advantage over the trivial count here — confirming
the faker-kerberos finding on a second, larger, real corpus. Conformal, riding the same mediocre ROC,
adds no detection over a fixed threshold (its value stays the orthogonal auto-calibration/FAR).
"""
import collections
import datetime as dt
import glob
import gzip
import json

import numpy as np

from forge_core import conformal_pvalues, shannon_entropy

_EPOCH = dt.datetime(1970, 1, 1)
_DIR = "/Users/shunhonda/dev/csat/data/flaws/cloudtrail_logs"
_POS = {"backup", "Level6"}
_LEGIT = {"piper", "flaws", "SecurityMokey", "Root"}


def _under_user(e):
    u = e.get("userIdentity", {}) or {}
    return u.get("userName") or u.get("type") or "?"


def _load():
    recs = []
    for f in sorted(glob.glob(f"{_DIR}/*.json")) + sorted(glob.glob(f"{_DIR}/*.json.gz")):
        op = gzip.open if f.endswith(".gz") else open
        with op(f) as fh:
            for e in json.load(fh).get("Records", []):
                t = e.get("eventTime")
                if t:
                    recs.append((t, _under_user(e), e.get("awsRegion", "-")))
    return recs


def _auc(pos, neg):  # Mann-Whitney U / |pos||neg| = P(random pos ranks above random neg)
    if not pos or not neg:
        return float("nan")
    pos, neg = np.array(pos), np.array(neg)
    return float(sum(np.sum(v > neg) + 0.5 * np.sum(v == neg) for v in pos) / (len(pos) * len(neg)))


def main():
    recs = _load()
    print(f"records: {len(recs)}")
    for grain, label in [(86400, "DAY"), (3600, "HOUR"), (900, "15min")]:
        cells = collections.defaultdict(list)
        for t, who, reg in recs:
            w = int((dt.datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ") - _EPOCH).total_seconds() // grain)
            cells[(who, w)].append(reg)
        rows = []
        for (who, _w), regs in cells.items():
            _, c = np.unique(np.asarray(regs), return_counts=True)
            rows.append((who, len(c), shannon_entropy(c)))
        pd = [d for who, d, e in rows if who in _POS]
        nd = [d for who, d, e in rows if who in _LEGIT]
        pe = [e for who, d, e in rows if who in _POS]
        ne = [e for who, d, e in rows if who in _LEGIT]
        print(f"\n[{label}] cells={len(rows)} POS={len(pd)} LEGIT={len(nd)}")
        print(f"  Q1 feature: distinct AUC={_auc(pd, nd):.3f}   entropy AUC={_auc(pe, ne):.3f}")
        # Q2 calibration: conformal vs a fixed entropy threshold, at matched FAR on LEGIT cells.
        alle = np.array([e for _w, _d, e in rows])
        p = conformal_pvalues(np.array(pe + ne), alle, tail="upper")
        pos_p, leg_p = p[: len(pe)], p[len(pe):]
        for alpha in (0.05, 0.01):
            recall = float(np.mean(pos_p <= alpha))
            far = float(np.mean(leg_p <= alpha))
            print(f"  Q2 conformal @alpha={alpha}: recall(POS)={recall:.2f} FAR(LEGIT)={far:.2f}")


if __name__ == "__main__":
    main()
