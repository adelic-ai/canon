"""DGA char-entropy — entropy's HOME TURF: does it earn its keep where shape (not count) carries signal?

A reproducible, self-contained fair test (no network): real English words (`/usr/share/dict/words`, a
benign-like proxy) vs real *documented* DGA algorithms (mechanism-faithful, not random strings tuned for
entropy). Char-entropy is held against the best cheap baselines — length, vowel-ratio, distinct-char
ratio, and an English **bigram log-likelihood** (the strong, standard DGA feature) — by Mann-Whitney AUC.

Two DGA families, deliberately:
  - RANDOM (Conficker/CryptoLocker-style: pseudorandom a-z) — HIGH entropy, entropy's home turf.
  - DICTIONARY (suppobox/matsnu-style: concatenated real words) — LOW entropy, entropy's KNOWN BLIND SPOT.
The point is not "entropy beats random strings" (trivially true) but to locate, per the universal
primitive-discipline, exactly WHERE char-entropy beats the cheap baselines and where it does not.

RESULT (2026-06-03, |disc| = |AUC - 0.5|, RANDOM-DGA):
  bigram_loglik 0.499 (near-perfect) > kl_from_english 0.423 > vowel_ratio 0.409 > char_entropy 0.200
  > length 0.141 > distinct_ratio 0.073.
Two findings:
  1. Naive char-frequency Shannon entropy is WEAK even on its supposed home turf — beaten by the trivial
     vowel-ratio. Third strike for naive symbol-entropy (redundant on fan-out, mediocre here).
  2. The IT approach done RIGHT wins decisively, via canon's RELATIONAL primitives: KL-from-English
     (canon's kl_divergence, reference-relative) and bigram cross-entropy (sequential). Same split MI
     surfaced — marginal symbol-entropy is weak; relational/conditional/reference IT (KL, cross-entropy,
     MI) carries the signal. Product guidance: ship KL / cross-entropy / MI; demote naive entropy.
Caveats: benign = dict-words proxy (no real top-domains list, no network); simplified DGA generators; the
DICT-DGA length=0.986 is a generation artifact (concatenation runs long); single-feature AUC, not a fitted
model — demonstrated on a self-contained fair test, not validated on real DGA feeds.
"""
import collections
import math
import random

import numpy as np

from forge_core import shannon_entropy

_VOWELS = set("aeiou")
_AZ = "abcdefghijklmnopqrstuvwxyz"


def _benign_words(seed=42):
    words = [w.strip().lower() for w in open("/usr/share/dict/words")]
    words = [w for w in words if w.isalpha() and w.isascii() and 6 <= len(w) <= 16]
    random.Random(seed).shuffle(words)
    return words


def _random_dga(n, seed):  # Conficker/CryptoLocker family: pseudorandom lowercase, len 8-14
    r = random.Random(seed)
    return ["".join(r.choice(_AZ) for _ in range(r.randint(8, 14))) for _ in range(n)]


def _dict_dga(words, n, seed):  # suppobox/matsnu family: two concatenated real words (low entropy)
    r = random.Random(seed)
    return ["".join(r.choice(words) for _ in range(2))[:16] for _ in range(n)]


def _bigram_model(train):
    bg, uni = collections.Counter(), collections.Counter()
    for w in train:
        for a, b in zip(w, w[1:]):
            bg[(a, b)] += 1
        for a in w:
            uni[a] += 1
    return bg, uni


def _english_char_dist(train):
    c = collections.Counter()
    for w in train:
        c.update(w)
    tot = sum(c.values())
    return {ch: c[ch] / tot for ch in _AZ}


def _kl_from_english(s, eng):  # KL(domain-char-dist || english-char-dist) — canon's kl_divergence idea
    c = collections.Counter(s)
    n = len(s)
    kl = 0.0
    for ch in set(s):
        p = c[ch] / n
        q = eng.get(ch, 1e-6) or 1e-6
        kl += p * math.log2(p / q)
    return kl


def _features(s, bg, uni, eng):
    chars = np.array(list(s))
    _, counts = np.unique(chars, return_counts=True)
    ll = (
        sum(math.log((bg[(a, b)] + 1) / (uni[a] + 26)) for a, b in zip(s, s[1:])) / (len(s) - 1)
        if len(s) > 1 else -10.0
    )
    return {
        "char_entropy": shannon_entropy(counts),         # THE IT feature under test
        "length": float(len(s)),                         # trivial baseline
        "distinct_ratio": len(counts) / len(s),          # trivial baseline
        "vowel_ratio": sum(c in _VOWELS for c in s) / len(s),  # trivial baseline (DGAs vowel-poor)
        "bigram_loglik": ll,                             # STRONG baseline: sequential cross-entropy (IT)
        "kl_from_english": _kl_from_english(s, eng),     # canon's KL primitive: reference-relative IT
    }


def _auc(pos, neg):  # P(pos > neg); discriminative power = max(auc, 1-auc)
    pos, neg = np.array(pos), np.array(neg)
    a = float(sum(np.sum(v > neg) + 0.5 * np.sum(v == neg) for v in pos) / (len(pos) * len(neg)))
    return a


def main():
    words = _benign_words()
    train, benign = words[:60000], words[60000:70000]   # bigram trained on held-out benign (no leakage)
    bg, uni = _bigram_model(train)
    eng = _english_char_dist(train)
    rand_dga = _random_dga(10000, seed=7)
    dict_dga = _dict_dga(train, 10000, seed=11)

    feats = ["char_entropy", "kl_from_english", "length", "distinct_ratio", "vowel_ratio", "bigram_loglik"]
    B = [_features(s, bg, uni, eng) for s in benign]
    for name, dga in [("RANDOM-DGA (Conficker-like)", rand_dga), ("DICT-DGA (suppobox-like)", dict_dga)]:
        D = [_features(s, bg, uni, eng) for s in dga]
        print(f"\n[{name}]  benign={len(B)} dga={len(D)}")
        print(f"  {'feature':16s}{'AUC':>8s}{'|disc|':>9s}   (AUC=P(dga>benign))")
        for f in feats:
            a = _auc([d[f] for d in D], [b[f] for b in B])
            print(f"  {f:16s}{a:>8.3f}{abs(a - 0.5):>9.3f}")
    print("\nfeature under test = char_entropy; baselines = length/distinct_ratio/vowel_ratio/bigram_loglik")


if __name__ == "__main__":
    main()
