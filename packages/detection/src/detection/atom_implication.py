"""The atom-implication lattice — the atom-altitude twin of the rule-relation lattice.

The rule lattice orders *rules* by clause-set ⊆ (broad/narrow). This orders *atoms* by **logical
implication** of their predicates: ``a ⟹ b`` means *whenever a is True, b is True* — e.g.

    Image|endswith \\rundll32.exe   ⟹  Image|contains rundll32       (stricter op ⟹ looser)
    CommandLine|contains "comsvcs.dll MiniDump" ⟹ CommandLine|contains "comsvcs"   (superstring ⟹ substring)
    Image|equals X  ⟹  Image|endswith X  ⟹  Image|contains X
    EventID == 10   ⟹  NOT (EventID == 1)                            (mutual EXCLUSION)
    GrantedAccess > n ⟹ GrantedAccess >= n                           (numeric)

It is computed from a finite implication-rule set over ``(field, op, value)`` — corpus-free, structural.
Two uses (the "either don't run or are a check" split):

- **Derive** — given the *generator* atoms' truth, an implied atom is True for free wherever its generator
  fired (no evaluation). Shrinks the atom-eval set beyond dedup. *(One-sided: only the True direction — a
  False generator leaves the looser atom unknown.)*
- **Check** — the contrapositive is a soundness probe: if ``a ⟹ b`` and you observe ``a`` True **and** ``b``
  False (or ``a excludes b`` and both True), that is a contradiction → a Belnap ``Both`` / self-falsification
  alarm (the matcher or the implication is wrong).

Conservative by construction: claims an edge only when the op/value relation provably holds (case-insensitive,
matching Sigma); multi-value (OR) clauses and regex are left unrelated unless identical. Never a false
implication — same discipline as ``structural_relation``.
"""

from __future__ import annotations

from collections import defaultdict

from detection.rule_ir import Clause

_STR_OPS = ("endswith", "startswith", "contains", "re", "cidr")
_NUM_OPS = ("gt", "gte", "lt", "lte")


def _op(c: Clause) -> str:
    """The clause's primary operator — the first recognized string/numeric modifier, else ``equals`` (no
    modifier = exact match)."""
    mods = set(c.mods)
    for o in (*_STR_OPS, *_NUM_OPS):
        if o in mods:
            return o
    return "equals"


def _single(c: Clause) -> str | None:
    """The single value of a clause, or ``None`` if it is a multi-value (OR) clause (conservatively skipped)."""
    return str(c.values[0]) if len(c.values) == 1 else None


def _isnum(s: str) -> bool:
    try:
        float(s)
        return True
    except ValueError:
        return False


def _num_implies(ao: str, av: float, bo: str, bv: float) -> bool:
    """Interval implication for numeric ops: does ``field ao av`` imply ``field bo bv``?"""
    def lo_hi(op, v):                          # the [lo, hi] interval an op+value constrains the field to
        return {"gt": (v, float("inf")), "gte": (v, float("inf")),
                "lt": (float("-inf"), v), "lte": (float("-inf"), v)}[op]
    alo, ahi = lo_hi(ao, av)
    blo, bhi = lo_hi(bo, bv)
    return alo >= blo and ahi <= bhi           # a's interval ⊆ b's interval ⟹ a implies b


def implies(a: Clause, b: Clause) -> bool:
    """Does atom ``a`` logically imply atom ``b`` (a True ⟹ b True)? Same field, single-valued, conservative."""
    if a.field != b.field:
        return False
    av, bv = _single(a), _single(b)
    if av is None or bv is None:
        return False
    ao, bo = _op(a), _op(b)
    if ao in _NUM_OPS and bo in _NUM_OPS and _isnum(av) and _isnum(bv):
        return _num_implies(ao, float(av), bo, float(bv))
    if "re" in (ao, bo) or "cidr" in (ao, bo):
        return a.as_tuple() == b.as_tuple()    # regex/cidr: only identical implies
    la, lb = av.lower(), bv.lower()             # Sigma string matching is case-insensitive
    if ao == "equals":
        return {"equals": la == lb, "endswith": la.endswith(lb),
                "startswith": la.startswith(lb), "contains": lb in la}.get(bo, False)
    if ao == "endswith":
        return (bo == "endswith" and la.endswith(lb)) or (bo == "contains" and lb in la)
    if ao == "startswith":
        return (bo == "startswith" and la.startswith(lb)) or (bo == "contains" and lb in la)
    if ao == "contains":
        return bo == "contains" and lb in la
    return False


def excludes(a: Clause, b: Clause) -> bool:
    """Are ``a`` and ``b`` mutually exclusive (a True ⟹ b False)? v1: same field, both exact equality, distinct
    values (a single-valued field can't equal two different things). Numeric-disjoint left for later."""
    if a.field != b.field:
        return False
    av, bv = _single(a), _single(b)
    if av is None or bv is None:
        return False
    return _op(a) == "equals" and _op(b) == "equals" and av.lower() != bv.lower()


def build_atom_implications(atoms: list[Clause]) -> dict:
    """Over a set of distinct atoms, compute the implication edges (``a ⟹ b``) and exclusion pairs, grouping
    by field so the pairwise check is per-field, not global. Returns ``implications`` (list of (i, j) with
    ``atoms[i] ⟹ atoms[j]``), ``exclusions`` (unordered pairs), and the ``generators`` (atoms not implied by
    any *other* atom — the ones you must actually evaluate; the rest can be derived where a generator fires)."""
    by_field: dict[str, list[int]] = defaultdict(list)
    for i, a in enumerate(atoms):
        by_field[a.field].append(i)
    implications: list[tuple[int, int]] = []
    exclusions: list[tuple[int, int]] = []
    implied_by_other: set[int] = set()
    for idxs in by_field.values():
        for i in idxs:
            for j in idxs:
                if i == j:
                    continue
                if implies(atoms[i], atoms[j]):
                    implications.append((i, j))
                    implied_by_other.add(j)
            for j in idxs:
                if i < j and excludes(atoms[i], atoms[j]):
                    exclusions.append((i, j))
    generators = [i for i in range(len(atoms)) if i not in implied_by_other]
    return {"implications": implications, "exclusions": exclusions, "generators": generators,
            "n_atoms": len(atoms)}


def derive(truth: dict[int, bool], implications: list[tuple[int, int]]) -> dict[int, bool]:
    """Propagate True up the implication edges: if ``a`` is True and ``a ⟹ b``, then ``b`` is True (for free).
    Returns the augmented truth (closure over the True direction)."""
    out = dict(truth)
    changed = True
    while changed:
        changed = False
        for i, j in implications:
            if out.get(i) and not out.get(j):
                out[j] = True
                changed = True
    return out


def consistency_violations(truth: dict[int, bool], implications: list[tuple[int, int]],
                           exclusions: list[tuple[int, int]]) -> list[dict]:
    """The soundness check: an implication violated (``a`` True, ``b`` False where ``a ⟹ b``) or an exclusion
    violated (both True where they exclude) is a contradiction → a Belnap ``Both``. Returns the violations."""
    bad = []
    for i, j in implications:
        if truth.get(i) is True and truth.get(j) is False:
            bad.append({"kind": "implication", "a": i, "b": j})
    for i, j in exclusions:
        if truth.get(i) is True and truth.get(j) is True:
            bad.append({"kind": "exclusion", "a": i, "b": j})
    return bad
