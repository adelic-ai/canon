# Kill-chains as entity-path analysis

**Status:** design note, 2026-06-21. The conceptual frame behind the chain checker (`detection/chain.py`): a
kill-chain is an actor's *path* toward a crown jewel, and detecting one is the same shape of problem as
e-business navigation/funnel analysis. **Relates to:** the chain checker (`detection/chain.py`),
the abduction loop, [verdict_coverage_space](verdict_coverage_space.md) (verdict as a location / chain as
a trajectory), [enterprise_allowlist_entrypoint](../web/adoption/enterprise_allowlist_entrypoint.html) (peer-group baseline), the killchain/HMM machinery.

## Detections don't go away — they become the observables

The kill-chain view doesn't replace detections; it **composes** them. The stages *are* detections (a 4768
auth, an RC4 TGS fan-out, a network logon to a crown jewel). What changes is the **unit of analysis** and the
**question**:

- from *"did this detection fire?"* → to *"is a path toward a crown jewel assembling?"*

And the factoring shifts with it. Earlier: **atoms factor rules** (a clause shared by many rules is one atom).
Now: **segments factor paths** — the kill-chain graph has shared edges (many attacks traverse the same
lateral-movement segment), so paths decompose into reusable segments the way rules decompose into atoms. Same
move, one level up.

## The scoring has two factors — completeness × abnormality

The boolean chain checker (`check_chain`) answers a corner case: *is the full path present, in order?* The
fuller, abductive question has two factors:

- **Completeness** — how much of a coherent path toward a crown jewel is assembled (1 stage vs 3 in order).
- **Abnormality** — weighted by how abnormal that path is **for this account**. A service account fanning out
  to SPNs may be half-normal; a finance user doing it is not.

> **threat-likelihood ≈ completeness × abnormality.** The boolean chain is the `completeness = full,
> abnormality = ignored` corner; the abductive layer generalizes both — *more of the path + more abnormal for
> this entity → more likely a real actor.*

## It is structurally e-business navigation / funnel analysis

The mechanics transfer exactly, and canon already has a piece for each rung:

- **Sessionize events per entity** (web: per user; security: per account) → the W-record / `group_by_actor`.
- **Funnel / path analysis** (which steps assembled, where the drop-off is) → the chain checker.
- **Markov model of navigation** (`P(next step | current)`) → the HMM / killchain machinery.
- **"Normal for this user"** (vs their own history or their segment) → the baseline / the battery's
  anomaly-vs-normal.
- **Segment / peer group** (compare a user to *similar* users) → the allowlist-derived identity class (device
  account / service account / admin) from [enterprise_allowlist_entrypoint](../web/adoption/enterprise_allowlist_entrypoint.html) — "is this path normal
  *for this class*."

So mature web-analytics path analysis (sessionization, funnel analysis, sequence mining, Markov navigation
models, baseline/personalization) is a direct toolkit for kill-chain detection — the security version is the
same problem with a different (and harder) sign on a few terms.

## Where the analogy honestly breaks

- **Adversarial.** Web users follow cooperative funnels; the attacker *hides* the path, varies the tools
  (LOLBins), and improvises — there is no designed funnel, and the negative class is overwhelmingly benign.
- **Sparse positives.** E-business models millions of conversions; real attack paths are rare — the
  tiny-positive-class problem dominates.
- **Abnormality is data-gated.** "Normal for this account" needs the account's *history* (or its segment's
  baseline) — standing longitudinal data. That is the recurring data-shape wall: the **completeness** factor
  (the boolean chain) is checkable on a single capture and we built it; the **abnormality** weighting needs the
  baseline data we keep running short of.

## The takeaway

The perspective shift is the right one: **detections are the observables, the path is the unit, and the frame
is e-business-style entity-path analysis** — sessionize per actor, check which segments of the path-to-crown-
jewel assembled, score by completeness and (when there's baseline data) abnormality-for-this-entity. The
boolean completeness layer is buildable now (the chain checker); the abnormality weighting is the next layer,
and it is the part that waits on longitudinal baseline data.
