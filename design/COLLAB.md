# COLLAB — cross-instance coordination ledger

The shared channel for multiple Claude Code instances working canon in parallel, so the **human is not the
message bus**. Separate Claude sessions cannot talk directly (no IPC); coordination must go through a shared
medium. This file is it: the durable protocol + an append-only handoff log.

## The hard constraint

Two separately-launched instances share only the **filesystem and git**. They do not share context. So:
state that must cross instances lives in **git** (commits, branches, design notes) + **this ledger**. A
"done" message that just restates commits is redundant — fetch the branch and read instead.

## Protocol (every instance follows this)

**Lane = branch = worktree.** Each instance owns one lane: a feature branch, ideally in its own git worktree
(e.g. main instance in `~/canon` on `feat/...`; a peer in `~/canon-maude` on `feat/...`). Never two instances
on one working tree (HEAD collision).

**Turn start — sync before acting:**
```
git fetch --all -q
# read the other lane's latest ledger entry without switching branches:
git show origin/<other-lane-branch>:design/COLLAB.md | tail -40
```
Then read the other lane's recent commits (`git log --oneline origin/<other-branch> -5`) for the actual work.

**Turn end — record the handoff:** append ONE entry to the log below (newest at top of the log section),
commit it on your own lane branch, and push. Entries are **append-only** — never edit or delete another
lane's entry. Keep entries short: what changed, what's handed off, what decision (if any) the other lane owns.

**Reading across branches:** because each lane commits the ledger on its own branch, the union of both
branches' entries is the full timeline (entries are timestamped + lane-tagged, so they merge cleanly and
reconcile when branches land on main). To see the merged view, read both: `git show origin/<A>:design/COLLAB.md`
and `git show origin/<B>:design/COLLAB.md`.

**Routing / decisions:** put cross-lane decisions in the "Open decisions" section, tagged with who owns the
call. The human says "go" to each instance; they don't relay content — the ledger + git carry it.

**Lower-friction alternative (optional):** for zero git overhead on a single machine, a peer can instead use a
plain shared file outside both worktrees (e.g. `~/canon-collab/LEDGER.md`) read/appended by absolute path.
Same append-only discipline; not versioned. Use it only if the git-show flow is too heavy; the in-repo ledger
is the default because it's versioned and discoverable.

## Lane registry

```
<<< lane: sigma-treatment | instance: main         | worktree: ~/canon        | branch: feat/sigma-treatment-pipeline | status: ACTIVE >>>
<<< lane: catch-set        | instance: peer (Maude) | worktree: ~/canon-maude  | branch: feat/catch-set-grounding      | status: CLOSED (de-risk) >>>
```

## Open decisions

- **Branch merges (owner: human).** `feat/sigma-treatment-pipeline` and `feat/catch-set-grounding` are both
  heavy and unmerged — review gate. Nothing blocks on them; flagged so they don't accumulate further.
- **Population frontier data (owner: either lane, when picked up).** Both lanes converged: atomic-red-team
  captures are structurally thin (no benign population; cross-channel-disjoint). `bots-v3` (1.1G mixed
  enterprise, already on disk, UNVERIFIED) is the candidate both-class corpus for the battery + same-channel
  grouping. Verify before relying.
- **Assembly-diagnosis refinement (owner: main).** `unvouched-miss` is a weak bug signal (real data: mostly
  variant-specific discriminators, not typos). Real signal is NEAR-MISS (atom value one edit from a value
  present in the event). Edit-distance filter deferred.

## Handoff log (append-only, newest first)

### 2026-06-20 · main · assembly-level non-fire diagnosis landed
`feat/sigma-treatment-pipeline` @ `c58b9d0`. Built `assembly_diagnosis.py` (atom-reuse exoneration oracle) +
6 tests + OTRF runner. Real comsvcs run (79 rules): 2 fire / 54 wrong-channel / 10 variant-miss / 1
filter-excluded / 12 unvouched-miss — corroborates the fidelity-scorecard causes at per-atom resolution.
Honest finding: rule-uniqueness ≠ bug; real signal is near-miss (deferred → Open decisions). Earlier this
lane: lattice product HTML, full-corpus dedup pass, stage-5 coverage + corroboration layer, Sigma
evaluability reconciled to 99.3%, T1558.003 battery regime-bounded negative, underpowered-verdict worked
example, IR-vocabulary-stratification note. Nothing handed off; next slice TBD by human.

### 2026-06-20 · catch-set (Maude) · lane CLOSED at de-risk
`feat/catch-set-grounding` (worktree `~/canon-maude`, pushed). Stage-4 catch-set machinery: `catch_set.py`
(`rule_catch_sets`/`group_by_catch_set`/`ground_lattice`), `evtx_xml.py`, `grounded_fidelity` returns
`caught_on`. Under-group corroborated on two techniques (OTRF T1003.001, splunk T1558.003): behavioral
synonyms are structurally *related*, not exact → graded edges load-bearing, dedup-by-exactMatch under-groups.
Both off-diagonals pinned. Splunk-text parser deferred (one-cell payoff, no blocked consumer). Nothing
pending. Handed off to main: assembly-level non-fire diagnosis (done, above).
