# Full-corpus dedup pass — exactMatch over-grouped (DIAGNOSED, then RESOLVED by the structure-aware fix)

**Status:** result, 2026-06-20; **numbers regenerated 2026-06-21** after the fix below. Ran the `exactMatch`
slice of the SKOS lattice over the **whole** SigmaHQ corpus to test whether it yields a fileable duplicate
report for SigmaHQ. **It does not** — and the *original* run revealed that `exactMatch` itself over-grouped.
**Relates to:** [[cross_check_validation_kerberos]], the catch-set grounding result (Maude's n=1 OTRF),
[[project_sigma_consumption_audit]], [[project_skos_graded_mapping_seam]].

> **UPDATE (2026-06-21) — the over-grouping this note diagnosed was FIXED.** The original run found 40 exact
> edges / **31 classes / 66 rules**, most of them over-groups: rules with equal *positive clause-sets* but
> distinct discriminators in **keyword** blocks (the linux/auditd trio → `{type=EXECVE}`) or **filter** blocks
> (the svchost pair). A code review made `exactMatch` **structure-aware** — it now requires the full
> `content_digest` (all blocks + condition AST) to match, not just the positive clause-set. Re-run over the
> same 3720 rules: **exact 11 edges / 11 classes / 22 rules** (close 4 → **33** — the demoted over-groups land
> here). The auditd keyword over-group and the svchost filter over-group are **gone from exact** (confirmed
> absent). So this note's diagnosis drove a real fix; the body below is the *as-found* analysis that motivated
> it, and the "kinds" decomposition now applies to the **11** residual classes — which are genuine
> content-duplicates, dominated by **cross-platform ports** (Linux/macOS/Windows variants of one rule:
> Python-path, Ngrok, Find, MeshAgent, Remote-System-Discovery, Shai-Hulud, TeamViewer) plus a few
> same-/cross-logsource pairs (LocaltoNet, SILENTTRINITY DLL-load↔execution, Dns.exe delete↔modify, the
> PowerShell credential pair). The keyword/filter cases are no longer mis-grouped at all.

## Setup (as-found, original run)

- Corpus: 3748 rules with a `detection:` block; **3720 evaluable/structured** (compile to IR).
- Lattice (original, clause-set-only exactMatch): 13780 edges, `{related: 13200, narrower: 347, broader: 189,
  exact: 40, close: 4}`; `exact_classes` **31 multi-member classes / 66 rules**. *(Post-fix: exact 11 / close
  33; see UPDATE above.)*
- Verification: for each class, pulled `logsource`, `level`, filter-presence, and `clause_set` (what the
  lattice actually compared) — so the claim is checked, not asserted (the LSASS over-claim lesson).

## Result — exactMatch-on-positive is not a duplicate detector

Of 31 classes, **~zero are clean, fileable duplicates.** They decompose into four kinds, three of which are
*not* duplication:

1. **Cross-platform ports (~9 classes)** — identical detection string ported to a different OS; `logsource`
   product differs (linux/macos/windows). Intentional, separate rules. E.g. TeamViewer linux↔macos,
   MeshAgent macos↔windows, "System Network Connections Discovery" linux↔macos, Shai-Hulud linux↔windows.
   The `logsource` check flags these `DIFFERS` correctly.

2. **Filter-distinguished, same logsource (~10 classes)** — positive selection is genuinely identical; the
   entire distinction lives in `not 1 of filter_*` exclusion blocks, which `clause_set` excludes **by
   design** (filters are a separate, deferred axis). E.g. `[2]` svchost: *Masquerading As SvcHost* vs
   *Uncommon Svchost Parent* both reduce to `{Image endswith \svchost.exe}` — the discriminator is the
   filter. **This is Maude's n=1 lesson, mirror image.** Not duplicates; not mergeable.

3. **Keyword-discriminator over-groups (several)** — the real discriminator is in **keyword blocks**, which
   `clause_set` skips (`rule_lattice.py` clause_set: "Keyword blocks have no field and are skipped"). A rule
   with one generic field-map block + keyword discriminators collapses to the generic clause. Verified on
   `[3]` linux/auditd: *File Time Attribute Change*, *Suspicious History File Operations*, and *System
   Shutdown/Reboot* — three unrelated detections — **all reduce to `clause_set = {type=EXECVE}`** because
   their discriminators (`touch`, `history`, `shutdowncmd`/`init`) are keyword blocks. This is the silent
   failure: keyword-*only* rules are correctly excluded (empty set), but the **mixed** case (one generic
   field-map + keyword discriminator) is mis-grouped, not excluded.

4. **Plausible near-dups needing eyeball (~4 pairs)** — same logsource, no logsource/keyword artifact, e.g.
   `[8]` SDelete overwrite vs renamed-execution, `[9]` Userinit suspicious vs uncommon (differ only by
   `level`: medium vs high), `[18]` SCR write vs screensaver-binary-creation, `[28]` Mfdetours sideload
   potential vs unsigned (differ only by `level` + a signature field). Every one needs manual review, and at
   least two are general/specific pairs distinguished only by `level` — a **`level`-consistency** question
   for SigmaHQ, not a merge candidate.

## The two over-grouping mechanisms (verified, not asserted)

```
auditd [3]   FileTime / HistFile / Shutdown   → all clause_set = {type=EXECVE}
             discriminators (touch/history/shutdowncmd) are KEYWORD blocks → skipped → false exact
svchost [2]  SvcMasq / SvcParent              → both clause_set = {Image endswith \svchost.exe}
             discriminator is `not 1 of filter_main_*` → filters EXCLUDED by design → false exact
```

Both are **false positives** of exactMatch. Maude's n=1 OTRF result is the **false negative** of the same
proxy: two comsvcs catchers that co-catch the one labeled instance sit in the `related` band (share only
`TargetImage endswith \lsass.exe`, differ on CallTrace+rundll32 vs StartModule). Put together:

> Positive-clause structural identity is neither necessary nor sufficient for behavioral identity. The
> lattice is a proxy in **both** directions. Only catch-set grounding decides synonymy.

## What this means for a SigmaHQ contribution

The clean automated dedup PR does not exist on this corpus. What's real:

- **A tiny human-review shortlist** (kind 4, ~4 pairs) — offered as "candidate duplicates / `level`
  inconsistencies," explicitly not as bugs.
- **Not contributable:** kinds 1–3 are correct-as-designed Sigma, mis-flagged by a positive-only proxy.

## What this means for canon (the higher-value takeaway)

Before any dedup claim, exactMatch must be computed on a **filter-aware, keyword-inclusive content digest**,
not the positive-only `clause_set`:

- **Keyword inclusion** would fix kind 3 (the auditd over-group) — a mechanical extractor fix.
- **Filter-awareness** would fix kind 2 (svchost) — a `content_digest` that hashes exclusion blocks too;
  this is the deferred "separate axis" the `clause_set` docstring names.
- Neither fixes the `related`-band synonymy Maude found (kind = false negative) — that is **irreducibly
  behavioral** and only catch-set grounding recovers it.

Net: the dedup pass did its job by **failing informatively** — it bounded what structure can claim and
handed the rest to grounding. The lattice product's caption ("structural, not behavioral; catch-set would
correct it") is now backed by full-corpus evidence in both directions, not just the n=1 slice.
