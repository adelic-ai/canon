# The schema-impedance seam as a SKOS-graded, justified mapping

**Status: design direction, not built (2026-06-16).** Captures a thread from the corroboration work:
how cross-platform type/field correspondence should be represented so a "close but no guarantee" mapping
is *honest* rather than silently flattened to equality.

## The problem: impedance

**Field/type impedance** = two platforms describe the *same* event with different field names or value
encodings, so a rule or detector written against one schema silently fails against the other even though
the underlying fact is identical. The wiring is connected; nothing transfers. Concretely: a SigmaHQ rule
keys on raw-Windows `ServiceName`/`TicketEncryptionType`; our Splunk-CIM corpus carries the same fact as
`Service_Name`/`Ticket_Encryption_Type`. Same 4769 RC4 ticket, no match — a schema mismatch masquerading
as a non-detection. (Distinct from a genuine *telemetry/model* difference — e.g. Rubeus's EID-4611 logon
artifact vs the behavioral 4769 fan-out — which is two *different events*, not a naming mismatch, and a
field map cannot fix. Keep the two separate.)

Two structural answers, complementary:
- **OCSF (data-side):** normalize each source *into* a common schema once; detections target OCSF.
- **pySigma pipelines (rule-side):** keep data native; transform the *rule* per-schema.

Both reduce impedance. Neither eliminates it — because the mapping itself is **lossy and approximate**:
each platform's "Process" or "Authentication" type is *close but not identical*, "usually very close but
no guarantee."

## The formalism: SKOS mapping relations

Cross-scheme correspondence is **not equality** — it is a [SKOS](https://www.w3.org/2004/02/skos/) mapping
relation, and SKOS already carries the graded vocabulary:

- `skos:exactMatch` — interchangeable with confidence (equivalent across schemes).
- `skos:closeMatch` — usable interchangeably in *some* applications, explicitly **not** equivalent. The
  "close but no guarantee" case, named.
- `skos:broadMatch` / `skos:narrowMatch` — one type is more general than the other (OCSF `service.name`
  may be *broader* than Windows `ServiceName`).
- `skos:relatedMatch` — associated, non-hierarchical.

**Two distinct gradings live here:**
1. **Tightness** — exact / close / related. *How safe* to treat the two as the same.
2. **Position** — broad / narrow. *Which direction* the mismatch goes (does the mapping generalize or
   specialize).

Canon already uses the **position** axis internally: the Sigma panel's FCA/SKOS dedup orders rules by
broader/narrower *field-sets* (`{TargetImage}` is `skos:broader` than `{GrantedAccess, CallTrace}`). What
this note proposes is the *same lattice generalized across schemes* — from "which rule is broader" to
"which platform's type is broader."

## The canon move: the grade propagates into the verdict tier

A detection that matched through an `exactMatch` carries full guarantee; one that matched only through a
`closeMatch` *may* warrant **demotion** — "close but no guarantee" becomes a *recorded*, inspectable tier
adjustment (or a `NONE` on the affected W), never a silent `TRUE`. This is canon's thesis applied to the
schema seam: a graded mapping is graded evidence, and the validity/guarantee fold should carry the grade,
not flatten it. The mapping layer becomes a **tracked tier**, not an assumed-faithful identity.

### Load-bearing is the judgment; the grade only informs it

Separate two things that must not be conflated:

- **The grade + its reasons are ALWAYS stored** on the mapping edge — computed once, intrinsic to the
  edge, independent of any detection. *Every* grade points to its reasons, full stop (the `.why()`
  principle); this never depends on load-bearingness. The edge for `windows:ServiceName ≈ cim:Service_Name`
  carries its `closeMatch` + sub-scores + definitional pointers whether or not any rule uses the field.
- **The demotion *consequence* on a particular verdict is what load-bearingness gates.** A `closeMatch`
  on a field a given rule never reads should **not** drag that rule's tier down. If a rule keys on
  `EventID` (an `exactMatch`) and the only `closeMatch` is on an unread `ServiceName`, the difference is
  **inert for that verdict** — no demotion. If the rule keys *exactly* on the mismatched field, it is
  **load-bearing** and the grade takes effect. So the demotion is a **join**:
  `(mapping grade) × (does this detection depend on the differing dimension?)`.

"Takes effect" = a **recorded tier demotion** in the verdict's guarantee (shown on demand, demotable) —
mechanical, not a manual gate; surfacing a demoted verdict for analyst review is a downstream consequence,
not the mechanism. And **inert ≠ unrecorded**: even when the difference doesn't apply, the verdict still
carries "field X is a `closeMatch`, here's why, but this detection doesn't depend on X → no demotion." The
*non*-demotion is itself a shown-on-demand decision; nothing is ever silently dropped.

This is the whole point of making the grade justified and per-dimension: the transparent sub-scores +
definitional pointers exist **so the user (or an agent) can reason for themselves whether the difference
is load-bearing on *this* detection event** — rather than the system applying a uniform, context-blind
demotion. Part of that judgment is mechanically checkable (does the detection's predicate reference the
differing field?); part is semantic (does a value-encoding `closeMatch` change the truth of the predicate?
e.g. `0x17` vs `RC4-HMAC` is inert if normalized, load-bearing if compared literally). The seam supplies
the evidence — always, fully justified; the load-bearing call is the analyst's, or a verifier's where it
reduces to "is the differing dimension in the rule's support set?"

## The grade must be JUSTIFIED and CALLABLE, not a flat label

The load-bearing requirement (the reason this is a canon problem at all): a SKOS grade you cannot justify
back to its inputs is exactly the asserted-not-earned result the project refuses. So the mapping edge is
itself a **justified verdict** — a fold over sub-scores, each leaf a concrete definitional difference with
metadata — and the *instance* answers "why this grade?" on demand. The grade carries:

- **the reason** — which dimension(s) of difference drove it (name vs value-encoding vs semantic-scope vs
  OSI/IP layer vs cardinality …), *if* a difference is even the cause;
- **the sub-scores** — the per-dimension contributions the final relation/magnitude folded over;
- **definitional pointers** — a link to *each platform's actual definition* of the type, so the concrete
  difference is showable, not asserted;
- **positional metadata** — the coordinate-system view: OSI/IP layer, a node *coordinate* in the concept
  space, and *relative position to neighbors* (the lattice/topographic neighborhood).

Realized as a class whose instance can *call* its own justification (sketch — not yet implemented):

```python
@dataclass(frozen=True)
class DiffScore:
    """One dimension of difference, grounded in the two definitions — a justification leaf, not an opinion."""
    dimension: str          # "name" | "value-encoding" | "semantic-scope" | "osi-layer" | "cardinality" | ...
    score: float            # contribution to the mismatch on this dimension (0 = identical)
    source_defn: str        # pointer/URI to the SOURCE platform's definition of the concept
    target_defn: str        # pointer/URI to the TARGET's definition
    note: str = ""          # human-readable "what differs"

@dataclass(frozen=True)
class TypeMapping:
    """A graded, justified correspondence between two platform concepts — the impedance seam, made honest."""
    source: str                      # e.g. "windows:ServiceName"
    target: str                      # e.g. "ocsf:service.name"
    relation: str                    # exact | close | broad | narrow | related  (the SKOS bucket — qualitative)
    subscores: tuple[DiffScore, ...] # the leaves the relation/magnitude fold over
    # positional metadata — the coordinate-system view (WHERE the concept sits)
    osi_layer: int | None = None
    coordinate: tuple[float, ...] | None = None    # node coordinate in the concept space
    neighbors: tuple[str, ...] = ()                # relative position to neighbors

    @property
    def magnitude(self) -> float:
        """Quantitative distance — a fold over subscores. SKOS gives the bucket; this gives 'how far',
        enabling PROPORTIONAL demotion rather than only stepwise."""
        ...

    def why(self) -> "Justification":
        """Shown on demand: relation + magnitude + every subscore + the definitional pointers.
        The instance justifies its own grade — no opaque label. This is the 'shown on demand' thesis,
        one level up: applied to the mapping edge instead of the detection verdict."""
        ...

    def is_load_bearing(self, detection_support: "set[str]") -> bool:
        """Does this mapping bite on a given detection? True iff the differing dimension is in the
        detection's SUPPORT SET (the fields/aspects its predicate actually reads). An exactMatch on a
        used field, or any match on an UNUSED field, is inert. The mechanically-checkable half of the
        load-bearing judgment; the semantic half (does a value-encoding closeMatch change the predicate's
        truth) is the analyst's / a verifier's call, informed by `why()`."""
        ...

    def demotes(self, tier: "Tier", *, load_bearing: bool) -> "Tier":
        """How a verdict that depended on THIS mapping demotes — GATED on load-bearing. Not load-bearing →
        tier unchanged (the difference is inert). Load-bearing: exact → unchanged; close → cap/step down;
        broad/narrow → record the direction; magnitude can make it proportional. Never a silent pass."""
        ...
```

## The recursion (why this is on-thesis, not a detour)

The mapping edge is **the same justified-verdict pattern, one level up**: instead of "a detection, justified
back to its telemetry," it is "a type-correspondence, justified back to the two definitions." Same shape —
a fold over leaves, each leaf grounded and pointable, the result demotable and shown on demand. The Belnap
`NONE ≠ FALSE` discipline applies directly: an *unmapped* field is `NONE` (couldn't bridge), not a silent
drop; a `closeMatch` is graded-TRUE, not full-TRUE.

## Open questions

- **Where do sub-scores come from** — authored (a human grades the edge, like the OCSF mappers) or computed
  (a metric over the two definitions)? Either way the grade is itself a *claim with provenance*, demotable,
  possibly wrong — not ground truth.
- **OSI/IP layer → coordinate** — how a stack layer becomes one axis of the node coordinate, and what the
  other axes are (the concept lattice rank? a topographic embedding? — see `reference_topographical_distance_options`).
- **Magnitude vs bucket** — SKOS gives 5 qualitative buckets; proportional demotion needs a number. Is the
  magnitude a calibrated distance, or just an ordering? Don't invent a false precision.
- **Who validates the grade** — the mapping edge should be checkable (a wrong `exactMatch` is a soundness
  hole), so the seam wants its own validation, the same way detections earn their tier.

## The edges as a living, contested commons (peer review + reviewer credibility)

A mapping edge's grade is not a one-time static assignment — it is a **contestable claim that accrues
review over time**, and the reviews are themselves canon-native objects. The edges become a living layer
that sharpens as evidence accumulates (and, where the platform boundary is genuinely fuzzy, *stays*
contested — which is itself honest signal, not noise to resolve away).

Where verdicts are emitted (e.g. evaluating a Splunk notable), the verdict artifact is ephemeral — a tmp
file tagged with the notable id as metadata; **retention is the customer's SIEM policy**, not canon's, and
the verdict is anyway *reconstructable from the content-addressed inputs* (re-derivable from the retained
notable + the deterministic DAG). But the **platform-difference edges warrant peer review**, almost like
academic review — and that review machinery is established, not invented:

- **Reviewers grade edges; reviewers are themselves graded.** This is crowd-labeling with *latent
  annotator reliability* — the canonical model is **Dawid–Skene** (EM estimating the true grade AND each
  reviewer's reliability jointly from disagreeing labels). "Some reviewers are more reliable" is the latent
  parameter that model already recovers; inter-rater agreement (Krippendorff's α) measures how contestable
  an edge actually is. Reviewer-reliability is a legitimate **telemetry candidate**.
- **Reviewer reliability over time = credibility theory** (Bühlmann) — the actuarial per-entity-baseline
  thread, pointed at reviewers instead of accounts. A reviewer is an entity; their grading track record is
  their baseline; their next grade is credibility-weighted by it. Recursive: verdicts about mappings,
  verdicts about reviewers, same machinery.
- **A review is an ARGUMENT, not a vote.** Because the grade is justified (sub-scores, definitional
  pointers), a review carries its *reasons*, so it is weighted by justification quality + track record, not
  raw count. This is the canon differentiator and the defense against the failure mode — **majority ≠
  correct**, especially for expert schema judgments. Closer to an argumentation framework (claims
  adjudicated by support/attack structure) than to voting.

**Even agreement is contestable.** An `exactMatch` is a claim with provenance, not a fact; an AI or human
can contest it. A credible contestation does not silently flip the edge — it enters a **recorded contested
state** (Belnap-`BOTH`-flavored: agreement + credible dissent = a soundness flag), cataloged and analyzed.
Contestations and their outcomes are data.

**Layer separation.** Canon *core* needs only that the edge be a justified, contestable verdict with
provenance — reviews and reviewer-reliability are just more such verdicts. The *ecosystem* layer (the "whole
other business") — contribution/governance/attribution: opt-in, open-source, named-or-anonymous reviewers,
recognition/attribution if desired — is separable and undecided; the core works with one reviewer and scales
to a crowd unchanged.

**Known failure modes (do not hand-wave).** Reputation systems get gamed — collusion, sockpuppets,
majority-tyranny, cold-start (a new edge has no reviews). Dawid–Skene + credibility-weighting down-weight
unreliable/colluding raters but do not immunize; the justification-weighting (a graded argument is
auditable, a vote is not) is the real mitigation. Convergence of edges is *likely but not guaranteed* — the
non-convergent edges are the interesting ones (genuine platform ambiguity); represent the contestation,
don't force a single grade.

## Connections

- Builds on the FCA/SKOS dedup already in `detection/sigma_panel.py` (subsumption on field-sets).
- The data-side target is OCSF (`project_ocsf_data_shape_standard`); the rule-side patch is pySigma pipelines.
- The coordinate/position idea ties to the "W's as a coordinate system" thread and `reference_topographical_distance_options`.
- The demotion mechanics reuse `provenance/guarantee.py` (assumption-bearing tiers that cap at a floor).
