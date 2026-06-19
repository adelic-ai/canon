"""Source→OCSF adapters — the data-plane side of the OFF-able normalization waist.

This is step 2 of ``design/ocsf_ingest_normalization.md``: turn a source's native event
fields into one shared field vocabulary so detections run against a single shape
regardless of origin. The target here is OCSF **Process Activity** (``class_uid`` 1007).
Two source adapters — ``ps`` (the macOS snapshot the live test exposed) and Sysmon (OTRF)
— map onto the *same* OCSF attribute paths for the same semantic role (subject process,
parent process, user), so a rule rewritten to OCSF fires against a normalized event from
**either** source. That cross-source reuse is the whole point of normalizing.

The map is graded and lossy, **never assumed faithful** (the faithfulness-gate discipline,
mirroring ``attest_rust_agreement`` — native is the oracle, OCSF the candidate; step 4).
Every field mapping carries a SKOS-style grade (``exact``/``close``/``broad``/``narrow``)
and a rationale, shown on demand via :meth:`SourceAdapter.why`. Lossiness is not hidden:

- A source field with no OCSF home does **not** cross — it is dropped from the normalized
  view (the "load-bearing field with no clean OCSF home" off-case). :meth:`coverage`
  reports what crossed and what didn't, so the loss is visible rather than silent.
- A normalized event omits an attribute whose source field is absent (a ``ps`` snapshot has
  no parent command line, only a parent pid). A rule reading that attribute then gets a
  NONE — *missing telemetry*, not a false match. This is the coverage-space NONE made
  visible in a shared vocabulary, which is strictly better than burying it in per-source
  field-name mismatches.

Events are emitted as a **flat dict keyed by dotted OCSF attribute paths**
(``"process.cmd_line"``), not nested objects: the IR keys on field strings and pySigma's
OCSF pipeline names fields the same dotted way, so the firing engine is unchanged — only
the field vocabulary changes. That is what makes OCSF optional without a second engine.

Workspace-side per ``design/engine_workspace_boundary.md``: *which* adapter and vocab a run
uses is workspace config; the adapters themselves are shippable engine code.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from detection.vocab import OCSF, Vocabulary


def _get_path(event: dict, path: str) -> Any:
    """Read a dotted path out of a (possibly nested) event. Flat sources (ps/Sysmon) use
    bare field names (no dot → top-level lookup); Endpoint Security events are deeply nested
    (``event.exec.target.executable.path``), so the same getter walks both. Returns ``None``
    the moment any segment is missing — an absent source field, propagated honestly."""
    cur: Any = event
    for seg in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(seg)
        if cur is None:
            return None
    return cur

# SKOS-style mapping grades, coarsest-fidelity-loss last. ``exact`` = the source field and
# the OCSF attribute denote the same thing with no loss; ``close`` = same thing, minor loss
# (truncation, format); ``broad`` = the source field carries MORE than the OCSF attribute
# (bundles extra, e.g. DOMAIN\user into a bare name); ``narrow`` = carries less.
EXACT, CLOSE, BROAD, NARROW = "exact", "close", "broad", "narrow"

# ``carried`` is a different axis: the source field has NO core-OCSF home, so it rides verbatim in
# OCSF's sanctioned ``unmapped`` catch-all (``unmapped.<Field>``). It is MATCH-FAITHFUL (the value is
# verbatim, so a rule reading it fires correctly and does NOT over-match) but NOT cross-source-normalized
# (two sources' unmapped keys don't line up by themselves). It is the immediate, OCSF-valid alternative
# to dropping a no-home field; the typed cross-source lift (a canon profile attribute like
# ``process.call_stack``) is the follow-on. See design/ir_canonical_ruleset.md Corollary 2b.
CARRIED = "carried"

# The OCSF schema version + class this slice targets. Pinned so the vocabulary names a
# concrete shape; schema variants under the ``ocsf`` name are the mapping layer's concern.
OCSF_SCHEMA = "1.3.0/process_activity"


@dataclass(frozen=True)
class FieldMapping:
    """One source-field → OCSF-attribute edge, with its fidelity grade and the rationale
    behind it. ``rationale`` names the definitional alignment and, crucially, *what is lost*
    — so a consumer can decide whether the loss is load-bearing on a given detection.

    ``source_field`` is a dotted path read by :func:`_get_path`. Two refinements the live
    Endpoint Security data forced (past the design doc's "1:1, no value transforms" rule):

    - ``transform`` — a value transform applied to the extracted source value (ES gives
      ``args`` as an argv *array*; ``process.cmd_line`` is one string, so the mapping joins).
    - ``grade_of`` — a function ``event → grade`` for a **data-conditioned** grade (the ES
      executable-path edge is *exact* when ``path_truncated`` is false, *close* when ES
      truncated it). The static ``grade`` is the conservative base (the worst case), so a
      data-conditioned edge still reports as lossy by default until the data proves it exact.
    """

    source_field: str
    ocsf_path: str
    grade: str
    rationale: str
    transform: Callable[[Any], Any] | None = None
    grade_of: Callable[[dict], str] | None = None
    source: str | None = None      # provenance: where the field pair came from / was cross-checked

    @property
    def lossless(self) -> bool:
        return self.grade == EXACT

    def grade_for(self, event: dict) -> str:
        """The grade this edge earns on *this* event — the data-conditioned grade when one is
        defined, else the static base grade."""
        return self.grade_of(event) if self.grade_of is not None else self.grade

    def extract(self, event: dict) -> Any:
        """The source value for this edge, transformed if a transform is set. ``None`` when the
        source path is absent (→ an omitted OCSF attribute → a downstream NONE)."""
        v = _get_path(event, self.source_field)
        if v is None:
            return None
        return self.transform(v) if self.transform is not None else v


@dataclass(frozen=True)
class SourceAdapter:
    """A graded map from one source's native fields onto a target vocabulary's attribute
    paths. ``source`` is the origin (``"ps"``, ``"sysmon"``); ``target`` is the vocabulary
    name the normalized events speak (``ocsf``)."""

    source: str
    mappings: tuple[FieldMapping, ...]
    target: str = OCSF
    schema: str = OCSF_SCHEMA

    def _by_source(self) -> dict[str, FieldMapping]:
        return {m.source_field: m for m in self.mappings}

    def vocabulary(self) -> Vocabulary:
        """The vocabulary normalized events speak — the target name, pinned to the schema, so
        a round can assert coherence with OCSF-targeted rules before firing."""
        return Vocabulary(name=self.target, schema=self.schema)

    def normalize(self, event: dict) -> dict:
        """One native event → its OCSF view: a flat dict keyed by dotted attribute paths.

        Only mapped, present, non-``None`` source fields cross; an attribute whose source
        field is absent is omitted (→ a NONE / missing-telemetry for any rule reading it),
        and an unmapped source field is dropped (reported by :meth:`coverage`). The map is
        applied verbatim — value transforms (splitting ``DOMAIN\\user``) are deliberately
        out of scope for this 1:1 slice; the lossiness is recorded in the grade instead."""
        out: dict = {}
        for m in self.mappings:
            v = m.extract(event)
            if v is not None:
                out[m.ocsf_path] = v
        return out

    def normalize_all(self, events: list[dict]) -> list[dict]:
        return [self.normalize(e) for e in events]

    def why(self, source_field: str) -> FieldMapping | None:
        """The graded mapping for a source field, shown on demand — its OCSF target, grade,
        and the rationale (what aligns, what is lost). ``None`` if the field has no OCSF
        home under this adapter."""
        return self._by_source().get(source_field)

    def ocsf_for(self, native_field: str) -> FieldMapping | None:
        """The OCSF mapping for a *rule's* native field reference — the same graded map used
        to normalize events, read in reverse for rewriting rule fields (step 3). The event
        field a source emits and the field name a rule for that source reads are the *same*
        vocabulary, so one map serves both. ``None`` if the field has no OCSF home (→ the
        rewrite must drop and report it; firing the rule against OCSF would over-match)."""
        return self._by_source().get(native_field)

    def grades(self) -> dict[str, str]:
        """``source_field → grade`` for every mapped field."""
        return {m.source_field: m.grade for m in self.mappings}

    def lossy_fields(self) -> tuple[FieldMapping, ...]:
        """The mappings that lose something (grade ≠ ``exact``) — the ones to check against
        load-bearingness before trusting a normalized match (ride OCSF until a lossy edge
        sits on a field a detection leans on, then tighten by hand: the ``bespoke`` point)."""
        return tuple(m for m in self.mappings if not m.lossless)

    def coverage(self, event: dict) -> dict:
        """What crossed and what didn't, for one event — honesty about the normalization, not
        a silent transform. ``mapped`` = source fields (dotted) that produced an OCSF
        attribute; ``absent`` = mapped fields whose path isn't present on this event (→ NONE
        downstream); ``unmapped`` = present *top-level* event keys no mapping consumes (the
        dropped data — for nested sources this is coarse: a top-level key counts as consumed
        if any mapping's path descends into it)."""
        mapped = sorted(m.source_field for m in self.mappings if _get_path(event, m.source_field) is not None)
        absent = sorted(m.source_field for m in self.mappings if _get_path(event, m.source_field) is None)
        consumed_roots = {m.source_field.split(".", 1)[0] for m in self.mappings}
        present_roots = {k for k, v in event.items() if v is not None}
        return {
            "mapped": mapped,
            "absent": absent,
            "unmapped": sorted(present_roots - consumed_roots),
        }


# ── ps (macOS process snapshot) → OCSF Process Activity ──────────────────────────────────
# Formalizes + grades the hand-rolled ``comm→Image, args→CommandLine`` adapter the macOS
# live test exposed. A ps row IS a process, so its own fields map to the subject ``process``;
# the parent is known only by pid (no parent image/cmd in a snapshot), so a rule reading
# ``actor.process.cmd_line`` against normalized ps gets a NONE — missing telemetry, visible.
PS_ADAPTER = SourceAdapter(
    source="ps",
    mappings=(
        FieldMapping("comm", "process.file.path", CLOSE,
                     "ps `comm` is the executable path/name of the process; OCSF "
                     "`process.file.path` wants the full path. Lossy: ps may truncate to the "
                     "accounting name or terminal width, so close not exact."),
        FieldMapping("args", "process.cmd_line", CLOSE,
                     "ps `args` is the full argv command line = OCSF `process.cmd_line`. "
                     "Lossy: ps truncates at terminal width unless `-ww`, so close not exact."),
        FieldMapping("pid", "process.pid", EXACT,
                     "ps `pid` is the process id = OCSF `process.pid`."),
        FieldMapping("ppid", "actor.process.pid", EXACT,
                     "ps `ppid` is the parent process id = OCSF `actor.process.pid` (the "
                     "initiating process). Note: a snapshot gives only the parent's pid, so "
                     "other `actor.process.*` attributes stay absent → NONE."),
        FieldMapping("user", "actor.user.name", CLOSE,
                     "ps `user` is the resolved owning username = OCSF `actor.user.name`. "
                     "Lossy: ps shows the numeric uid when the name can't be resolved."),
    ),
)


# ── Sysmon (Windows) → OCSF Process Activity ─────────────────────────────────────────────
# EventID 1 (process creation): the new process is the subject (`process.*`), the spawning
# process is the actor (`actor.process.*`). Same OCSF paths as PS_ADAPTER for the shared
# roles, so one OCSF rule fires against either source — the cross-source reuse normalization
# buys.
SYSMON_ADAPTER = SourceAdapter(
    source="sysmon",
    mappings=(
        FieldMapping("Image", "process.file.path", EXACT,
                     "Sysmon `Image` is the full path of the created process's executable = "
                     "OCSF `process.file.path`."),
        FieldMapping("CommandLine", "process.cmd_line", EXACT,
                     "Sysmon `CommandLine` is the created process's command line = OCSF "
                     "`process.cmd_line`."),
        FieldMapping("ProcessId", "process.pid", EXACT,
                     "Sysmon `ProcessId` = OCSF `process.pid` (carried verbatim; Sysmon "
                     "renders it as a string).",
                     source="cross-checked vs AWS Security Lake windows-sysmon (ProcessId→process.pid)"),
        FieldMapping("ProcessGuid", "process.uid", CLOSE,
                     "Sysmon `ProcessGuid` is a globally-unique process identifier; OCSF "
                     "`process.uid` is a generic unique id. Semantics align, format differs "
                     "(GUID vs opaque string) — close, not exact.",
                     source="cross-checked vs AWS Security Lake windows-sysmon (ProcessGuid→process.uid)"),
        FieldMapping("ParentImage", "actor.process.file.path", EXACT,
                     "Sysmon `ParentImage` is the spawning process's executable path = OCSF "
                     "`actor.process.file.path`."),
        FieldMapping("ParentCommandLine", "actor.process.cmd_line", EXACT,
                     "Sysmon `ParentCommandLine` is the spawning process's command line = "
                     "OCSF `actor.process.cmd_line`."),
        FieldMapping("ParentProcessId", "actor.process.pid", EXACT,
                     "Sysmon `ParentProcessId` = OCSF `actor.process.pid`."),
        FieldMapping("User", "actor.user.name", BROAD,
                     "Sysmon `User` is `DOMAIN\\user`; OCSF `actor.user.name` is the bare "
                     "name (the domain belongs in `actor.user.domain`). The whole composite "
                     "string crosses into `name`, bundling the domain — broad (lossy)."),
        # process_access (EID 10) fields — a different Sysmon event class, but the same
        # actor/subject roles, so they share the Process Activity attribute paths: the
        # accessing process is the actor, the accessed process is the subject. This is what
        # lets the comsvcs LSASS-dump rule be rewritten. NOTE: CallTrace is deliberately NOT
        # mapped — the call stack of the access has NO clean OCSF home, and it is the
        # load-bearing field of that detection. Its absence is the honest loss the rewrite
        # reports and the faithfulness gate (step 4) explains, not a thing to paper over.
        FieldMapping("SourceImage", "actor.process.file.path", EXACT,
                     "Sysmon process_access `SourceImage` is the accessing process's "
                     "executable path = OCSF `actor.process.file.path` (the actor)."),
        FieldMapping("TargetImage", "process.file.path", EXACT,
                     "Sysmon process_access `TargetImage` is the accessed process's executable "
                     "path = OCSF `process.file.path` (the subject of the access)."),
        # process_creation fields with verified OCSF homes (paths confirmed against the live
        # OCSF process/file object schema; AWS Security Lake's windows-sysmon mapping does NOT
        # map these, so they are hand-authored, not borrowed).
        FieldMapping("CurrentDirectory", "process.working_directory", EXACT,
                     "Sysmon `CurrentDirectory` = OCSF `process.working_directory`."),
        FieldMapping("IntegrityLevel", "process.integrity", CLOSE,
                     "Sysmon `IntegrityLevel` (e.g. 'High'/'System') = OCSF `process.integrity` "
                     "(string). Close: OCSF also has an enum `integrity_id`; the label crosses "
                     "into the free-text `integrity`, not the enum."),
        FieldMapping("Description", "process.file.desc", CLOSE,
                     "Sysmon `Description` is the PE FileDescription version-info string; OCSF "
                     "`process.file.desc` is 'the file description as returned by the filesystem'. "
                     "Definitionally adjacent (both the human description of the file) — close."),
        FieldMapping("Hashes", "process.file.hashes", BROAD,
                     "Sysmon `Hashes` is a delimited STRING ('SHA256=..,MD5=..'); OCSF "
                     "`process.file.hashes` is an ARRAY of Fingerprint objects. The raw string "
                     "is carried verbatim (so a rule's substring match still fires faithfully), "
                     "but the structural shape is wrong — broad. A real array transform would "
                     "break the rule's string match, so faithfulness is preferred over shape here."),
        # NO CORE-OCSF HOME → CARRIED verbatim in OCSF's sanctioned `unmapped` catch-all (extend, don't
        # fork — design/ir_canonical_ruleset.md Corollary 2b). These are the load-bearing discriminators
        # of LSASS-dump detection (CallTrace ≈ comsvcs; GrantedAccess ≈ the read mask). Carrying them in
        # `unmapped.<Field>` is match-faithful (a rewritten rule reads the verbatim value → fires
        # correctly, no over-match) but not cross-source-normalized; the typed lift (a canon profile
        # attribute) is the follow-on. The faithfulness gate's dropped-field list is the spec for that lift.
        FieldMapping("CallTrace", "unmapped.CallTrace", CARRIED,
                     "Sysmon process_access `CallTrace` (the call stack of the access) has no core OCSF "
                     "attribute — carried verbatim in `unmapped`. Match-faithful (a rule reading it fires "
                     "correctly), not cross-source-normalized. Typed lift → a canon `process.call_stack` "
                     "profile attribute."),
        FieldMapping("GrantedAccess", "unmapped.GrantedAccess", CARRIED,
                     "Sysmon process_access `GrantedAccess` (the access-rights mask) has no core OCSF "
                     "attribute — carried verbatim in `unmapped`. Typed lift → `process.granted_access`."),
        FieldMapping("OriginalFileName", "unmapped.OriginalFileName", CARRIED,
                     "Sysmon `OriginalFileName` (the PE OriginalFilename) has no core OCSF home (`file.name` "
                     "is the on-disk name, `file.internal_name` is a different PE field) — carried verbatim "
                     "in `unmapped`. Typed lift → a canon `process.file.original_name` profile attribute."),
        # process_access actor fields with real OCSF homes (the accessing/parent process = the actor)
        FieldMapping("SourceCommandLine", "actor.process.cmd_line", EXACT,
                     "Sysmon process_access `SourceCommandLine` is the accessing process's command line = "
                     "OCSF `actor.process.cmd_line`."),
        FieldMapping("SourceUser", "actor.user.name", BROAD,
                     "Sysmon process_access `SourceUser` is the accessing process's `DOMAIN\\user` = OCSF "
                     "`actor.user.name` (bundles the domain — broad, like `User`)."),
        FieldMapping("ParentUser", "actor.process.user.name", BROAD,
                     "Sysmon `ParentUser` is the parent process's `DOMAIN\\user` = OCSF "
                     "`actor.process.user.name` (the actor process's user; bundles the domain — broad)."),
    ),
)


# ── eslogger (macOS Endpoint Security exec stream) → OCSF Process Activity ───────────────
# Built against a real `eslogger exec` capture (inspected, not guessed). The richest of the
# three sources: the top-level `process` is the CALLER and `event.exec.target` is the NEW
# process, a clean parent→child edge with the parent's full struct (no ppid-guessing). It
# carries code-signing identity Sysmon EID1 lacks. The live data forced two design moves the
# flat sources didn't: data-conditioned grades (read `path_truncated`) and a typed transform
# (argv array → cmd_line string).


def _exact_unless_truncated(trunc_path: str) -> Callable[[dict], str]:
    """A data-conditioned grade: ``exact`` when the named ``path_truncated`` flag is false (the
    path is the whole path), ``close`` when ES truncated it (lossy)."""
    def grade(event: dict) -> str:
        return CLOSE if _get_path(event, trunc_path) else EXACT
    return grade


def _join_argv(args: Any) -> Any:
    """argv array → one command-line string. Lossy (arg boundaries are lost), hence the edge
    is graded ``close``; left as-is if it isn't a list."""
    return " ".join(args) if isinstance(args, list) else args


# Present-but-unmapped ES fields with no first-class OCSF Process Activity home — recorded,
# not silently dropped. The code-signing *identifier* (signing_id, the bundle-id-like CS id)
# and the platform-binary/cdhash flags are strong detection signal with no clean standard
# slot; they are the `bespoke` candidates (design: extend the target vocab by hand where a
# load-bearing field has no OCSF home), deliberately left for the bespoke point, not forced
# into a wrong attribute.
ESLOGGER_BESPOKE_CANDIDATES = (
    "event.exec.target.signing_id",
    "event.exec.target.cdhash",
    "event.exec.target.codesigning_flags",
    "event.exec.target.is_platform_binary",
)

ESLOGGER_ADAPTER = SourceAdapter(
    source="eslogger",
    mappings=(
        # subject = the newly exec'd process (event.exec.target)
        FieldMapping("event.exec.target.executable.path", "process.file.path", CLOSE,
                     "ES exec target executable path = OCSF `process.file.path`. Grade is "
                     "data-conditioned: exact when `target.executable.path_truncated` is false "
                     "(the path is whole), close when ES truncated it. Base close (conservative) "
                     "until the flag proves it exact.",
                     grade_of=_exact_unless_truncated("event.exec.target.executable.path_truncated")),
        FieldMapping("event.exec.args", "process.cmd_line", CLOSE,
                     "ES `event.exec.args` is argv (an array); OCSF `process.cmd_line` is one "
                     "string. The mapping joins with spaces — close, because the join loses "
                     "argument boundaries (an arg containing a space is indistinguishable from "
                     "two args). This is the one transform the live data forced.",
                     transform=_join_argv),
        FieldMapping("event.exec.target.audit_token.pid", "process.pid", EXACT,
                     "ES target `audit_token.pid` is the new process id = OCSF `process.pid`."),
        FieldMapping("event.exec.target.audit_token.euid", "actor.user.uid", CLOSE,
                     "ES gives the effective uid (numeric); OCSF `actor.user.uid` holds it. "
                     "Close, not exact: ES carries the uid, not the resolved name — Windows "
                     "sources give `DOMAIN\\name` (→ `actor.user.name`). A real cross-source "
                     "impedance, surfaced (uid vs name) rather than hidden; uid→name resolution "
                     "is a separate transform, out of scope here."),
        FieldMapping("event.exec.target.start_time", "process.created_time", CLOSE,
                     "ES target `start_time` (ISO-8601 string) = OCSF `process.created_time`. "
                     "Close: OCSF expects an epoch timestamp, so the value needs parsing — "
                     "format loss, not semantic loss."),
        FieldMapping("event.exec.target.team_id", "process.file.signature.developer_uid", CLOSE,
                     "ES `team_id` is the Apple developer team identifier = OCSF "
                     "`developer_uid`. Close: a null `team_id` on a platform binary is a REAL "
                     "null (Apple-signed, no third-party team), NOT missing telemetry — the "
                     "attribute is correctly absent, not unknown."),
        # parent = the caller (top-level process). Note: ES carries argv only for the target,
        # so there is NO actor.process.cmd_line — a rule reading it gets a NONE (a real
        # coverage gap vs Sysmon's ParentCommandLine), surfaced by coverage().
        FieldMapping("process.executable.path", "actor.process.file.path", CLOSE,
                     "ES caller (top-level `process`) executable path = OCSF "
                     "`actor.process.file.path`. Data-conditioned exact/close on the caller's "
                     "`path_truncated` flag.",
                     grade_of=_exact_unless_truncated("process.executable.path_truncated")),
        FieldMapping("process.audit_token.pid", "actor.process.pid", EXACT,
                     "ES caller `audit_token.pid` = OCSF `actor.process.pid` (the initiating "
                     "process)."),
    ),
)


ADAPTERS: dict[str, SourceAdapter] = {a.source: a for a in (PS_ADAPTER, SYSMON_ADAPTER, ESLOGGER_ADAPTER)}


def adapter(source: str) -> SourceAdapter:
    """The registered source→OCSF adapter for a source name (``"ps"``/``"sysmon"``)."""
    try:
        return ADAPTERS[source]
    except KeyError:
        raise KeyError(
            f"no source→OCSF adapter for {source!r}; have {sorted(ADAPTERS)}. "
            f"Add one in detection.ocsf_adapter or run native (vocabulary off)."
        ) from None
