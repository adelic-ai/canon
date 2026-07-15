"""Stage 2 — the axes: the one real knob, *which attributes you feed FCA*.

:func:`attributes` projects a :class:`~omega.ir.CompiledRule` to a set of namespaced attribute tokens. Which
tokens depends on the ``axes`` you enable — and that choice is the whole game (the essay's over-collapse is
just ``field`` vs ``clause`` on the same rules). Everything here is ruleset-agnostic: it reads the IR, never
pySigma.

Axes:
  ``field``      value-BLIND — ``field:<name>`` (which fields the rule reads, values thrown away)
  ``clause``     value-AWARE — ``clause:<field>|<mods>=<values>`` (``keyword:<value>`` for keyword items)
  ``polarity``   MODIFIER — prefix field/clause tokens with the block's sign (``+`` selection, ``-`` filter)
  ``fieldref``   relational — ``fieldref:<field>~<referenced-field>`` (the field-to-field predicate)
  ``logsource``  orientation tags — ``<dimension>:<value>`` (product:windows, category:process_creation, …)
  ``attack``     the ATT&CK tags verbatim — ``tag:<t>``

The tokens are just strings, deliberately: two rules share an attribute iff their tokens are equal, so the
whole FCA formal context is ``rules × frozenset[token]`` — a bag of tags, exactly as the logsource discussion
concluded the source dimensions should be.
"""

from __future__ import annotations

from omega.ir import CompiledRule

# Default axis-sets — NOT a privileged "concept key", just named defaults for the two common questions.
# They are PURE LOGIC (the base of the refinement tower): the coarsest meaningful projection. Everything
# else — product / category / attack / fieldref — is an OPT-IN axis you *add* to refine, never a special
# toggle. "Same?" is a family of relations indexed by the axis-set, not a fixed verdict.
FIELD_SET = frozenset({"field"})                # value-blind pure logic
CONTENT = frozenset({"clause", "polarity"})     # value-aware pure logic (filters signed)


def attributes(ir: CompiledRule, *, axes: frozenset[str] | set[str]) -> frozenset[str]:
    """The attribute token-set for ``ir`` under the enabled ``axes`` (see the module docstring)."""
    signed = "polarity" in axes
    out: set[str] = set()

    for block in ir.blocks:
        prefix = ("+" if block.polarity > 0 else "-") if signed else ""
        for atom in block.atoms:
            # A field-reference atom (its value IS another field) contributes a relational token under the
            # fieldref axis — but it still READS its field and carries a value-aware predicate, so it must
            # ALSO flow through the field/clause emission below. (Fix: the old early `continue` dropped the
            # field entirely under the value-blind projection, over-collapsing the headline figure.)
            if "fieldreference" in atom.mods and "fieldref" in axes and atom.field:
                for ref in atom.values:
                    out.add(f"{prefix}fieldref:{atom.field}~{ref}")

            if atom.field is None:                                  # keyword / whole-event item
                if "clause" in axes:
                    for value in atom.values:
                        out.add(f"{prefix}keyword:{value}")
                continue

            if "field" in axes:
                out.add(f"{prefix}field:{atom.field}")
            if "clause" in axes:
                # Delimiter-safe, order-normalised value-aware key. Values are joined on the ASCII unit
                # separator (\x1f, never present in rule values), so a comma inside a value cannot masquerade
                # as two values; values are SORTED (a Sigma value list is an order-independent OR / `all`);
                # mods stay ORDERED (chained modifiers like base64|contains are sequential — sorting is wrong).
                values = "\x1f".join(sorted(atom.values))
                out.add(f"{prefix}clause:{atom.field}|{'|'.join(atom.mods)}={values}")

    if "logsource" in axes:
        for dimension, value in ir.logsource:
            out.add(f"{dimension}:{value}")
    if "attack" in axes:
        for tag in ir.tags:
            out.add(f"tag:{tag}")

    return frozenset(out)
