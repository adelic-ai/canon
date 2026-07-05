"""Dev REPL bootstrap for omega — land in an interactive session with the corpus already loaded.

Run:
    uv run --project packages/omega python -i packages/omega/repl.py

The ``-i`` flag runs this file and then drops you into the REPL with everything below in scope:
    SIGMA    absolute path to the vendored SigmaHQ corpus (computed from this file, so CWD-independent)
    rules    the parsed pySigma SigmaRule objects              (Stage 0)
    report   the ParseReport for the load
    ir       the corpus lowered to omega CompiledRule          (Stage 1)
    corpus   an indexed view over ir — by_id / by_title / by_logsource
    load, load_ir, to_ir, Corpus, Atom, Block, CompiledRule    imported, ready to poke

Example, once you're in:
    >>> report.rules, report.clean
    >>> corpus.get("195e1b9d-bfc2-4ffa-ab4e-35aef69815f8")     # lookup by id
    >>> corpus.titled("Bitbucket Full Data Export Triggered")  # lookup by title (a list)
    >>> [b for r in ir for b in r.blocks if b.polarity == -1][:3]
"""

from pathlib import Path

from omega.corpus import Corpus                           # noqa: F401 (exposed for the REPL)
from omega.ingest.sigma import load, load_ir, to_ir       # noqa: F401 (exposed for the REPL)
from omega.ir import Atom, Block, CompiledRule            # noqa: F401 (exposed for the REPL)

SIGMA = Path(__file__).resolve().parents[1] / "semantic-cyber/data/sigma-rules"

rules, report = load(SIGMA)
ir = [to_ir(r) for r in rules]
corpus = Corpus(ir)

print(f"omega REPL ready — {report.rules} rules, clean={report.clean}, {len(ir)} lowered to IR")
print("  in scope: SIGMA, rules, report, ir, corpus, load, load_ir, to_ir, Corpus, Atom, Block, CompiledRule")
