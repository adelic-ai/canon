"""The Corpus index — by-id / by-title / by-logsource lookup over the lowered rules, with list-like access."""

from omega.corpus import Corpus
from omega.ir import CompiledRule


def _rule(rid, title, logsource):
    return CompiledRule(id=rid, title=title, logsource=logsource, tags=(), blocks=(), condition="")


def test_indices_and_list_access():
    a = _rule("id1", "Alpha", (("product", "windows"),))
    b = _rule("id2", "Beta", (("category", "process_creation"), ("product", "windows")))
    b2 = _rule("id3", "Beta", (("category", "process_creation"), ("product", "windows")))   # title collision
    c = Corpus([a, b, b2])

    # list-like
    assert len(c) == 3 and c[0] is a and list(c)[1] is b

    # by id (unique) — both dict and .get()
    assert c.by_id["id2"] is b
    assert c.get("id1") is a and c.get("missing") is None

    # by title — collisions preserved as a list
    assert c.titled("Beta") == [b, b2]
    assert c.by_title["Alpha"] == [a]

    # by logsource — the platform taxonomy, recovered from each rule (open dimension/value pairs)
    assert set(c.by_logsource) == {(("product", "windows"),),
                                   (("category", "process_creation"), ("product", "windows"))}
    assert c.by_logsource[(("category", "process_creation"), ("product", "windows"))] == [b, b2]


def test_ignores_missing_ids_and_titles():
    r = _rule(None, None, ())
    c = Corpus([r])
    assert c.by_id == {} and c.by_title == {}      # no id/title -> not indexed, but still in the list
    assert len(c) == 1 and c[0] is r
