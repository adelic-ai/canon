"""Probe 2: deeper Kerberoasting coverage.

(1) T1558 (parent) and siblings — is defensive coverage at the parent level?
(2) Unpack the blank-node restriction on T1558.003's subClassOf.
(3) OWL DL reasoning via owlready2 — does subclass inheritance surface counters?
"""

import pathlib

from rdflib import Graph, Namespace, URIRef, BNode, RDF, RDFS, OWL
from collections import defaultdict

D3F = Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#")

g = Graph()
g.parse("d3fend.ttl", format="turtle")


def shorten(uri):
    s = str(uri)
    s = s.replace("http://d3fend.mitre.org/ontologies/d3fend.owl#", "d3f:")
    s = s.replace("http://www.w3.org/2002/07/owl#", "owl:")
    s = s.replace("http://www.w3.org/2000/01/rdf-schema#", "rdfs:")
    return s


print("=== (1) T1558 PARENT — DEFENSIVE COVERAGE ===\n")
T1558 = D3F["T1558"]

# Subclasses (the family)
q = """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT DISTINCT ?sub ?label WHERE {
  ?sub rdfs:subClassOf d3f:T1558 .
  ?sub rdfs:label ?label .
}
"""
print("T1558 direct subtechniques:")
for sub, label in g.query(q):
    print(f"  {shorten(sub):20s}  {label}")

# Anything that counters or detects T1558 directly
print("\nDirect counters/detectors of T1558 (parent):")
q = """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT DISTINCT ?def ?label ?rel WHERE {
  ?def ?rel d3f:T1558 .
  ?def rdfs:label ?label .
  FILTER(REGEX(STR(?rel), "counter|detect|may-counter|may-detect|prevent|mitigat", "i"))
}
"""
results = list(g.query(q))
print(f"  count: {len(results)}")
for def_, label, rel in results[:30]:
    print(f"    {shorten(def_):50s} via {shorten(rel):25s}  {label}")


print("\n=== (2) UNPACK BLANK-NODE RESTRICTION ON T1558.003 ===\n")

T1558_003 = D3F["T1558.003"]
for sup in g.objects(T1558_003, RDFS.subClassOf):
    if isinstance(sup, BNode):
        print(f"Blank-node superclass: {sup}")
        for p, o in g.predicate_objects(sup):
            o_str = shorten(o) if isinstance(o, URIRef) else f"BNode({o})" if isinstance(o, BNode) else str(o)
            print(f"  {shorten(p):35s}  {o_str}")
            # recurse one level if blank
            if isinstance(o, BNode):
                for p2, o2 in g.predicate_objects(o):
                    o2_str = shorten(o2) if isinstance(o2, URIRef) else f"BNode({o2})" if isinstance(o2, BNode) else str(o2)
                    print(f"      {shorten(p2):30s}  {o2_str}")


print("\n=== (3) OWL DL REASONING WITH owlready2 ===\n")
import owlready2

_TTL = pathlib.Path(__file__).resolve().parent / "d3fend.ttl"
onto = owlready2.get_ontology("file://" + str(_TTL)).load()
print(f"Loaded ontology: {onto.base_iri}")
print(f"Classes: {len(list(onto.classes())):,}")

# Find T1558.003 class
T1558_003_cls = None
for c in onto.classes():
    if c.name == "T1558.003":
        T1558_003_cls = c
        break

if T1558_003_cls:
    print(f"\nT1558.003 ancestors (transitive subclass closure):")
    for anc in T1558_003_cls.ancestors():
        if anc.name and not anc.name.startswith("Thing"):
            print(f"  - {anc.name}")

    # What defensive techniques counter ANY ancestor of T1558.003?
    print(f"\nDefensive coverage via parent class hierarchy:")
    ancestor_iris = {anc.iri for anc in T1558_003_cls.ancestors()}
    ancestor_iris.add(T1558_003_cls.iri)
    counter_count = 0
    for cls in onto.classes():
        for prop_name in ["counters", "may_counter", "may_counter_attack", "detects", "may_detect"]:
            prop = getattr(onto, prop_name, None)
            if prop is None:
                continue
            try:
                targets = getattr(cls, prop_name, None)
                if targets:
                    for t in targets:
                        if hasattr(t, 'iri') and t.iri in ancestor_iris:
                            print(f"  {cls.name:50s} --{prop_name}--> {t.name}")
                            counter_count += 1
            except Exception:
                pass
    print(f"\nTotal counter/detect relations to T1558.003 or any ancestor: {counter_count}")

# Try the reasoner — see if it surfaces inferred relations
print(f"\nRunning HermiT reasoner (this may take a moment)...")
try:
    with onto:
        owlready2.sync_reasoner_hermit(infer_property_values=True, debug=0)
    print("Reasoner completed.")
except Exception as e:
    print(f"Reasoner error: {e}")


print("\n=== ALTERNATIVE: dump T1558 + all subtechniques + every relation ===\n")
q = """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT DISTINCT ?tech ?p ?o ?olabel WHERE {
  { ?tech rdfs:subClassOf* d3f:T1558 . }
  UNION
  { BIND(d3f:T1558 AS ?tech) }
  ?tech ?p ?o .
  OPTIONAL { ?o rdfs:label ?olabel }
  FILTER(REGEX(STR(?p), "counter|detect|produce|use|abuse|may-", "i") || REGEX(STR(?p), "subClassOf"))
}
ORDER BY ?tech ?p
"""
results = list(g.query(q))
print(f"Relations across T1558 family: {len(results)}")
by_tech = defaultdict(list)
for tech, p, o, olabel in results:
    by_tech[shorten(tech)].append((shorten(p), shorten(o) if isinstance(o, URIRef) else "BNode", olabel))
for tech in sorted(by_tech.keys()):
    print(f"\n  {tech}:")
    for p, o, olabel in by_tech[tech]:
        ls = f" — {olabel}" if olabel else ""
        print(f"    {p:30s}  {o}{ls}")
