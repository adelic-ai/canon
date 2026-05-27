"""Probe 1: actionability — what does D3FEND say about Kerberoasting (T1558.003) specifically?

Plus: does D3FEND ship executable detection rules, or only conceptual ones?
"""

from rdflib import Graph, Namespace, URIRef, RDF, RDFS, OWL

D3F = Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#")
SKOS = Namespace("http://www.w3.org/2004/02/skos/core#")

g = Graph()
g.parse("d3fend.ttl", format="turtle")

KERB = D3F["T1558.003"]


def shorten(uri):
    s = str(uri)
    s = s.replace("http://d3fend.mitre.org/ontologies/d3fend.owl#", "d3f:")
    s = s.replace("http://www.w3.org/2002/07/owl#", "owl:")
    s = s.replace("http://www.w3.org/2000/01/rdf-schema#", "rdfs:")
    s = s.replace("http://www.w3.org/2004/02/skos/core#", "skos:")
    return s


print("=== ALL OUTGOING TRIPLES FOR T1558.003 (Kerberoasting) ===\n")
for p, o in sorted(g.predicate_objects(KERB)):
    print(f"  {shorten(p):45s}  →  {shorten(o)[:120]}")

print("\n=== ALL INCOMING TRIPLES (what points AT T1558.003) ===\n")
for s, p in sorted(g.subject_predicates(KERB)):
    print(f"  {shorten(s):60s}  --{shorten(p)}-->")


print("\n=== DEFENSIVE TECHNIQUES THAT COUNTER T1558.003 ===\n")
q = """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT DISTINCT ?def ?label ?relation WHERE {
  ?def ?relation d3f:T1558.003 .
  ?def rdfs:label ?label .
  FILTER(REGEX(STR(?relation), "counter|detect|prevent|mitigat", "i"))
}
ORDER BY ?label
"""
results = list(g.query(q))
print(f"Defensive techniques: {len(results)}")
for def_, label, rel in results:
    print(f"  {shorten(def_):50s} via {shorten(rel):30s}  {label}")


print("\n=== DIGITAL ARTIFACTS INVOLVED IN T1558.003 ===\n")
q = """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT DISTINCT ?artifact ?label WHERE {
  d3f:T1558.003 ?p ?artifact .
  ?artifact rdfs:subClassOf* d3f:DigitalArtifact .
  ?artifact rdfs:label ?label .
}
"""
results = list(g.query(q))
print(f"Artifacts: {len(results)}")
for art, label in results:
    print(f"  {shorten(art):50s}  {label}")


print("\n=== T1558.003 AS A WHOLE (full structural picture) ===\n")
q = """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT DISTINCT ?p ?o ?olabel WHERE {
  d3f:T1558.003 ?p ?o .
  OPTIONAL { ?o rdfs:label ?olabel }
}
ORDER BY ?p
"""
results = list(g.query(q))
for p, o, olabel in results:
    label_str = f" — {olabel}" if olabel else ""
    print(f"  {shorten(p):35s}  {shorten(o)}{label_str}")


print("\n=== DOES D3FEND SHIP EXECUTABLE DETECTION RULES? ===\n")
# Search for any reference to Sigma, CAR, EQL, SPL, KQL, Suricata, Snort rule IDs/code
q = """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT DISTINCT ?prop ?label WHERE {
  ?prop a <http://www.w3.org/2002/07/owl#ObjectProperty> ;
        rdfs:label ?label .
  FILTER(REGEX(STR(?prop), "sigma|car|eql|spl|kql|suricata|snort|rule|signature|query|yara", "i")
      || REGEX(STR(?label), "sigma|car analytic|rule|signature|query|yara", "i"))
}
"""
results = list(g.query(q))
print(f"Properties hinting at executable rules: {len(results)}")
for prop, label in results:
    print(f"  {shorten(prop):50s}  {label}")

# Search for any literal that looks like a rule reference
q = """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT DISTINCT ?s ?p ?o WHERE {
  ?s ?p ?o .
  FILTER(isLiteral(?o) && REGEX(STR(?o), "sigma|CAR-[0-9]|^DET-|signature:|index=|EventCode=", "i"))
}
LIMIT 20
"""
results = list(g.query(q))
print(f"\nLiterals that look like rule references: {len(results)}")
for s, p, o in results:
    print(f"  {shorten(s)} {shorten(p)}\n    {str(o)[:150]}")


print("\n=== WHAT KIND OF REFERENCES DOES D3FEND CARRY? ===\n")
# What are the d3f:has-reference / kb-reference / external-reference props?
q = """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT DISTINCT ?prop ?label WHERE {
  ?prop a <http://www.w3.org/2002/07/owl#ObjectProperty> ;
        rdfs:label ?label .
  FILTER(REGEX(STR(?prop), "reference|kb-|external", "i"))
}
"""
results = list(g.query(q))
print(f"Reference-related properties: {len(results)}")
for prop, label in results:
    print(f"  {shorten(prop):50s}  {label}")


print("\n=== SAMPLE: a defensive technique's structure ===\n")
# Pick the first defensive technique we found and see all its outgoing triples
q = """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT DISTINCT ?def WHERE {
  ?def ?relation d3f:T1558.003 .
  FILTER(REGEX(STR(?relation), "counter|detect", "i"))
} LIMIT 1
"""
for (def_,) in g.query(q):
    print(f"Sample defensive technique: {shorten(def_)}\n")
    for p, o in sorted(g.predicate_objects(def_)):
        olabel = list(g.objects(o, RDFS.label))
        ls = f" — {olabel[0]}" if olabel else ""
        o_str = shorten(o) if isinstance(o, URIRef) else str(o)[:100]
        print(f"  {shorten(p):40s}  {o_str}{ls}")
