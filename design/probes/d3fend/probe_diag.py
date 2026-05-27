"""Diagnostic: where do d3f:counters / d3f:may-counter actually point?

If they exist as properties but never appear in triples, that's one story.
If they exist and point at non-OffensiveTechnique nodes, that's another.
"""

from rdflib import Graph, Namespace, URIRef, RDF, RDFS

D3F = Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#")

g = Graph()
g.parse("d3fend.ttl", format="turtle")


def shorten(uri):
    return str(uri).replace("http://d3fend.mitre.org/ontologies/d3fend.owl#", "d3f:")


# Sample each counter/detect property — how many triples use it, and what do they look like?
for prop_name in [
    "counters", "may-counter", "may-counter-attack", "attack-may-be-countered-by",
    "detects", "may-detect", "may-be-detected-by",
]:
    print(f"\n=== d3f:{prop_name} ===")
    prop_uri = D3F[prop_name]

    q = f"""
    PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
    SELECT (COUNT(*) AS ?n) WHERE {{ ?s d3f:{prop_name} ?o }}
    """
    n = int(list(g.query(q))[0][0])
    print(f"Triples using d3f:{prop_name}: {n}")

    if n > 0:
        q_sample = f"""
        PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        SELECT ?s ?slabel ?o ?olabel WHERE {{
          ?s d3f:{prop_name} ?o .
          OPTIONAL {{ ?s rdfs:label ?slabel }}
          OPTIONAL {{ ?o rdfs:label ?olabel }}
        }} LIMIT 5
        """
        for s, slabel, o, olabel in g.query(q_sample):
            print(f"  {shorten(s):45s}  ({slabel or '—'})")
            print(f"    --> {shorten(o):40s}  ({olabel or '—'})")


# What does d3f:T1558.003 actually look like as a TYPE (rdf:type)?
print("\n\n=== TYPE of T1558.003 and what's used to express 'this technique' ===")
q = """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
SELECT ?t WHERE { d3f:T1558.003 a ?t }
"""
for (t,) in g.query(q):
    print(f"  T1558.003 rdf:type: {shorten(t)}")

# Is there a separate ATT&CK-side node like 'attack:T1558.003' or similar?
print("\n=== Are there NON-d3f nodes that look like ATT&CK techniques? ===")
q = """
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT DISTINCT ?s ?label WHERE {
  ?s rdfs:label ?label .
  FILTER(REGEX(STR(?s), "T1558", "i") && !STRSTARTS(STR(?s), "http://d3fend.mitre.org"))
}
"""
results = list(g.query(q))
print(f"Non-d3f T1558 references: {len(results)}")
for s, label in results[:20]:
    print(f"  {s}  ({label})")


# What's the structure of an actual counter relationship? Take the first one we found, look at it deeply.
print("\n\n=== STRUCTURE OF A REAL COUNTER RELATIONSHIP ===")
q = """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT ?def ?dlabel ?o ?olabel WHERE {
  ?def d3f:may-counter ?o .
  OPTIONAL { ?def rdfs:label ?dlabel }
  OPTIONAL { ?o rdfs:label ?olabel }
} LIMIT 5
"""
for def_, dlabel, o, olabel in g.query(q):
    print(f"  {shorten(def_)}  ({dlabel}) -- may-counter --> {shorten(o)}  ({olabel})")
    # And what's o's type?
    print(f"    types of target:")
    for (t,) in g.query("SELECT ?t WHERE { ?o a ?t }", initBindings={"o": o}):
        print(f"      {shorten(t)}")


# Is there a property that bridges OWL-restriction-shaped axioms? Look for "may-counter someValuesFrom"
print("\n\n=== may-counter as OWL RESTRICTION (instead of direct triple)? ===")
q = """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>
SELECT ?def ?dlabel ?target ?tlabel WHERE {
  ?def rdfs:subClassOf ?r .
  ?r a owl:Restriction .
  ?r owl:onProperty d3f:may-counter .
  ?r owl:someValuesFrom ?target .
  OPTIONAL { ?def rdfs:label ?dlabel }
  OPTIONAL { ?target rdfs:label ?tlabel }
} LIMIT 20
"""
results = list(g.query(q))
print(f"DefensiveTechniques with may-counter restriction: {len(results)}")
for def_, dlabel, target, tlabel in results[:15]:
    print(f"  {shorten(def_):50s}  --may-counter (restriction)-->  {shorten(target)}  ({tlabel})")
