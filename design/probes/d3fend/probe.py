"""D3FEND probe — does the ontology have the shape the unhedged architecture assumes?

Probe questions:
1. Does it load cleanly? Basic graph stats.
2. Does it have Kerberoasting-relevant content?
3. ATT&CK cross-references in expected shape?
4. Defensive techniques + countered offensive techniques bound by SKOS-typed relations?
5. Is the formal-context shape there (techniques × artifacts) for FCA?
"""

from rdflib import Graph, Namespace, URIRef, RDF, RDFS, OWL
from collections import Counter
import sys

D3F = Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#")
SKOS = Namespace("http://www.w3.org/2004/02/skos/core#")

g = Graph()
g.parse("d3fend.ttl", format="turtle")

print(f"=== 1. BASIC STATS ===")
print(f"Total triples: {len(g):,}")

classes = set(g.subjects(RDF.type, OWL.Class))
object_props = set(g.subjects(RDF.type, OWL.ObjectProperty))
data_props = set(g.subjects(RDF.type, OWL.DatatypeProperty))
individuals = set(g.subjects(RDF.type, OWL.NamedIndividual))
print(f"Classes: {len(classes):,}")
print(f"Object properties: {len(object_props):,}")
print(f"Data properties: {len(data_props):,}")
print(f"Named individuals: {len(individuals):,}")


print(f"\n=== 2. KERBEROASTING-RELEVANT CONTENT ===")

q_kerb = """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX skos: <http://www.w3.org/2004/02/skos/core#>
SELECT DISTINCT ?s ?label WHERE {
  ?s rdfs:label ?label .
  FILTER(REGEX(STR(?label), "kerbero", "i") || REGEX(STR(?label), "ticket", "i"))
}
ORDER BY ?label
"""
results = list(g.query(q_kerb))
print(f"Hits for kerberoast/ticket terms: {len(results)}")
for s, label in results[:25]:
    short = str(s).replace("http://d3fend.mitre.org/ontologies/d3fend.owl#", "d3f:")
    print(f"  {short:60s}  {label}")


print(f"\n=== 3. ATT&CK CROSS-REFERENCES ===")

q_attack_props = """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT DISTINCT ?prop ?label WHERE {
  ?prop a <http://www.w3.org/2002/07/owl#ObjectProperty> ;
        rdfs:label ?label .
  FILTER(REGEX(STR(?prop), "attack", "i") || REGEX(STR(?label), "attack", "i"))
}
"""
results = list(g.query(q_attack_props))
print(f"ATT&CK-linking object properties: {len(results)}")
for prop, label in results:
    short = str(prop).replace("http://d3fend.mitre.org/ontologies/d3fend.owl#", "d3f:")
    print(f"  {short:50s}  {label}")

q_t1558 = """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT DISTINCT ?s ?label WHERE {
  ?s ?p ?o .
  ?s rdfs:label ?label .
  FILTER(REGEX(STR(?o), "T1558", "i") || REGEX(STR(?s), "T1558", "i") || REGEX(STR(?label), "T1558", "i"))
}
"""
results = list(g.query(q_t1558))
print(f"\nT1558-linked nodes: {len(results)}")
for s, label in results[:15]:
    short = str(s).replace("http://d3fend.mitre.org/ontologies/d3fend.owl#", "d3f:")
    print(f"  {short:60s}  {label}")


print(f"\n=== 4. DEFENSIVE TECHNIQUES + COUNTERED OFFENSIVE TECHNIQUES ===")

q_counters = """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT DISTINCT ?prop ?label WHERE {
  ?prop a <http://www.w3.org/2002/07/owl#ObjectProperty> ;
        rdfs:label ?label .
  FILTER(REGEX(STR(?prop), "counter|detect|mitigat|prevent|defen", "i"))
}
"""
results = list(g.query(q_counters))
print(f"Counter/detect/mitigate object properties: {len(results)}")
for prop, label in results:
    short = str(prop).replace("http://d3fend.mitre.org/ontologies/d3fend.owl#", "d3f:")
    print(f"  {short:50s}  {label}")


print(f"\n=== 5. FORMAL-CONTEXT SHAPE (FCA feasibility) ===")

q_def_techs = """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT (COUNT(DISTINCT ?s) AS ?n) WHERE {
  ?s rdfs:subClassOf* d3f:DefensiveTechnique .
}
"""
for (n,) in g.query(q_def_techs):
    print(f"DefensiveTechnique subclasses: {n}")

q_off_techs = """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT (COUNT(DISTINCT ?s) AS ?n) WHERE {
  ?s rdfs:subClassOf* d3f:OffensiveTechnique .
}
"""
for (n,) in g.query(q_off_techs):
    print(f"OffensiveTechnique subclasses: {n}")

q_artifacts = """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT (COUNT(DISTINCT ?s) AS ?n) WHERE {
  ?s rdfs:subClassOf* d3f:DigitalArtifact .
}
"""
for (n,) in g.query(q_artifacts):
    print(f"DigitalArtifact subclasses: {n}")

q_top_classes = """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT ?s ?label WHERE {
  ?s a <http://www.w3.org/2002/07/owl#Class> ;
     rdfs:label ?label .
  FILTER NOT EXISTS { ?s rdfs:subClassOf ?super . FILTER(?super != <http://www.w3.org/2002/07/owl#Thing>) }
}
ORDER BY ?label
"""
results = list(g.query(q_top_classes))
print(f"\nTop-level classes (no superclass except owl:Thing): {len(results)}")
for s, label in results[:30]:
    short = str(s).replace("http://d3fend.mitre.org/ontologies/d3fend.owl#", "d3f:")
    print(f"  {short:50s}  {label}")
