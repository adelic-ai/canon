"""Probe 3: is D3FEND's thin defensive coverage Kerberos-specific or general?

(a) Subclass-transitive counter query for T1558.003 (catches inherited counters).
(b) Sample 10 common TTPs and report defensive-coverage distribution.
(c) Also convert d3fend.ttl → d3fend.owl for future owlready2 use.
"""

from rdflib import Graph, Namespace, URIRef

D3F = Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#")

g = Graph()
g.parse("d3fend.ttl", format="turtle")


def shorten(uri):
    s = str(uri)
    return s.replace("http://d3fend.mitre.org/ontologies/d3fend.owl#", "d3f:")


# ----------------------------------------------------------------------
# (a) Subclass-transitive counter query for T1558.003
# ----------------------------------------------------------------------
print("=== (a) ANCESTOR-AWARE COVERAGE FOR T1558.003 ===\n")
q = """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT DISTINCT ?def ?def_label ?target ?target_label ?rel WHERE {
  d3f:T1558.003 rdfs:subClassOf* ?target .
  ?target rdfs:label ?target_label .
  ?def ?rel ?target .
  ?def rdfs:label ?def_label .
  FILTER(REGEX(STR(?rel), "counter|detect|may-counter|may-detect|prevent|mitigat", "i"))
}
ORDER BY ?target ?def_label
"""
results = list(g.query(q))
print(f"Inherited counters (T1558.003 + ancestors): {len(results)}")
for def_, dlabel, target, tlabel, rel in results[:30]:
    print(f"  {shorten(def_):45s} --{shorten(rel):25s}--> {shorten(target):20s}  ({tlabel})")


# ----------------------------------------------------------------------
# (b) Defensive-coverage distribution across common TTPs
# ----------------------------------------------------------------------
print("\n=== (b) DEFENSIVE-COVERAGE DISTRIBUTION ACROSS COMMON TTPs ===\n")

ttps = [
    "T1059",     # Command and Scripting Interpreter
    "T1003",     # OS Credential Dumping
    "T1071",     # Application Layer Protocol
    "T1078",     # Valid Accounts
    "T1547",     # Boot or Logon Autostart
    "T1190",     # Exploit Public-Facing Application
    "T1027",     # Obfuscated Files
    "T1558",     # Steal or Forge Kerberos Tickets
    "T1558.003", # Kerberoasting
    "T1110",     # Brute Force
    "T1486",     # Data Encrypted for Impact (ransomware)
    "T1055",     # Process Injection
    "T1021",     # Remote Services
]

print(f"{'TTP':12s}  {'Direct counters':>15s}  {'Inherited counters':>20s}  {'Artifacts':>10s}")
print("-" * 65)
for ttp in ttps:
    # Direct counters (only this exact class)
    q_direct = f"""
    PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    SELECT (COUNT(DISTINCT ?def) AS ?n) WHERE {{
      ?def ?rel d3f:{ttp} .
      FILTER(REGEX(STR(?rel), "counter|detect|may-counter|may-detect", "i"))
    }}
    """
    # Inherited counters (this class + any ancestor)
    q_inherited = f"""
    PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    SELECT (COUNT(DISTINCT ?def) AS ?n) WHERE {{
      d3f:{ttp} rdfs:subClassOf* ?target .
      ?def ?rel ?target .
      FILTER(REGEX(STR(?rel), "counter|detect|may-counter|may-detect", "i"))
    }}
    """
    # Digital artifacts (via may-produce, uses, etc.)
    q_artifacts = f"""
    PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    SELECT (COUNT(DISTINCT ?art) AS ?n) WHERE {{
      d3f:{ttp} ?p ?art .
      ?art rdfs:subClassOf* d3f:DigitalArtifact .
    }}
    """
    direct = int(list(g.query(q_direct))[0][0])
    inherited = int(list(g.query(q_inherited))[0][0])
    artifacts = int(list(g.query(q_artifacts))[0][0])
    print(f"  {ttp:10s}  {direct:>15d}  {inherited:>20d}  {artifacts:>10d}")


# ----------------------------------------------------------------------
# (c) Convert to RDF/XML for future owlready2 use
# ----------------------------------------------------------------------
print("\n=== (c) CONVERT TTL → OWL (RDF/XML) FOR owlready2 ===\n")
g.serialize("d3fend.owl", format="xml")
import os
size = os.path.getsize("d3fend.owl")
print(f"Wrote d3fend.owl: {size/1024/1024:.1f} MB")


# ----------------------------------------------------------------------
# Aggregate stats: how many OffensiveTechniques have ZERO inherited counters?
# ----------------------------------------------------------------------
print("\n=== AGGREGATE: how many OffensiveTechniques have ZERO inherited counter coverage? ===\n")

q = """
PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT DISTINCT ?tech WHERE {
  ?tech rdfs:subClassOf* d3f:OffensiveTechnique .
}
"""
all_offensive = [row[0] for row in g.query(q)]
print(f"Total OffensiveTechnique subclasses: {len(all_offensive)}")

with_counters = 0
without_counters = 0
for tech in all_offensive:
    q_check = """
    PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    ASK {
      ?this rdfs:subClassOf* ?target .
      ?def ?rel ?target .
      FILTER(REGEX(STR(?rel), "counter|detect|may-counter|may-detect", "i"))
    }
    """
    has = g.query(q_check, initBindings={"this": tech}).askAnswer
    if has:
        with_counters += 1
    else:
        without_counters += 1

print(f"With at least one inherited counter: {with_counters} ({100*with_counters/len(all_offensive):.1f}%)")
print(f"With NO counter coverage:           {without_counters} ({100*without_counters/len(all_offensive):.1f}%)")
