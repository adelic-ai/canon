"""Probe: does derive-countering-via-shared-artifacts work for T1558.003?

Pattern: find defensive techniques whose action verb (monitors/analyzes/filters/...)
targets the SAME artifact that T1558.003's action verb (may-produce/uses/...) targets.
"""

from rdflib import Graph, Namespace

D3F = Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#")

g = Graph()
g.parse("d3fend.ttl", format="turtle")


def shorten(uri):
    return str(uri).replace("http://d3fend.mitre.org/ontologies/d3fend.owl#", "d3f:")


print("=== DERIVE COUNTERING FOR T1558.003 VIA SHARED ARTIFACTS ===\n")

q = """
PREFIX d3f:  <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl:  <http://www.w3.org/2002/07/owl#>

SELECT DISTINCT ?defensive ?defLabel ?artifact ?artLabel ?offRel ?defRel WHERE {
  d3f:T1558.003 rdfs:subClassOf* ?offClass .
  ?offClass rdfs:subClassOf ?offR .
  ?offR a owl:Restriction ;
        owl:onProperty ?offRel ;
        owl:someValuesFrom ?artifact .
  FILTER(?offRel IN (d3f:may-produce, d3f:produces, d3f:uses, d3f:modifies,
                     d3f:accesses, d3f:abuses, d3f:invokes, d3f:creates,
                     d3f:executes, d3f:reads, d3f:writes))

  ?defensive rdfs:subClassOf* d3f:DefensiveTechnique .
  ?defensive rdfs:subClassOf ?defR .
  ?defR a owl:Restriction ;
        owl:onProperty ?defRel ;
        owl:someValuesFrom ?artifact .
  FILTER(?defRel IN (d3f:monitors, d3f:analyzes, d3f:filters, d3f:restricts,
                     d3f:hardens, d3f:isolates, d3f:authenticates, d3f:blocks,
                     d3f:detects, d3f:validates, d3f:verifies, d3f:enforces,
                     d3f:quarantines, d3f:identifies))

  OPTIONAL { ?defensive rdfs:label ?defLabel }
  OPTIONAL { ?artifact rdfs:label ?artLabel }
}
ORDER BY ?defLabel
"""
results = list(g.query(q))
print(f"Derived defensive coverage for T1558.003: {len(results)} hits\n")
for d, dl, a, al, ofr, dfr in results:
    print(f"  {dl or '—':40s}  --{shorten(dfr):20s}--> {al or '—':40s}  <--{shorten(ofr):15s}--  T1558.003")


# Also test more broadly — sample other TTPs with the same pattern
print("\n\n=== DERIVED COVERAGE DISTRIBUTION ACROSS COMMON TTPs ===\n")

ttps = ["T1059", "T1003", "T1071", "T1078", "T1547", "T1190", "T1027",
        "T1558", "T1558.003", "T1110", "T1486", "T1055", "T1021"]

print(f"{'TTP':12s}  {'Artifacts touched':>17s}  {'Defensive hits (derived)':>26s}")
print("-" * 65)
for ttp in ttps:
    q_arts = f"""
    PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    PREFIX owl: <http://www.w3.org/2002/07/owl#>
    SELECT (COUNT(DISTINCT ?artifact) AS ?n) WHERE {{
      d3f:{ttp} rdfs:subClassOf* ?c .
      ?c rdfs:subClassOf ?r .
      ?r a owl:Restriction ; owl:onProperty ?p ; owl:someValuesFrom ?artifact .
      FILTER(?p IN (d3f:may-produce, d3f:produces, d3f:uses, d3f:modifies,
                    d3f:accesses, d3f:abuses, d3f:invokes, d3f:creates,
                    d3f:executes, d3f:reads, d3f:writes))
    }}
    """
    q_derived = f"""
    PREFIX d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    PREFIX owl: <http://www.w3.org/2002/07/owl#>
    SELECT (COUNT(DISTINCT ?defensive) AS ?n) WHERE {{
      d3f:{ttp} rdfs:subClassOf* ?offClass .
      ?offClass rdfs:subClassOf ?offR .
      ?offR a owl:Restriction ; owl:onProperty ?offRel ; owl:someValuesFrom ?artifact .
      FILTER(?offRel IN (d3f:may-produce, d3f:produces, d3f:uses, d3f:modifies,
                         d3f:accesses, d3f:abuses, d3f:invokes, d3f:creates,
                         d3f:executes, d3f:reads, d3f:writes))
      ?defensive rdfs:subClassOf* d3f:DefensiveTechnique .
      ?defensive rdfs:subClassOf ?defR .
      ?defR a owl:Restriction ; owl:onProperty ?defRel ; owl:someValuesFrom ?artifact .
      FILTER(?defRel IN (d3f:monitors, d3f:analyzes, d3f:filters, d3f:restricts,
                         d3f:hardens, d3f:isolates, d3f:authenticates, d3f:blocks,
                         d3f:detects, d3f:validates, d3f:verifies, d3f:enforces,
                         d3f:quarantines, d3f:identifies))
    }}
    """
    arts = int(list(g.query(q_arts))[0][0])
    derived = int(list(g.query(q_derived))[0][0])
    print(f"  {ttp:10s}  {arts:>17d}  {derived:>26d}")
