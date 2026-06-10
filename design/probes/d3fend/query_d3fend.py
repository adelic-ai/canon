"""Manual OWL querying playground — query the D3FEND ontology by hand.

OWL-in-a-file is just RDF triples. A .ttl is a pile of (subject, predicate, object)
statements; OWL "axioms" (subClassOf, Restriction, someValuesFrom...) are themselves
triples using owl:/rdfs: predicates. So there are two ways to "query OWL":

  (1) QUERY IT      — SPARQL / triple lookups over the ASSERTED triples (what's written).
  (2) QUERY THROUGH — follow subClassOf / restriction paths, or run a REASONER to get
                      ENTAILED triples (what logically follows but isn't written).

This script demonstrates both against canon's real ontology, with verified output.
Run:  .venv/bin/python design/probes/d3fend/query_d3fend.py
"""

import rdflib

TTL = "packages/semantic-cyber/data/d3fend.ttl"
D3F = "http://d3fend.mitre.org/ontologies/d3fend.owl#"
PREFIXES = """
PREFIX d3f:  <http://d3fend.mitre.org/ontologies/d3fend.owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX owl:  <http://www.w3.org/2002/07/owl#>
"""


def short(uri):
    return str(uri).split("#")[-1]


def main():
    g = rdflib.Graph()
    g.parse(TTL, format="turtle")
    print(f"# loaded {len(g):,} triples\n")

    # --- (1) QUERY IT: plain SPARQL SELECT over asserted triples --------------
    # "What are the direct subclasses of DigitalArtifact?" (one hop, no recursion)
    print("[1] direct subclasses of d3f:DigitalArtifact (one hop):")
    q = PREFIXES + "SELECT ?c WHERE { ?c rdfs:subClassOf d3f:DigitalArtifact }"
    for r in g.query(q):
        print("   ", short(r.c))
    # -> only 2 (DigitalInformation, DigitalInformationBearer): the taxonomy is DEEP, not WIDE.

    # --- (2a) QUERY THROUGH: transitive closure with a property path ----------
    # "What is KerberosTicket, all the way up?" The + means "one-or-more subClassOf hops".
    # This is the reasoning the d3fend.py walker does by hand; SPARQL property paths do it
    # for you, and (seed-bound, one end fixed) it's fast even in plain rdflib.
    print("\n[2] superclass chain of d3f:KerberosTicket (subClassOf+ — transitive):")
    q = PREFIXES + "SELECT ?s WHERE { d3f:KerberosTicket rdfs:subClassOf+ ?s }"
    for r in g.query(q):
        if "d3fend" in str(r.s):
            print("   ->", short(r.s))
    # -> AccessToken -> Credential -> DigitalInformationBearer -> DigitalArtifact -> Artifact ...

    # --- (2b) QUERY THROUGH: ASK (boolean) — "does this relation hold?" --------
    # A defense that monitors `Credential` should cover a stolen KerberosTicket BECAUSE
    # KerberosTicket subClassOf+ Credential. That subsumption is the join's whole basis.
    print("\n[3] ASK — is a KerberosTicket a (transitive) Credential?")
    holds = bool(g.query(PREFIXES + "ASK { d3f:KerberosTicket rdfs:subClassOf+ d3f:Credential }"))
    print("   ->", holds)
    # NOTE: d3f:ServiceTicket does NOT exist in the real ontology (it's a test-fixture
    # invention). The real class is KerberosTicket. Querying by hand is how you catch that.
    print("   (sanity) does d3f:ServiceTicket exist at all? ->",
          bool(list(g.triples((rdflib.URIRef(D3F + "ServiceTicket"), None, None)))))

    # --- (2c) QUERY THROUGH the OWL RESTRICTION structure ---------------------
    # The interesting OWL is not subClassOf — it's the RESTRICTIONS. A technique relates
    # to an artifact via an anonymous owl:Restriction node:
    #     <technique> rdfs:subClassOf [ a owl:Restriction ;
    #                                   owl:onProperty d3f:accesses ;
    #                                   owl:someValuesFrom d3f:Process ]
    # To read "what does T1003.001 act on", you walk INTO that blank node.
    print("\n[4] what artifacts does T1003.001 (LSASS Memory) act on? (restriction walk):")
    q = PREFIXES + """
    SELECT ?prop ?art WHERE {
      ?t d3f:attack-id "T1003.001" .
      ?t rdfs:subClassOf ?restr .
      ?restr a owl:Restriction ;
             owl:onProperty ?prop ;
             owl:someValuesFrom ?art .
    }"""
    for r in g.query(q):
        print(f"   --{short(r.prop)}--> {short(r.art)}")
    # -> accesses Process, accesses AuthenticationService.
    # GOTCHA: the PARENT class T1003 carries NO restrictions — they live on the
    # sub-techniques (T1003.001 ...). The d3fend.py walker handles that bidirectionally.

    # --- (2d) the JOIN: technique-touched artifact -> defenses on it -----------
    # "Which defensive techniques act on Process?" — the other half of the counter join.
    print("\n[5] defensive techniques that act on d3f:Process (sample):")
    q = PREFIXES + """
    SELECT DISTINCT ?d ?prop WHERE {
      ?d rdfs:subClassOf ?restr .
      ?restr a owl:Restriction ; owl:onProperty ?prop ; owl:someValuesFrom d3f:Process .
      ?d d3f:d3fend-id ?id .
    } LIMIT 5"""
    for r in g.query(q):
        print(f"   {short(r.d)} --{short(r.prop)}--> Process")

    # --- WHEN TO REACH FOR A REASONER instead of SPARQL -----------------------
    # SPARQL property paths give you subClassOf-transitivity. A full OWL reasoner
    # (owlready2, in semantic_core.reasoning) additionally gives you ENTAILMENTS that
    # aren't reachable by path-walking — e.g. classifying an INDIVIDUAL into a class by
    # its properties (a Process with these restrictions IS-A CredentialDumpingEvent).
    # Canon's rule (the d3fend.py docstring): a single double-`subClassOf*` cross-join
    # over the 3.4MB ontology hung 20+ min in rdflib. So: reason ONCE at the schema
    # (materialize the closure), then per-event work is cheap typed lookup. Seed-BOUND
    # path queries (one end fixed, as in [2]/[4]/[5]) are fine live; all-pairs are not.
    print("\n# done. edit the queries above and re-run to explore.")


if __name__ == "__main__":
    main()
