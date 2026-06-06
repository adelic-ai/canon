"""Wrap OS process execution as a content-addressed PROV graph — the substrate's NATIVE input.

A Sysmon ProcessCreate (EventID 1) log is a flattened view of system-execution provenance: each event
records a process, the binary it ran (with hash), the user, the command line, and its parent. That is
*already* a PROV graph — Entity/Activity/Agent — so the substrate ingests it NATIVELY, with no imaging /
gridding (unlike point-process signals, which the battery must impose a grid on).

This demonstrates, on the real OTRF LSASS_campaign_03 dataset (staged locally):
  process execution  -> prov:Activity
  binary (by HASH)   -> prov:Entity, id = its content hash   (one-hash-three-roles, literal)
  user               -> prov:Agent  (wasAssociatedWith)
  parent -> child    -> prov:wasInformedBy
  command line, time -> attributes
The binary hash is simultaneously: node identity (same binary across events = ONE node, free dedup),
provenance entity (what executed), and custody digest (checkable vs known-good / known-bad).

Detection is ONE fold over this graph (a flagged subgraph -> a justified verdict). The graph itself is
wider: forensics, audit, causality, blast-radius all read the same object. This is why the substrate is
"almost canon, but wider and more native" — canon's detection sits on top of this graph.
"""
from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path

import rdflib
from rdflib import Literal, Namespace, URIRef
from rdflib.namespace import PROV, RDF, XSD

DATA = Path.home() / "data/otrf-security-datasets/LSASS_campaign_03/lsass_campaign_03.json"
EX = Namespace("urn:canon:procgraph:")
BIN = Namespace("urn:canon:binary:")  # binaries addressed by content hash
USR = Namespace("urn:canon:user:")


def _hash(hashes_field: str) -> str | None:
    """Pull the content hash from Sysmon's 'SHA1=..,MD5=..' field (prefer SHA256>SHA1>MD5)."""
    d = dict(p.split("=", 1) for p in str(hashes_field).split(",") if "=" in p)
    for algo in ("SHA256", "SHA1", "MD5"):
        if algo in d:
            return f"{algo.lower()}:{d[algo].lower()}"
    return None


def build_graph() -> tuple[rdflib.Graph, dict]:
    events = [json.loads(l) for l in DATA.read_text().splitlines() if l.strip()]
    pc = [e for e in events if str(e.get("EventID")) == "1"]
    g = rdflib.Graph()
    g.bind("prov", PROV)
    g.bind("bin", BIN)

    binaries: dict[str, str] = {}     # hash -> image path (dedup witness)
    users: set[str] = set()
    procs: dict[str, dict] = {}       # ProcessGuid -> event (for parent linking)

    for e in pc:
        guid = e.get("ProcessGuid") or f"{e.get('Image')}|{e.get('ProcessId')}"
        procs[guid] = e

    for guid, e in procs.items():
        act = EX[re.sub(r"[^A-Za-z0-9]", "_", str(guid))]
        g.add((act, RDF.type, PROV.Activity))
        g.add((act, PROV.startedAtTime, Literal(e.get("UtcTime", ""), datatype=XSD.string)))
        g.add((act, EX.commandLine, Literal(str(e.get("CommandLine", ""))[:240])))

        # binary -> content-addressed Entity (hash IS the id; one-hash-three-roles)
        h = _hash(e.get("Hashes", ""))
        if h:
            ent = BIN[re.sub(r"[^A-Za-z0-9:]", "_", h)]
            g.add((ent, RDF.type, PROV.Entity))
            g.add((ent, EX.image, Literal(e.get("Image", ""))))
            g.add((act, PROV.used, ent))          # the process USED (ran) this binary
            binaries[h] = e.get("Image", "")

        # user -> Agent
        u = str(e.get("User", ""))
        if u:
            agent = USR[re.sub(r"[^A-Za-z0-9]", "_", u)]
            g.add((agent, RDF.type, PROV.Agent))
            g.add((agent, EX.name, Literal(u)))
            g.add((act, PROV.wasAssociatedWith, agent))
            users.add(u)

        # parent -> child = wasInformedBy
        pguid = e.get("ParentProcessGuid")
        if pguid and pguid in procs:
            g.add((act, PROV.wasInformedBy, EX[re.sub(r"[^A-Za-z0-9]", "_", str(pguid))]))

    stats = {
        "process_executions": len(procs),
        "distinct_binaries_by_hash": len(binaries),
        "distinct_users": len(users),
        "triples": len(g),
        "users": sorted(users),
    }
    return g, stats


def main() -> None:
    g, stats = build_graph()
    print("=== OS process execution wrapped as a content-addressed PROV graph ===")
    print(f"  process executions (Activities): {stats['process_executions']}")
    print(f"  distinct binaries by HASH (Entities): {stats['distinct_binaries_by_hash']}  "
          f"<- same binary across processes = ONE node (free dedup, the Merkle property)")
    print(f"  distinct users (Agents): {stats['distinct_users']}  {stats['users']}")
    print(f"  total RDF triples: {stats['triples']}")

    # walk the attack: find the payload process, show its agent + binary hash
    events = [json.loads(l) for l in DATA.read_text().splitlines() if l.strip()]
    payload = next((e for e in events if str(e.get("EventID")) == "1"
                    and "winx64_payload" in str(e.get("Image", "")).lower()), None)
    if payload:
        print("\n=== one attack node, fully attributed (who/what/how, content-addressed) ===")
        print(f"  process : {payload.get('Image')}")
        print(f"  user    : {payload.get('User')}        <- prov:Agent")
        print(f"  parent  : {payload.get('ParentImage')}   <- prov:wasInformedBy")
        print(f"  command : {str(payload.get('CommandLine',''))[:70]}")
        print(f"  hash    : {_hash(payload.get('Hashes',''))}   <- node id = provenance entity = custody digest")
        print(f"            (one-hash-three-roles, LITERAL: checkable vs known-bad / known-good)")

    out = DATA.parent / "process_graph.ttl"
    g.serialize(destination=str(out), format="turtle")
    print(f"\nPROV-O Turtle written: {out}  ({out.stat().st_size} bytes)")
    print("This is the SAME PROV-O vocabulary the substrate's provenance fold emits — the OS execution")
    print("graph is expressible in the exact representation canon already uses. Detection = one fold over it.")


if __name__ == "__main__":
    main()
