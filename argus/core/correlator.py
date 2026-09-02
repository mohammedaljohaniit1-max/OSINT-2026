"""
Correlation & Risk Scoring engine.

After all modules run, this pass:
  1. Boosts confidence for entities corroborated by multiple sources.
  2. Applies risk heuristics (exposed secret = CRITICAL, breach = HIGH, ...).
  3. Infers implicit relationships (email <-> its domain, subdomain <-> ip).
  4. Flags high-value clusters (e.g. same favicon-hash across hosts,
     same tracker id across domains = same owner).

This is where raw findings become *intelligence*.
"""
from __future__ import annotations

from .models import EntityType, FindingState, IntelGraph, RiskLevel


RISK_RULES = {
    EntityType.SECRET: RiskLevel.CRITICAL,
    EntityType.CREDENTIAL: RiskLevel.CRITICAL,
    EntityType.VULNERABILITY: RiskLevel.HIGH,
    EntityType.BREACH: RiskLevel.HIGH,
    EntityType.BUCKET: RiskLevel.HIGH,
    EntityType.ONION: RiskLevel.HIGH,
    EntityType.DORK_HIT: RiskLevel.MEDIUM,
    EntityType.PORT: RiskLevel.MEDIUM,
    EntityType.SUBDOMAIN: RiskLevel.LOW,
    EntityType.EMAIL: RiskLevel.LOW,
}


def correlate(graph: IntelGraph):
    _apply_risk(graph)
    _infer_relationships(graph)
    _cluster_owners(graph)
    _multi_source_boost(graph)


def _apply_risk(graph: IntelGraph):
    for e in graph.entities.values():
        base = RISK_RULES.get(e.type)
        if base and e.risk.score < base.score:
            e.risk = base
        # metadata-driven bumps
        if e.metadata.get("password") or e.metadata.get("plaintext"):
            e.risk = RiskLevel.CRITICAL
        if "admin" in e.value.lower() or "vpn" in e.value.lower():
            if e.type == EntityType.SUBDOMAIN and e.risk.score < RiskLevel.MEDIUM.score:
                e.risk = RiskLevel.MEDIUM
                e.tags.add("sensitive-name")


def _infer_relationships(graph: IntelGraph):
    domains = {e.value: e for e in graph.by_type(EntityType.DOMAIN)}
    # email -> domain
    for em in graph.by_type(EntityType.EMAIL):
        dom = em.value.split("@")[-1]
        if dom in domains:
            graph.link(em, domains[dom], "belongs_to_domain", confidence=0.9,
                       sources={"correlator"})
    # subdomain -> parent domain
    for sd in graph.by_type(EntityType.SUBDOMAIN):
        for dname, dent in domains.items():
            if sd.value.endswith("." + dname):
                graph.link(sd, dent, "subdomain_of", confidence=0.95,
                           sources={"correlator"})
                break


def _cluster_owners(graph: IntelGraph):
    """Same tracker id / favicon hash across hosts => same operator."""
    for etype, rel in [
        (EntityType.TRACKER_ID, "shared_tracker"),
        (EntityType.FAVICON_HASH, "shared_favicon"),
    ]:
        for e in graph.by_type(etype):
            linked = e.metadata.get("linked_hosts", [])
            if len(linked) > 1:
                e.tags.add("owner-cluster")
                e.risk = RiskLevel.MEDIUM if e.risk.score < 50 else e.risk


def _multi_source_boost(graph: IntelGraph):
    """Calibrate by independent evidence families, never adapter name count.

    This deliberately does not promote CANDIDATE to CONFIRMED.  Identity
    confirmation requires a module to emit that state based on direct evidence.
    """
    for e in graph.entities.values():
        families = e.evidence_families()
        n = len(families)
        if n < 2:
            continue
        # A bounded calibration bump acknowledges corroboration while preventing
        # Sherlock/Maigret/native wrappers of the same page from reaching 100%.
        e.confidence = min(0.95, e.confidence + min(0.09, 0.03 * (n - 1)))
        e.tags.add(f"independent-evidence-x{n}")
        e.metadata["evidence_families"] = sorted(families)
        if e.state == FindingState.UNKNOWN:
            e.state = FindingState.CANDIDATE
