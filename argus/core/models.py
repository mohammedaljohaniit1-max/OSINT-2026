"""
Core data model for Argus.

Everything the engine discovers is normalized into three primitives:
  - Entity        : a node of intelligence (domain, email, ip, person, secret...)
  - Relationship  : a typed edge between two entities
  - Evidence      : proof that ties an entity/relationship to a source + URL

The whole framework revolves around these. Modules never talk to each other;
they only emit Entities/Relationships/Evidence into a shared IntelGraph.
"""
from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


# --------------------------------------------------------------------------- #
#  Enumerations
# --------------------------------------------------------------------------- #
class EntityType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    URL = "url"
    IP = "ip"
    CIDR = "cidr"
    ASN = "asn"
    EMAIL = "email"
    PHONE = "phone"
    USERNAME = "username"
    PERSON = "person"
    ORG = "org"
    HASH = "hash"
    CRYPTO_WALLET = "crypto_wallet"
    SOCIAL_PROFILE = "social_profile"
    CREDENTIAL = "credential"          # leaked password / hash
    BREACH = "breach"
    SECRET = "secret"                  # API key / token found in code
    CERTIFICATE = "certificate"
    DNS_RECORD = "dns_record"
    TECHNOLOGY = "technology"
    PORT = "port"
    SERVICE = "service"
    VULNERABILITY = "vulnerability"
    FILE = "file"                      # exposed doc / bucket object
    BUCKET = "bucket"                  # S3/GCS/Azure blob
    FAVICON_HASH = "favicon_hash"
    TRACKER_ID = "tracker_id"          # GA / AdSense / GTM id
    ONION = "onion"                    # dark web service
    DORK_HIT = "dork_hit"              # a search-engine dork result
    GEO = "geo"
    PERSONA = "persona"                # a fused person identity (Persona Hunter)
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score(self) -> int:
        return {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 5}[self.value]


class FindingState(str, Enum):
    """Epistemic state of a finding, deliberately separate from risk.

    A URL that returned HTTP 200 may be OBSERVED, while ownership by the target
    remains only a CANDIDATE.  CONFIRMED is reserved for direct or independently
    corroborated evidence.  UNKNOWN/UNAVAILABLE are never reported as hits.
    """

    OBSERVED = "observed"
    CANDIDATE = "candidate"
    INFERRED = "inferred"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    UNKNOWN = "unknown"
    UNAVAILABLE = "unavailable"

    @property
    def rank(self) -> int:
        return {
            "unavailable": 0, "unknown": 1, "rejected": 1,
            "candidate": 2, "inferred": 3, "observed": 4, "confirmed": 5,
        }[self.value]


# --------------------------------------------------------------------------- #
#  Evidence
# --------------------------------------------------------------------------- #
@dataclass
class Evidence:
    source: str                        # module / source name
    url: str = ""                      # where it was seen
    snippet: str = ""                  # raw proof text
    timestamp: float = field(default_factory=time.time)
    raw: dict[str, Any] = field(default_factory=dict)
    source_family: str = ""            # independent provider/tool family
    independence_key: str = ""         # same key means correlated evidence
    method: str = "observation"         # observation/search/inference/derivation
    reliability: float = 0.5            # quality of this evidence, not entity risk

    def __post_init__(self):
        if not self.source_family:
            self.source_family = self.source
        if not self.independence_key:
            self.independence_key = self.source_family
        self.reliability = max(0.0, min(1.0, float(self.reliability)))

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
#  Entity
# --------------------------------------------------------------------------- #
@dataclass
class Entity:
    type: EntityType
    value: str
    confidence: float = 0.5            # 0..1 identity/fact confidence
    risk: RiskLevel = RiskLevel.INFO
    state: FindingState = FindingState.OBSERVED
    sources: set[str] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)
    evidence: list[Evidence] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    id: str = ""

    def __post_init__(self):
        if isinstance(self.type, str):
            self.type = EntityType(self.type)
        if isinstance(self.risk, str):
            self.risk = RiskLevel(self.risk)
        if isinstance(self.state, str):
            try:
                self.state = FindingState(self.state)
            except ValueError:
                self.state = FindingState.UNKNOWN
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        # normalize value
        self.value = str(self.value).strip()
        if self.type in (EntityType.DOMAIN, EntityType.SUBDOMAIN, EntityType.EMAIL):
            self.value = self.value.lower()
        if not self.id:
            self.id = self.make_id(self.type, self.value)

    @staticmethod
    def make_id(etype: EntityType, value: str) -> str:
        key = f"{etype.value if isinstance(etype, EntityType) else etype}:{value.lower().strip()}"
        return hashlib.sha1(key.encode()).hexdigest()[:16]

    def add_evidence(self, ev: Evidence):
        # Deduplicate retries of exactly the same observation.  Repeated output
        # from Sherlock + a wrapper around Sherlock is not independent proof.
        sig = (ev.source, ev.url, ev.snippet, ev.independence_key)
        if not any((x.source, x.url, x.snippet, x.independence_key) == sig
                   for x in self.evidence):
            self.evidence.append(ev)
        self.sources.add(ev.source)
        self.last_seen = time.time()

    def evidence_families(self) -> set[str]:
        return {e.independence_key or e.source_family or e.source
                for e in self.evidence if e.source}

    def merge(self, other: "Entity"):
        """Merge duplicates without pretending correlated sources are independent."""
        before_families = self.evidence_families()
        self.sources |= other.sources
        self.tags |= other.tags
        for evidence in other.evidence:
            self.add_evidence(evidence)
        self.first_seen = min(self.first_seen, other.first_seen)
        self.last_seen = max(self.last_seen, other.last_seen)
        if other.risk.score > self.risk.score:
            self.risk = other.risk
        # Never use the old Bayesian formula: it drove repeated guesses to 1.0.
        # Keep the strongest claim; one modest bump is allowed only when a truly
        # new evidence family was added. Confirmation itself remains explicit.
        merged_families = self.evidence_families()
        independent_added = bool(merged_families - before_families)
        strongest = max(self.confidence, other.confidence)
        if independent_added and len(merged_families) >= 2:
            strongest = min(0.95, strongest + min(0.10, 0.03 * (len(merged_families) - 1)))
        self.confidence = strongest
        if other.state.rank > self.state.rank and other.state != FindingState.REJECTED:
            self.state = other.state
        for k, v in other.metadata.items():
            self.metadata.setdefault(k, v)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["type"] = self.type.value
        d["risk"] = self.risk.value
        d["state"] = self.state.value
        d["sources"] = sorted(self.sources)
        d["evidence_families"] = sorted(self.evidence_families())
        d["tags"] = sorted(self.tags)
        d["evidence"] = [e.to_dict() for e in self.evidence]
        return d


# --------------------------------------------------------------------------- #
#  Relationship
# --------------------------------------------------------------------------- #
@dataclass
class Relationship:
    src_id: str
    dst_id: str
    rel_type: str                      # e.g. "resolves_to", "employee_of", "hosts"
    confidence: float = 0.5
    sources: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = ""

    def __post_init__(self):
        if not self.id:
            key = f"{self.src_id}-{self.rel_type}-{self.dst_id}"
            self.id = hashlib.sha1(key.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["sources"] = sorted(self.sources)
        return d


# --------------------------------------------------------------------------- #
#  IntelGraph - the shared blackboard
# --------------------------------------------------------------------------- #
class IntelGraph:
    """Thread-safe-ish blackboard where all modules deposit findings."""

    def __init__(self):
        self.entities: dict[str, Entity] = {}
        self.relationships: dict[str, Relationship] = {}
        self.run_meta: dict[str, Any] = {"started": time.time()}
        self._new_count = 0          # count of genuinely NEW entities (not merges)

    def add_entity(self, e: Entity) -> Entity:
        if e.id in self.entities:
            self.entities[e.id].merge(e)   # duplicate -> merged, NOT counted as new
            return self.entities[e.id]
        self.entities[e.id] = e
        self._new_count += 1
        return e

    def add(self, etype, value, **kw) -> Entity:
        """Convenience: build + add an entity in one call."""
        ev = kw.pop("evidence", None)
        e = Entity(type=etype, value=value, **kw)
        if ev:
            if isinstance(ev, Evidence):
                e.add_evidence(ev)
            elif isinstance(ev, list):
                for x in ev:
                    e.add_evidence(x)
        return self.add_entity(e)

    def add_relationship(self, r: Relationship) -> Relationship:
        if r.id in self.relationships:
            self.relationships[r.id].sources |= r.sources
            self.relationships[r.id].confidence = max(
                self.relationships[r.id].confidence, r.confidence
            )
            return self.relationships[r.id]
        self.relationships[r.id] = r
        return r

    def link(self, src: Entity, dst: Entity, rel_type: str, **kw) -> Relationship:
        r = Relationship(src_id=src.id, dst_id=dst.id, rel_type=rel_type, **kw)
        return self.add_relationship(r)

    def by_type(self, etype: EntityType) -> list[Entity]:
        return [e for e in self.entities.values() if e.type == etype]

    def find(self, etype: EntityType, value: str) -> Optional[Entity]:
        return self.entities.get(Entity.make_id(etype, value))

    def stats(self) -> dict:
        by_type: dict[str, int] = {}
        for e in self.entities.values():
            by_type[e.type.value] = by_type.get(e.type.value, 0) + 1
        by_risk: dict[str, int] = {}
        by_state: dict[str, int] = {}
        for e in self.entities.values():
            by_risk[e.risk.value] = by_risk.get(e.risk.value, 0) + 1
            by_state[e.state.value] = by_state.get(e.state.value, 0) + 1
        return {
            "total_entities": len(self.entities),
            "total_relationships": len(self.relationships),
            "by_type": by_type,
            "by_risk": by_risk,
            "by_state": by_state,
        }

    def to_dict(self) -> dict:
        return {
            "meta": self.run_meta,
            "stats": self.stats(),
            "entities": [e.to_dict() for e in self.entities.values()],
            "relationships": [r.to_dict() for r in self.relationships.values()],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "IntelGraph":
        """Rebuild a graph from a stored to_dict() payload (mgmt/report reuse)."""
        g = cls()
        g.run_meta = d.get("meta", {})
        for ed in d.get("entities", []):
            evs = [Evidence(**{k: v for k, v in x.items()})
                   for x in ed.get("evidence", [])]
            e = Entity(
                type=ed["type"], value=ed["value"],
                confidence=ed.get("confidence", 0.5),
                risk=ed.get("risk", "info"),
                state=ed.get("state", "observed"),
                sources=set(ed.get("sources", [])),
                tags=set(ed.get("tags", [])),
                metadata=ed.get("metadata", {}),
                first_seen=ed.get("first_seen", time.time()),
                last_seen=ed.get("last_seen", time.time()),
                id=ed.get("id", ""),
            )
            e.evidence = evs
            g.entities[e.id] = e
        for rd in d.get("relationships", []):
            r = Relationship(
                src_id=rd["src_id"], dst_id=rd["dst_id"],
                rel_type=rd["rel_type"], confidence=rd.get("confidence", 0.5),
                sources=set(rd.get("sources", [])),
                metadata=rd.get("metadata", {}), id=rd.get("id", ""),
            )
            g.relationships[r.id] = r
        return g
