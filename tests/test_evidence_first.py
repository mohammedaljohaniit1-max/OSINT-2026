"""Deterministic acceptance tests for evidence-first truth guarantees."""
import asyncio

from argus.core.models import Evidence, Entity, EntityType, FindingState, IntelGraph
from argus.sources.username import SiteCheck, classify_presence


class Response:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.headers = {}


def test_correlated_duplicates_do_not_reach_certainty():
    graph = IntelGraph()
    first = Entity(EntityType.SOCIAL_PROFILE, "https://example.test/alice",
                   confidence=0.65, state=FindingState.CANDIDATE)
    first.add_evidence(Evidence("sherlock", source_family="example.test",
                                independence_key="profile:example.test"))
    second = Entity(EntityType.SOCIAL_PROFILE, "https://example.test/alice",
                    confidence=0.65, state=FindingState.CANDIDATE)
    second.add_evidence(Evidence("maigret", source_family="example.test",
                                 independence_key="profile:example.test"))
    merged = graph.add_entity(first)
    graph.add_entity(second)
    assert merged.confidence == 0.65
    assert merged.state == FindingState.CANDIDATE
    assert len(merged.evidence_families()) == 1


def test_independent_family_bump_is_bounded():
    entity = Entity(EntityType.DOMAIN, "example.test", confidence=0.7)
    entity.add_evidence(Evidence("crt", independence_key="certificate-transparency"))
    other = Entity(EntityType.DOMAIN, "example.test", confidence=0.7)
    other.add_evidence(Evidence("rdap", independence_key="registry"))
    entity.merge(other)
    assert 0.7 < entity.confidence < 0.9


def test_generic_http_200_fails_negative_control():
    site = SiteCheck("Generic", "https://example.test/{u}")
    target = Response(200, "<html><title>Welcome</title><p>login</p></html>")
    control = Response(200, "<html><title>Welcome</title><p>login</p></html>")
    result = classify_presence(site, "alice", target, control)
    assert result.verdict == "unknown"
    assert "negative control" in result.reason


def test_rich_profile_can_only_be_probable_without_binding():
    site = SiteCheck("Example", "https://example.test/{u}")
    target = Response(200, '<meta property="og:title" content="Alice">'
                           '<meta property="og:description" content="Researcher">')
    control = Response(404, "not found")
    result = classify_presence(site, "alice", target, control)
    assert result.verdict == "probable"


def test_graph_serialization_preserves_truth_state_and_provenance():
    graph = IntelGraph()
    graph.add(EntityType.USERNAME, "alice", state=FindingState.CANDIDATE,
              evidence=Evidence("derived", source_family="email-derivation",
                                independence_key="same-email"))
    restored = IntelGraph.from_dict(graph.to_dict())
    entity = restored.by_type(EntityType.USERNAME)[0]
    assert entity.state == FindingState.CANDIDATE
    assert entity.evidence[0].source_family == "email-derivation"
