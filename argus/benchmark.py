"""Deterministic quality gates for Argus truth and identity controls.

This benchmark is intentionally offline.  It measures whether generic pages,
soft 404s, and weak identity coincidences are rejected before live-source
availability is allowed to influence a release claim.  Operators may supply an
expanded JSON corpus with the same schema.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .persona.persona import ProfileHit, _same_person_reason
from .sources.username import SiteCheck, classify_presence


DEFAULT_CASES: list[dict[str, Any]] = [
    {
        "id": "presence-bound-platform-marker",
        "kind": "presence",
        "username": "alice",
        "site": {"name": "Fixture", "url": "https://fixture.test/{u}",
                 "present": ["profile-card"], "absent": ["not found"]},
        "target": {"status": 200, "body": "<title>Alice</title><div class='profile-card'>@alice</div>"},
        "control": {"status": 404, "body": "not found"},
        "expected_positive": True,
        "expected_verdict": "present",
    },
    {
        "id": "generic-http-200",
        "kind": "presence",
        "username": "alice",
        "site": {"name": "Fixture", "url": "https://fixture.test/{u}"},
        "target": {"status": 200, "body": "<title>Welcome</title><p>Sign in</p>"},
        "control": {"status": 200, "body": "<title>Welcome</title><p>Sign in</p>"},
        "expected_positive": False,
        "expected_verdict": "unknown",
    },
    {
        "id": "soft-404-marker",
        "kind": "presence",
        "username": "alice",
        "site": {"name": "Fixture", "url": "https://fixture.test/{u}",
                 "absent": ["user not found"]},
        "target": {"status": 200, "body": "<title>Error</title>User not found"},
        "control": {"status": 200, "body": "<title>Error</title>User not found"},
        "expected_positive": False,
        "expected_verdict": "absent",
    },
    {
        "id": "login-wall",
        "kind": "presence",
        "username": "alice",
        "site": {"name": "Fixture", "url": "https://fixture.test/{u}",
                 "shell": ["sign in to continue"]},
        "target": {"status": 200, "body": "<title>Fixture</title>Sign in to continue"},
        "control": {"status": 200, "body": "<title>Fixture</title>Sign in to continue"},
        "expected_positive": False,
        "expected_verdict": "unknown",
    },
    {
        "id": "identity-cross-link",
        "kind": "fusion",
        "left": {"platform": "GitHub", "url": "https://github.test/alice",
                 "handle": "alice", "links": ["https://social.test/alice_dev"]},
        "right": {"platform": "Social", "url": "https://social.test/alice_dev",
                  "handle": "alice_dev"},
        "expected_positive": True,
    },
    {
        "id": "identity-same-name-city-only",
        "kind": "fusion",
        "left": {"platform": "A", "url": "https://a.test/1", "handle": "alice_one",
                 "display_name": "Alice Smith", "location": "Riyadh"},
        "right": {"platform": "B", "url": "https://b.test/2", "handle": "alice_two",
                  "display_name": "Alice Smith", "location": "Riyadh"},
        "expected_positive": False,
    },
    {
        "id": "identity-same-handle-city",
        "kind": "fusion",
        "left": {"platform": "A", "url": "https://a.test/alice_dev", "handle": "alice_dev",
                 "location": "المدينة المنورة"},
        "right": {"platform": "B", "url": "https://b.test/alice_dev", "handle": "alice_dev",
                  "location": "Medina"},
        "expected_positive": True,
    },
    {
        "id": "identity-same-handle-different-city",
        "kind": "fusion",
        "left": {"platform": "A", "url": "https://a.test/alice_dev", "handle": "alice_dev",
                 "location": "Riyadh"},
        "right": {"platform": "B", "url": "https://b.test/alice_dev", "handle": "alice_dev",
                  "location": "Medina"},
        "expected_positive": False,
    },
]


class _Response:
    def __init__(self, status: int, body: str):
        self.status_code = status
        self.text = body


@dataclass
class BenchmarkResult:
    total: int
    passed: int
    failed: int
    true_positive: int
    true_negative: int
    false_positive: int
    false_negative: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    false_merge_rate: float
    false_split_rate: float
    verdict_accuracy: float
    gate_passed: bool
    failures: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_cases(path: str | None = None) -> list[dict[str, Any]]:
    if not path:
        return list(DEFAULT_CASES)
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    cases = payload.get("cases", payload) if isinstance(payload, dict) else payload
    if not isinstance(cases, list):
        raise ValueError("benchmark dataset must be a list or {'cases': [...]} object")
    return cases


def _presence(case: dict[str, Any]) -> tuple[bool, str]:
    raw = case["site"]
    site = SiteCheck(
        raw["name"], raw["url"], tuple(raw.get("present", ())),
        tuple(raw.get("absent", ())), tuple(raw.get("shell", ())),
        bool(raw.get("username_binding", True)),
    )
    target = _Response(case["target"]["status"], case["target"].get("body", ""))
    control = _Response(case["control"]["status"], case["control"].get("body", ""))
    result = classify_presence(site, case["username"], target, control)
    return result.verdict in {"present", "probable"}, result.verdict


def _fusion(case: dict[str, Any]) -> tuple[bool, str]:
    reason = _same_person_reason(ProfileHit(**case["left"]), ProfileHit(**case["right"]))
    return bool(reason), reason or "not-fused"


def run_benchmark(
    cases: list[dict[str, Any]], *, min_precision: float = 0.98,
    max_false_positive_rate: float = 0.01,
) -> BenchmarkResult:
    tp = tn = fp = fn = passed = verdict_matches = verdict_total = 0
    false_merges = false_splits = fusion_negatives = fusion_positives = 0
    failures: list[dict[str, Any]] = []

    for case in cases:
        kind = case.get("kind")
        if kind == "presence":
            predicted, detail = _presence(case)
            if "expected_verdict" in case:
                verdict_total += 1
                verdict_matches += detail == case["expected_verdict"]
        elif kind == "fusion":
            predicted, detail = _fusion(case)
        else:
            raise ValueError(f"unknown benchmark case kind: {kind!r}")

        expected = bool(case["expected_positive"])
        if predicted and expected:
            tp += 1
        elif predicted and not expected:
            fp += 1
            if kind == "fusion":
                false_merges += 1
        elif not predicted and expected:
            fn += 1
            if kind == "fusion":
                false_splits += 1
        else:
            tn += 1
        if kind == "fusion":
            fusion_positives += expected
            fusion_negatives += not expected

        if predicted == expected and (
            "expected_verdict" not in case or detail == case["expected_verdict"]
        ):
            passed += 1
        else:
            failures.append({
                "id": case.get("id", "unnamed"), "kind": kind,
                "expected_positive": expected, "predicted_positive": predicted,
                "expected_verdict": case.get("expected_verdict"), "actual": detail,
            })

    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    total = len(cases)
    result = BenchmarkResult(
        total=total, passed=passed, failed=total - passed,
        true_positive=tp, true_negative=tn, false_positive=fp, false_negative=fn,
        precision=precision, recall=recall, f1=f1, false_positive_rate=fpr,
        false_merge_rate=false_merges / fusion_negatives if fusion_negatives else 0.0,
        false_split_rate=false_splits / fusion_positives if fusion_positives else 0.0,
        verdict_accuracy=verdict_matches / verdict_total if verdict_total else 1.0,
        gate_passed=(not failures and precision >= min_precision and fpr <= max_false_positive_rate),
        failures=failures,
    )
    return result
