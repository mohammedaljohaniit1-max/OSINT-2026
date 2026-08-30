"""
Adapters for git/secret scanners: trufflehog, gitleaks, git-dumper hint.

Given a domain/org, discovers GitHub org repos (via public API scrape) and runs
trufflehog against them to find verified secrets. Used if installed.
"""
from __future__ import annotations

import json

from ..core.models import EntityType, IntelGraph, RiskLevel
from ..core.module import Module, ModuleSpec
from ..sources._base import ev
from ._base import run_cmd


class TruffleHog(Module):
    spec = ModuleSpec(
        name="trufflehog", category="adapter", external_bin="trufflehog",
        accepts={EntityType.ORG, EntityType.DOMAIN},
        produces={EntityType.SECRET},
        description="trufflehog verified-secret scan of org GitHub", priority=44,
        tags={"adapter", "secret", "github"},
    )

    async def run(self, target, graph: IntelGraph):
        org = target.value.split(".")[0]
        code, out, _ = await run_cmd(
            ["trufflehog", "github", f"--org={org}", "--json", "--only-verified"],
            timeout=400)
        for line in out.splitlines():
            try:
                d = json.loads(line)
            except Exception:
                continue
            det = d.get("DetectorName", "secret")
            src = (d.get("SourceMetadata", {}) or {}).get("Data", {})
            link = json.dumps(src)[:200]
            graph.add(EntityType.SECRET, f"{det} (verified)", risk=RiskLevel.CRITICAL,
                      confidence=0.95, tags={"secret", "verified", "trufflehog"},
                      metadata={"detector": det, "source": link},
                      evidence=ev("trufflehog", snippet=f"verified {det}"))
