"""
GENIUS MODULE #7 - Company-Wide Password-Reuse & Breach Correlation.

Out-of-the-box idea: individual breach hits are noise. The INTELLIGENCE is the
pattern across the whole company:
  - How many employees appear in breaches?
  - Which breaches recur (indicating a shared 3rd-party the company used)?
  - Do multiple employees share a leaked password (spray/reuse risk)?
  - Which employees have PLAINTEXT (vs hashed) creds exposed = immediate ATO risk?

This module runs AFTER the per-email breach modules, aggregates their findings
into a single "Organizational Exposure Score", and emits a summary VULNERABILITY
entity that drives the executive risk section. Turns scattered facts into a
board-level metric.
"""
from __future__ import annotations

from collections import Counter

from ..core.models import EntityType, IntelGraph, RiskLevel
from ..core.module import Module, ModuleSpec
from ..sources._base import ev


class BreachCorrelation(Module):
    spec = ModuleSpec(
        name="breach_correlation", category="native",
        accepts={EntityType.DOMAIN},
        produces={EntityType.VULNERABILITY},
        description="Aggregate employee breaches -> org exposure score", priority=90,
        tags={"native", "genius", "breach", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        dom = target.value
        emails = [e for e in graph.by_type(EntityType.EMAIL)
                  if e.value.endswith("@" + dom)]
        breached = [e for e in emails if "breached" in e.tags]
        creds = [e for e in graph.by_type(EntityType.CREDENTIAL)]

        if not emails:
            return

        # recurring breaches (points to a shared vendor)
        all_breaches = []
        for e in breached:
            all_breaches.extend(e.metadata.get("breaches", []))
        recurring = [(b, c) for b, c in Counter(all_breaches).items() if c >= 2]

        pct = round(100 * len(breached) / max(1, len(emails)))
        score = min(100, pct + 10 * len(recurring) + 15 * bool(creds))

        if score >= 70:
            risk = RiskLevel.CRITICAL
        elif score >= 40:
            risk = RiskLevel.HIGH
        elif score > 0:
            risk = RiskLevel.MEDIUM
        else:
            risk = RiskLevel.INFO

        summary = (f"Org exposure {score}/100: {len(breached)}/{len(emails)} "
                   f"employee emails breached ({pct}%), "
                   f"{len(creds)} credential(s) in leak compilations, "
                   f"{len(recurring)} recurring breach source(s).")
        v = graph.add(EntityType.VULNERABILITY,
                      f"Organizational credential exposure - {dom}",
                      risk=risk, confidence=0.85,
                      tags={"org-exposure", "executive"},
                      metadata={"score": score, "breached_pct": pct,
                                "recurring_breaches": recurring,
                                "employees_checked": len(emails)},
                      evidence=ev("breach_correlation", "", summary))
        for b, c in recurring:
            v.metadata.setdefault("shared_vendor_hint", []).append(
                f"{b} appears for {c} employees -> likely shared 3rd-party vendor")
