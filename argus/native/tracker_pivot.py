"""
GENIUS MODULE #4 - Analytics/AdSense ID Pivoting.

Out-of-the-box idea: organizations reuse the SAME Google Analytics (UA-/G-),
GTM, or AdSense (ca-pub-) ID across ALL their web properties - including
personal blogs, forgotten campaign sites, and shadow domains. Public reverse-
analytics services map an ID -> every domain that embeds it, WITHOUT any key.

So a single tracker ID found on the corporate site can unmask the entire
portfolio of related domains (attribution / same-owner clustering).

Sources used (all free / scrape): SpyOnWeb, DNSlytics reverse-analytics,
Nerdydata-style public search. Argus tries each and unions the results.
"""
from __future__ import annotations

import re

from ..core.models import EntityType, IntelGraph, RiskLevel
from ..core.module import Module, ModuleSpec
from ..sources._base import clean_sub, ev


class TrackerPivot(Module):
    spec = ModuleSpec(
        name="tracker_pivot", category="native",
        accepts={EntityType.TRACKER_ID},
        produces={EntityType.DOMAIN},
        description="Reverse GA/AdSense/GTM id -> sibling domains (same owner)",
        priority=55, tags={"native", "genius", "pivot", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        tid = target.value
        found = set()

        # SpyOnWeb reverse lookup (public)
        url = f"https://spyonweb.com/{tid}"
        html = await self.ctx.http.get(url)
        if html:
            for m in re.findall(r'href="https?://spyonweb\.com/([a-z0-9.\-]+\.[a-z]{2,})"',
                                html):
                found.add(clean_sub(m))

        # DNSlytics reverse analytics API (free JSON)
        for kind in ("ga", "adsense"):
            api = f"https://dnslytics.com/api/v1/reverseanalytics?type={kind}&q={tid}"
            data = await self.ctx.http.get(api, expect="json")
            if isinstance(data, dict):
                for d in data.get("domains", []) or []:
                    if isinstance(d, dict):
                        d = d.get("domain", "")
                    if d:
                        found.add(clean_sub(d))

        linked = target.metadata.setdefault("linked_hosts", [])
        for d in found:
            linked.append(d)
            graph.add(EntityType.DOMAIN, d, confidence=0.6,
                      tags={"same-owner", "tracker-linked"},
                      metadata={"linked_via": tid},
                      evidence=ev("tracker_pivot", url,
                                  f"shares tracker {tid} -> same owner"))
        if len(found) > 1:
            target.risk = RiskLevel.MEDIUM
            target.tags.add("owner-cluster")
