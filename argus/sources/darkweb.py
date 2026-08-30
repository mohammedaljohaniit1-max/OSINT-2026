"""
Dark web exposure signals via Ahmia (clearnet, no key) + optional Tor.

Ahmia indexes .onion services and is reachable on the clearnet, so Argus can
search for the target org/domain mention WITHOUT Tor. If Tor is enabled
(stealth profile), it can additionally fetch onion result pages for context.

Ethics: Argus reports EXPOSURE SIGNALS only (that the name appears on a
leak/market index). It never downloads, buys, or displays stolen data.
"""
from __future__ import annotations

import re

from ..core.models import EntityType, IntelGraph, RiskLevel
from ..core.module import Module, ModuleSpec
from ._base import ev


class Ahmia(Module):
    spec = ModuleSpec(
        name="ahmia", category="source",
        accepts={EntityType.DOMAIN, EntityType.ORG, EntityType.EMAIL},
        produces={EntityType.ONION, EntityType.DORK_HIT},
        description="Ahmia dark-web index search (clearnet, no key)", priority=45,
        tags={"passive", "darkweb", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        import urllib.parse
        q = urllib.parse.quote(target.value)
        url = f"https://ahmia.fi/search/?q={q}"
        html = await self.ctx.http.get(url)
        if not html:
            return
        onions = set(re.findall(r"([a-z2-7]{16,56}\.onion)", html))
        for o in onions:
            graph.add(EntityType.ONION, o, risk=RiskLevel.HIGH, confidence=0.6,
                      tags={"darkweb", "exposure-signal"},
                      evidence=ev("ahmia", url,
                                  f"'{target.value}' mentioned near {o}"))
        if onions:
            target.tags.add("darkweb-mention")
