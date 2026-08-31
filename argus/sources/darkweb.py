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

    # Ahmia's own infrastructure / index onions — never report these as hits
    IGNORE_ONIONS = {
        "juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion",  # ahmia
        "msydqstlz2kzerdg.onion",  # ahmia legacy
    }

    async def run(self, target, graph: IntelGraph):
        import urllib.parse
        q = urllib.parse.quote(target.value)
        url = f"https://ahmia.fi/search/?q={q}"
        html = await self.ctx.http.get(url)
        if not html:
            return
        # Ahmia renders a "no results" page — bail out truthfully instead of
        # scraping its own template onions.
        low = html.lower()
        if ("no results" in low or "did not match" in low
                or "0 results" in low):
            return
        # Parse actual result blocks: each result links to a real onion + snippet.
        # Ahmia result items live inside <li class="result"> ... <cite>onion</cite>
        results = re.findall(
            r'<li class="result".*?</li>', html, re.S | re.I)
        hits = 0
        for block in results:
            onion_m = re.search(r"([a-z2-7]{16}|[a-z2-7]{56})\.onion", block)
            if not onion_m:
                continue
            onion = onion_m.group(0)
            if onion in self.IGNORE_ONIONS:
                continue
            # confirm the TARGET string genuinely appears in this result block
            snippet = re.sub(r"<[^>]+>", " ", block)
            if target.value.lower() not in snippet.lower():
                continue
            hits += 1
            graph.add(EntityType.ONION, onion, risk=RiskLevel.HIGH, confidence=0.55,
                      tags={"darkweb", "exposure-signal"},
                      metadata={"context": snippet.strip()[:200]},
                      evidence=ev("ahmia", url,
                                  f"'{target.value}' appears in dark-web result "
                                  f"linking to {onion}"))
        if hits:
            target.tags.add("darkweb-mention")
