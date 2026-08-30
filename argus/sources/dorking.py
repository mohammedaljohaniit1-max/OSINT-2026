"""
Dorking engine via SearXNG - Google/Bing/DuckDuckGo dorks with NO CAPTCHA, NO KEY.

Direct Google scraping is dead (CAPTCHA + TLS fingerprinting). The genius
workaround: run a LOCAL SearXNG meta-search (spun up by install.sh/Docker) that
aggregates 20+ engines and returns clean JSON. Argus fires a curated dork pack
at it. If SearXNG isn't running, it degrades to DuckDuckGo HTML + Bing scrape.

Dork packs are tuned per target type (domain/email/person/username).
"""
from __future__ import annotations

import re
import urllib.parse

from ..core.models import EntityType, IntelGraph, RiskLevel
from ..core.module import Module, ModuleSpec
from ._base import ev, extract_emails

# ---- curated dork packs ---------------------------------------------------- #
DOMAIN_DORKS = [
    'site:{t} ext:sql OR ext:env OR ext:log OR ext:bak OR ext:config',
    'site:{t} inurl:admin OR inurl:login OR inurl:dashboard',
    'site:{t} intitle:"index of"',
    'site:{t} ext:pdf OR ext:xls OR ext:docx confidential OR internal',
    'site:pastebin.com "{t}"',
    'site:github.com "{t}" password OR secret OR api_key',
    'site:trello.com "{t}"',
    'site:s3.amazonaws.com "{t}"',
    'site:drive.google.com "{t}"',
    '"{t}" filetype:env DB_PASSWORD',
    'inurl:"{t}" intext:"@{t}"',
    'site:linkedin.com/in "{t}"',
]
EMAIL_DORKS = [
    '"{t}"',
    '"{t}" site:pastebin.com',
    '"{t}" password',
    '"{t}" site:github.com',
]
PERSON_DORKS = [
    '"{t}" email',
    '"{t}" site:linkedin.com',
    '"{t}" phone OR contact',
    '"{t}" resume OR cv filetype:pdf',
]
USERNAME_DORKS = [
    '"{t}"',
    'intext:"{t}" site:github.com',
    '"{t}" site:reddit.com OR site:twitter.com',
]

PACKS = {
    EntityType.DOMAIN: DOMAIN_DORKS,
    EntityType.EMAIL: EMAIL_DORKS,
    EntityType.PERSON: PERSON_DORKS,
    EntityType.ORG: PERSON_DORKS,
    EntityType.USERNAME: USERNAME_DORKS,
}


class DorkEngine(Module):
    spec = ModuleSpec(
        name="dork_engine", category="source",
        accepts={EntityType.DOMAIN, EntityType.EMAIL, EntityType.PERSON,
                 EntityType.ORG, EntityType.USERNAME},
        produces={EntityType.DORK_HIT, EntityType.URL, EntityType.EMAIL,
                  EntityType.FILE},
        description="Google/Bing dorking via local SearXNG (no key, no CAPTCHA)",
        priority=40, tags={"passive", "dorking", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        pack = PACKS.get(target.type, [])
        for tmpl in pack:
            dork = tmpl.format(t=target.value)
            hits = await self._search(dork)
            for h in hits[:8]:
                risk = RiskLevel.INFO
                low = (h.get("url", "") + h.get("title", "")).lower()
                if any(k in low for k in ("password", ".env", ".sql", "secret",
                                          "confidential", "index of", "backup")):
                    risk = RiskLevel.MEDIUM
                graph.add(EntityType.DORK_HIT, h.get("url", dork)[:200],
                          risk=risk, confidence=0.55, tags={"dork"},
                          metadata={"dork": dork, "title": h.get("title", "")},
                          evidence=ev("dork_engine", h.get("url", ""),
                                      f"dork: {dork}"))
                # mine emails from snippets
                for em in extract_emails(h.get("content", "")):
                    graph.add(EntityType.EMAIL, em, confidence=0.5,
                              evidence=ev("dork_engine", h.get("url", ""), "dork snippet"))

    async def _search(self, query: str) -> list[dict]:
        # 1) local SearXNG (preferred)
        sx = self.ctx.config.searxng_url.rstrip("/")
        url = f"{sx}/search"
        data = await self.ctx.http.get(
            url, params={"q": query, "format": "json"}, expect="json")
        if isinstance(data, dict) and data.get("results"):
            return data["results"]
        # 2) fallback: DuckDuckGo HTML
        return await self._ddg(query)

    async def _ddg(self, query: str) -> list[dict]:
        url = "https://html.duckduckgo.com/html/"
        html = await self.ctx.http.post(url, data={"q": query})
        if not html:
            return []
        out = []
        for m in re.finditer(
            r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', html):
            href = urllib.parse.unquote(m.group(1))
            title = re.sub("<.*?>", "", m.group(2))
            out.append({"url": href, "title": title, "content": ""})
        return out
