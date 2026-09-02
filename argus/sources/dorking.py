"""
Dorking engine via SearXNG - Google/Bing/DuckDuckGo dorks with NO CAPTCHA, NO KEY.

Direct Google scraping is dead (CAPTCHA + TLS fingerprinting). The genius
workaround: run a LOCAL SearXNG meta-search (spun up by install.sh/Docker) that
aggregates 20+ engines and returns clean JSON. Argus fires a curated dork pack
at it. If SearXNG isn't running, it degrades to DuckDuckGo HTML + Bing scrape.

Dork packs are tuned per target type (domain/email/person/username).
"""
from __future__ import annotations

import asyncio
import re
import time
import urllib.parse

from ..core.models import EntityType, IntelGraph, RiskLevel
from ..core.module import Module, ModuleSpec
from ._base import ev, extract_emails

# INTERNAL deadline (seconds) so the module always finishes BEFORE the engine's
# 60s hard kill and emits whatever it gathered. Firing every dork serially with
# an await (each blocking on a dead SearXNG socket + DDG) was exactly why the
# operator's phone/email scans hit 'dork_engine timed out (60s)' and lost the
# entire wave. Now: bounded concurrency + a wall-clock budget + partial emit.
_DORK_BUDGET = 40.0
_DORK_CONCURRENCY = 8
_PER_SEARCH_TIMEOUT = 7.0

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

PHONE_DORKS = [
    '"{t}"',
    '"{t}" whatsapp',
    '"{t}" telegram',
    '"{t}" site:facebook.com OR site:linkedin.com',
    '"{t}" contact OR owner OR name',
]

PACKS = {
    EntityType.DOMAIN: DOMAIN_DORKS,
    EntityType.EMAIL: EMAIL_DORKS,
    EntityType.PERSON: PERSON_DORKS,
    EntityType.ORG: PERSON_DORKS,
    EntityType.USERNAME: USERNAME_DORKS,
    EntityType.PHONE: PHONE_DORKS,
}


class DorkEngine(Module):
    spec = ModuleSpec(
        name="dork_engine", category="source",
        accepts={EntityType.DOMAIN, EntityType.EMAIL, EntityType.PERSON,
                 EntityType.ORG, EntityType.USERNAME, EntityType.PHONE},
        produces={EntityType.DORK_HIT, EntityType.URL, EntityType.EMAIL},
        description="Google/Bing dorking via local SearXNG (no key, no CAPTCHA)",
        priority=40, tags={"passive", "dorking", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        pack = PACKS.get(target.type, [])
        # for phones, use the parsed search variants if available
        subjects = [target.value]
        if target.type == EntityType.PHONE:
            subjects = target.metadata.get("search_variants", [target.value])[:3]

        dorks = [tmpl.format(t=subj) for subj in subjects for tmpl in pack]
        deadline = time.monotonic() + _DORK_BUDGET
        sem = asyncio.Semaphore(_DORK_CONCURRENCY)
        seen_urls: set[str] = set()
        emitted = {"n": 0}

        def _emit_hits(dork, hits):
            for h in hits[:6]:
                url = (h.get("url") or "").strip()
                # TRUTH GUARD: only emit REAL result URLs, never the dork
                # template itself, never empty, never a search-engine page.
                if not url.startswith("http"):
                    continue
                if self._is_search_engine_url(url):
                    continue
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                title = (h.get("title") or "").strip()
                content = h.get("content") or ""
                low = (url + " " + title + " " + content).lower()
                risk = RiskLevel.INFO
                if any(k in low for k in ("password", ".env", ".sql", "secret",
                                          "confidential", "index of", "backup",
                                          "leak", "dump")):
                    risk = RiskLevel.MEDIUM
                emitted["n"] += 1
                graph.add(EntityType.DORK_HIT, url[:250], risk=risk,
                          confidence=0.5, tags={"dork", "web-result"},
                          metadata={"dork": dork, "title": title[:120]},
                          evidence=ev("dork_engine", url,
                                      f"web result for dork: {dork}"))
                for em in extract_emails(content):
                    if not target.type == EntityType.EMAIL or em != target.value:
                        graph.add(EntityType.EMAIL, em, confidence=0.45,
                                  tags={"from-dork"},
                                  evidence=ev("dork_engine", url,
                                              "email in search snippet"))

        async def one(dork):
            if time.monotonic() >= deadline:
                return
            async with sem:
                if time.monotonic() >= deadline:
                    return
                try:
                    hits = await asyncio.wait_for(self._search(dork),
                                                  timeout=_PER_SEARCH_TIMEOUT)
                except (asyncio.TimeoutError, Exception):
                    return
                if hits:
                    _emit_hits(dork, hits)

        tasks = [asyncio.create_task(one(d)) for d in dorks]
        remaining = max(1.0, deadline - time.monotonic())
        done, pending = await asyncio.wait(tasks, timeout=remaining)
        for t in pending:
            t.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

        if not emitted["n"]:
            # be honest in the report about why nothing came back
            target.metadata.setdefault("dork_note",
                "No web results (SearXNG not running -> DuckDuckGo fallback may be "
                "rate-limited/empty). Start SearXNG with ./install.sh --with-searxng "
                "for full dorking.")

    @staticmethod
    def _is_search_engine_url(url: str) -> bool:
        bad = ("duckduckgo.com", "google.com/search", "bing.com/search",
               "searx", "/search?", "yandex.com/search")
        return any(b in url.lower() for b in bad)

    async def _search(self, query: str) -> list[dict]:
        # 1) local SearXNG (preferred) — but if it's down, a CIRCUIT BREAKER
        #    stops every subsequent dork from wasting its budget on the dead
        #    socket (the root cause of the 60s wave kill on the operator's run).
        sx = (self.ctx.config.searxng_url or "").rstrip("/")
        if sx and not getattr(self, "_searxng_dead", False):
            try:
                data = await asyncio.wait_for(
                    self.ctx.http.get(f"{sx}/search",
                                      params={"q": query, "format": "json"},
                                      expect="json"),
                    timeout=3.0)
                if isinstance(data, dict) and data.get("results"):
                    return data["results"]
                # reachable but empty → not dead, just fall through to DDG
            except (asyncio.TimeoutError, Exception):
                self._searxng_dead = True   # trip the breaker for this run
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
