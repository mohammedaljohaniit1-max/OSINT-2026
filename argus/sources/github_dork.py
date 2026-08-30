"""
GitHub dorking (no token needed for basic search scraping) + secret regexes.

Searches GitHub code/commits/issues for the target org/domain and flags leaked
secrets via a battery of high-signal regexes (the same class trufflehog uses).
With an optional GITHUB_TOKEN it uses the API (higher rate); WITHOUT it, it
scrapes the public code-search HTML.
"""
from __future__ import annotations

import re

from ..core.models import EntityType, IntelGraph, RiskLevel
from ..core.module import Module, ModuleSpec
from ._base import ev

SECRET_REGEXES = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret": re.compile(r"(?i)aws_secret_access_key.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    "Google API": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,48}"),
    "GitHub PAT": re.compile(r"ghp_[0-9A-Za-z]{36}"),
    "Stripe Live": re.compile(r"sk_live_[0-9a-zA-Z]{24}"),
    "Private Key": re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "Generic Secret": re.compile(
        r"(?i)(api[_\-]?key|secret|token|passwd|password)['\"\s:=]{1,6}['\"][0-9a-zA-Z_\-!@#$%^&*]{12,}['\"]"),
}


class GitHubDork(Module):
    spec = ModuleSpec(
        name="github_dork", category="source",
        accepts={EntityType.DOMAIN, EntityType.ORG, EntityType.EMAIL},
        produces={EntityType.SECRET, EntityType.DORK_HIT, EntityType.URL},
        description="GitHub code-search dorking + secret detection", priority=42,
        tags={"passive", "dorking", "github", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        token = self.ctx.config.keys.get("github")
        term = target.value
        queries = [
            f'"{term}" password', f'"{term}" api_key', f'"{term}" secret',
            f'"{term}" BEGIN PRIVATE KEY', f'"{term}" DB_PASSWORD',
        ]
        for q in queries:
            if token:
                await self._api_search(q, token, graph)
            else:
                await self._scrape_search(q, graph)

    async def _api_search(self, q, token, graph):
        url = "https://api.github.com/search/code"
        data = await self.ctx.http.get(
            url, params={"q": q, "per_page": 20},
            headers={"Authorization": f"token {token}",
                     "Accept": "application/vnd.github.v3+json"}, expect="json")
        if not isinstance(data, dict):
            return
        for item in data.get("items", []):
            html_url = item.get("html_url", "")
            graph.add(EntityType.DORK_HIT, html_url, risk=RiskLevel.MEDIUM,
                      confidence=0.6, tags={"github"},
                      evidence=ev("github_dork", html_url, f"code match: {q}"))

    async def _scrape_search(self, q, graph):
        import urllib.parse
        url = f"https://github.com/search?q={urllib.parse.quote(q)}&type=code"
        html = await self.ctx.http.get(url)
        if not html:
            return
        for m in re.finditer(r'href="(/[^"]+/blob/[^"]+)"', html):
            link = "https://github.com" + m.group(1)
            graph.add(EntityType.DORK_HIT, link, risk=RiskLevel.MEDIUM,
                      confidence=0.5, tags={"github"},
                      evidence=ev("github_dork", link, f"scrape: {q}"))

    @staticmethod
    def scan_secrets(text: str, source_url: str, graph: IntelGraph, origin="github"):
        """Reusable secret scanner (also used by JS-endpoint native module)."""
        for label, rx in SECRET_REGEXES.items():
            for m in rx.finditer(text or ""):
                sample = m.group(0)
                masked = sample[:6] + "…" + sample[-4:] if len(sample) > 12 else sample
                graph.add(EntityType.SECRET, f"{label}: {masked}",
                          risk=RiskLevel.CRITICAL, confidence=0.85,
                          tags={"secret", label.lower().replace(" ", "-")},
                          metadata={"kind": label, "url": source_url},
                          evidence=ev(origin, source_url, f"{label} leaked"))
