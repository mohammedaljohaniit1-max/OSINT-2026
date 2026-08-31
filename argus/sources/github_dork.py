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
        term = target.value.split(".")[0] if target.type == EntityType.DOMAIN else target.value

        # 1) With a token: real code-search for leaked secrets (the strong path).
        if token:
            for q in [f'"{target.value}" password', f'"{target.value}" api_key',
                      f'"{target.value}" secret', f'"{target.value}" DB_PASSWORD']:
                await self._api_code_search(q, token, graph)

        # 2) No token: use the UNAUTHENTICATED REST search API for USERS + REPOS
        #    (these work without auth, unlike code search). Then scan the repos'
        #    default-branch README/config raw files for secrets. This is real,
        #    verifiable data - no HTML scraping guesswork.
        await self._api_users_repos(term, target, graph)

    async def _api_code_search(self, q, token, graph):
        url = "https://api.github.com/search/code"
        data = await self.ctx.http.get(
            url, params={"q": q, "per_page": 20},
            headers={"Authorization": f"token {token}",
                     "Accept": "application/vnd.github.v3+json"}, expect="json")
        if not isinstance(data, dict) or "items" not in data:
            return
        for item in data.get("items", []):
            html_url = item.get("html_url", "")
            if not html_url.startswith("http"):
                continue
            graph.add(EntityType.DORK_HIT, html_url, risk=RiskLevel.MEDIUM,
                      confidence=0.7, tags={"github", "code-match"},
                      metadata={"query": q},
                      evidence=ev("github_dork", html_url, f"code match: {q}"))

    async def _api_users_repos(self, term, target, graph):
        # find org/user matching the term
        u = await self.ctx.http.get(
            "https://api.github.com/search/users",
            params={"q": term, "per_page": 5},
            headers={"Accept": "application/vnd.github.v3+json"}, expect="json")
        if not isinstance(u, dict) or not u.get("items"):
            return
        for user in u["items"][:3]:
            login = user.get("login")
            if not login:
                continue
            # list their public repos
            repos = await self.ctx.http.get(
                f"https://api.github.com/users/{login}/repos",
                params={"per_page": 20, "sort": "updated"},
                headers={"Accept": "application/vnd.github.v3+json"}, expect="json")
            if not isinstance(repos, list):
                continue
            for r in repos[:10]:
                full = r.get("full_name")
                if not full:
                    continue
                graph.add(EntityType.URL, r.get("html_url", ""), confidence=0.4,
                          tags={"github-repo"},
                          metadata={"owner": login, "repo": full},
                          evidence=ev("github_dork", r.get("html_url", ""),
                                      f"public repo of GitHub user {login}"))
                # scan raw README + common config files for secrets
                branch = r.get("default_branch", "main")
                for fn in ("README.md", ".env", "config.js", "config.py",
                           "settings.py", "docker-compose.yml"):
                    raw = f"https://raw.githubusercontent.com/{full}/{branch}/{fn}"
                    body = await self.ctx.http.get(raw)
                    if body and len(body) < 500000:
                        GitHubDork.scan_secrets(body, raw, graph, origin="github_dork")

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
