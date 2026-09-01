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
    # High-signal only: a key-like assignment to a LONG high-entropy value.
    # (The old loose pattern flagged any token:"short" in JS as critical.)
    "Generic Secret": re.compile(
        r"(?i)(api[_\-]?key|secret[_\-]?key|access[_\-]?token|client[_\-]?secret|"
        r"aws[_\-]?secret|private[_\-]?key)['\"\s:=]{1,6}['\"][0-9a-zA-Z_\-/+]{24,}['\"]"),
}

# obvious placeholders / examples that are NOT real leaks
_SECRET_FALSE_POSITIVES = re.compile(
    r"(?i)(your[_\-]?|example|placeholder|xxxx|<[^>]+>|changeme|dummy|test|sample|"
    r"0000000000|1234567890|abcdef|redacted|\*{4,})")


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
        # Only run org-level ownership discovery for a company DOMAIN/ORG. A raw
        # single-letter/short term (e.g. "x") matches an unrelated GitHub user
        # and produced false-positive "secrets". Require a plausible org handle.
        if len(term) < 3:
            target.metadata["github_note"] = (
                f"term '{term}' too generic for reliable GitHub org matching")
            return
        full_domain = target.value if target.type == EntityType.DOMAIN else None

        # find org/user matching the term
        u = await self.ctx.http.get(
            "https://api.github.com/search/users",
            params={"q": f"{term} in:login", "per_page": 5},
            headers={"Accept": "application/vnd.github.v3+json"}, expect="json")
        if not isinstance(u, dict) or not u.get("items"):
            return
        for user in u["items"][:3]:
            login = user.get("login")
            if not login:
                continue
            # OWNERSHIP GUARD: the GitHub account must credibly belong to the
            # target — its login/blog/email should reference the domain. Without
            # this, we were scanning strangers' repos and mislabeling their
            # config tokens as the target's leaked secrets.
            owns = True
            if full_domain:
                prof = await self.ctx.http.get(
                    f"https://api.github.com/users/{login}",
                    headers={"Accept": "application/vnd.github.v3+json"},
                    expect="json")
                root = full_domain.split(".")[0]
                hay = ""
                if isinstance(prof, dict):
                    hay = " ".join(str(prof.get(k, "")) for k in
                                   ("blog", "email", "name", "company", "login",
                                    "twitter_username")).lower()
                owns = (full_domain in hay) or (login.lower() == root)
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
                # record the repo (low confidence if ownership unproven)
                graph.add(EntityType.URL, r.get("html_url", ""),
                          confidence=0.5 if owns else 0.25,
                          tags={"github-repo"} | (set() if owns else {"unverified-owner"}),
                          metadata={"owner": login, "repo": full,
                                    "owner_verified": owns},
                          evidence=ev("github_dork", r.get("html_url", ""),
                                      f"public repo of GitHub user {login}"
                                      + ("" if owns else " (ownership UNVERIFIED)")))
                # ONLY scan for secrets when ownership is credibly established —
                # otherwise we'd flag strangers' tokens as the target's leaks.
                if not owns:
                    continue
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
                # skip obvious placeholders/examples (not real leaks)
                if _SECRET_FALSE_POSITIVES.search(sample):
                    continue
                masked = sample[:6] + "…" + sample[-4:] if len(sample) > 12 else sample
                graph.add(EntityType.SECRET, f"{label}: {masked}",
                          risk=RiskLevel.CRITICAL, confidence=0.85,
                          tags={"secret", label.lower().replace(" ", "-")},
                          metadata={"kind": label, "url": source_url},
                          evidence=ev(origin, source_url, f"{label} leaked"))
