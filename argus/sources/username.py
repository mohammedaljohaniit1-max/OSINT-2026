"""Evidence-first username enumeration using public profile pages.

A successful HTTP request is not a finding.  Every platform check uses explicit
absence/presence signals and a random negative-control account.  Generic login
walls, soft-404s and pages that look the same for every username are classified
as UNKNOWN and are never emitted as profiles.
"""
from __future__ import annotations

import asyncio
import hashlib
import re
import secrets
from dataclasses import dataclass, field
from urllib.parse import urlparse

from ..core.models import EntityType, FindingState, IntelGraph, RiskLevel
from ..core.module import Module, ModuleSpec
from ._base import ev


@dataclass(frozen=True)
class SiteCheck:
    name: str
    url: str
    present: tuple[str, ...] = ()
    absent: tuple[str, ...] = ()
    shell: tuple[str, ...] = ()
    username_binding: bool = True


@dataclass
class PresenceResult:
    verdict: str  # present | probable | absent | unknown | blocked
    reason: str
    url: str
    status: int = 0
    body: str = ""
    signals: list[str] = field(default_factory=list)
    control_status: int = 0


# Fewer, curated definitions beat dozens of HTTP-200 guesses. Definitions are
# intentionally inspectable and can be updated without changing engine logic.
SITES: tuple[SiteCheck, ...] = (
    SiteCheck("GitHub", "https://github.com/{u}",
              present=('itemprop="additionalName"', 'data-hovercard-type="user"'),
              absent=("page not found", "not found · github"),
              shell=("sign in to github",)),
    SiteCheck("GitLab", "https://gitlab.com/{u}",
              present=("user-profile", "profile-header"),
              absent=("the page could not be found", "404 page")),
    SiteCheck("Reddit", "https://www.reddit.com/user/{u}/about.json",
              present=('"kind": "t2"', '"name":'),
              absent=("account suspended", "page not found")),
    SiteCheck("Telegram", "https://t.me/{u}",
              present=("tgme_page_title", "tgme_page_extra"),
              absent=("if you have telegram, you can contact" ,)),
    SiteCheck("Keybase", "https://keybase.io/{u}",
              present=("proofs", "keybase profile"),
              absent=("user not found", "there was a problem")),
    SiteCheck("DevTo", "https://dev.to/{u}",
              present=("profile-header", "follow user"),
              absent=("404 not found", "page not found")),
    SiteCheck("Medium", "https://medium.com/@{u}",
              present=("followers", "following"),
              absent=("page not found", "out of nothing, something")),
    SiteCheck("About.me", "https://about.me/{u}",
              present=("about.me", "biography"),
              absent=("page not found", "doesn't exist")),
    SiteCheck("Gravatar", "https://en.gravatar.com/{u}.json",
              present=('"entry"', '"preferredusername"'),
              absent=("user not found", "no user found")),
    SiteCheck("PyPI", "https://pypi.org/user/{u}/",
              present=("author profile", "projects by"),
              absent=("404 not found", "page not found")),
    SiteCheck("NPM", "https://www.npmjs.com/~{u}",
              present=("packages", "npm profile"),
              absent=("not found", "404")),
    SiteCheck("DockerHub", "https://hub.docker.com/v2/users/{u}",
              present=('"username"', '"date_joined"'),
              absent=("not found", '"detail"')),
    SiteCheck("HackerNews", "https://news.ycombinator.com/user?id={u}",
              present=("user:", "created:"), absent=("no such user",)),
    SiteCheck("CodePen", "https://codepen.io/{u}",
              present=("profile-name", "followers"),
              absent=("couldn't find that user", "404")),
    SiteCheck("Replit", "https://replit.com/@{u}",
              present=("followers", "repls"),
              absent=("user not found", "404")),
    SiteCheck("Chess.com", "https://www.chess.com/member/{u}",
              present=("profile-header", "member since"),
              absent=("page not found", "404")),
)


def _text(response) -> str:
    return (getattr(response, "text", "") or "")[:2_000_000]


def _status(response) -> int:
    return int(getattr(response, "status_code", 0) or 0)


def _fingerprint(response) -> str:
    """Coarse page fingerprint that is stable across nonce/CSRF differences."""
    body = _text(response).lower()
    body = re.sub(r"[a-f0-9]{16,}", "#", body)
    body = re.sub(r"\d{5,}", "#", body)
    title = ""
    match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if match:
        title = re.sub(r"\s+", " ", match.group(1)).strip()
    structural = "|".join((str(_status(response)), title[:160], str(len(body) // 500)))
    return hashlib.sha256(structural.encode()).hexdigest()[:16]


def classify_presence(site: SiteCheck, username: str, response, control) -> PresenceResult:
    url = site.url.format(u=username)
    status = _status(response)
    control_status = _status(control)
    if response is None:
        return PresenceResult("unknown", "source request failed", url)
    if status in (401, 403, 429):
        return PresenceResult("blocked", f"source returned HTTP {status}", url,
                              status=status, control_status=control_status)
    if status in (404, 410):
        return PresenceResult("absent", f"explicit HTTP {status}", url,
                              status=status, control_status=control_status)

    body = _text(response)
    folded = body.lower()
    signals: list[str] = []
    absent = [m for m in site.absent if m and m.lower() in folded]
    if absent:
        return PresenceResult("absent", f"absence marker: {absent[0]}", url,
                              status=status, body=body, control_status=control_status)
    shell = [m for m in site.shell if m and m.lower() in folded]
    present = [m for m in site.present if m and m.lower() in folded]
    if present:
        signals.append(f"platform marker: {present[0]}")

    # Bind the returned content to the requested identity where possible.
    normalized_user = username.lower().lstrip("@").replace("_", "")
    normalized_body = re.sub(r"[^a-z0-9]", "", folded)
    bound = bool(normalized_user and normalized_user in normalized_body)
    if bound:
        signals.append("requested username appears in profile payload")

    control_generic = False
    if control is not None and status == control_status and status == 200:
        control_generic = _fingerprint(response) == _fingerprint(control)
        if control_generic:
            signals.append("negative control returned equivalent generic page")

    if shell and not (present and bound):
        return PresenceResult("unknown", f"generic/login shell: {shell[0]}", url,
                              status=status, body=body, signals=signals,
                              control_status=control_status)
    if control_generic and not (present and bound):
        return PresenceResult("unknown", "failed random negative control", url,
                              status=status, body=body, signals=signals,
                              control_status=control_status)
    if status != 200:
        return PresenceResult("unknown", f"non-conclusive HTTP {status}", url,
                              status=status, body=body, signals=signals,
                              control_status=control_status)
    if present and (bound or not site.username_binding):
        return PresenceResult("present", "platform-specific marker and identity binding", url,
                              status=status, body=body, signals=signals,
                              control_status=control_status)
    if present and not control_generic:
        return PresenceResult("probable", "platform marker without payload identity binding", url,
                              status=status, body=body, signals=signals,
                              control_status=control_status)
    rich_profile = (
        ('property="og:title"' in folded and 'property="og:description"' in folded)
        or ('"@type":"person"' in re.sub(r"\s+", "", folded))
    )
    if rich_profile and control_status in (404, 410):
        signals.append("rich profile metadata differs from absent negative control")
        return PresenceResult("probable", "profile metadata passed negative control", url,
                              status=status, body=body, signals=signals,
                              control_status=control_status)
    return PresenceResult("unknown", "HTTP 200 without sufficient profile evidence", url,
                          status=status, body=body, signals=signals,
                          control_status=control_status)


async def check_site(http, site: SiteCheck, username: str, control_username: str) -> PresenceResult:
    target_url = site.url.format(u=username)
    control_url = site.url.format(u=control_username)
    target_response, control_response = await asyncio.gather(
        http.get(target_url, expect="response"),
        http.get(control_url, expect="response"),
        return_exceptions=True,
    )
    if isinstance(target_response, Exception):
        target_response = None
    if isinstance(control_response, Exception):
        control_response = None
    return classify_presence(site, username, target_response, control_response)


class UsernameHunt(Module):
    spec = ModuleSpec(
        name="username_hunt", category="source",
        accepts={EntityType.USERNAME}, produces={EntityType.SOCIAL_PROFILE},
        description="Negative-control username checks on curated public platforms",
        priority=20, tags={"passive", "social", "nokey", "evidence-first"},
        source_family="direct-platform-profile", timeout=150, reliability=0.75,
    )

    async def run(self, target, graph: IntelGraph):
        username = target.value.strip().lstrip("@")
        control = f"argus_control_{secrets.token_hex(8)}"
        sem = asyncio.Semaphore(min(8, self.ctx.config.concurrency))
        audit: list[dict] = []

        async def one(site: SiteCheck):
            async with sem:
                result = await check_site(self.ctx.http, site, username, control)
            audit.append({
                "platform": site.name, "url": result.url,
                "verdict": result.verdict, "reason": result.reason,
                "status": result.status, "control_status": result.control_status,
                "signals": result.signals,
            })
            if result.verdict not in {"present", "probable"}:
                return
            confidence = 0.78 if result.verdict == "present" else 0.58
            graph.add(
                EntityType.SOCIAL_PROFILE, result.url,
                confidence=confidence, risk=RiskLevel.INFO,
                state=FindingState.CANDIDATE,
                tags={"social", site.name.lower(), "username-exists", "no-expand"},
                metadata={
                    "platform": site.name, "username": username,
                    "existence_verdict": result.verdict,
                    "ownership_verdict": "unverified",
                    "negative_control": "passed",
                    "signals": result.signals,
                },
                evidence=ev(
                    "username_hunt", result.url,
                    f"{site.name}: {result.reason}; ownership not established",
                    source_family=f"platform:{urlparse(result.url).netloc}",
                    independence_key=f"profile:{urlparse(result.url).netloc}",
                    method="direct-profile-observation", reliability=confidence,
                    status=result.status, control_status=result.control_status,
                ),
            )

        await asyncio.gather(*(one(site) for site in SITES))
        graph.run_meta.setdefault("username_checks", []).append({
            "username": username,
            "negative_control": control,
            "platforms_checked": len(SITES),
            "present": sum(x["verdict"] == "present" for x in audit),
            "probable": sum(x["verdict"] == "probable" for x in audit),
            "absent": sum(x["verdict"] == "absent" for x in audit),
            "unknown": sum(x["verdict"] in {"unknown", "blocked"} for x in audit),
            "checks": audit,
        })
