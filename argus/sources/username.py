"""
Username enumeration across 50+ platforms - NO KEY, pure HTTP presence check.

Given a username, checks a large curated list of sites for an existing profile
(the same technique as Sherlock/Maigret, implemented natively so it works even
if those binaries aren't installed). Emits SOCIAL_PROFILE entities.
"""
from __future__ import annotations

import asyncio

from ..core.models import EntityType, IntelGraph
from ..core.module import Module, ModuleSpec
from ._base import ev

# (site, url_template, present_if) - present_if: "status" or a substring absent-marker
SITES = {
    "GitHub": ("https://github.com/{u}", "status"),
    "GitLab": ("https://gitlab.com/{u}", "status"),
    "Twitter/X": ("https://x.com/{u}", "status"),
    "Instagram": ("https://www.instagram.com/{u}/", "status"),
    "Reddit": ("https://www.reddit.com/user/{u}", "status"),
    "TikTok": ("https://www.tiktok.com/@{u}", "status"),
    "YouTube": ("https://www.youtube.com/@{u}", "status"),
    "Facebook": ("https://www.facebook.com/{u}", "status"),
    "Pinterest": ("https://www.pinterest.com/{u}/", "status"),
    "Telegram": ("https://t.me/{u}", "status"),
    "Medium": ("https://medium.com/@{u}", "status"),
    "DevTo": ("https://dev.to/{u}", "status"),
    "HackerNews": ("https://news.ycombinator.com/user?id={u}", "No such user"),
    "Keybase": ("https://keybase.io/{u}", "status"),
    "Steam": ("https://steamcommunity.com/id/{u}", "status"),
    "Twitch": ("https://www.twitch.tv/{u}", "status"),
    "Vimeo": ("https://vimeo.com/{u}", "status"),
    "SoundCloud": ("https://soundcloud.com/{u}", "status"),
    "Spotify": ("https://open.spotify.com/user/{u}", "status"),
    "Patreon": ("https://www.patreon.com/{u}", "status"),
    "Behance": ("https://www.behance.net/{u}", "status"),
    "Dribbble": ("https://dribbble.com/{u}", "status"),
    "Flickr": ("https://www.flickr.com/people/{u}", "status"),
    "About.me": ("https://about.me/{u}", "status"),
    "Gravatar": ("https://en.gravatar.com/{u}", "status"),
    "Replit": ("https://replit.com/@{u}", "status"),
    "CodePen": ("https://codepen.io/{u}", "status"),
    "Bitbucket": ("https://bitbucket.org/{u}/", "status"),
    "PyPI": ("https://pypi.org/user/{u}/", "status"),
    "NPM": ("https://www.npmjs.com/~{u}", "status"),
    "DockerHub": ("https://hub.docker.com/u/{u}", "status"),
    "Kaggle": ("https://www.kaggle.com/{u}", "status"),
    "Wordpress": ("https://{u}.wordpress.com", "status"),
    "Blogger": ("https://{u}.blogspot.com", "status"),
    "Tumblr": ("https://{u}.tumblr.com", "status"),
    "Mastodon": ("https://mastodon.social/@{u}", "status"),
    "ProductHunt": ("https://www.producthunt.com/@{u}", "status"),
    "Chess.com": ("https://www.chess.com/member/{u}", "status"),
    "Last.fm": ("https://www.last.fm/user/{u}", "status"),
    "Goodreads": ("https://www.goodreads.com/{u}", "status"),
    "Quora": ("https://www.quora.com/profile/{u}", "status"),
    "Wattpad": ("https://www.wattpad.com/user/{u}", "status"),
    "Trello": ("https://trello.com/{u}", "status"),
    "AngelList": ("https://angel.co/u/{u}", "status"),
    "Fiverr": ("https://www.fiverr.com/{u}", "status"),
}


class UsernameHunt(Module):
    spec = ModuleSpec(
        name="username_hunt", category="source",
        accepts={EntityType.USERNAME},
        produces={EntityType.SOCIAL_PROFILE},
        description="Native username presence check across 45+ platforms",
        priority=20, tags={"passive", "social", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        u = target.value

        async def check(site, tmpl, marker):
            url = tmpl.format(u=u)
            r = await self.ctx.http.get(url, expect="response")
            if r is None:
                return
            code = getattr(r, "status_code", 0)
            body = getattr(r, "text", "") or ""
            found = False
            if marker == "status":
                found = code == 200
            else:
                found = code == 200 and marker.lower() not in body.lower()
            if found:
                graph.add(EntityType.SOCIAL_PROFILE, url, confidence=0.65,
                          tags={"social", site.lower()},
                          metadata={"platform": site, "username": u},
                          evidence=ev("username_hunt", url, f"{site} profile exists"))

        await asyncio.gather(*[check(s, t, m) for s, (t, m) in SITES.items()])
