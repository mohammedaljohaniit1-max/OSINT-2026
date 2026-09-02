"""
Search-engine people discovery — the method that finds real people.
=====================================================================

Handle-guessing only finds accounts whose username *derives from the name*.
Real humans (especially ones with 0 followers, private handles, or nicknames)
are found the way an analyst finds them: by **searching their name + city on
search engines and social sites**, then reading the profile links that come
back.

This module builds locale-aware people queries:

    site:twitter.com   "فراس الحربي" (المدينة | المدينة المنورة | Madinah)
    site:linkedin.com/in "Firas Alharby" Medina
    site:instagram.com "فراس الحربي" المدينة المنورة
    "Firas Al-Harbi" Medina  (facebook | tiktok | snapchat …)

runs them through SearXNG (or DuckDuckGo/Bing HTML fallback — zero API keys),
then extracts (platform, profile_url, handle) from every result link.

100% passive. Returns candidate handles + direct profile URLs for the
investigator to confirm/score. Because it is search-driven, it surfaces people
that pure username permutation can never reach.
"""
from __future__ import annotations

import re
import urllib.parse

from . import locale as L

# platform -> (netloc fragment(s), regex capturing the handle from the path)
# order matters: most identity-bearing first.
PROFILE_PATTERNS = [
    ("Twitter/X",  ("twitter.com", "x.com"),
     re.compile(r"(?:twitter|x)\.com/(?!home|search|hashtag|i/|intent)([A-Za-z0-9_]{2,30})/?$")),
    ("Instagram",  ("instagram.com",),
     re.compile(r"instagram\.com/(?!p/|reel/|explore/|accounts/)([A-Za-z0-9_.]{2,30})/?$")),
    ("LinkedIn",   ("linkedin.com",),
     re.compile(r"linkedin\.com/in/([A-Za-z0-9\-_%]{3,80})/?")),
    ("Facebook",   ("facebook.com", "fb.com"),
     re.compile(r"(?:facebook|fb)\.com/(?!pages/|groups/|events/|watch/)([A-Za-z0-9.]{4,50})/?")),
    ("TikTok",     ("tiktok.com",),
     re.compile(r"tiktok\.com/@([A-Za-z0-9_.]{2,30})")),
    ("Snapchat",   ("snapchat.com",),
     re.compile(r"snapchat\.com/add/([A-Za-z0-9_.\-]{2,30})")),
    ("YouTube",    ("youtube.com",),
     re.compile(r"youtube\.com/@([A-Za-z0-9_.\-]{2,40})")),
    ("GitHub",     ("github.com",),
     re.compile(r"github\.com/(?!search|topics|orgs|about)([A-Za-z0-9\-]{1,39})/?$")),
    ("Telegram",   ("t.me",),
     re.compile(r"t\.me/([A-Za-z0-9_]{4,32})")),
    ("Reddit",     ("reddit.com",),
     re.compile(r"reddit\.com/user/([A-Za-z0-9_\-]{3,20})")),
    ("Medium",     ("medium.com",),
     re.compile(r"medium\.com/@([A-Za-z0-9_.]{2,40})")),
    ("Behance",    ("behance.net",),
     re.compile(r"behance\.net/([A-Za-z0-9_\-]{2,40})")),
    ("Keybase",    ("keybase.io",),
     re.compile(r"keybase\.io/([A-Za-z0-9_]{2,40})")),
]

# social sites we explicitly target with site: dorks (identity-rich)
SOCIAL_SITES = [
    "twitter.com", "x.com", "instagram.com", "linkedin.com/in",
    "facebook.com", "tiktok.com", "youtube.com", "snapchat.com",
    "t.me", "github.com", "medium.com", "behance.net",
]


def build_queries(name: "L.NormalizedName", city_meta: dict | None,
                  country) -> list[str]:
    """Locale-aware people queries: every name spelling × city token × site."""
    # name phrases in both scripts (deduped, capped)
    phrases = _name_phrases(name)
    # city tokens (arabic + english + aliases) so 'المدينة المنورة'/'Medina' both hit
    city_terms = []
    if city_meta:
        city_terms = _uniq([city_meta.get("canonical", "")]
                           + city_meta.get("aliases", []))[:4]
    queries: list[str] = []
    for phrase in phrases:
        pq = f'"{phrase}"'
        # 1) targeted site: dorks (strongest — a profile page in that city)
        for site in SOCIAL_SITES:
            if city_terms:
                # OR the city spellings so any of them qualifies
                city_or = " OR ".join(f'"{c}"' for c in city_terms if c)
                queries.append(f'site:{site} {pq} ({city_or})')
            else:
                queries.append(f'site:{site} {pq}')
        # 2) open web with city (catches blogs/news/bios linking their socials)
        for c in city_terms[:2]:
            queries.append(f'{pq} "{c}"')
    return _uniq(queries)


def _latin_only(variants) -> list[str]:
    """Keep only Latin-script spellings (drop the source Arabic token)."""
    return [v for v in (variants or []) if v and not L.has_arabic(v)]


def _name_phrases(name) -> list[str]:
    out = []
    # 1) the native display name (e.g. Arabic 'فراس الحربي') — most precise
    disp = name.display() if hasattr(name, "display") else str(name)
    if disp:
        out.append(disp)
    # 2) LATIN given × family (both orders) — 'Firas Alharby', 'Alharby Firas'
    givens, familes = [], []
    if getattr(name, "part_variants", None):
        givens = _latin_only(name.part_variants[0]) if name.part_variants else []
        familes = (_latin_only(name.part_variants[-1])
                   if len(name.part_variants) > 1 else [])
    for g in givens[:4]:
        for f in familes[:5]:
            out.append(f"{g} {f}".strip().title())
            out.append(f"{f} {g}".strip().title())
    # 3) single family name (Latin) in case given name is rare/nickname
    for f in familes[:2]:
        out.append(f.title())
    return _uniq([p for p in out if len(p) >= 3])[:12]


def extract_profiles(results: list[dict]) -> list[dict]:
    """Turn raw search results into [{platform, url, handle, title}] rows."""
    found = []
    seen = set()
    for r in results or []:
        url = (r.get("url") or r.get("href") or "").strip()
        title = r.get("title", "") or ""
        if not url:
            continue
        low = url.lower()
        for platform, hosts, rx in PROFILE_PATTERNS:
            if not any(h in low for h in hosts):
                continue
            m = rx.search(url)
            if not m:
                continue
            handle = urllib.parse.unquote(m.group(1))
            key = (platform, handle.lower())
            if key in seen:
                continue
            seen.add(key)
            found.append({"platform": platform, "url": url,
                          "handle": handle, "title": title})
            break
    return found


def _uniq(seq):
    seen, out = set(), []
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out
