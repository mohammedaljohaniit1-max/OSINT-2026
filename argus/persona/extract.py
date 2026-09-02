"""
extract.py — passive profile-field extraction.
===============================================

Given a fetched public profile page (HTML or JSON), pull out the fields the
geo-confirmer needs — display name, bio/about, declared location, language,
external links — WITHOUT any API key. Uses OpenGraph/Twitter meta tags, JSON-LD,
and a few platform-specific selectors. Best-effort and defensive: a profile
that yields only a display name still gets scored.
"""
from __future__ import annotations

import json
import re

# meta property/name -> field
_META_MAP = {
    "og:title": "display_name",
    "twitter:title": "display_name",
    "og:description": "bio",
    "twitter:description": "bio",
    "description": "bio",
    "og:locale": "language",
    "profile:username": "handle",
}

_RE_META = re.compile(
    r"<meta[^>]+(?:property|name)=[\"']([^\"']+)[\"'][^>]+content=[\"']([^\"']*)[\"']",
    re.I)
_RE_META2 = re.compile(
    r"<meta[^>]+content=[\"']([^\"']*)[\"'][^>]+(?:property|name)=[\"']([^\"']+)[\"']",
    re.I)
_RE_TITLE = re.compile(r"<title[^>]*>([^<]+)</title>", re.I)
_RE_HTMLLANG = re.compile(r"<html[^>]+lang=[\"']([^\"']+)[\"']", re.I)
_RE_LDJSON = re.compile(
    r"<script[^>]+type=[\"']application/ld\+json[\"'][^>]*>(.*?)</script>",
    re.I | re.S)

# location hint words (both scripts) that often precede a place in a bio
_LOC_HINTS = ["based in", "located in", "from", "lives in", "city of",
              "من", "مقيم في", "أعيش في", "اعيش في", "سكان", "مدينة"]


def extract_profile(html_or_json: str) -> dict:
    """Return {display_name, bio, location, language, handle, links[]}."""
    out = {"display_name": "", "bio": "", "location": "",
           "language": "", "handle": "", "links": []}
    if not html_or_json:
        return out
    text = html_or_json

    # 1) JSON payload (some platforms serve JSON profiles)
    stripped = text.lstrip()
    if stripped[:1] in "{[":
        try:
            data = json.loads(stripped)
            _from_json_obj(data, out)
            if out["display_name"] or out["bio"]:
                return out
        except Exception:
            pass

    # 2) meta tags
    for rx in (_RE_META, _RE_META2):
        for a, b in rx.findall(text):
            key, val = (a, b) if rx is _RE_META else (b, a)
            f = _META_MAP.get(key.lower())
            if f and val and not out[f]:
                out[f] = _unescape(val)

    # 3) JSON-LD (schema.org Person / ProfilePage)
    for block in _RE_LDJSON.findall(text):
        try:
            data = json.loads(block.strip())
            _from_json_obj(data, out)
        except Exception:
            continue

    # 4) <html lang>
    if not out["language"]:
        m = _RE_HTMLLANG.search(text)
        if m:
            out["language"] = m.group(1)

    # 5) <title> as last-resort display name
    if not out["display_name"]:
        m = _RE_TITLE.search(text)
        if m:
            out["display_name"] = _unescape(m.group(1)).strip()

    # 6) mine a location out of the bio if none declared
    if not out["location"] and out["bio"]:
        out["location"] = _guess_location(out["bio"])

    # dedupe links
    out["links"] = list(dict.fromkeys(out["links"]))[:10]
    return out


def _from_json_obj(data, out):
    """Walk a JSON-LD / API object pulling person-ish fields."""
    if isinstance(data, list):
        for x in data:
            _from_json_obj(x, out)
        return
    if not isinstance(data, dict):
        return
    def g(*keys):
        for k in keys:
            v = data.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
        return ""
    if not out["display_name"]:
        out["display_name"] = g("name", "fullName", "full_name", "displayName")
    if not out["bio"]:
        out["bio"] = g("description", "bio", "about", "summary")
    if not out["location"]:
        loc = data.get("address") or data.get("location") or data.get("homeLocation")
        if isinstance(loc, dict):
            out["location"] = (loc.get("addressLocality") or loc.get("name")
                               or loc.get("addressRegion") or "")
        elif isinstance(loc, str):
            out["location"] = loc
    if not out["handle"]:
        out["handle"] = g("alternateName", "additionalName")
    url = g("url", "sameAs")
    if url:
        out["links"].append(url)
    # recurse into common nested containers
    for k in ("author", "mainEntity", "@graph", "creator", "publisher"):
        if k in data:
            _from_json_obj(data[k], out)


def _guess_location(bio: str) -> str:
    low = bio.lower()
    for hint in _LOC_HINTS:
        idx = low.find(hint)
        if idx >= 0:
            tail = bio[idx + len(hint): idx + len(hint) + 40].strip(" :،,.-")
            # first 3 words after the hint
            words = re.split(r"[\s،,]+", tail)[:3]
            cand = " ".join(w for w in words if w)
            if cand:
                return cand
    return ""


def _unescape(s: str) -> str:
    import html
    return html.unescape(s or "").replace("\n", " ").strip()
