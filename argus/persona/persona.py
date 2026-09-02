"""
persona.py — cross-account identity fusion.
============================================

Once we have a set of confirmed/likely profiles, some of them are the SAME
person (same avatar, same bio, same linked handle). This fuses them into one
Persona: a single unified identity card listing every account, the strongest
evidence, and an aggregate confidence.

Fusion signals (any strong one links two profiles):
  * identical/near-identical bio text
  * a link from profile A to profile B's platform+handle
  * same declared location + same handle stem
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import locale as L


@dataclass
class ProfileHit:
    platform: str
    url: str
    handle: str = ""
    display_name: str = ""
    bio: str = ""
    location: str = ""
    language: str = ""
    links: list[str] = field(default_factory=list)
    score: int = 0
    verdict: str = "possible"
    reasons: list[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "platform": self.platform, "url": self.url, "handle": self.handle,
            "display_name": self.display_name, "bio": self.bio,
            "location": self.location, "language": self.language,
            "links": self.links, "score": self.score, "verdict": self.verdict,
            "reasons": self.reasons,
        }


def _bio_key(bio: str) -> str:
    return L.fold(bio)[:80]


def fuse(hits: list[ProfileHit]) -> list[list[ProfileHit]]:
    """Group ProfileHits that are the same person. Returns list of clusters."""
    n = len(hits)
    parent = list(range(n))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a, b):
        parent[find(a)] = find(b)

    for i in range(n):
        for j in range(i + 1, n):
            if _same_person(hits[i], hits[j]):
                union(i, j)

    clusters: dict[int, list[ProfileHit]] = {}
    for i in range(n):
        clusters.setdefault(find(i), []).append(hits[i])
    # sort clusters by best score desc
    out = list(clusters.values())
    out.sort(key=lambda c: max(h.score for h in c), reverse=True)
    return out


def _same_person(a: ProfileHit, b: ProfileHit) -> bool:
    # 1) cross-link: A's links mention B's handle or platform url
    hb = L.fold(b.handle)
    for lk in a.links:
        if hb and hb in L.fold(lk):
            return True
    ha = L.fold(a.handle)
    for lk in b.links:
        if ha and ha in L.fold(lk):
            return True
    # 2) identical non-trivial bio
    ka, kb = _bio_key(a.bio), _bio_key(b.bio)
    if ka and len(ka) >= 20 and ka == kb:
        return True
    # 3) same handle stem + same city
    if ha and ha == hb and _same_city(a.location, b.location):
        return True
    # 4) both CONFIRMED in the SAME city with a shared handle stem: strong
    #    evidence it's one person across platforms (handles differ only by
    #    separators/spelling/script). City compared via the gazetteer so
    #    'Medina' (en) and 'المدينة المنورة' (ar) count as the same place.
    if (a.verdict == "confirmed" and b.verdict == "confirmed"
            and _same_city(a.location, b.location)):
        if ha and hb and (ha in hb or hb in ha or _stem(ha) == _stem(hb)):
            return True
    return False


def _same_city(loc_a: str, loc_b: str) -> bool:
    """True if both locations resolve to the same gazetteer city (any language)."""
    if not loc_a or not loc_b:
        return False
    ka, _ = L.resolve_city(loc_a)
    kb, _ = L.resolve_city(loc_b)
    if ka and kb:
        return ka == kb
    return L.fold(loc_a) == L.fold(loc_b)


def _stem(h: str) -> str:
    """Handle stem for comparison: drop trailing digits and the 'al' article
    so firasalharbi, firasharbi and firas.al.harbi all reduce to the same key."""
    import re
    s = re.sub(r"\d+$", "", h)
    s = s.replace("al", "").replace("el", "")
    return s
