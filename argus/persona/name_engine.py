"""
name_engine.py — genius Name -> username / handle generator.
=============================================================

Given a NormalizedName (with cross-language spelling variants), produce a
ranked list of candidate usernames/handles that a real person with that name
is likely to use — the exact patterns humans pick when creating accounts:

    firas.alharbi   f.alharbi   firasalharbi   alharbi.firas
    firas_alharbi   firasharbi  firas1990      f_alharbi ...

Ranked so the most probable handles come first (the engine only checks the top
N against platforms, keeping the passive scan fast and precise).

No network, no keys — pure combinatorics over the locale-expanded spellings.
"""
from __future__ import annotations

import re

from .locale import NormalizedName, fold

# common birth-year / number suffixes people append to handles
_YEARS = ["", "1", "2", "7", "11", "99", "90", "91", "92", "93", "94", "95",
          "96", "97", "98", "2000", "2020", "123", "01"]
_SEPS = ["", ".", "_"]


def _clean_handle(h: str) -> str:
    """Lowercase + strip accents but PRESERVE . and _ (valid handle chars)."""
    import unicodedata
    h = unicodedata.normalize("NFKD", h.strip())
    h = "".join(c for c in h if not unicodedata.combining(c))
    h = h.lower()
    h = re.sub(r"[^a-z0-9._]", "", h)       # keep dots & underscores
    h = re.sub(r"[._]{2,}", ".", h).strip("._")
    return h


def generate_usernames(name: NormalizedName, limit: int = 60) -> list[str]:
    """Return up to `limit` ranked candidate handles (folded, ascii-only).

    Ranking philosophy (this is the intelligence):
      * The PRIMARY spelling of each name part (the first Latin variant, e.g.
        'firas' / 'alharbi') is what a person overwhelmingly uses — it ranks
        far above secondary transliterations ('feras', 'harby', ...).
      * The FULL family form ('alharbi') and the article-dropped short form
        ('harbi') are BOTH first-class: real handles use either. We never let
        one starve the other out of the top-N.
      * Format quality (given.family / givenfamily / initial+family) dominates
        the ordering — raw string length is only the final, weakest tiebreak,
        so 'firas.alharbi' is NOT pushed below 'frasharbi' just for being longer.
    """
    # Only Latin spellings are usable as handles (platforms want ascii).
    def latin_only(variants):
        return [v for v in variants if not any("\u0600" <= c <= "\u06FF" for c in v)]

    given_vars = latin_only(name.part_variants[0]) if name.part_variants else []
    # given names don't take the "al" family article — drop that artifact so we
    # don't generate 'alfiras' for a first name of Firas.
    if len(given_vars) > 1:
        base_given = fold(given_vars[0])
        given_vars = [g for g in given_vars
                      if not (fold(g) == "al" + base_given)] or given_vars
    family_vars = (latin_only(name.part_variants[-1])
                   if len(name.part_variants) > 1 else [])
    # middle parts (rare) — fold into family pool
    mids = []
    for i in range(1, len(name.part_variants) - 1):
        mids += latin_only(name.part_variants[i])

    given_vars = given_vars or [""]

    # variant-index penalty: the 1st (canonical) spelling is free, each further
    # transliteration costs a little rank so canonical handles always surface.
    # BUT the article-dropped short form ('harbi' vs 'alharbi') is a legitimate
    # *handle style*, not a worse spelling — so it inherits the penalty of the
    # full form it derives from instead of being buried at the end of the list.
    def _variant_penalties(variants):
        pen, base_rank = {}, {}
        rank = 0
        for v in variants:
            fv = fold(v)
            # a form that is another form with a leading 'al'/'el' stripped
            # shares that parent's rank (both are tier-equal handle styles)
            parent = None
            for u in variants:
                fu = fold(u)
                if fu != fv and (fu == "al" + fv or fu == "el" + fv):
                    parent = u
                    break
            if parent is not None and parent in base_rank:
                pen[v] = base_rank[parent]
            else:
                base_rank[v] = rank
                pen[v] = rank
                rank += 1
        return {v: min(r, 5) * 3 for v, r in pen.items()}

    g_pen = _variant_penalties(given_vars)
    f_pen = _variant_penalties(family_vars)

    ranked: list[tuple[int, int, str]] = []
    seen: set[str] = set()
    _order = 0

    def push(handle: str, rank: int):
        nonlocal _order
        h = _clean_handle(handle)
        if not h or len(h) < 3 or len(h) > 30:
            return
        if h in seen:
            return
        seen.add(h)
        # stable insertion order as a mid-tiebreak keeps canonical-first
        ranked.append((rank, _order, h))
        _order += 1

    # ---- Tier 0: the classic first+last patterns (highest probability) ----
    for g in given_vars:
        gi = g[0] if g else ""
        gp = g_pen.get(g, 0)
        for f in family_vars or [""]:
            fp = f_pen.get(f, 0)
            base = gp + fp                     # spelling-variant penalty
            if not f:
                # given-only handles
                push(g, 30 + base)
                for y in _YEARS[1:8]:
                    push(g + y, 60 + base)
                continue
            for sep in _SEPS:
                push(f"{g}{sep}{f}", 0 + base)   # firas.alharbi / firasalharbi (best)
                push(f"{f}{sep}{g}", 12 + base)  # alharbi.firas
            push(f"{gi}{f}", 8 + base)           # falharbi
            for sep in _SEPS:
                push(f"{gi}{sep}{f}", 10 + base) # f.alharbi
            push(f"{g}{f[0]}", 20 + base)        # firasa
            # with year suffixes on the strongest pattern
            for y in _YEARS[1:10]:
                push(f"{g}{f}{y}", 40 + base)
                push(f"{g}.{f}{y}", 45 + base)

    # ---- Tier 1: middle-name inclusions ----
    for g in given_vars[:2]:
        for m in mids[:2]:
            for f in (family_vars or [""])[:2]:
                if f:
                    push(f"{g}.{m}.{f}", 50)
                    push(f"{g}{m}{f}", 55)

    # rank first, then original push order, then length as the weakest tiebreak
    ranked.sort(key=lambda x: (x[0], x[1], len(x[2])))
    return [h for _, _, h in ranked[:limit]]


def display_name_queries(name: NormalizedName) -> list[str]:
    """Human-readable *display name* search phrases (used for search-engine /
    people-search dorks, not handle checks). Keeps BOTH scripts."""
    out, seen = [], set()

    def add(s):
        s = s.strip()
        k = fold(s)
        if s and k and k not in seen:
            seen.add(k)
            out.append(s)

    # full raw name (both scripts if provided)
    add(name.raw)
    # given + family in each script variant (Latin combos)
    if name.part_variants:
        given = name.part_variants[0]
        family = name.part_variants[-1] if len(name.part_variants) > 1 else [""]
        for g in given[:3]:
            for f in family[:3]:
                if any("\u0600" <= c <= "\u06FF" for c in g + f):
                    add(f"{g} {f}")           # arabic display
                else:
                    add(f"{g} {f}".title())   # Firas Alharbi
                    add(f"{g} {f}")           # firas alharbi
    return out[:12]
