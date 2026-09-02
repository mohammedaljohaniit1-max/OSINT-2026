"""
geo_confirm.py — identity + geo confirmation scoring.
=====================================================

The single most important idea in Persona Hunter: given a candidate profile we
found (its handle, display name, bio text, declared location, links, language),
decide **how likely it is the target person in the target city** — and, just as
important, produce a human-readable *explanation* of why.

Output for each profile:
    ConfirmScore(
        total = 0..100,                # overall identity+geo confidence
        name_score, geo_score, signal_score,
        reasons = ["name 'firas alharbi' matches handle", "bio mentions المدينة", ...],
        in_city = True/False,          # HARD geo gate for ranking
        verdict = "confirmed" | "likely" | "possible" | "rejected",
    )

The engine ranks CONFIRMED/LIKELY hits in the target city at the top and pushes
wrong-city same-name accounts down (or rejects them) — the exact behaviour the
user asked for: "لو حصلت فراس الحربي في الرياض ماتطلعه".
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import locale as L


# other KSA/Gulf cities → used to detect a *conflicting* location in a bio
_ALL_CITY_TOKENS: dict[str, set[str]] = {
    key: L.city_match_tokens(key) for key in L.CITIES
}


@dataclass
class ConfirmScore:
    total: int = 0
    name_score: int = 0
    geo_score: int = 0
    signal_score: int = 0
    in_city: bool = False
    conflict_city: str = ""            # a different city detected in the bio
    verdict: str = "rejected"
    reasons: list[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "total": self.total, "name_score": self.name_score,
            "geo_score": self.geo_score, "signal_score": self.signal_score,
            "in_city": self.in_city, "conflict_city": self.conflict_city,
            "verdict": self.verdict, "reasons": self.reasons,
        }


class GeoConfirmer:
    """Holds the target context and scores candidate profiles against it."""

    def __init__(self, name: L.NormalizedName, country_code: str | None,
                 city_key: str | None):
        self.name = name
        self.country = country_code
        self.city_key = city_key
        self.name_tokens = name.all_tokens_folded()      # every spelling
        self.city_tokens = L.city_match_tokens(city_key) if city_key else set()
        self.dial = L.country_dial(country_code) if country_code else ""

    # ---- name matching ---------------------------------------------------- #
    def _name_hits(self, text: str) -> set[str]:
        """Which target name-tokens appear in this text (folded contains)."""
        if not text:
            return set()
        tf = L.fold(text)
        hits = set()
        for tok in self.name_tokens:
            if len(tok) >= 3 and tok in tf:
                hits.add(tok)
        return hits

    def _has_given_and_family(self, hits: set[str]) -> bool:
        """True only if a hit from the given-name group AND family group both
        appear — prevents matching only on a common family name."""
        if not self.name.part_variants:
            return False
        given = {L.fold(v) for v in self.name.part_variants[0]}
        family = ({L.fold(v) for v in self.name.part_variants[-1]}
                  if len(self.name.part_variants) > 1 else set())
        g_hit = any(any(t in h or h in t for t in given) for h in hits) if given else False
        f_hit = any(any(t in h or h in t for t in family) for h in hits) if family else True
        return g_hit and f_hit

    # ---- geo matching ----------------------------------------------------- #
    def _detect_city(self, text: str):
        """Return (matched_target_city: bool, conflicting_city_key: str|'')."""
        if not text:
            return False, ""
        tf = L.fold(text)
        target = any(t and t in tf for t in self.city_tokens)
        conflict = ""
        if not target:
            for key, toks in _ALL_CITY_TOKENS.items():
                if key == self.city_key:
                    continue
                if any(t and len(t) >= 4 and t in tf for t in toks):
                    conflict = key
                    break
        return target, conflict

    def _country_signals(self, text: str, links: list[str]) -> list[str]:
        r = []
        tf = L.fold(text or "")
        if self.country and self.dial and self.dial.replace("+", "") in (text or ""):
            r.append(f"phone dial code {self.dial} present")
        if self.country:
            for n in L.COUNTRIES.get(self.country, {}).get("names", []):
                if L.fold(n) and L.fold(n) in tf:
                    r.append(f"country '{n}' mentioned")
                    break
        return r

    # ---- main scoring ----------------------------------------------------- #
    def score(self, *, handle: str = "", display_name: str = "",
              bio: str = "", location: str = "", language: str = "",
              links: list[str] | None = None) -> ConfirmScore:
        links = links or []
        cs = ConfirmScore()

        blob_name = " ".join([handle or "", display_name or ""])
        blob_all = " ".join([handle or "", display_name or "", bio or "",
                             location or "", " ".join(links)])

        # ---- NAME (max 55) ----
        hits_name_field = self._name_hits(blob_name)
        hits_anywhere = self._name_hits(blob_all)
        if self._has_given_and_family(hits_name_field):
            cs.name_score = 55
            cs.reasons.append(f"full name matches (handle/display): {sorted(hits_name_field)}")
        elif self._has_given_and_family(hits_anywhere):
            cs.name_score = 40
            cs.reasons.append(f"full name matches (in bio): {sorted(hits_anywhere)}")
        elif hits_name_field:
            cs.name_score = 18
            cs.reasons.append(f"partial name match: {sorted(hits_name_field)}")
        elif hits_anywhere:
            cs.name_score = 10
            cs.reasons.append(f"weak name token: {sorted(hits_anywhere)}")

        # ---- GEO (max 35) ----
        loc_blob = " ".join([location or "", bio or ""])
        in_city, conflict = self._detect_city(loc_blob)
        cs.in_city = in_city
        cs.conflict_city = conflict
        if in_city:
            cs.geo_score = 35
            canon = L.CITIES.get(self.city_key, {}).get("canonical", self.city_key)
            cs.reasons.append(f"location matches target city ({canon})")
        elif conflict:
            cs.geo_score = 0
            canon = L.CITIES.get(conflict, {}).get("canonical", conflict)
            cs.reasons.append(f"⚠ location is a DIFFERENT city ({canon}) — likely not the target")
        else:
            cs.geo_score = 0
            cs.reasons.append("no location stated (city unconfirmed)")

        # ---- SIGNALS (max 10) ----
        sig = 0
        if language and self.country:
            if language.lower().startswith("ar") and self.country in (
                    "SA", "AE", "KW", "QA", "BH", "OM", "EG", "JO"):
                sig += 4
                cs.reasons.append("profile language is Arabic (matches region)")
        for r in self._country_signals(blob_all, links):
            sig += 3
            cs.reasons.append(r)
        cs.signal_score = min(sig, 10)

        # ---- combine + verdict ----
        cs.total = min(cs.name_score + cs.geo_score + cs.signal_score, 100)

        # HARD RULE: a strong name match in a *different* city is demoted, not
        # promoted — exactly "لو حصلته في الرياض ماتطلعه".
        if conflict and cs.name_score >= 40:
            cs.verdict = "rejected"
            cs.total = min(cs.total, 20)
            return cs

        if cs.name_score >= 40 and in_city:
            cs.verdict = "confirmed"
        elif cs.name_score >= 40 and not conflict:
            cs.verdict = "likely"          # right name, city unstated
        elif cs.name_score >= 18:
            cs.verdict = "possible"
        else:
            cs.verdict = "rejected"
        return cs
