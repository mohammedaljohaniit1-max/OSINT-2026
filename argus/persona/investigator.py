"""
GENIUS MODULE — Persona Hunter (person investigation).
=======================================================

Given a PERSON seed (name + country + city, any language), find every online
account that plausibly belongs to THAT person in THAT city:

  1. normalize the name across Arabic + Latin spellings
  2. generate ranked candidate handles (firas.alharbi, f.alharbi, ...)
  3. passively check each handle on a curated platform set (public HTTP only)
  4. for every existing profile, extract display-name/bio/location/language
  5. geo-confirm & score each hit (name × city × signals) with explanations
  6. fuse duplicate accounts into a single Persona
  7. emit CONFIRMED/LIKELY profiles in the target city; reject wrong-city hits

100% passive, zero API keys. This is what makes Argus a *person* intelligence
tool, not just a domain scanner.
"""
from __future__ import annotations

import asyncio

from ..core.models import EntityType, IntelGraph, RiskLevel
from ..core.module import Module, ModuleSpec
from ..sources._base import ev
from . import locale as L
from .name_engine import generate_usernames, display_name_queries
from .geo_confirm import GeoConfirmer
from .extract import extract_profile
from .persona import ProfileHit, fuse

# Platforms whose PUBLIC profile page exposes name/bio/location in HTML meta
# (no login wall for the profile head). (label, url_template, absent_marker)
PLATFORMS = {
    "GitHub":      ("https://github.com/{u}", "status"),
    "GitLab":      ("https://gitlab.com/{u}", "status"),
    "Instagram":   ("https://www.instagram.com/{u}/", "status"),
    "TikTok":      ("https://www.tiktok.com/@{u}", "status"),
    "YouTube":     ("https://www.youtube.com/@{u}", "status"),
    "Twitter/X":   ("https://x.com/{u}", "status"),
    "Reddit":      ("https://www.reddit.com/user/{u}", "status"),
    "Telegram":    ("https://t.me/{u}", "status"),
    "Pinterest":   ("https://www.pinterest.com/{u}/", "status"),
    "Medium":      ("https://medium.com/@{u}", "status"),
    "Behance":     ("https://www.behance.net/{u}", "status"),
    "SoundCloud":  ("https://soundcloud.com/{u}", "status"),
    "About.me":    ("https://about.me/{u}", "status"),
    "Gravatar":    ("https://en.gravatar.com/{u}", "status"),
    "Keybase":     ("https://keybase.io/{u}", "status"),
    "Linktree":    ("https://linktr.ee/{u}", "status"),
    "Snapchat":    ("https://www.snapchat.com/add/{u}", "status"),
    "Threads":     ("https://www.threads.net/@{u}", "status"),
}

# how many top-ranked handles we bother to check per platform (keeps it fast)
MAX_HANDLES = {"quick": 8, "standard": 18, "deep": 40,
               "stealth": 12, "monitor": 18}


class PersonaHunter(Module):
    spec = ModuleSpec(
        name="persona_hunter", category="native",
        accepts={EntityType.PERSON},
        produces={EntityType.PERSONA, EntityType.SOCIAL_PROFILE,
                  EntityType.USERNAME},
        description="Locale-locked person search: find a named person's "
                    "accounts in a specific city, any language (ar+en+…)",
        priority=15, tags={"passive", "social", "nokey", "person", "genius"},
    )

    async def run(self, target, graph: IntelGraph):
        cfg = self.ctx.config
        raw_name = cfg.person_name or target.value
        name = L.normalize_name(raw_name)
        country = L.resolve_country(cfg.person_country) if cfg.person_country else None
        city_key, city_meta = (L.resolve_city(cfg.person_city)
                               if cfg.person_city else (None, None))

        confirmer = GeoConfirmer(name, country, city_key)
        n_handles = MAX_HANDLES.get(cfg.profile, 18)
        handles = generate_usernames(name, limit=n_handles)

        # record the investigation context on the graph for the report
        graph.run_meta["persona"] = {
            "name": raw_name,
            "name_parts": name.parts,
            "country": country,
            "city": (city_meta or {}).get("canonical") if city_meta else cfg.person_city,
            "city_key": city_key,
            "handles_tried": handles,
            "display_queries": display_name_queries(name),
            "_rejected_count": 0,
            "_rejected_examples": [],
        }

        hits: list[ProfileHit] = []

        async def probe(platform, tmpl, marker, handle):
            url = tmpl.format(u=handle)
            r = await self.ctx.http.get(url, expect="response")
            if r is None:
                return
            code = getattr(r, "status_code", 0)
            body = getattr(r, "text", "") or ""
            exists = (code == 200) if marker == "status" else (
                code == 200 and marker.lower() not in body.lower())
            if not exists:
                return
            prof = extract_profile(body)
            cs = confirmer.score(
                handle=handle,
                display_name=prof.get("display_name", ""),
                bio=prof.get("bio", ""),
                location=prof.get("location", ""),
                language=prof.get("language", ""),
                links=prof.get("links", []),
            )
            if cs.verdict == "rejected":
                # DO NOT emit a full entity per rejection (that is what created
                # the "giant useless log"). Just COUNT it, and keep a few
                # examples for audit — summarized later in _emit().
                pm = graph.run_meta["persona"]
                pm["_rejected_count"] += 1
                if len(pm["_rejected_examples"]) < 12:
                    pm["_rejected_examples"].append({
                        "platform": platform, "url": url, "handle": handle,
                        "location": prof.get("location", ""),
                        "conflict_city": cs.conflict_city,
                        "reason": (cs.reasons[0] if cs.reasons else ""),
                    })
                return
            hits.append(ProfileHit(
                platform=platform, url=url, handle=handle,
                display_name=prof.get("display_name", ""),
                bio=prof.get("bio", ""), location=prof.get("location", ""),
                language=prof.get("language", ""), links=prof.get("links", []),
                score=cs.total, verdict=cs.verdict, reasons=cs.reasons,
            ))

        tasks = [probe(p, t, m, h)
                 for h in handles
                 for p, (t, m) in PLATFORMS.items()]
        # bounded concurrency (respect global semaphore via gather; http client
        # already rate-limits per host)
        await asyncio.gather(*tasks)

        self._emit(hits, graph, name, country, raw_name)

    # ------------------------------------------------------------------ #
    #  Result emission — LEAN & INTELLIGENT.
    #
    #  The #1 failure mode of person-search is a "giant useless log": every
    #  same-name account on earth dumped as a separate result. We prevent that
    #  with a strict, tiered policy:
    #
    #    CONFIRMED  (name + TARGET city)  -> fused personas, full detail. RESULTS.
    #    LIKELY     (name, city unstated) -> ONE grouped "unconfirmed" persona
    #                                        holding all of them (never 1-each).
    #    POSSIBLE   (weak/partial name)   -> a single COUNT summary entity.
    #    REJECTED   (wrong city/name)     -> a single COUNT summary entity
    #                                        (+ up to a few examples for audit).
    #
    #  So the graph stays small and every top-level entity is genuinely useful.
    # ------------------------------------------------------------------ #
    # tunable ceilings so output can never explode (still fully configurable)
    MAX_LIKELY_ACCOUNTS = 25
    MAX_REJECTED_EXAMPLES = 8

    def _emit(self, hits, graph, name, country, raw_name):
        city_disp = graph.run_meta["persona"].get("city") or country or "?"

        # rejected hits were already stored as low findings inside probe(); we
        # only summarize their COUNT here from run_meta counters.
        confirmed = [h for h in hits if h.verdict == "confirmed"]
        likely = [h for h in hits if h.verdict == "likely"]
        possible = [h for h in hits if h.verdict == "possible"]

        emitted_persona = False

        # ---- CONFIRMED: fuse into personas, full detail (the real answer) ----
        clusters = fuse(confirmed)
        for idx, cluster in enumerate(clusters):
            best = max(cluster, key=lambda h: h.score)
            agg = max(h.score for h in cluster)
            self._make_persona(
                graph, raw_name, country, city_disp, cluster,
                verdict="confirmed", agg=agg,
                label=f"{name.display()} @ {city_disp}"
                      + (f" #{idx+1}" if len(clusters) > 1 else ""),
                risk=RiskLevel.HIGH)
            emitted_persona = True

        # ---- LIKELY: ONE grouped bucket (right name, city not stated) ----
        if likely:
            likely = sorted(likely, key=lambda h: h.score, reverse=True)[:self.MAX_LIKELY_ACCOUNTS]
            agg = max(h.score for h in likely)
            self._make_persona(
                graph, raw_name, country, city_disp, likely,
                verdict="likely", agg=agg,
                label=f"{name.display()} — {len(likely)} account(s), city UNCONFIRMED",
                risk=RiskLevel.MEDIUM)
            emitted_persona = True

        # ---- POSSIBLE / REJECTED: compact COUNT summaries only ----
        rej_examples = graph.run_meta.get("persona", {}).get("_rejected_examples", [])
        rej_count = graph.run_meta.get("persona", {}).get("_rejected_count", 0)
        summary_bits = []
        if possible:
            summary_bits.append(f"{len(possible)} weak-name match(es) ignored")
        if rej_count:
            summary_bits.append(f"{rej_count} same-name account(s) in OTHER cities rejected")
        if summary_bits:
            graph.add(
                EntityType.PERSONA,
                f"{name.display()} — filtered noise summary",
                confidence=0.1, risk=RiskLevel.INFO,
                tags={"persona", "person-search", "summary", "no-expand"},
                metadata={"name": raw_name, "verdict": "summary",
                          "note": "; ".join(summary_bits),
                          "possible_count": len(possible),
                          "rejected_count": rej_count,
                          "rejected_examples": rej_examples[:self.MAX_REJECTED_EXAMPLES]},
                evidence=ev("persona_hunter", "",
                            "noise filtered so results stay useful: "
                            + "; ".join(summary_bits)))

        graph.run_meta["persona"]["result_summary"] = {
            "confirmed_personas": len(clusters),
            "confirmed_accounts": len(confirmed),
            "likely_accounts": len(likely),
            "possible_ignored": len(possible),
            "rejected_wrong_city": rej_count,
            "found_target": emitted_persona and bool(confirmed),
        }

    def _make_persona(self, graph, raw_name, country, city_disp, cluster,
                      *, verdict, agg, label, risk):
        p_ent = graph.add(
            EntityType.PERSONA, label,
            confidence=round(agg / 100, 2), risk=risk,
            tags={"persona", "person-search", verdict, "no-expand"},
            metadata={
                "name": raw_name, "city": city_disp, "country": country,
                "verdict": verdict, "aggregate_score": agg,
                "account_count": len(cluster),
                "accounts": [h.to_dict() for h in
                             sorted(cluster, key=lambda x: x.score, reverse=True)],
            },
            evidence=ev("persona_hunter",
                        max(cluster, key=lambda h: h.score).url,
                        f"{verdict} persona: {len(cluster)} account(s), "
                        f"top score {agg}"))
        for h in cluster:
            se = graph.add(
                EntityType.SOCIAL_PROFILE, h.url,
                confidence=round(h.score / 100, 2), risk=risk,
                tags={"social", h.platform.lower(), "person-search",
                      h.verdict, "no-expand"},
                metadata={"platform": h.platform, "handle": h.handle,
                          "display_name": h.display_name,
                          "location": h.location, "language": h.language,
                          "score": h.score, "verdict": h.verdict,
                          "reasons": h.reasons, "bio": h.bio[:200]},
                evidence=ev("persona_hunter", h.url,
                            f"{h.platform}: {h.verdict} ({h.score})"))
            graph.link(p_ent, se, "has_account",
                       confidence=round(h.score / 100, 2))
