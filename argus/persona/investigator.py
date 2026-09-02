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
import time

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

# INTERNAL time budget (seconds) — the module MUST finish and emit whatever it
# found before the engine's hard kill (60s passive / 120s active). If we simply
# fired all handle×platform probes into asyncio.gather, a few slow hosts would
# stall past 60s, the engine would TimeoutError the whole coroutine, and ALL
# results would be lost (this is exactly why the person scan returned 0 hits).
TIME_BUDGET = {"quick": 25, "standard": 40, "deep": 50,
               "stealth": 40, "monitor": 40}
# how many profile probes may be in flight at once (per module)
PROBE_CONCURRENCY = 24
# per-request ceiling so one dead host can't eat the whole budget
PER_REQUEST_TIMEOUT = 8.0


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
        deadline = time.monotonic() + TIME_BUDGET.get(cfg.profile, 40)

        async def probe(platform, tmpl, marker, handle):
            url = tmpl.format(u=handle)
            try:
                r = await asyncio.wait_for(
                    self.ctx.http.get(url, expect="response"),
                    timeout=PER_REQUEST_TIMEOUT)
            except (asyncio.TimeoutError, Exception):
                return
            if r is None:
                return
            code = getattr(r, "status_code", 0)
            body = getattr(r, "text", "") or ""
            exists = (code == 200) if marker == "status" else (
                code == 200 and marker.lower() not in body.lower())
            if not exists:
                return
            self._score_and_record(platform, url, handle, body,
                                   confirmer, hits, graph, origin="handle probe")

        # -- SEARCH-ENGINE DISCOVERY FIRST (finds people with 0 followers) ----
        # A person with no followers still shows up when you *search their name
        # + city*, so we dork the display-name queries and mine any profile URLs
        # / handles the results expose, then feed those handles into the probe
        # pool alongside the generated ones. This is the genius bit that plain
        # handle-guessing can't do.
        discovered_rows: list[dict] = []
        try:
            discovered_rows = await asyncio.wait_for(
                self._search_discovery(name, city_meta, country),
                timeout=max(1.0, min(20.0, deadline - time.monotonic())))
        except (asyncio.TimeoutError, Exception):
            discovered_rows = []

        # probe every directly-discovered profile URL on ITS platform first —
        # these are the real people (found by name+city search, not guessed).
        disc_handles = []
        for row in discovered_rows:
            disc_handles.append(row["handle"])
            await self._probe_url(row["platform"], row["url"], row["handle"],
                                  confirmer, hits, graph,
                                  origin="name+city search")

        # merge discovered handles into the generated pool (dedup, discovered
        # first). Only CLEAN, portable handles get swept across all 18 platforms
        # — a platform-specific id like LinkedIn's 'firas-alharby-123' or a
        # hyphenated slug is meaningless on GitHub/Instagram, so we keep those
        # to their own discovered URL (already probed above) and don't spray them.
        def _portable(h):
            return h and "-" not in h and not any(c.isdigit() for c in h[-3:]) \
                   and 3 <= len(h) <= 30
        sweepable_disc = [h for h in disc_handles if _portable(h)]
        seen = set()
        merged = []
        for h in sweepable_disc + handles:
            if h and h not in seen:
                seen.add(h)
                merged.append(h)
        handles = merged
        graph.run_meta["persona"]["handles_tried"] = handles
        graph.run_meta["persona"]["discovered_handles"] = disc_handles
        graph.run_meta["persona"]["discovered_profiles"] = [
            {"platform": r["platform"], "url": r["url"]} for r in discovered_rows]

        # -- BOUNDED, TIME-BUDGETED PROBING (always returns partial results) ---
        sem = asyncio.Semaphore(PROBE_CONCURRENCY)

        async def bounded(platform, tmpl, marker, handle):
            if time.monotonic() >= deadline:
                return
            async with sem:
                if time.monotonic() >= deadline:
                    return
                await probe(platform, tmpl, marker, handle)

        tasks = [asyncio.create_task(bounded(p, t, m, h))
                 for h in handles
                 for p, (t, m) in PLATFORMS.items()]
        remaining = max(1.0, deadline - time.monotonic())
        done, pending = await asyncio.wait(tasks, timeout=remaining)
        # cancel anything still running past the budget — we emit what we have
        for t in pending:
            t.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

        self._emit(hits, graph, name, country, raw_name)

    # ------------------------------------------------------------------ #
    #  Search-engine people discovery (finds 0-follower / nickname people)
    # ------------------------------------------------------------------ #
    async def _search_discovery(self, name, city_meta, country) -> list[dict]:
        """Dork 'name + city' across social sites, mine profile links.
        Returns [{platform, url, handle, title}] rows (deduped)."""
        from . import search_discovery as SD
        queries = SD.build_queries(name, city_meta, country)
        # cap how many queries we fire so we stay inside the budget
        queries = queries[:14]
        results: list[dict] = []
        sem = asyncio.Semaphore(6)

        async def one(q):
            async with sem:
                try:
                    rows = await asyncio.wait_for(self._web_search(q),
                                                  timeout=PER_REQUEST_TIMEOUT)
                except (asyncio.TimeoutError, Exception):
                    return
                if rows:
                    results.extend(rows)

        await asyncio.gather(*[one(q) for q in queries], return_exceptions=True)
        return SD.extract_profiles(results)

    async def _web_search(self, query: str) -> list[dict]:
        """SearXNG (preferred) -> DuckDuckGo HTML fallback. Zero API keys."""
        import re as _re
        import urllib.parse as _up
        sx = (self.ctx.config.searxng_url or "").rstrip("/")
        if sx:
            data = await self.ctx.http.get(
                f"{sx}/search", params={"q": query, "format": "json"},
                expect="json")
            if isinstance(data, dict) and data.get("results"):
                return data["results"]
        # fallback: DuckDuckGo HTML (no key, no CAPTCHA for this endpoint)
        html = await self.ctx.http.post(
            "https://html.duckduckgo.com/html/", data={"q": query})
        if not html:
            return []
        out = []
        for m in _re.finditer(
                r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
                html):
            href = _up.unquote(m.group(1))
            # DDG wraps external links; pull the real uddg= target if present
            mm = _re.search(r"uddg=([^&]+)", href)
            if mm:
                href = _up.unquote(mm.group(1))
            title = _re.sub("<.*?>", "", m.group(2))
            out.append({"url": href, "title": title, "content": ""})
        return out

    async def _probe_url(self, platform, url, handle, confirmer, hits, graph,
                         *, origin):
        """Fetch a specific profile URL and score it."""
        try:
            r = await asyncio.wait_for(
                self.ctx.http.get(url, expect="response"),
                timeout=PER_REQUEST_TIMEOUT)
        except (asyncio.TimeoutError, Exception):
            return
        if r is None:
            return
        code = getattr(r, "status_code", 0)
        body = getattr(r, "text", "") or ""
        if code != 200:
            return
        self._score_and_record(platform, url, handle, body,
                               confirmer, hits, graph, origin=origin)

    def _score_and_record(self, platform, url, handle, body,
                          confirmer, hits, graph, *, origin):
        """Shared scoring/verdict logic for both discovery and handle probes."""
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
        # avoid duplicate hits for the same URL
        if any(h.url == url for h in hits):
            return
        reasons = list(cs.reasons)
        if origin:
            reasons.append(f"source: {origin}")
        hits.append(ProfileHit(
            platform=platform, url=url, handle=handle,
            display_name=prof.get("display_name", ""),
            bio=prof.get("bio", ""), location=prof.get("location", ""),
            language=prof.get("language", ""), links=prof.get("links", []),
            score=cs.total, verdict=cs.verdict, reasons=reasons,
        ))

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
    # a real person in a specific city is ONE identity (occasionally a couple).
    # if fusion somehow yields more distinct confirmed clusters than this, we
    # collapse the tail into a single same-city bucket so the output is never a
    # wall of near-duplicate personas.
    MAX_CONFIRMED_PERSONAS = 3

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
        # keep the strongest few as distinct personas; fold the rest into one
        # "additional same-city accounts" bucket to stay lean.
        head = clusters[:self.MAX_CONFIRMED_PERSONAS]
        tail = clusters[self.MAX_CONFIRMED_PERSONAS:]
        for idx, cluster in enumerate(head):
            agg = max(h.score for h in cluster)
            self._make_persona(
                graph, raw_name, country, city_disp, cluster,
                verdict="confirmed", agg=agg,
                label=f"{name.display()} @ {city_disp}"
                      + (f" #{idx+1}" if len(head) > 1 else ""),
                risk=RiskLevel.HIGH)
            emitted_persona = True
        if tail:
            tail_accts = [h for c in tail for h in c]
            agg = max(h.score for h in tail_accts)
            self._make_persona(
                graph, raw_name, country, city_disp,
                sorted(tail_accts, key=lambda h: h.score, reverse=True)[:self.MAX_LIKELY_ACCOUNTS],
                verdict="confirmed", agg=agg,
                label=f"{name.display()} @ {city_disp} — "
                      f"{len(tail_accts)} more same-city account(s)",
                risk=RiskLevel.HIGH)
            emitted_persona = True
            clusters = head + [tail_accts]  # for accurate summary count

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
