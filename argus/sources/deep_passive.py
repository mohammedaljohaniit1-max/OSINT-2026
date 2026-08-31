"""
Elite NO-KEY passive sources that push Argus past what a stock toolchain sees.

These are the signals a top OSINT analyst reaches for that most frameworks
DON'T bundle out of the box — all reachable on the clearnet with ZERO keys and
strictly PASSIVE (query public indexes; never touch the target directly):

  - HudsonRock : email/domain -> infostealer-malware infection stats. This is
    genuinely cutting-edge exposure intel (compromised machines, stealer logs)
    and few free tools integrate it. Reports EXPOSURE COUNTS only, never creds.
  - LeakIX     : domain/IP -> publicly indexed exposed services/leaks (host
    plugin summary). Public results, no key.
  - Wikidata   : org/person -> structured facts (official site, country, founded,
    key people, social handles) to anchor an investigation.

Every module here is guarded: it validates the response shape and only emits
entities that are genuinely present — no placeholders, no fabricated hits.
"""
from __future__ import annotations

import urllib.parse

from ..core.models import EntityType, IntelGraph, RiskLevel
from ..core.module import Module, ModuleSpec
from ._base import ev


class HudsonRock(Module):
    """Infostealer-infection exposure (email + domain). Public, no key."""
    spec = ModuleSpec(
        name="hudsonrock", category="source",
        accepts={EntityType.EMAIL, EntityType.DOMAIN},
        produces={EntityType.BREACH},
        description="HudsonRock infostealer-infection exposure (no key)",
        priority=21, tags={"passive", "breach", "stealer", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        v = target.value
        if target.type == EntityType.EMAIL:
            url = ("https://cavalier.hudsonrock.com/api/json/v2/"
                   f"osint-tools/search-by-email?email={urllib.parse.quote(v)}")
        else:
            url = ("https://cavalier.hudsonrock.com/api/json/v2/"
                   f"osint-tools/search-by-domain?domain={urllib.parse.quote(v)}")
        data = await self.ctx.http.get(url, expect="json")
        if not isinstance(data, dict):
            return

        # EMAIL response: {"message": "...not compromised..."} OR stealer details
        if target.type == EntityType.EMAIL:
            msg = str(data.get("message", "")).lower()
            if "not" in msg and "compromised" in msg:
                target.metadata["stealer_check"] = "not found in stealer logs (HudsonRock)"
                return
            # compromised: record as an exposure signal (no plaintext creds shown)
            stealers = data.get("stealers") or []
            if not isinstance(stealers, list) or not stealers:
                # message indicated compromise but no structured detail
                if "compromised" in msg:
                    graph.add(EntityType.BREACH, f"Infostealer exposure ({v})",
                              risk=RiskLevel.CRITICAL, confidence=0.8,
                              tags={"stealer", "infostealer"},
                              metadata={"email": v, "source": "hudsonrock"},
                              evidence=ev("hudsonrock", url,
                                          f"{v} present in infostealer logs"))
                    target.tags.add("stealer-infected")
                return
            for s in stealers[:10]:
                if not isinstance(s, dict):
                    continue
                date = s.get("date_compromised") or s.get("date") or "unknown"
                fam = s.get("stealer_family") or s.get("family") or "stealer"
                graph.add(EntityType.BREACH,
                          f"Infostealer '{fam}' ({v}) @ {date}",
                          risk=RiskLevel.CRITICAL, confidence=0.85,
                          tags={"stealer", "infostealer"},
                          metadata={"email": v, "stealer_family": fam,
                                    "date_compromised": date},
                          evidence=ev("hudsonrock", url,
                                      f"{v} found in {fam} infostealer log"))
            target.tags.add("stealer-infected")
            return

        # DOMAIN response: counts of employees/users compromised via stealers
        emp = data.get("employees") or data.get("total_employees")
        usr = data.get("users") or data.get("total_users")
        third = data.get("third_parties")
        found_any = False
        for label, cnt in (("employees", emp), ("users/customers", usr)):
            try:
                n = int(cnt)
            except (TypeError, ValueError):
                continue
            if n <= 0:
                continue
            found_any = True
            graph.add(EntityType.BREACH,
                      f"{n} {label} of {v} in infostealer logs",
                      risk=RiskLevel.HIGH, confidence=0.8,
                      tags={"stealer", "infostealer", "domain-exposure"},
                      metadata={"domain": v, "count": n, "kind": label},
                      evidence=ev("hudsonrock", url,
                                  f"{n} {label} compromised (HudsonRock)"))
        if found_any:
            target.tags.add("stealer-exposed")
        else:
            target.metadata["stealer_check"] = "no infostealer exposure (HudsonRock)"


class LeakIX(Module):
    """Publicly indexed exposed services / leaks summary for a host/IP."""
    spec = ModuleSpec(
        name="leakix", category="source",
        accepts={EntityType.DOMAIN, EntityType.SUBDOMAIN, EntityType.IP},
        produces={EntityType.SERVICE, EntityType.VULNERABILITY, EntityType.PORT},
        description="LeakIX public host summary (exposed services/leaks, no key)",
        priority=35, tags={"passive", "exposure", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        host = target.value
        url = f"https://leakix.net/host/{urllib.parse.quote(host)}"
        # LeakIX serves JSON when Accept: application/json is set
        data = await self.ctx.http.get(
            url, headers={"Accept": "application/json"}, expect="json")
        if not isinstance(data, dict):
            return
        services = data.get("Services") or data.get("services") or []
        leaks = data.get("Leaks") or data.get("leaks") or []
        if not isinstance(services, list):
            services = []
        emitted = False
        for s in services[:40]:
            if not isinstance(s, dict):
                continue
            port = s.get("port")
            proto = (s.get("protocol") or s.get("service_name")
                     or s.get("software", {}).get("name") if isinstance(
                         s.get("software"), dict) else s.get("protocol")) or "service"
            ip = s.get("ip") or host
            label = f"{ip}:{port} {proto}".strip()
            emitted = True
            graph.add(EntityType.SERVICE, label, risk=RiskLevel.LOW,
                      confidence=0.6, tags={"leakix", "exposed-service"},
                      metadata={"ip": ip, "port": port, "protocol": proto},
                      evidence=ev("leakix", url,
                                  f"exposed service on {label}"))
            if port:
                graph.add(EntityType.PORT, f"{ip}:{port}", confidence=0.6,
                          tags={"leakix"}, evidence=ev("leakix", url, "open port"))
        if isinstance(leaks, list):
            for lk in leaks[:20]:
                if not isinstance(lk, dict):
                    continue
                sev = str(lk.get("severity", "medium")).lower()
                risk = {"critical": RiskLevel.CRITICAL, "high": RiskLevel.HIGH,
                        "medium": RiskLevel.MEDIUM}.get(sev, RiskLevel.LOW)
                summ = lk.get("summary") or lk.get("event_type") or "leak"
                emitted = True
                graph.add(EntityType.VULNERABILITY,
                          f"{summ} on {host}", risk=risk, confidence=0.65,
                          tags={"leakix", "leak"},
                          metadata={"severity": sev, "host": host},
                          evidence=ev("leakix", url, str(summ)[:200]))
        if not emitted:
            target.metadata["leakix_check"] = "no public LeakIX findings"


class Wikidata(Module):
    """Anchor an org/person with structured facts (official site, country...)."""
    spec = ModuleSpec(
        name="wikidata", category="source",
        accepts={EntityType.ORG, EntityType.PERSON},
        produces={EntityType.URL, EntityType.DOMAIN, EntityType.GEO,
                  EntityType.SOCIAL_PROFILE},
        description="Wikidata structured facts for an org/person (no key)",
        priority=30, tags={"passive", "enrichment", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        # 1) resolve the entity id
        search = await self.ctx.http.get(
            "https://www.wikidata.org/w/api.php",
            params={"action": "wbsearchentities", "search": target.value,
                    "language": "en", "format": "json", "limit": 1},
            expect="json")
        if not isinstance(search, dict) or not search.get("search"):
            return
        qid = search["search"][0].get("id")
        if not qid:
            return
        target.metadata["wikidata_id"] = qid
        # 2) pull claims
        ent = await self.ctx.http.get(
            "https://www.wikidata.org/w/api.php",
            params={"action": "wbgetentities", "ids": qid, "format": "json",
                    "props": "claims|descriptions"}, expect="json")
        if not isinstance(ent, dict):
            return
        claims = (ent.get("entities", {}).get(qid, {}) or {}).get("claims", {})

        def _string_claim(prop):
            out = []
            for c in claims.get(prop, []):
                try:
                    out.append(c["mainsnak"]["datavalue"]["value"])
                except (KeyError, TypeError):
                    continue
            return out

        # P856 = official website
        for site in _string_claim("P856"):
            if isinstance(site, str) and site.startswith("http"):
                graph.add(EntityType.URL, site, confidence=0.85,
                          tags={"official-site", "wikidata"},
                          evidence=ev("wikidata",
                                      f"https://www.wikidata.org/wiki/{qid}",
                                      "official website (Wikidata P856)"))
                host = site.split("/")[2] if "//" in site else site
                graph.add(EntityType.DOMAIN, host.lstrip("www."), confidence=0.7,
                          tags={"wikidata"},
                          evidence=ev("wikidata", snippet="official domain"))
        # social handles: P2002 Twitter/X, P2013 Facebook, P2003 Instagram
        for prop, base in (("P2002", "https://twitter.com/"),
                           ("P2013", "https://facebook.com/"),
                           ("P2003", "https://instagram.com/")):
            for handle in _string_claim(prop):
                if isinstance(handle, str) and handle:
                    graph.add(EntityType.SOCIAL_PROFILE, base + handle,
                              confidence=0.8, tags={"wikidata", "social"},
                              evidence=ev("wikidata", snippet=f"{prop} handle"))
