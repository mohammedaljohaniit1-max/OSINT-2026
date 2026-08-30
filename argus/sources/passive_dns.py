"""
Passive DNS & subdomain aggregators - NO API KEY.

  - HackerTarget hostsearch (free, rate-limited)
  - AlienVault OTX passive DNS
  - ThreatCrowd (legacy but still answers)
  - RapidDNS scrape
  - Anubis-DB
These each know subdomains the others don't; union = huge coverage.
"""
from __future__ import annotations

import json
import re

from ..core.models import EntityType, IntelGraph
from ..core.module import Module, ModuleSpec
from ._base import clean_sub, ev


class HackerTarget(Module):
    spec = ModuleSpec(
        name="hackertarget", category="source",
        accepts={EntityType.DOMAIN}, produces={EntityType.SUBDOMAIN, EntityType.IP},
        description="HackerTarget hostsearch passive DNS", priority=15,
        tags={"passive", "subdomains", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        url = f"https://api.hackertarget.com/hostsearch/?q={target.value}"
        txt = await self.ctx.http.get(url)
        if not txt or "error" in txt.lower():
            return
        for line in txt.splitlines():
            if "," in line:
                host, ip = line.split(",", 1)
                host = clean_sub(host)
                if host.endswith(target.value):
                    graph.add(EntityType.SUBDOMAIN, host, confidence=0.75,
                              evidence=ev("hackertarget", url))
                    if re.match(r"\d+\.\d+\.\d+\.\d+", ip.strip()):
                        graph.add(EntityType.IP, ip.strip(), confidence=0.7,
                                  evidence=ev("hackertarget", url))


class OTX(Module):
    spec = ModuleSpec(
        name="otx", category="source",
        accepts={EntityType.DOMAIN, EntityType.IP},
        produces={EntityType.SUBDOMAIN},
        description="AlienVault OTX passive DNS (no key required)", priority=15,
        tags={"passive", "subdomains", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        url = (f"https://otx.alienvault.com/api/v1/indicators/domain/"
               f"{target.value}/passive_dns")
        data = await self.ctx.http.get(url, expect="json")
        if not isinstance(data, dict):
            return
        for row in data.get("passive_dns", []):
            host = clean_sub(row.get("hostname", ""))
            if host.endswith(target.value) and "*" not in host:
                graph.add(EntityType.SUBDOMAIN, host, confidence=0.7,
                          evidence=ev("otx", url))


class RapidDNS(Module):
    spec = ModuleSpec(
        name="rapiddns", category="source",
        accepts={EntityType.DOMAIN}, produces={EntityType.SUBDOMAIN},
        description="RapidDNS.io subdomain scrape", priority=16,
        tags={"passive", "subdomains", "nokey", "scrape"},
    )

    async def run(self, target, graph: IntelGraph):
        url = f"https://rapiddns.io/subdomain/{target.value}?full=1"
        html = await self.ctx.http.get(url)
        if not html:
            return
        found = set(re.findall(r"<td>((?:[\w\-]+\.)+[\w\-]+)</td>", html))
        for host in found:
            host = clean_sub(host)
            if host.endswith(target.value):
                graph.add(EntityType.SUBDOMAIN, host, confidence=0.65,
                          evidence=ev("rapiddns", url))


class AnubisDB(Module):
    spec = ModuleSpec(
        name="anubisdb", category="source",
        accepts={EntityType.DOMAIN}, produces={EntityType.SUBDOMAIN},
        description="Anubis-DB (jonlu.ca) subdomain dataset", priority=16,
        tags={"passive", "subdomains", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        url = f"https://jldc.me/anubis/subdomains/{target.value}"
        data = await self.ctx.http.get(url, expect="json")
        if not isinstance(data, list):
            return
        for host in data:
            host = clean_sub(host)
            if host.endswith(target.value):
                graph.add(EntityType.SUBDOMAIN, host, confidence=0.65,
                          evidence=ev("anubisdb", url))


class ThreatCrowd(Module):
    spec = ModuleSpec(
        name="threatcrowd", category="source",
        accepts={EntityType.DOMAIN}, produces={EntityType.SUBDOMAIN, EntityType.EMAIL},
        description="ThreatCrowd domain report", priority=18,
        tags={"passive", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        url = ("https://www.threatcrowd.org/searchApi/v2/domain/report/"
               f"?domain={target.value}")
        data = await self.ctx.http.get(url, expect="json")
        if not isinstance(data, dict):
            return
        for host in data.get("subdomains", []) or []:
            host = clean_sub(host)
            if host.endswith(target.value):
                graph.add(EntityType.SUBDOMAIN, host, confidence=0.6,
                          evidence=ev("threatcrowd", url))
        for em in data.get("emails", []) or []:
            graph.add(EntityType.EMAIL, em, confidence=0.6,
                      evidence=ev("threatcrowd", url))
