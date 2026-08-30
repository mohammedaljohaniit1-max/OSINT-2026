"""
Live DNS resolution + record harvesting (dnspython). NO KEY.

Resolves A/AAAA/MX/NS/TXT/SOA/CNAME, extracts SPF/DMARC (email-security posture),
and turns MX/NS into new entities to pivot on. Also does reverse DNS on IPs.
"""
from __future__ import annotations

import asyncio

from ..core.models import EntityType, IntelGraph, RiskLevel
from ..core.module import Module, ModuleSpec
from ._base import ev

try:
    import dns.resolver
    import dns.reversename
    HAVE_DNS = True
except ImportError:
    HAVE_DNS = False


class DNSRecords(Module):
    spec = ModuleSpec(
        name="dns_records", category="source",
        accepts={EntityType.DOMAIN, EntityType.SUBDOMAIN},
        produces={EntityType.IP, EntityType.DNS_RECORD, EntityType.DOMAIN},
        description="Resolve A/MX/NS/TXT + SPF/DMARC posture", priority=20,
        tags={"passive", "dns", "nokey"},
    )

    def available(self):
        return HAVE_DNS

    async def run(self, target, graph: IntelGraph):
        dom = target.value
        res = dns.resolver.Resolver()
        res.timeout = 5
        res.lifetime = 5

        async def q(rtype):
            try:
                return await asyncio.to_thread(res.resolve, dom, rtype)
            except Exception:
                return []

        # A / AAAA
        for rtype in ("A", "AAAA"):
            for rr in await q(rtype):
                graph.add(EntityType.IP, str(rr), confidence=0.85,
                          evidence=ev("dns_records", snippet=rtype))
        # MX
        for rr in await q("MX"):
            mx = str(rr.exchange).rstrip(".")
            graph.add(EntityType.DNS_RECORD, f"MX:{mx}", confidence=0.8,
                      evidence=ev("dns_records"))
        # NS
        for rr in await q("NS"):
            graph.add(EntityType.DNS_RECORD, f"NS:{str(rr).rstrip('.')}",
                      confidence=0.8, evidence=ev("dns_records"))
        # TXT: SPF/DMARC posture
        spf = dmarc = None
        for rr in await q("TXT"):
            txt = str(rr).strip('"')
            if txt.startswith("v=spf1"):
                spf = txt
            graph.add(EntityType.DNS_RECORD, f"TXT:{txt[:80]}", confidence=0.7,
                      evidence=ev("dns_records"))
        try:
            for rr in await asyncio.to_thread(res.resolve, f"_dmarc.{dom}", "TXT"):
                dmarc = str(rr).strip('"')
        except Exception:
            pass
        # email-security scoring
        if target.type == EntityType.DOMAIN:
            if not spf:
                graph.add(EntityType.VULNERABILITY, f"No SPF record on {dom}",
                          risk=RiskLevel.MEDIUM, confidence=0.9,
                          evidence=ev("dns_records", snippet="missing SPF -> spoofable"))
            if not dmarc or "p=none" in (dmarc or ""):
                graph.add(EntityType.VULNERABILITY,
                          f"Weak/missing DMARC on {dom}",
                          risk=RiskLevel.MEDIUM, confidence=0.85,
                          evidence=ev("dns_records", snippet=dmarc or "no DMARC"))


class ReverseDNS(Module):
    spec = ModuleSpec(
        name="reverse_dns", category="source",
        accepts={EntityType.IP}, produces={EntityType.DOMAIN, EntityType.SUBDOMAIN},
        description="Reverse DNS (PTR) lookup on IPs", priority=25,
        tags={"passive", "dns", "nokey"},
    )

    def available(self):
        return HAVE_DNS

    async def run(self, target, graph: IntelGraph):
        try:
            rev = dns.reversename.from_address(target.value)
            ans = await asyncio.to_thread(dns.resolver.resolve, rev, "PTR")
            for rr in ans:
                host = str(rr).rstrip(".")
                graph.add(EntityType.SUBDOMAIN, host, confidence=0.6,
                          evidence=ev("reverse_dns", snippet="PTR"))
        except Exception:
            pass
