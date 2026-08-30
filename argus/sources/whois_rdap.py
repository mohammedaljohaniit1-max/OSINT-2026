"""
RDAP + WHOIS - registration intel, NO KEY.

RDAP (the modern JSON WHOIS) gives registrar, dates, registrant org/emails
(when not redacted), and abuse contacts. Also RDAP for IP -> owning org/ASN.
"""
from __future__ import annotations

from ..core.models import EntityType, IntelGraph
from ..core.module import Module, ModuleSpec
from ._base import ev, extract_emails


class RDAPDomain(Module):
    spec = ModuleSpec(
        name="rdap_domain", category="source",
        accepts={EntityType.DOMAIN},
        produces={EntityType.EMAIL, EntityType.ORG, EntityType.PERSON},
        description="RDAP domain registration lookup", priority=20,
        tags={"passive", "whois", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        url = f"https://rdap.org/domain/{target.value}"
        data = await self.ctx.http.get(url, expect="json")
        if not isinstance(data, dict):
            return
        # events
        for evt in data.get("events", []):
            target.metadata[f"date_{evt.get('eventAction')}"] = evt.get("eventDate")
        # entities (registrant/registrar/abuse)
        blob = str(data)
        for em in extract_emails(blob):
            graph.add(EntityType.EMAIL, em, confidence=0.7, tags={"whois"},
                      evidence=ev("rdap_domain", url, "registration contact"))
        for entc in data.get("entities", []):
            for vc in entc.get("vcardArray", [[], []])[1:]:
                for item in vc:
                    if isinstance(item, list) and item and item[0] == "org":
                        graph.add(EntityType.ORG, str(item[-1]), confidence=0.6,
                                  evidence=ev("rdap_domain", url))


class RDAPIp(Module):
    spec = ModuleSpec(
        name="rdap_ip", category="source",
        accepts={EntityType.IP},
        produces={EntityType.ASN, EntityType.ORG, EntityType.CIDR},
        description="RDAP IP -> ASN/owner/CIDR", priority=22,
        tags={"passive", "whois", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        url = f"https://rdap.org/ip/{target.value}"
        data = await self.ctx.http.get(url, expect="json")
        if not isinstance(data, dict):
            return
        if data.get("name"):
            target.metadata["net_name"] = data["name"]
        # CIDR
        start, end = data.get("startAddress"), data.get("endAddress")
        if data.get("cidr0_cidrs"):
            for c in data["cidr0_cidrs"]:
                pref = c.get("v4prefix") or c.get("v6prefix")
                ln = c.get("length")
                if pref and ln is not None:
                    graph.add(EntityType.CIDR, f"{pref}/{ln}", confidence=0.7,
                              evidence=ev("rdap_ip", url))
        # ASN via arin
        for rem in data.get("remarks", []):
            pass


class BGPView(Module):
    spec = ModuleSpec(
        name="bgpview", category="source",
        accepts={EntityType.IP, EntityType.ASN},
        produces={EntityType.ASN, EntityType.CIDR, EntityType.ORG, EntityType.DOMAIN},
        description="BGPView ASN/IP -> prefixes, org, related domains", priority=24,
        tags={"passive", "asn", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        if target.type == EntityType.IP:
            url = f"https://api.bgpview.io/ip/{target.value}"
            data = await self.ctx.http.get(url, expect="json")
            if isinstance(data, dict) and data.get("data"):
                for p in data["data"].get("prefixes", []):
                    if p.get("prefix"):
                        graph.add(EntityType.CIDR, p["prefix"], confidence=0.7,
                                  evidence=ev("bgpview", url))
                    asn = p.get("asn", {})
                    if asn.get("asn"):
                        graph.add(EntityType.ASN, f"AS{asn['asn']}", confidence=0.7,
                                  evidence=ev("bgpview", url))
        else:  # ASN
            asn = target.value.upper().replace("AS", "")
            url = f"https://api.bgpview.io/asn/{asn}/prefixes"
            data = await self.ctx.http.get(url, expect="json")
            if isinstance(data, dict) and data.get("data"):
                for p in data["data"].get("ipv4_prefixes", [])[:200]:
                    if p.get("prefix"):
                        graph.add(EntityType.CIDR, p["prefix"], confidence=0.7,
                                  evidence=ev("bgpview", url))
