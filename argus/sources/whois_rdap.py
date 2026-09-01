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

    # generic registrar / privacy / abuse mailbox owners — NEVER a real person
    # tied to the target org. Emails at these domains (or with these local parts)
    # must be recorded as registrar contacts and NOT cascaded into breach/holehe.
    REGISTRAR_DOMAINS = {
        "godaddy.com", "markmonitor.com", "wix.com", "web.com", "aws.com",
        "namecheap.com", "cloudflare.com", "gandi.net", "ovh.net", "ovh.com",
        "enom.com", "tucows.com", "publicdomainregistry.com", "name.com",
        "networksolutions.com", "google.com", "amazon.com", "alpinedomains.com",
        "whoisguard.com", "domainsbyproxy.com", "contactprivacy.com",
        "withheldforprivacy.com", "privacyprotect.org", "1and1.com", "ionos.com",
    }
    REGISTRAR_LOCALPARTS = {"abuse", "abusecomplaints", "domainabuse",
                            "domain-abuse", "domainops", "domainadmin",
                            "hostmaster", "trustandsafety", "noc", "registrar",
                            "support", "privacy", "compliance"}

    def _is_registrar_contact(self, email: str) -> bool:
        local, _, dom = email.lower().partition("@")
        return dom in self.REGISTRAR_DOMAINS or local in self.REGISTRAR_LOCALPARTS

    async def run(self, target, graph: IntelGraph):
        url = f"https://rdap.org/domain/{target.value}"
        data = await self.ctx.http.get(url, expect="json")
        if not isinstance(data, dict):
            return
        # events (creation / expiry / update dates)
        for evt in data.get("events", []):
            target.metadata[f"date_{evt.get('eventAction')}"] = evt.get("eventDate")
        # registrar name (info only)
        registrar = None
        for entc in data.get("entities", []):
            roles = entc.get("roles", [])
            for vc in entc.get("vcardArray", [[], []])[1:]:
                for item in vc:
                    if isinstance(item, list) and item and item[0] == "org":
                        org_name = str(item[-1])
                        if "registrar" in roles:
                            registrar = org_name
                        else:
                            # only registrant/admin org is a real pivot
                            graph.add(EntityType.ORG, org_name, confidence=0.6,
                                      tags={"whois-org"},
                                      evidence=ev("rdap_domain", url,
                                                  f"{','.join(roles) or 'org'}"))
        if registrar:
            target.metadata["registrar"] = registrar

        # emails: separate REGISTRAR/abuse contacts (dead-ends) from any genuine
        # registrant email. Registrar contacts are tagged so the scope guard
        # blocks breach/holehe cascade (fixes the abuse@godaddy.com fake breaches).
        blob = str(data)
        for em in extract_emails(blob):
            if self._is_registrar_contact(em):
                graph.add(EntityType.EMAIL, em, confidence=0.3,
                          tags={"whois", "registrar-contact", "no-expand"},
                          metadata={"role": "registrar/abuse contact",
                                    "finding_only": True},
                          evidence=ev("rdap_domain", url,
                                      "registrar/abuse contact (not a target user)"))
            else:
                graph.add(EntityType.EMAIL, em, confidence=0.6,
                          tags={"whois", "registrant"},
                          evidence=ev("rdap_domain", url, "registrant contact"))


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
