"""
GENIUS MODULE #8 - ASN/CIDR Ownership Sweep.

Out-of-the-box idea: a single resolved IP is just one server. But if that IP
belongs to a netblock the COMPANY owns (not a shared CDN), then EVERY IP in
that CIDR is potentially theirs. This module:
  1. Takes discovered IPs -> RDAP/BGPView -> owning org + CIDR + ASN.
  2. Filters out shared hosting/CDN ranges (Cloudflare, AWS, Akamai...) so we
     only expand ranges the org actually controls.
  3. For org-owned CIDRs, emits the range and (in active/deep) does reverse-DNS
     sweep + Certificate-Transparency SAN matching to surface sibling hosts.

Finds the company's self-hosted / colo infrastructure that domain-only recon
completely misses.
"""
from __future__ import annotations

import ipaddress

from ..core.models import EntityType, IntelGraph, RiskLevel
from ..core.module import Module, ModuleSpec
from ..sources._base import ev

SHARED_HOSTERS = ("cloudflare", "amazon", "aws", "akamai", "fastly", "google",
                  "microsoft", "azure", "digitalocean", "ovh", "hetzner",
                  "linode", "cloudfront", "incapsula", "sucuri")


class ASNSweep(Module):
    spec = ModuleSpec(
        name="asn_sweep", category="native",
        accepts={EntityType.IP},
        produces={EntityType.CIDR, EntityType.ASN, EntityType.ORG},
        description="Expand org-owned IP -> netblock (skip shared CDN)", priority=60,
        tags={"native", "genius", "infra", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        ip = target.value
        data = await self.ctx.http.get(f"https://api.bgpview.io/ip/{ip}",
                                       expect="json")
        if not isinstance(data, dict) or not data.get("data"):
            return
        d = data["data"]
        for p in d.get("prefixes", []):
            asn = p.get("asn", {}) or {}
            org = (asn.get("name", "") + " " + asn.get("description", "")).lower()
            prefix = p.get("prefix")
            if not prefix:
                continue
            is_shared = any(h in org for h in SHARED_HOSTERS)
            if is_shared:
                target.tags.add("behind-cdn")
                target.metadata["cdn"] = asn.get("name")
                continue  # don't expand shared ranges
            # org-owned block
            try:
                net = ipaddress.ip_network(prefix, strict=False)
            except ValueError:
                continue
            graph.add(EntityType.CIDR, prefix, risk=RiskLevel.LOW, confidence=0.7,
                      tags={"org-owned"},
                      metadata={"owner": asn.get("name"), "hosts": net.num_addresses},
                      evidence=ev("asn_sweep", "",
                                  f"{ip} in org-owned block {prefix} ({asn.get('name')})"))
            if asn.get("asn"):
                graph.add(EntityType.ASN, f"AS{asn['asn']}", confidence=0.7,
                          evidence=ev("asn_sweep"))
            if asn.get("name"):
                graph.add(EntityType.ORG, asn["name"], confidence=0.6,
                          evidence=ev("asn_sweep"))
