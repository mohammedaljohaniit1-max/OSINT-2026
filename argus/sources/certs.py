"""
Certificate Transparency sources - subdomain goldmine, NO API KEY.

crt.sh, and CertSpotter's free CT endpoint. CT logs record every TLS cert
issued, so they leak internal/forgotten subdomains that DNS never reveals.
"""
from __future__ import annotations

import json

from ..core.models import EntityType, IntelGraph
from ..core.module import Module, ModuleSpec
from ._base import clean_sub, ev


class CrtSh(Module):
    spec = ModuleSpec(
        name="crtsh", category="source",
        accepts={EntityType.DOMAIN},
        produces={EntityType.SUBDOMAIN, EntityType.CERTIFICATE},
        description="crt.sh Certificate Transparency subdomain enumeration",
        priority=10, tags={"passive", "subdomains", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        dom = target.value
        url = f"https://crt.sh/?q=%25.{dom}&output=json"
        data = await self.ctx.http.get(url, expect="json")
        if not data:
            return
        subs = set()
        for row in data:
            for field in ("name_value", "common_name"):
                for name in str(row.get(field, "")).split("\n"):
                    name = clean_sub(name)
                    if name.endswith(dom) and "*" not in name:
                        subs.add(name)
        for s in subs:
            etype = EntityType.SUBDOMAIN if s != dom else EntityType.DOMAIN
            graph.add(etype, s, confidence=0.8,
                      evidence=ev("crtsh", url, "CT log"))


class CertSpotter(Module):
    spec = ModuleSpec(
        name="certspotter", category="source",
        accepts={EntityType.DOMAIN},
        produces={EntityType.SUBDOMAIN},
        description="CertSpotter CT API (free tier, no key needed)",
        priority=11, tags={"passive", "subdomains", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        dom = target.value
        url = (f"https://api.certspotter.com/v1/issuances?domain={dom}"
               f"&include_subdomains=true&expand=dns_names")
        data = await self.ctx.http.get(url, expect="json")
        if not isinstance(data, list):
            return
        for row in data:
            for name in row.get("dns_names", []):
                name = clean_sub(name)
                if name.endswith(dom) and "*" not in name:
                    et = EntityType.SUBDOMAIN if name != dom else EntityType.DOMAIN
                    graph.add(et, name, confidence=0.8,
                              evidence=ev("certspotter", url, "CT issuance"))
