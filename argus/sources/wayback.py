"""
Wayback Machine + Common Crawl + URLScan - archived-URL intelligence. NO KEY.

Archived URLs reveal: old endpoints, admin panels, parameters, leaked files
(.sql/.env/.bak), API paths, and emails embedded in historical pages. Argus
mines the archive index (CDX) which is fast and unauthenticated.
"""
from __future__ import annotations

import json
import re

from ..core.models import EntityType, IntelGraph, RiskLevel
from ..core.module import Module, ModuleSpec
from ._base import clean_sub, ev, extract_emails

SENSITIVE_EXT = re.compile(
    r"\.(sql|bak|old|zip|tar|gz|env|config|conf|log|json|xml|db|sqlite|"
    r"pem|key|p12|pfx|git|svn|yml|yaml|ini|passwd|htpasswd)(\?|$)", re.I)
SENSITIVE_PATH = re.compile(
    r"(admin|login|backup|dump|phpinfo|\.git|wp-config|debug|test|api/|"
    r"internal|staging|dev|secret|token|password|swagger|graphql)", re.I)


class Wayback(Module):
    spec = ModuleSpec(
        name="wayback", category="source",
        accepts={EntityType.DOMAIN, EntityType.SUBDOMAIN},
        produces={EntityType.URL, EntityType.SUBDOMAIN, EntityType.FILE,
                  EntityType.EMAIL},
        description="Wayback CDX archived URL mining + sensitive-file flagging",
        priority=30, tags={"passive", "archive", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        dom = target.value
        url = (f"http://web.archive.org/cdx/search/cdx?url=*.{dom}/*"
               f"&output=json&fl=original&collapse=urlkey&limit=8000")
        data = await self.ctx.http.get(url, expect="json")
        if not isinstance(data, list) or len(data) < 2:
            return
        seen_hosts = set()
        for row in data[1:]:
            u = row[0] if isinstance(row, list) else row
            if not u:
                continue
            # subdomain harvest
            m = re.search(r"https?://([^/]+)/?", u)
            if m:
                host = clean_sub(m.group(1).split(":")[0])
                if host.endswith(dom) and host not in seen_hosts:
                    seen_hosts.add(host)
                    graph.add(EntityType.SUBDOMAIN, host, confidence=0.6,
                              evidence=ev("wayback", u))
            # sensitive file/path
            if SENSITIVE_EXT.search(u) or SENSITIVE_PATH.search(u):
                risk = RiskLevel.HIGH if SENSITIVE_EXT.search(u) else RiskLevel.MEDIUM
                graph.add(EntityType.FILE, u, risk=risk, confidence=0.7,
                          tags={"archived", "sensitive"},
                          evidence=ev("wayback", u, "archived sensitive URL"))


class CommonCrawl(Module):
    spec = ModuleSpec(
        name="commoncrawl", category="source",
        accepts={EntityType.DOMAIN},
        produces={EntityType.URL, EntityType.SUBDOMAIN},
        description="Common Crawl index URL/subdomain mining", priority=32,
        tags={"passive", "archive", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        # latest index; endpoint list is public
        idx = "https://index.commoncrawl.org/CC-MAIN-2024-33-index"
        url = f"{idx}?url=*.{target.value}&output=json&limit=3000"
        txt = await self.ctx.http.get(url)
        if not txt:
            return
        hosts = set()
        for line in txt.splitlines():
            try:
                rec = json.loads(line)
            except Exception:
                continue
            u = rec.get("url", "")
            m = re.search(r"https?://([^/]+)/?", u)
            if m:
                host = clean_sub(m.group(1).split(":")[0])
                if host.endswith(target.value):
                    hosts.add(host)
        for h in hosts:
            graph.add(EntityType.SUBDOMAIN, h, confidence=0.55,
                      evidence=ev("commoncrawl", idx))


class URLScan(Module):
    spec = ModuleSpec(
        name="urlscan", category="source",
        accepts={EntityType.DOMAIN, EntityType.SUBDOMAIN},
        produces={EntityType.URL, EntityType.SUBDOMAIN, EntityType.IP,
                  EntityType.TECHNOLOGY},
        description="urlscan.io public scans (no key for search)", priority=30,
        tags={"passive", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        url = f"https://urlscan.io/api/v1/search/?q=domain:{target.value}&size=1000"
        data = await self.ctx.http.get(url, expect="json")
        if not isinstance(data, dict):
            return
        for res in data.get("results", []):
            page = res.get("page", {})
            host = clean_sub(page.get("domain", ""))
            if host.endswith(target.value):
                graph.add(EntityType.SUBDOMAIN, host, confidence=0.6,
                          evidence=ev("urlscan", res.get("result", "")))
            if page.get("ip"):
                graph.add(EntityType.IP, page["ip"], confidence=0.6,
                          evidence=ev("urlscan"))
