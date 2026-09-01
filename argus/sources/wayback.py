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

# HIGH-SIGNAL only: real leak/backup/secret file extensions. The old pattern
# also matched .json/.xml/.log/.conf which flagged thousands of ordinary URLs
# as "sensitive" (8966 FILE entities on x.com — pure noise that buried signal).
SENSITIVE_EXT = re.compile(
    r"\.(sql|bak|old|backup|zip|tar\.gz|tgz|env|db|sqlite|dump|"
    r"pem|key|p12|pfx|kdbx|passwd|htpasswd)(\?|$)", re.I)
SENSITIVE_PATH = re.compile(
    r"(/\.git/|/\.env|wp-config\.php|/backup|/dump|phpinfo|/\.svn/|"
    r"/id_rsa|/credentials|/secrets?\.|/\.aws/|/\.ssh/|/config\.php\.bak)", re.I)
# how many FILE findings to keep per host (dedup + cap to avoid floods)
MAX_FILES_PER_HOST = 60


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
        files_kept = 0
        seen_files = set()
        for row in data[1:]:
            u = row[0] if isinstance(row, list) else row
            if not u:
                continue
            # subdomain harvest (always — this is the real value of the archive)
            m = re.search(r"https?://([^/]+)/?", u)
            if m:
                host = clean_sub(m.group(1).split(":")[0])
                if host.endswith(dom) and host not in seen_hosts:
                    seen_hosts.add(host)
                    graph.add(EntityType.SUBDOMAIN, host, confidence=0.6,
                              evidence=ev("wayback", u))
            # sensitive file/path — HIGH-SIGNAL only, deduped and capped so a
            # handful of real leaks aren't buried under thousands of URLs.
            if files_kept < MAX_FILES_PER_HOST and (
                    SENSITIVE_EXT.search(u) or SENSITIVE_PATH.search(u)):
                key = u.split("?")[0]
                if key in seen_files:
                    continue
                seen_files.add(key)
                files_kept += 1
                graph.add(EntityType.FILE, u, risk=RiskLevel.HIGH, confidence=0.7,
                          tags={"archived", "sensitive"},
                          evidence=ev("wayback", u, "archived sensitive file"))


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
