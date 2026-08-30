"""
GENIUS MODULE #5 - Wayback "Removed Secrets" Diffing.

Out-of-the-box idea: companies delete sensitive files/pages when they realize
they're exposed - but the Wayback Machine still has the OLD snapshot. This
module finds URLs that:
    (a) were archived historically, AND
    (b) now return 404/403/moved (i.e. deliberately removed).
A file someone bothered to DELETE is high-signal. Argus retrieves the archived
copy of the most sensitive ones and scans them for secrets/emails/credentials.

This surfaces the "they thought they cleaned it up" class of leaks.
"""
from __future__ import annotations

import re

from ..core.models import EntityType, IntelGraph, RiskLevel
from ..core.module import Module, ModuleSpec
from ..sources._base import ev, extract_emails
from ..sources.github_dork import GitHubDork

INTERESTING = re.compile(
    r"\.(sql|env|bak|old|config|conf|json|xml|yml|yaml|log|txt|csv|"
    r"xls|xlsx|db|sqlite|pem|key|git)(\?|$)", re.I)


class WaybackDiff(Module):
    spec = ModuleSpec(
        name="wayback_diff", category="native",
        accepts={EntityType.DOMAIN},
        produces={EntityType.FILE, EntityType.SECRET, EntityType.EMAIL},
        description="Find + recover deliberately-removed sensitive files from archive",
        priority=52, tags={"native", "genius", "archive", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        dom = target.value
        cdx = (f"http://web.archive.org/cdx/search/cdx?url=*.{dom}/*"
               f"&output=json&fl=original,timestamp,statuscode"
               f"&filter=statuscode:200&collapse=urlkey&limit=4000")
        rows = await self.ctx.http.get(cdx, expect="json")
        if not isinstance(rows, list) or len(rows) < 2:
            return
        candidates = []
        for r in rows[1:]:
            u = r[0]
            ts = r[1] if len(r) > 1 else ""
            if INTERESTING.search(u):
                candidates.append((u, ts))
        # probe live status; if gone -> recover from archive
        checked = 0
        for u, ts in candidates[:40]:
            if checked >= 15:
                break
            live = await self.ctx.http.get(u, expect="response")
            code = getattr(live, "status_code", 0) if live else 0
            if code in (404, 403, 410, 0):
                checked += 1
                archived_url = f"https://web.archive.org/web/{ts}id_/{u}"
                body = await self.ctx.http.get(archived_url)
                risk = RiskLevel.HIGH
                fe = graph.add(EntityType.FILE, u, risk=risk, confidence=0.75,
                               tags={"removed", "recovered-from-archive"},
                               metadata={"archive": archived_url, "gone_status": code},
                               evidence=ev("wayback_diff", archived_url,
                                           f"file removed (HTTP {code}) but recoverable"))
                if body:
                    GitHubDork.scan_secrets(body, archived_url, graph,
                                            origin="wayback_diff")
                    for em in extract_emails(body, dom):
                        graph.add(EntityType.EMAIL, em, confidence=0.6,
                                  evidence=ev("wayback_diff", archived_url,
                                              "email in removed file"))
