"""
GENIUS MODULE #1 - Favicon-Hash Pivoting.

Idea (out-of-the-box): every deployment of the same app/brand serves the SAME
favicon. Shodan/Censys index hosts by MurmurHash3 of the base64-encoded favicon
(the "favicon hash", exactly like Shodan's http.favicon.hash). So:

  1. Fetch the target's /favicon.ico.
  2. Compute its mmh3 hash (Shodan-compatible).
  3. This hash is a fingerprint that links ALL the org's other servers -
     including hidden ones behind different domains / IPs / CDNs.

Argus emits the FAVICON_HASH entity and a ready-to-run Shodan/Censys/FOFA query
string so the analyst can pivot instantly (works even with no Shodan key by
handing the query to the free Netlas/FOFA web UIs). This finds shadow-IT and
staging servers that share the corporate favicon but nothing else.
"""
from __future__ import annotations

import base64
import codecs

from ..core.models import EntityType, IntelGraph, RiskLevel
from ..core.module import Module, ModuleSpec
from ..sources._base import ev

try:
    import mmh3
    HAVE_MMH3 = True
except ImportError:
    HAVE_MMH3 = False


def favicon_hash(content: bytes) -> int:
    """Shodan-compatible favicon hash (mmh3 of standard-base64 with newlines)."""
    b64 = codecs.encode(content, "base64")
    return mmh3.hash(b64)


class FaviconPivot(Module):
    spec = ModuleSpec(
        name="favicon_pivot", category="native",
        accepts={EntityType.DOMAIN, EntityType.SUBDOMAIN, EntityType.URL},
        produces={EntityType.FAVICON_HASH},
        description="Favicon MurmurHash3 fingerprint -> pivot to sibling assets",
        priority=35, tags={"native", "genius", "pivot", "nokey"},
    )

    def available(self):
        return HAVE_MMH3

    async def run(self, target, graph: IntelGraph):
        host = target.value
        if not host.startswith("http"):
            host = "https://" + host
        for path in ("/favicon.ico", "/assets/favicon.ico", "/static/favicon.ico"):
            content = await self.ctx.http.get(host.rstrip("/") + path, expect="bytes")
            if content and len(content) > 50:
                h = favicon_hash(content)
                queries = {
                    "shodan": f"http.favicon.hash:{h}",
                    "censys": f"services.http.response.favicons.md5_hash",
                    "fofa": f'icon_hash="{h}"',
                    "netlas": f"http.favicon.hash_sha256",
                    "zoomeye": f"iconhash:\"{h}\"",
                }
                e = graph.add(EntityType.FAVICON_HASH, str(h),
                              risk=RiskLevel.LOW, confidence=0.85,
                              tags={"favicon", "pivot"},
                              metadata={"pivot_queries": queries,
                                        "linked_hosts": [target.value]},
                              evidence=ev("favicon_pivot", host + path,
                                          f"favicon mmh3={h} -> FOFA icon_hash query"))
                # hint for the report: how to expand
                e.metadata["howto"] = (
                    f"Paste into FOFA: icon_hash=\"{h}\"  (free web UI) to reveal "
                    f"every server on the internet serving this exact favicon.")
                return
