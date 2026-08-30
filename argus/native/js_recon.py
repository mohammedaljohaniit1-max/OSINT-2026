"""
GENIUS MODULE #3 - JavaScript Endpoint & Secret Extraction.

Modern web apps ship their entire API surface inside JS bundles. This module:
  1. Fetches the target page, extracts every <script src> + inline script.
  2. Downloads the JS files.
  3. Mines them (LinkFinder/SecretFinder-style) for:
        - hidden API endpoints / paths  (/api/v2/internal/... )
        - hardcoded secrets (reuses github_dork.SECRET_REGEXES)
        - tracker IDs (GA/GTM/AdSense) -> feeds the tracker-pivot module
        - cloud bucket URLs (S3/GCS/Azure)
This routinely surfaces internal admin endpoints and leaked keys that no
subdomain tool ever sees.
"""
from __future__ import annotations

import re

from ..core.models import EntityType, IntelGraph, RiskLevel
from ..core.module import Module, ModuleSpec
from ..sources._base import ev
from ..sources.github_dork import GitHubDork

RE_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
RE_ENDPOINT = re.compile(
    r'["\'`](/(?:api|v\d|internal|admin|graphql|rest|service|auth|user|account)'
    r'[a-zA-Z0-9_\-/.?=&{}]{2,120})["\'`]')
RE_FULLURL = re.compile(r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{6,180}')
RE_BUCKET = re.compile(
    r'([a-z0-9.\-]{3,63}\.s3[.\-][a-z0-9\-]*\.amazonaws\.com'
    r'|s3\.amazonaws\.com/[a-z0-9.\-]{3,63}'
    r'|[a-z0-9.\-]{3,63}\.storage\.googleapis\.com'
    r'|[a-z0-9.\-]{3,63}\.blob\.core\.windows\.net)', re.I)
RE_GA = re.compile(r'\b(UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{6,12}|GTM-[A-Z0-9]{4,8})\b')
RE_ADSENSE = re.compile(r'\b(ca-pub-\d{10,20})\b')


class JSRecon(Module):
    spec = ModuleSpec(
        name="js_recon", category="native",
        accepts={EntityType.DOMAIN, EntityType.SUBDOMAIN, EntityType.URL},
        produces={EntityType.URL, EntityType.SECRET, EntityType.BUCKET,
                  EntityType.TRACKER_ID},
        description="Extract hidden endpoints/secrets/buckets/trackers from JS",
        priority=48, tags={"native", "genius", "js", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        base = target.value
        if not base.startswith("http"):
            base = "https://" + base
        html = await self.ctx.http.get(base)
        if not html:
            return
        scripts = RE_SCRIPT_SRC.findall(html)
        # resolve relative
        js_urls = []
        for s in scripts[:25]:
            if s.startswith("//"):
                s = "https:" + s
            elif s.startswith("/"):
                s = base.rstrip("/") + s
            elif not s.startswith("http"):
                s = base.rstrip("/") + "/" + s
            js_urls.append(s)

        corpus = html
        for ju in js_urls:
            body = await self.ctx.http.get(ju)
            if body:
                corpus += "\n" + body
        self._mine(corpus, base, graph)

    def _mine(self, corpus: str, source_url: str, graph: IntelGraph):
        # endpoints
        for m in set(RE_ENDPOINT.findall(corpus)):
            risk = RiskLevel.MEDIUM if re.search(r"admin|internal|auth|token", m) else RiskLevel.LOW
            graph.add(EntityType.URL, m, risk=risk, confidence=0.55,
                      tags={"js-endpoint"},
                      evidence=ev("js_recon", source_url, "endpoint in JS"))
        # buckets
        for m in set(RE_BUCKET.findall(corpus)):
            b = m if isinstance(m, str) else m[0]
            graph.add(EntityType.BUCKET, b, risk=RiskLevel.HIGH, confidence=0.7,
                      tags={"cloud-bucket"},
                      evidence=ev("js_recon", source_url, "cloud bucket ref in JS"))
        # trackers
        for m in set(RE_GA.findall(corpus)) | set(RE_ADSENSE.findall(corpus)):
            tid = m if isinstance(m, str) else m[0]
            graph.add(EntityType.TRACKER_ID, tid, confidence=0.8,
                      tags={"tracker", "pivot"},
                      metadata={"linked_hosts": [source_url]},
                      evidence=ev("js_recon", source_url, "analytics/ads id"))
        # secrets (reuse the battery)
        GitHubDork.scan_secrets(corpus, source_url, graph, origin="js_recon")
