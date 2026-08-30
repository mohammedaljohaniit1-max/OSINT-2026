"""
GENIUS MODULE #9 - Cloud Bucket / Storage Hunter.

Out-of-the-box idea: companies leak data in misconfigured public buckets. This
module generates likely bucket names from the org/domain (like s3scanner +
cloud_enum) and checks S3 / GCS / Azure for existence & PUBLIC LISTING - all
via anonymous HTTP, NO KEY. A world-readable bucket = HIGH/CRITICAL.
"""
from __future__ import annotations

import asyncio

from ..core.models import EntityType, IntelGraph, RiskLevel
from ..core.module import Module, ModuleSpec
from ..sources._base import ev

AFFIXES = ["", "-prod", "-dev", "-staging", "-backup", "-backups", "-data",
           "-assets", "-static", "-media", "-uploads", "-logs", "-db",
           "-private", "-public", "-files", "-storage", "-archive", "-bucket",
           "prod", "dev", "backup", "assets", "static", "media"]


def candidates(name: str) -> list[str]:
    base = name.split(".")[0]
    names = set()
    for a in AFFIXES:
        names.add(f"{base}{a}")
        names.add(f"{a}{base}" if not a.startswith("-") else f"{base}{a}")
    return list(names)


class BucketHunter(Module):
    spec = ModuleSpec(
        name="bucket_hunter", category="native",
        accepts={EntityType.DOMAIN, EntityType.ORG},
        produces={EntityType.BUCKET},
        description="Enumerate + test public S3/GCS/Azure buckets (anon, no key)",
        priority=62, tags={"native", "genius", "cloud", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        names = candidates(target.value)[:60]

        async def test(n):
            urls = {
                "s3": f"https://{n}.s3.amazonaws.com/",
                "gcs": f"https://storage.googleapis.com/{n}/",
                "azure": f"https://{n}.blob.core.windows.net/{n}?restype=container&comp=list",
            }
            for kind, url in urls.items():
                r = await self.ctx.http.get(url, expect="response")
                if r is None:
                    continue
                code = getattr(r, "status_code", 0)
                body = getattr(r, "text", "") or ""
                if code == 200 and ("<ListBucketResult" in body
                                    or "<EnumerationResults" in body
                                    or "<Contents>" in body):
                    graph.add(EntityType.BUCKET, url, risk=RiskLevel.CRITICAL,
                              confidence=0.85, tags={"cloud", "public-listing", kind},
                              evidence=ev("bucket_hunter", url,
                                          f"PUBLIC {kind} bucket - directory listing open"))
                elif code in (403,):
                    graph.add(EntityType.BUCKET, url, risk=RiskLevel.MEDIUM,
                              confidence=0.6, tags={"cloud", "exists-private", kind},
                              evidence=ev("bucket_hunter", url,
                                          f"{kind} bucket exists (private)"))

        sem = asyncio.Semaphore(20)

        async def bounded(n):
            async with sem:
                await test(n)
        await asyncio.gather(*[bounded(n) for n in names])
