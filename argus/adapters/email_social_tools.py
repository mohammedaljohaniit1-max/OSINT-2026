"""
Adapters for email / people / social tools.

theHarvester (emails+subs+hosts), holehe (email->accounts on 120+ sites),
sherlock/maigret (username->profiles), GHunt hint. Used if installed.
"""
from __future__ import annotations

import json
import re
import tempfile

from ..core.models import EntityType, IntelGraph
from ..core.module import Module, ModuleSpec
from ..sources._base import ev, extract_emails, clean_sub
from ._base import run_cmd


class TheHarvester(Module):
    spec = ModuleSpec(
        name="theharvester", category="adapter", external_bin="theHarvester",
        accepts={EntityType.DOMAIN},
        produces={EntityType.EMAIL, EntityType.SUBDOMAIN, EntityType.IP},
        description="theHarvester (emails/subs/hosts from many engines)",
        priority=20, tags={"adapter", "email"},
    )

    async def run(self, target, graph: IntelGraph):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            base = tf.name[:-5]
        code, out, _ = await run_cmd(
            ["theHarvester", "-d", target.value, "-b",
             "duckduckgo,bing,crtsh,anubis,otx,rapiddns,threatminer",
             "-f", base], timeout=300)
        try:
            with open(base + ".json") as f:
                data = json.load(f)
            for em in data.get("emails", []):
                graph.add(EntityType.EMAIL, em, confidence=0.75,
                          evidence=ev("theharvester"))
            for h in data.get("hosts", []):
                host = clean_sub(h.split(":")[0])
                if host.endswith(target.value):
                    graph.add(EntityType.SUBDOMAIN, host, confidence=0.75,
                              evidence=ev("theharvester"))
        except Exception:
            for em in extract_emails(out, target.value):
                graph.add(EntityType.EMAIL, em, confidence=0.7,
                          evidence=ev("theharvester"))


class Holehe(Module):
    spec = ModuleSpec(
        name="holehe", category="adapter", external_bin="holehe",
        accepts={EntityType.EMAIL}, produces={EntityType.SOCIAL_PROFILE},
        description="holehe: which sites an email is registered on",
        priority=22, tags={"adapter", "email", "social"},
    )

    async def run(self, target, graph: IntelGraph):
        # structured CSV output is far more reliable than parsing the pretty table
        import csv
        import io
        import os
        import tempfile
        tmpdir = tempfile.mkdtemp()
        code, out, err = await run_cmd(
            ["holehe", "--only-used", "-C", target.value], timeout=200)
        parsed = False
        # holehe -C writes <email>.csv in the CWD of the process; but since we
        # can't easily set cwd here, fall back to robust stdout parsing.
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("[+]"):
                continue
            site = line[3:].strip()
            # REJECT holehe's legend/header line and any non-domain token
            if "email used" in site.lower() or "rate limit" in site.lower():
                continue
            if not self._looks_like_site(site):
                continue
            parsed = True
            graph.add(EntityType.SOCIAL_PROFILE, f"{target.value} @ {site}",
                      confidence=0.85, tags={"email-registered", site.lower()},
                      metadata={"platform": site, "email": target.value,
                                "method": "holehe"},
                      evidence=ev("holehe", snippet=f"{target.value} registered on {site}"))

    @staticmethod
    def _looks_like_site(s: str) -> bool:
        # must look like a domain/service token, e.g. "github.com", "twitter.com"
        import re
        return bool(re.match(r"^[a-z0-9][a-z0-9.\-]{1,40}\.[a-z]{2,}$", s.lower()))


class Sherlock(Module):
    spec = ModuleSpec(
        name="sherlock", category="adapter", external_bin="sherlock",
        accepts={EntityType.USERNAME}, produces={EntityType.SOCIAL_PROFILE},
        description="Sherlock username hunter (400+ sites)", priority=18,
        tags={"adapter", "social"},
    )

    async def run(self, target, graph: IntelGraph):
        code, out, _ = await run_cmd(
            ["sherlock", "--print-found", "--no-color", "--timeout", "10",
             target.value], timeout=300)
        for m in re.findall(r"https?://\S+", out):
            graph.add(EntityType.SOCIAL_PROFILE, m.strip(), confidence=0.8,
                      tags={"social"}, evidence=ev("sherlock"))


class Maigret(Module):
    spec = ModuleSpec(
        name="maigret", category="adapter", external_bin="maigret",
        accepts={EntityType.USERNAME}, produces={EntityType.SOCIAL_PROFILE},
        description="Maigret username hunter (3000+ sites, richer than sherlock)",
        priority=17, tags={"adapter", "social"},
    )

    async def run(self, target, graph: IntelGraph):
        code, out, _ = await run_cmd(
            ["maigret", target.value, "--no-color", "-a", "--timeout", "10"],
            timeout=400)
        for m in re.findall(r"https?://\S+", out):
            graph.add(EntityType.SOCIAL_PROFILE, m.strip(), confidence=0.8,
                      tags={"social"}, evidence=ev("maigret"))
