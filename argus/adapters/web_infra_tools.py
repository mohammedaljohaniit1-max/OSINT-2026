"""
Adapters for web/infra tools: httpx (probe), naabu (ports), nuclei (vulns),
katana/gau (crawl+urls), whatweb (tech), dnsx. Used if installed. httpx/naabu/
nuclei are ACTIVE (only run in deep/active profile).
"""
from __future__ import annotations

import json

from ..core.models import EntityType, IntelGraph, RiskLevel
from ..core.module import Module, ModuleSpec
from ..sources._base import clean_sub, ev
from ._base import run_cmd


class Httpx(Module):
    spec = ModuleSpec(
        name="httpx", category="adapter", external_bin="httpx",
        accepts={EntityType.SUBDOMAIN, EntityType.DOMAIN},
        produces={EntityType.URL, EntityType.TECHNOLOGY}, active=True,
        description="httpx live host probe + tech detect", priority=30,
        tags={"adapter", "active", "web"},
    )

    async def run(self, target, graph: IntelGraph):
        code, out, _ = await run_cmd(
            ["httpx", "-silent", "-json", "-title", "-tech-detect", "-status-code",
             "-u", target.value], timeout=60)
        for line in out.splitlines():
            try:
                d = json.loads(line)
            except Exception:
                continue
            if d.get("url"):
                graph.add(EntityType.URL, d["url"], confidence=0.85,
                          metadata={"status": d.get("status_code"),
                                    "title": d.get("title")},
                          evidence=ev("httpx"))
            for tech in d.get("tech", []) or []:
                graph.add(EntityType.TECHNOLOGY, tech, confidence=0.8,
                          evidence=ev("httpx"))


class Naabu(Module):
    spec = ModuleSpec(
        name="naabu", category="adapter", external_bin="naabu",
        accepts={EntityType.IP, EntityType.DOMAIN},
        produces={EntityType.PORT}, active=True,
        description="naabu fast port scan", priority=40,
        tags={"adapter", "active", "ports"},
    )

    async def run(self, target, graph: IntelGraph):
        code, out, _ = await run_cmd(
            ["naabu", "-silent", "-host", target.value, "-top-ports", "1000"],
            timeout=180)
        for line in out.splitlines():
            if ":" in line:
                _, port = line.rsplit(":", 1)
                graph.add(EntityType.PORT, line.strip(), risk=RiskLevel.LOW,
                          confidence=0.9, metadata={"port": port},
                          evidence=ev("naabu"))


class Nuclei(Module):
    spec = ModuleSpec(
        name="nuclei", category="adapter", external_bin="nuclei",
        accepts={EntityType.URL, EntityType.DOMAIN, EntityType.SUBDOMAIN},
        produces={EntityType.VULNERABILITY}, active=True,
        description="nuclei templated vuln/misconfig scan", priority=70,
        tags={"adapter", "active", "vuln"},
    )

    async def run(self, target, graph: IntelGraph):
        url = target.value if target.value.startswith("http") else "https://" + target.value
        code, out, _ = await run_cmd(
            ["nuclei", "-silent", "-jsonl", "-u", url,
             "-severity", "critical,high,medium"], timeout=300)
        sev_map = {"critical": RiskLevel.CRITICAL, "high": RiskLevel.HIGH,
                   "medium": RiskLevel.MEDIUM, "low": RiskLevel.LOW,
                   "info": RiskLevel.INFO}
        for line in out.splitlines():
            try:
                d = json.loads(line)
            except Exception:
                continue
            info = d.get("info", {})
            sev = sev_map.get(info.get("severity", "info"), RiskLevel.INFO)
            graph.add(EntityType.VULNERABILITY,
                      f"{info.get('name', d.get('template-id'))} @ {d.get('matched-at','')}",
                      risk=sev, confidence=0.85, tags={"nuclei"},
                      metadata={"template": d.get("template-id")},
                      evidence=ev("nuclei", d.get("matched-at", "")))


class WhatWeb(Module):
    spec = ModuleSpec(
        name="whatweb", category="adapter", external_bin="whatweb",
        accepts={EntityType.DOMAIN, EntityType.URL},
        produces={EntityType.TECHNOLOGY}, active=True,
        description="WhatWeb technology fingerprint", priority=32,
        tags={"adapter", "active", "web"},
    )

    async def run(self, target, graph: IntelGraph):
        url = target.value if target.value.startswith("http") else "https://" + target.value
        code, out, _ = await run_cmd(["whatweb", "--no-errors", "-q", url],
                                     timeout=60)
        import re
        for tech in re.findall(r"([A-Z][A-Za-z0-9\-]+)(?:\[[^\]]*\])?", out):
            if len(tech) > 2:
                graph.add(EntityType.TECHNOLOGY, tech, confidence=0.6,
                          evidence=ev("whatweb"))


class GauUrls(Module):
    spec = ModuleSpec(
        name="gau", category="adapter", external_bin="gau",
        accepts={EntityType.DOMAIN},
        produces={EntityType.URL},
        description="gau (GetAllUrls) from wayback/otx/commoncrawl", priority=34,
        tags={"adapter", "urls"},
    )

    async def run(self, target, graph: IntelGraph):
        import re as _re
        code, out, _ = await run_cmd(["gau", "--subs", target.value], timeout=180)
        # Dumping every archived URL floods the graph (5000+ noise entities that
        # bury real findings). Instead: harvest SUBDOMAINS from the URLs and keep
        # only URLs that carry intel value (params, sensitive paths/extensions).
        INTERESTING = _re.compile(
            r"(\?|=|/api/|/admin|/login|/upload|/download|/backup|/config|"
            r"\.(env|sql|bak|json|xml|yml|yaml|git|log|zip|tar|gz|key|pem))",
            _re.I)
        dom = target.value
        subs_seen, kept = set(), 0
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("http"):
                continue
            m = _re.search(r"https?://([^/:]+)", line)
            if m:
                host = m.group(1).lower().lstrip("*.")
                if host.endswith(dom) and host not in subs_seen:
                    subs_seen.add(host)
                    graph.add(EntityType.SUBDOMAIN, host, confidence=0.55,
                              evidence=ev("gau", snippet="host seen in archived URL"))
            if kept < 300 and INTERESTING.search(line):
                graph.add(EntityType.URL, line, confidence=0.55,
                          tags={"archived", "has-params"},
                          evidence=ev("gau"))
                kept += 1
