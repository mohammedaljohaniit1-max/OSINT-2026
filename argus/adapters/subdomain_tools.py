"""
Adapters for the best subdomain / recon tools (used if installed).

subfinder, amass, assetfinder, findomain, sublist3r, github-subdomains.
Each parses its native output into SUBDOMAIN entities. install.sh installs
subfinder/amass/assetfinder via Kali apt / go. Missing tools are skipped.
"""
from __future__ import annotations

from ..core.models import EntityType, IntelGraph
from ..core.module import Module, ModuleSpec
from ..sources._base import clean_sub, ev
from ._base import run_cmd


class Subfinder(Module):
    spec = ModuleSpec(
        name="subfinder", category="adapter", external_bin="subfinder",
        accepts={EntityType.DOMAIN}, produces={EntityType.SUBDOMAIN},
        description="ProjectDiscovery subfinder", priority=12,
        tags={"adapter", "subdomains"},
    )

    async def run(self, target, graph: IntelGraph):
        code, out, _ = await run_cmd(
            ["subfinder", "-d", target.value, "-silent", "-all"], timeout=240)
        for line in out.splitlines():
            h = clean_sub(line)
            if h.endswith(target.value):
                graph.add(EntityType.SUBDOMAIN, h, confidence=0.85,
                          evidence=ev("subfinder"))


class Amass(Module):
    spec = ModuleSpec(
        name="amass", category="adapter", external_bin="amass",
        accepts={EntityType.DOMAIN}, produces={EntityType.SUBDOMAIN},
        description="OWASP Amass passive enum", priority=13,
        tags={"adapter", "subdomains"},
    )

    async def run(self, target, graph: IntelGraph):
        code, out, _ = await run_cmd(
            ["amass", "enum", "-passive", "-d", target.value], timeout=300)
        for line in out.splitlines():
            h = clean_sub(line.split()[0]) if line.split() else ""
            if h.endswith(target.value):
                graph.add(EntityType.SUBDOMAIN, h, confidence=0.85,
                          evidence=ev("amass"))


class Assetfinder(Module):
    spec = ModuleSpec(
        name="assetfinder", category="adapter", external_bin="assetfinder",
        accepts={EntityType.DOMAIN}, produces={EntityType.SUBDOMAIN},
        description="tomnomnom assetfinder", priority=14,
        tags={"adapter", "subdomains"},
    )

    async def run(self, target, graph: IntelGraph):
        code, out, _ = await run_cmd(
            ["assetfinder", "--subs-only", target.value], timeout=120)
        for line in out.splitlines():
            h = clean_sub(line)
            if h.endswith(target.value):
                graph.add(EntityType.SUBDOMAIN, h, confidence=0.8,
                          evidence=ev("assetfinder"))


class Findomain(Module):
    spec = ModuleSpec(
        name="findomain", category="adapter", external_bin="findomain",
        accepts={EntityType.DOMAIN}, produces={EntityType.SUBDOMAIN},
        description="Findomain fast subdomain enum", priority=14,
        tags={"adapter", "subdomains"},
    )

    async def run(self, target, graph: IntelGraph):
        code, out, _ = await run_cmd(
            ["findomain", "-t", target.value, "-q"], timeout=180)
        for line in out.splitlines():
            h = clean_sub(line)
            if h.endswith(target.value):
                graph.add(EntityType.SUBDOMAIN, h, confidence=0.8,
                          evidence=ev("findomain"))
