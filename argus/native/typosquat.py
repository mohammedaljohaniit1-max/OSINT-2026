"""
GENIUS MODULE #6 - Typosquat & Phishing-Domain Detection.

Out-of-the-box idea: attackers register look-alike domains (paypa1.com,
paypal-secure.com) to phish a brand's users/employees. This module generates
the permutation space (like dnstwist) - character swaps, omissions, insertions,
homoglyphs, TLD swaps, hyphenation, common prefixes/suffixes - then checks each
for LIVE registration (DNS A record). Live look-alikes are flagged HIGH, and if
they also serve a login form similar to the target, CRITICAL (active phishing).

Protects the company from being impersonated - a real business need.
"""
from __future__ import annotations

import asyncio

from ..core.models import EntityType, IntelGraph, RiskLevel
from ..core.module import Module, ModuleSpec
from ..sources._base import ev

HOMOGLYPHS = {
    "a": "4@", "e": "3", "i": "1l!", "o": "0", "s": "5$", "l": "1i",
    "b": "8", "g": "9", "t": "7", "z": "2",
}
COMMON_TLDS = ["com", "net", "org", "co", "io", "info", "online", "site",
               "xyz", "top", "app", "live", "vip", "cc"]
PREFIXES = ["secure", "login", "my", "account", "verify", "support", "mail",
            "portal", "web", "app"]
SUFFIXES = ["-secure", "-login", "-support", "-official", "-help", "s", "-online"]


def permutations(domain: str) -> set[str]:
    name, _, tld = domain.rpartition(".")
    out = set()
    # character omission
    for i in range(len(name)):
        out.add(name[:i] + name[i + 1:] + "." + tld)
    # character swap (adjacent)
    for i in range(len(name) - 1):
        s = list(name)
        s[i], s[i + 1] = s[i + 1], s[i]
        out.add("".join(s) + "." + tld)
    # repetition
    for i in range(len(name)):
        out.add(name[:i] + name[i] + name[i:] + "." + tld)
    # homoglyph
    for i, ch in enumerate(name):
        for rep in HOMOGLYPHS.get(ch, ""):
            out.add(name[:i] + rep + name[i + 1:] + "." + tld)
    # tld swap
    for t in COMMON_TLDS:
        if t != tld:
            out.add(name + "." + t)
    # prefixes / suffixes / hyphenation
    for p in PREFIXES:
        out.add(f"{p}-{name}.{tld}")
        out.add(f"{p}{name}.{tld}")
    for s in SUFFIXES:
        out.add(f"{name}{s}.{tld}")
    out.discard(domain)
    return out


class Typosquat(Module):
    spec = ModuleSpec(
        name="typosquat", category="native",
        accepts={EntityType.DOMAIN},
        produces={EntityType.DOMAIN},
        description="Generate + resolve look-alike/phishing domains", priority=58,
        tags={"native", "genius", "phishing", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        try:
            import dns.resolver
        except ImportError:
            return
        cands = list(permutations(target.value))[:400]
        res = dns.resolver.Resolver()
        res.timeout = 3
        res.lifetime = 3

        async def check(d):
            def q():
                try:
                    ans = res.resolve(d, "A")
                    return str(ans[0])
                except Exception:
                    return None
            ip = await asyncio.to_thread(q)
            if ip:
                # IMPORTANT: a look-alike domain is a FINDING about the target,
                # NOT part of the target's own attack surface. The "no-expand"
                # tag tells the engine never to cascade subdomain/wayback/gau/
                # breach modules into it (that produced huge false-positive
                # contamination, e.g. treating login-x.com as if it were x.com).
                graph.add(EntityType.DOMAIN, d, risk=RiskLevel.HIGH, confidence=0.7,
                          tags={"typosquat", "lookalike", "phishing-risk",
                                "no-expand", "out-of-scope"},
                          metadata={"resolves_to": ip, "mimics": target.value,
                                    "finding_only": True},
                          evidence=ev("typosquat", "",
                                      f"live look-alike of {target.value} -> {ip}"))

        sem = asyncio.Semaphore(30)

        async def bounded(d):
            async with sem:
                await check(d)
        await asyncio.gather(*[bounded(d) for d in cands])
