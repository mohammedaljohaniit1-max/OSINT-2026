"""
GENIUS MODULE #2 - Employee Email Permutation + SMTP catch-all verification.

The primary use case: "I need the emails of a company's employees." Ready tools
give you SOME emails; this GENERATES the likely ones and VERIFIES them for free.

Pipeline:
  1. Collect employee PERSON names discovered elsewhere (LinkedIn dorks, PDFs,
     WHOIS, page bylines) - or accept first/last provided by the analyst.
  2. Generate the standard corporate patterns:
        first.last, first, flast, f.last, firstl, last.first, first_last ...
  3. Detect the company's real pattern by cross-checking any KNOWN emails.
  4. Verify candidates WITHOUT sending mail:
        - MX lookup
        - SMTP RCPT-TO probe (only in deep profile, polite, single connection)
        - catch-all detection (probe a random address; if it accepts, mark
          the domain catch-all so we don't over-trust results)

Output: high-confidence employee emails with a "verified/pattern/guessed" tag.
"""
from __future__ import annotations

import asyncio
import random
import string

from ..core.models import EntityType, IntelGraph, RiskLevel
from ..core.module import Module, ModuleSpec
from ..sources._base import ev

PATTERNS = [
    "{first}.{last}", "{first}{last}", "{f}{last}", "{first}{l}",
    "{f}.{last}", "{first}", "{last}", "{last}.{first}", "{first}_{last}",
    "{f}_{last}", "{last}{f}",
]


def gen_candidates(first: str, last: str, domain: str) -> list[str]:
    first, last = first.lower(), last.lower()
    f, l = (first[:1] or ""), (last[:1] or "")
    out = []
    for p in PATTERNS:
        try:
            local = p.format(first=first, last=last, f=f, l=l)
            if local:
                out.append(f"{local}@{domain}")
        except Exception:
            pass
    return list(dict.fromkeys(out))


class EmailPermutator(Module):
    spec = ModuleSpec(
        name="email_permutator", category="native",
        accepts={EntityType.DOMAIN, EntityType.PERSON},
        produces={EntityType.EMAIL},
        description="Generate + verify employee email addresses (SMTP, no key)",
        priority=50, tags={"native", "genius", "email", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        if target.type == EntityType.DOMAIN:
            domain = target.value
        else:  # PERSON - find a domain in the graph
            doms = graph.by_type(EntityType.DOMAIN)
            if not doms:
                return
            domain = doms[0].value

        # gather people
        people = graph.by_type(EntityType.PERSON)
        if target.type == EntityType.PERSON:
            people = [target]
        if not people:
            return

        # learn pattern from known emails
        known = [e.value for e in graph.by_type(EntityType.EMAIL)
                 if e.value.endswith("@" + domain)]
        learned = self._learn_pattern(known, domain)

        # catch-all detection
        catch_all = await self._is_catch_all(domain) if self.ctx.config.verify_smtp else None

        for person in people:
            parts = person.value.split()
            if len(parts) < 2:
                continue
            first, last = parts[0], parts[-1]
            cands = gen_candidates(first, last, domain)
            # prioritize learned pattern
            if learned:
                pref = learned.format(first=first.lower(), last=last.lower(),
                                      f=first[:1].lower(), l=last[:1].lower())
                pref_email = f"{pref}@{domain}"
                cands = [pref_email] + [c for c in cands if c != pref_email]

            for i, cand in enumerate(cands[:6]):
                conf = 0.4
                tag = "guessed"
                if learned and i == 0:
                    conf, tag = 0.7, "pattern-match"
                if self.ctx.config.verify_smtp and catch_all is False:
                    if await self._smtp_verify(cand, domain):
                        conf, tag = 0.9, "smtp-verified"
                    else:
                        continue
                graph.add(EntityType.EMAIL, cand, confidence=conf,
                          tags={"employee", tag},
                          metadata={"person": person.value, "method": tag},
                          evidence=ev("email_permutator", "",
                                      f"{tag} email for {person.value}"))

    @staticmethod
    def _learn_pattern(known: list[str], domain: str) -> str | None:
        # very light heuristic: if a known email has a dot -> first.last
        for e in known:
            local = e.split("@")[0]
            if "." in local:
                return "{first}.{last}"
            if "_" in local:
                return "{first}_{last}"
        if known:
            return "{f}{last}"
        return None

    async def _is_catch_all(self, domain: str) -> bool | None:
        rnd = "".join(random.choices(string.ascii_lowercase, k=16))
        return await self._smtp_verify(f"{rnd}@{domain}", domain)

    async def _smtp_verify(self, email: str, domain: str) -> bool:
        """Polite single RCPT-TO probe. Returns True if server accepts."""
        try:
            import dns.resolver
            import smtplib
            mx = sorted(
                [(r.preference, str(r.exchange).rstrip("."))
                 for r in dns.resolver.resolve(domain, "MX")])
            if not mx:
                return False
            host = mx[0][1]

            def probe():
                try:
                    s = smtplib.SMTP(host, 25, timeout=8)
                    s.helo("example.com")
                    s.mail("noreply@example.com")
                    code, _ = s.rcpt(email)
                    s.quit()
                    return code in (250, 251)
                except Exception:
                    return False
            return await asyncio.to_thread(probe)
        except Exception:
            return False
