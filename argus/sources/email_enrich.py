"""
Deep email enrichment — multiple NO-KEY techniques that actually return data.

  - Gravatar: MD5(email) -> profile (name, photo, linked accounts, location).
    This is a REAL, reliable signal and often the richest single email source.
  - Username derivation: email local-part -> candidate username, fed to the
    username-hunt module (cascade) so social presence is checked automatically.
  - Provider intelligence: classify the mailbox provider (Gmail/Outlook/
    corporate) and note deliverability posture.
"""
from __future__ import annotations

import hashlib
import re

from ..core.models import EntityType, IntelGraph, RiskLevel
from ..core.module import Module, ModuleSpec
from ._base import ev

FREE_PROVIDERS = {"gmail.com", "googlemail.com", "yahoo.com", "outlook.com",
                  "hotmail.com", "live.com", "icloud.com", "proton.me",
                  "protonmail.com", "aol.com", "gmx.com", "mail.com",
                  "yandex.com", "zoho.com"}


class GravatarEnrich(Module):
    spec = ModuleSpec(
        name="gravatar", category="source",
        accepts={EntityType.EMAIL},
        produces={EntityType.PERSON, EntityType.SOCIAL_PROFILE, EntityType.USERNAME,
                  EntityType.GEO, EntityType.URL},
        description="Gravatar profile lookup (name/photo/accounts/location)",
        priority=12, tags={"passive", "email", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        email = target.value.strip().lower()
        h = hashlib.md5(email.encode()).hexdigest()
        # profile JSON
        url = f"https://en.gravatar.com/{h}.json"
        data = await self.ctx.http.get(url, expect="json")
        target.metadata["gravatar_hash"] = h
        target.metadata["gravatar_avatar"] = f"https://www.gravatar.com/avatar/{h}"
        if not isinstance(data, dict) or "entry" not in data:
            target.metadata["gravatar"] = "no public gravatar profile"
            return
        for entry in data.get("entry", []):
            # display name / real name
            name = entry.get("displayName") or (
                entry.get("name", {}) or {}).get("formatted")
            if name:
                p = graph.add(EntityType.PERSON, name, confidence=0.8,
                              tags={"from-gravatar"},
                              metadata={"email": email},
                              evidence=ev("gravatar", url, "Gravatar display name"))
                graph.link(target, p, "owned_by", confidence=0.8,
                           sources={"gravatar"})
            # username
            uname = entry.get("preferredUsername")
            if uname:
                graph.add(EntityType.USERNAME, uname, confidence=0.75,
                          tags={"from-gravatar"},
                          evidence=ev("gravatar", url, "Gravatar username"))
            # location
            loc = entry.get("currentLocation")
            if loc:
                graph.add(EntityType.GEO, loc, confidence=0.7, tags={"from-gravatar"},
                          evidence=ev("gravatar", url, "Gravatar location"))
            # linked accounts (VERY useful)
            for acct in entry.get("accounts", []) or []:
                aurl = acct.get("url")
                shortname = acct.get("shortname", "account")
                if aurl:
                    graph.add(EntityType.SOCIAL_PROFILE, aurl, confidence=0.85,
                              tags={"from-gravatar", shortname},
                              metadata={"platform": shortname, "email": email},
                              evidence=ev("gravatar", url,
                                          f"linked {shortname} account"))
            # verified URLs
            for site in entry.get("urls", []) or []:
                if site.get("value"):
                    graph.add(EntityType.URL, site["value"], confidence=0.7,
                              tags={"from-gravatar"},
                              evidence=ev("gravatar", url, "Gravatar linked URL"))
        target.tags.add("has-gravatar")


class EmailToUsername(Module):
    spec = ModuleSpec(
        name="email_to_username", category="source",
        accepts={EntityType.EMAIL},
        produces={EntityType.USERNAME, EntityType.PERSON},
        description="Derive candidate username + name from email local-part",
        priority=8, tags={"passive", "email", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        local = target.value.split("@")[0]
        domain = target.value.split("@")[-1]

        # provider classification
        if domain in FREE_PROVIDERS:
            target.tags.add("free-provider")
            target.metadata["provider_type"] = "free/personal"
        else:
            target.tags.add("corporate-email")
            target.metadata["provider_type"] = "corporate/custom"
            # the domain itself is worth pivoting on
            graph.add(EntityType.DOMAIN, domain, confidence=0.7,
                      tags={"from-email"},
                      evidence=ev("email_to_username", snippet="email domain"))

        # username candidate: strip digits/dots only if it yields a real handle
        base = re.sub(r"[._\-]", "", local)
        candidates = {local}
        if base and base != local and len(base) >= 3:
            candidates.add(base)
        # also the dotted form as-is (many platforms allow it)
        for c in candidates:
            if len(c) >= 3 and re.match(r"^[a-z0-9_.\-]+$", c.lower()):
                graph.add(EntityType.USERNAME, c, confidence=0.5,
                          tags={"derived-from-email"},
                          metadata={"source_email": target.value},
                          evidence=ev("email_to_username", snippet="derived handle"))

        # name guess from patterns like first.last@
        if "." in local:
            parts = [p for p in re.split(r"[._\-]", local) if p.isalpha()]
            if len(parts) >= 2:
                name = " ".join(p.capitalize() for p in parts[:2])
                graph.add(EntityType.PERSON, name, confidence=0.4,
                          tags={"guessed-from-email"},
                          metadata={"source_email": target.value, "low_confidence": True},
                          evidence=ev("email_to_username",
                                      snippet="name guessed from email pattern"))
