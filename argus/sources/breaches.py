"""
Breach & credential-exposure sources - NO API KEY.

  - XposedOrNot : free breach-check API (email -> breaches). No key.
  - ProxyNova COMB: searches the compiled COMB leak index (email/user -> creds).
  - LeakCheck public : mention-only endpoint.
These tell you WHICH breaches an email/company appears in (exposure signal).
Argus never downloads or displays full plaintext dumps - it reports exposure.
"""
from __future__ import annotations

from ..core.models import EntityType, IntelGraph, RiskLevel
from ..core.module import Module, ModuleSpec
from ._base import ev


class XposedOrNot(Module):
    spec = ModuleSpec(
        name="xposedornot", category="source",
        accepts={EntityType.EMAIL},
        produces={EntityType.BREACH},
        description="XposedOrNot free breach check (no key)", priority=20,
        tags={"passive", "breach", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        email = target.value
        url = f"https://api.xposedornot.com/v1/check-email/{email}"
        data = await self.ctx.http.get(url, expect="json")
        if not isinstance(data, dict):
            return
        # API returns {"Error":"Not found"} when the email is clean -> report clean
        if data.get("Error") or "breaches" not in data:
            target.metadata["breach_check"] = "no breaches found (XposedOrNot)"
            return
        breaches = data.get("breaches")
        flat = []
        if isinstance(breaches, list):
            for b in breaches:
                if isinstance(b, list):
                    flat.extend(b)
                elif b:
                    flat.append(b)
        # TRUTH GUARD: only emit non-empty, string breach names
        flat = [str(n).strip() for n in flat if n and str(n).strip()]
        if not flat:
            target.metadata["breach_check"] = "no breaches found (XposedOrNot)"
            return
        for name in flat:
            graph.add(EntityType.BREACH, f"{name} ({email})",
                      risk=RiskLevel.HIGH, confidence=0.85,
                      tags={"breach"},
                      metadata={"breach_name": name, "email": email},
                      evidence=ev("xposedornot", url, f"{email} found in {name} breach"))
            target.tags.add("breached")
            target.metadata.setdefault("breaches", []).append(name)


class ProxyNovaCOMB(Module):
    spec = ModuleSpec(
        name="proxynova_comb", category="source",
        accepts={EntityType.EMAIL, EntityType.USERNAME},
        produces={EntityType.CREDENTIAL},
        description="ProxyNova COMB leak index (email/user -> exposed creds)",
        priority=25, tags={"passive", "breach", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        q = target.value
        url = f"https://api.proxynova.com/comb?query={q}&start=0&limit=25"
        data = await self.ctx.http.get(url, expect="json")
        if not isinstance(data, dict):
            return
        lines = data.get("lines")
        if not isinstance(lines, list) or not lines:
            target.metadata["comb_check"] = "no credentials found (ProxyNova COMB)"
            return
        emitted = 0
        for ln in lines:
            if not isinstance(ln, str) or ":" not in ln:
                continue
            user, _, pw = ln.partition(":")
            user, pw = user.strip(), pw.strip()
            # TRUTH GUARD: the returned line must actually contain the target
            # (COMB fuzzy-matches; reject unrelated rows)
            if q.lower() not in user.lower() and q.lower() not in ln.lower():
                continue
            if not user:
                continue
            masked = (pw[:2] + "*" * max(0, len(pw) - 2)) if pw else "(no password)"
            emitted += 1
            graph.add(EntityType.CREDENTIAL, f"{user}:{masked}",
                      risk=RiskLevel.CRITICAL, confidence=0.8,
                      tags={"leaked-cred", "password-reuse-risk"},
                      metadata={"user": user, "password_masked": masked,
                                "password_length": len(pw)},
                      evidence=ev("proxynova_comb", url,
                                  f"{user} appears in COMB leak compilation"))
            target.tags.add("credential-exposed")
        if not emitted:
            target.metadata["comb_check"] = "no matching credentials (ProxyNova COMB)"
