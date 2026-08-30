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
        breaches = (data.get("breaches") or [[]])
        flat = []
        for b in breaches:
            if isinstance(b, list):
                flat.extend(b)
            else:
                flat.append(b)
        for name in flat:
            b = graph.add(EntityType.BREACH, f"{name} ({email})",
                          risk=RiskLevel.HIGH, confidence=0.85,
                          tags={"breach"},
                          evidence=ev("xposedornot", url, f"{email} in {name}"))
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
        lines = data.get("lines", [])
        for ln in lines:
            # format usually user:password ; we mask the password
            if ":" in ln:
                user, _, pw = ln.partition(":")
                masked = (pw[:2] + "*" * max(0, len(pw) - 2)) if pw else ""
                graph.add(EntityType.CREDENTIAL, f"{user}:{masked}",
                          risk=RiskLevel.CRITICAL, confidence=0.8,
                          tags={"leaked-cred", "password-reuse-risk"},
                          metadata={"password_masked": masked, "source_line": True},
                          evidence=ev("proxynova_comb", url,
                                      "credential in COMB compilation"))
                target.tags.add("credential-exposed")
