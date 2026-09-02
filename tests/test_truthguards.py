"""Deterministic tests for the truth-guard fixes (no network)."""
import asyncio, sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from argus.core.models import IntelGraph, EntityType, Entity
from argus.core.config import Config

PASS = []
FAIL = []
def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(("  [PASS] " if cond else "  [FAIL] ") + name)

# ---- 1. holehe legend-line rejection --------------------------------------
from argus.adapters.email_social_tools import Holehe
class Ctx:  # minimal
    def __init__(self): 
        self.config=Config.load(); self.http=None; self.graph=None
h = Holehe(Ctx())
# fake holehe stdout with the legend line + one real site + rate limit line
fake_out = """*********************
[+] Email used,[-] Email not used,[x] Rate limit
*********************
[+] github.com
[+] twitter.com
[x] Rate limit reached
[-] someunused.com
"""
g = IntelGraph()
# monkeypatch run_cmd via direct parse emulation:
import argus.adapters.email_social_tools as est
async def fake_run_cmd(*a, **k): return (0, fake_out, "")
est.run_cmd = fake_run_cmd
tgt = Entity(type=EntityType.EMAIL, value="x@y.com")
asyncio.run(h.run(tgt, g))
sites = [e.metadata.get("platform") for e in g.by_type(EntityType.SOCIAL_PROFILE)]
check("holehe emits real sites (github.com, twitter.com)", set(sites) == {"github.com","twitter.com"})
check("holehe REJECTS legend line 'Email used...'", not any("email used" in str(s).lower() for s in sites))
check("holehe REJECTS 'Rate limit'", not any("rate limit" in str(s).lower() for s in sites))

# ---- 2. ahmia self-onion filter ------------------------------------------
from argus.sources.darkweb import Ahmia
a = Ahmia(Ctx())
check("ahmia ignores its own onion (juhanurmi...)",
      "juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion" in Ahmia.IGNORE_ONIONS)

# ---- 3. phone local-number fallback --------------------------------------
from argus.sources.phone import PhoneIntel
p = PhoneIntel(Ctx())
g2 = IntelGraph()
tgt2 = Entity(type=EntityType.PHONE, value="0576365924")  # Saudi local, no +CC
asyncio.run(p.run(tgt2, g2))
check("phone local 0576365924 parsed (not silently dropped)",
      "phone-parsed" in tgt2.tags or "phone-unparseable" in tgt2.tags)
if "phone-parsed" in tgt2.tags:
    check("phone resolved region code = SA", tgt2.metadata.get("region_code")=="SA")
    check("phone produced search_variants for dork pivot",
          bool(tgt2.metadata.get("search_variants")))

# ---- 4. truthful new-entity counter --------------------------------------
g3 = IntelGraph()
g3.add(EntityType.EMAIL, "a@b.com")
g3.add(EntityType.EMAIL, "a@b.com")  # duplicate -> merge, must NOT recount
g3.add(EntityType.DOMAIN, "b.com")
check("counter counts only genuinely NEW entities (2, not 3)", g3._new_count == 2)

if __name__ == "__main__":
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    sys.exit(1 if FAIL else 0)
else:
    assert not FAIL, "; ".join(FAIL)
