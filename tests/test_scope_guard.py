"""Regression tests for the x.com contamination bugs (scope guard + filters)."""
import os, sys, asyncio
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from argus.core.engine import Engine
from argus.core.config import Config
from argus.core.models import Entity, EntityType

PASS, FAIL = [], []
def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(("  [PASS] " if cond else "  [FAIL] ") + name)

e = Engine(Config.load(), quiet=True)
e.graph.run_meta["root_domain"] = "x.com"

# BUG1: typosquat look-alike domains must NOT be expanded
sibling = e.graph.add(EntityType.DOMAIN, "login-x.com",
                      tags={"typosquat","lookalike","no-expand","out-of-scope"})
check("BUG1 login-x.com (look-alike) is OUT of scope", not e._in_scope(sibling))
tld_sibling = e.graph.add(EntityType.DOMAIN, "x.vip", tags={"typosquat","lookalike","no-expand"})
check("BUG1 x.vip (tld-swap look-alike) is OUT of scope", not e._in_scope(tld_sibling))

# real subdomain IS in scope
realsub = e.graph.add(EntityType.SUBDOMAIN, "api.x.com")
check("real api.x.com IS in scope", e._in_scope(realsub))

# a subdomain of a look-alike (ebay.it.x.vip) must be out of scope
leaksub = e.graph.add(EntityType.SUBDOMAIN, "ebay.it.x.vip")
check("BUG1 ebay.it.x.vip (sub of look-alike) is OUT of scope", not e._in_scope(leaksub))

# BUG2: registrar/abuse contact email must NOT be expanded
from argus.sources.whois_rdap import RDAPDomain
class Ctx:
    def __init__(s): s.config=Config.load(); s.http=None; s.graph=None
rd = RDAPDomain(Ctx())
check("BUG2 abuse@godaddy.com detected as registrar contact",
      rd._is_registrar_contact("abuse@godaddy.com"))
check("BUG2 abusecomplaints@markmonitor.com is registrar contact",
      rd._is_registrar_contact("abusecomplaints@markmonitor.com"))
check("BUG2 real john.doe@x.com is NOT a registrar contact",
      not rd._is_registrar_contact("john.doe@somecorp.com"))
abuse_email = e.graph.add(EntityType.EMAIL, "abuse@godaddy.com",
                          tags={"whois","registrar-contact","no-expand"})
check("BUG2 abuse@godaddy.com email is OUT of scope (no breach/holehe cascade)",
      not e._in_scope(abuse_email))

# BUG4: github secret false-positive filter
from argus.sources.github_dork import _SECRET_FALSE_POSITIVES, SECRET_REGEXES
check("BUG4 placeholder 'your_api_key' rejected",
      bool(_SECRET_FALSE_POSITIVES.search('api_key="your_api_key_here"')))
# generic secret no longer matches a short token
gen = SECRET_REGEXES["Generic Secret"]
check("BUG4 short token:'abc' NOT flagged as secret",
      not gen.search('token: "abc123"'))

# BUG6: crtsh handles non-list (string) response without crashing
from argus.sources.certs import CrtSh
import types
class HttpStub:
    async def get(self, *a, **k): return "<html>error</html>"  # crt.sh error page
class Ctx2:
    def __init__(s): s.config=Config.load(); s.http=HttpStub(); s.graph=None
crt = CrtSh(Ctx2())
tgt = Entity(type=EntityType.DOMAIN, value="x.com")
try:
    asyncio.run(crt.run(tgt, e.graph))
    check("BUG6 crtsh survives non-list response (no crash)", True)
except Exception as ex:
    check(f"BUG6 crtsh survives non-list response (crashed: {ex})", False)

print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
sys.exit(1 if FAIL else 0)
