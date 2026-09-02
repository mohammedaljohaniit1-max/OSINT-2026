"""
Deterministic tests for PERSONA HUNTER (person search).
========================================================
No network. Proves the exact behaviour the user asked for:
  * name + country + city resolve across Arabic AND English
  * a person in the TARGET city is CONFIRMED (ar or en)
  * the same name in a DIFFERENT city is REJECTED ("لو حصلته في الرياض ماتطلعه")
  * cross-language duplicate accounts fuse into ONE persona
Run:  python3 tests/test_persona.py
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from argus.core.config import Config
from argus.core.models import IntelGraph, EntityType
from argus.core.detector import detect
from argus.persona import locale as L
from argus.persona.name_engine import generate_usernames
from argus.persona.geo_confirm import GeoConfirmer
from argus.persona.extract import extract_profile
from argus.persona.investigator import PersonaHunter

_p = _f = 0
def ok(cond, msg):
    global _p, _f
    if cond:
        _p += 1; print(f"  [PASS] {msg}")
    else:
        _f += 1; print(f"  [FAIL] {msg}")


# ---- mock HTTP ----
class _Resp:
    def __init__(self, s, t): self.status_code=s; self.text=t
class _Http:
    def __init__(self, pages): self.pages=pages
    async def get(self, url, expect="text"):
        for frag, r in self.pages.items():
            if frag in url: return r
        return _Resp(404, "")
    async def close(self): pass
class _Ctx:
    def __init__(self, cfg, http): self.config=cfg; self.http=http

def _page(name, desc, loc=""):
    return _Resp(200, f'<html lang="ar"><head>'
        f'<meta property="og:title" content="{name}">'
        f'<meta property="og:description" content="{desc}">'
        f'<script type="application/ld+json">{{"@type":"Person","name":"{name}",'
        f'"description":"{desc}","address":{{"addressLocality":"{loc}"}}}}</script>'
        f'</head></html>')


def test_locale():
    print("\n== locale / gazetteer ==")
    ok(L.resolve_country("Saudi Arabia") == "SA", "'Saudi Arabia' -> SA")
    ok(L.resolve_country("السعودية") == "SA", "'السعودية' -> SA")
    ok(L.resolve_country("KSA") == "SA", "'KSA' -> SA")
    ok(L.resolve_city("Al Madinah Al Munawwarah")[0] == "al_madinah", "EN city -> al_madinah")
    ok(L.resolve_city("المدينة المنورة")[0] == "al_madinah", "AR city -> al_madinah")
    ok(L.resolve_city("Medina")[0] == "al_madinah", "'Medina' -> al_madinah")
    ok(L.resolve_city("Riyadh")[0] == "riyadh", "'Riyadh' -> riyadh (distinct)")


def test_name_tokens():
    print("\n== name normalization (ar<->en converge) ==")
    ar = L.normalize_name("فراس الحربي").all_tokens_folded()
    en = L.normalize_name("Firas Al-Harbi").all_tokens_folded()
    ok("firas" in ar and "harbi" in ar, "arabic name yields latin firas+harbi")
    ok("firas" in en and ("harbi" in en or "alharbi" in en), "english name yields firas+harbi")
    ok(len(ar & en) >= 2, "ar & en names share >=2 folded tokens (same person)")


def test_username_gen():
    print("\n== username generation ==")
    u = generate_usernames(L.normalize_name("فراس الحربي"), limit=60)
    ok("firas.alharbi" in u or "firasalharbi" in u, "generates firas(.)alharbi")
    ok("f.alharbi" in u or "falharbi" in u, "generates initial+family handle")
    ok(all(len(h) >= 3 for h in u), "no handle shorter than 3 chars")
    ok("alfiras" not in u, "no 'al' article artifact on given name")


def test_geo_scoring():
    print("\n== geo confirmation scoring ==")
    name = L.normalize_name("فراس الحربي")
    c = GeoConfirmer(name, "SA", "al_madinah")
    a = c.score(handle="firas.alharbi", display_name="فراس الحربي",
                bio="من المدينة المنورة", location="المدينة المنورة", language="ar")
    ok(a.verdict == "confirmed" and a.total >= 80, "AR person in Medina -> CONFIRMED")
    b = c.score(handle="firasalharbi", display_name="Firas Al-Harbi",
                bio="Medina KSA", location="Medina", language="en")
    ok(b.verdict == "confirmed" and b.total >= 80, "EN person in Medina -> CONFIRMED")
    r = c.score(handle="firas_alharbi", display_name="فراس الحربي",
                bio="من الرياض", location="الرياض", language="ar")
    ok(r.verdict == "rejected", "same name in Riyadh -> REJECTED (ماتطلعه)")
    ok(r.conflict_city == "riyadh", "conflict city detected = riyadh")


def test_extract():
    print("\n== profile field extraction ==")
    prof = extract_profile(_page("فراس الحربي", "مطور من المدينة المنورة", "المدينة المنورة").text)
    ok(prof["display_name"] == "فراس الحربي", "extracts arabic display name")
    ok("المدينة" in prof["location"] or "المدينه" in prof["location"], "extracts location")


def test_detector():
    print("\n== detector routes person names ==")
    ok(detect("فراس الحربي").type == EntityType.PERSON, "arabic name -> PERSON")
    ok(detect("Firas Al-Harbi").type == EntityType.PERSON, "multi-word name -> PERSON")
    ok(detect("company.com").type == EntityType.DOMAIN, "domain still DOMAIN (no regression)")
    ok(detect("johndoe").type == EntityType.USERNAME, "single token still USERNAME")


def test_end_to_end():
    print("\n== end-to-end investigation (mock) ==")
    pages = {
        "github.com/firas.alharbi": _page("فراس الحربي", "مطور من المدينة المنورة", "المدينة المنورة"),
        "instagram.com/firasalharbi": _page("Firas Al-Harbi", "Engineer, Medina KSA", "Medina"),
        "x.com/firas_alharbi": _page("فراس الحربي", "من الرياض", "الرياض"),
    }
    cfg = Config.load(profile="standard")
    cfg.person_name = "فراس الحربي"; cfg.person_country = "Saudi Arabia"
    cfg.person_city = "Al Madinah Al Munawwarah"
    graph = IntelGraph()
    seed = graph.add(EntityType.PERSON, "فراس الحربي", tags={"seed"})
    asyncio.run(PersonaHunter(_Ctx(cfg, _Http(pages))).run(seed, graph))

    personas = graph.by_type(EntityType.PERSONA)
    confirmed = [p for p in personas if p.metadata.get("verdict") == "confirmed"]
    ok(len(confirmed) == 1, "exactly ONE confirmed persona (2 accounts fused)")
    if confirmed:
        ok(confirmed[0].metadata["account_count"] == 2,
           "confirmed persona fuses BOTH Medina accounts (ar+en)")
    # the Riyadh account must NOT be part of any confirmed persona
    all_urls = [a["url"] for p in confirmed for a in p.metadata["accounts"]]
    ok(not any("firas_alharbi" in u for u in all_urls),
       "Riyadh account NOT in confirmed persona (rejected)")
    # but it IS recorded as a low finding
    socials = graph.by_type(EntityType.SOCIAL_PROFILE)
    rej = [s for s in socials if s.metadata.get("verdict") == "rejected"]
    ok(any("firas_alharbi" in s.value for s in rej),
       "Riyadh account preserved as low-confidence finding")


if __name__ == "__main__":
    test_locale()
    test_name_tokens()
    test_username_gen()
    test_geo_scoring()
    test_extract()
    test_detector()
    test_end_to_end()
    print(f"\n{_p} passed, {_f} failed")
    sys.exit(1 if _f else 0)
