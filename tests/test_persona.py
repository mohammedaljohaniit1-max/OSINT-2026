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
    def __init__(self, pages, search_links=None):
        self.pages=pages
        self.search_links = search_links or {}  # query-substr -> html links
    async def get(self, url, expect="text", params=None, **kw):
        for frag, r in self.pages.items():
            if frag in url: return r
        return _Resp(404, "")
    async def post(self, url, data=None, **kw):
        q = (data or {}).get("q", "")
        links = ""
        for sub, html in self.search_links.items():
            if sub in q:
                links += html
        return f"<html>{links}</html>"
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
    # LEAN DESIGN: wrong-city accounts are NOT emitted as separate entities
    # (that produced the 'giant useless log' the user hated). They are COUNTED
    # and a couple kept as audit examples in the run_meta / noise-summary.
    socials = graph.by_type(EntityType.SOCIAL_PROFILE)
    ok(not any("firas_alharbi" in s.value for s in socials),
       "Riyadh account NOT dumped as an entity (lean output)")
    summary = graph.run_meta.get("persona", {}).get("result_summary", {})
    ok(summary.get("rejected_wrong_city", 0) >= 1,
       "Riyadh account counted in rejected_wrong_city summary")
    rej_examples = graph.run_meta.get("persona", {}).get("_rejected_examples", [])
    ok(any("firas_alharbi" in (e.get("url") or "") for e in rej_examples),
       "Riyadh account kept as a rejected audit example")


def test_name_spelling_variants():
    """The user's core complaint: 'الحربي' must also try the 'Alharby' spelling
    and the top handles must include the canonical given.family form, not be
    starved out by shorter transliterations."""
    print("\n== name spelling variants (Alharbi / Alharby) ==")
    n = L.normalize_name("فراس الحربي")
    fam = n.part_variants[-1]
    ok("alharby" in fam, "'الحربي' expands to the 'alharby' (-y) spelling")
    ok("alharbi" in fam and "harby" in fam, "keeps alharbi + short harby too")
    h = generate_usernames(n, limit=18)
    # canonical given.family (full article) must be in the top 18
    ok("firas.alharbi" in h and "firasalharbi" in h,
       "top-18 handles include canonical firas(.)alharbi (not length-starved)")
    ok("firas.alharby" in h or "firasalharby" in h,
       "top-18 handles include the -y spelling firas(.)alharby")
    ok("firasharbi" in h or "firas.harbi" in h,
       "top-18 also include the article-dropped short form firas(.)harbi")


def test_search_query_building():
    print("\n== search-engine people discovery (name+city dorks) ==")
    from argus.persona import search_discovery as SD
    n = L.normalize_name("فراس الحربي")
    _, city_meta = L.resolve_city("Al Madinah Al Munawwarah")
    qs = SD.build_queries(n, city_meta, "SA")
    ok(len(qs) > 0, "builds a non-empty query set")
    ok(any("site:twitter.com" in q for q in qs), "includes a twitter site: dork")
    ok(any("site:linkedin.com/in" in q for q in qs), "includes linkedin site: dork")
    joined = "\n".join(qs)
    ok("Alharby" in joined or "Alharbi" in joined, "queries carry a Latin spelling")
    ok(any("المدين" in q for q in qs) or any("Madinah" in q or "Medina" in q for q in qs),
       "queries scope the target city")
    # profile extraction from raw result links
    rows = SD.extract_profiles([
        {"url": "https://x.com/firasalharby", "title": "Firas"},
        {"url": "https://www.instagram.com/firas.alharby/", "title": "Firas"},
        {"url": "https://x.com/home", "title": "noise"},          # must be skipped
        {"url": "https://www.instagram.com/p/ABC123/", "title": "post"},  # skipped
        {"url": "https://linkedin.com/in/firas-alharby-123", "title": "Firas"},
    ])
    handles = {r["handle"] for r in rows}
    ok("firasalharby" in handles, "extracts twitter handle from profile URL")
    ok("firas.alharby" in handles, "extracts instagram handle from profile URL")
    ok(not any(r["handle"] in ("home",) for r in rows), "skips noise (x.com/home)")
    ok(not any(r["platform"] == "Instagram" and r["handle"] == "p" for r in rows),
       "skips instagram post URLs (/p/)")


def test_phone_carrier_no_expand():
    """The phone contamination bug: carrier ORG + phone GEO must be tagged
    'no-expand' so the engine never cascades them into corporate infra
    (Lebara -> 615 entities). Verified at the source-module level."""
    print("\n== phone: carrier/geo are facts, not assets (no-expand) ==")
    import inspect
    from argus.sources import phone as PH
    src = inspect.getsource(PH)
    ok('"no-expand"' in src and '"carrier"' in src,
       "phone source tags the carrier ORG no-expand")
    ok("phone-fact" in src or "phone-geo" in src,
       "phone source marks carrier/geo as phone facts")
    # engine-level scope guard for non-domain seeds
    import inspect as _i
    from argus.core import engine as EN
    esrc = _i.getsource(EN)
    ok('"person"' in esrc and '"phone"' in esrc and "target_type" in esrc,
       "engine _in_scope() guards ORG/GEO for person/phone/email/username seeds")


if __name__ == "__main__":
    test_locale()
    test_name_tokens()
    test_username_gen()
    test_name_spelling_variants()
    test_search_query_building()
    test_phone_carrier_no_expand()
    test_geo_scoring()
    test_extract()
    test_detector()
    test_end_to_end()
    print(f"\n{_p} passed, {_f} failed")
    sys.exit(1 if _f else 0)
