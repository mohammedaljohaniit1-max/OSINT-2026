"""
locale.py — the multilingual identity brain of Persona Hunter.
================================================================

Everything language-/geography-aware lives here so the rest of the subsystem
stays clean. Zero external deps (pure stdlib) so it runs anywhere Argus runs.

Capabilities
------------
* Arabic  ->  Latin transliteration (Buckwalter-ish, phonetic, *multiple*
  accepted spellings per name because real people spell their own names many
  ways: محمد -> mohammed / muhammad / mohamed / mohamad ...).
* Latin   ->  canonical Arabic guesses for common Gulf given names / tribes.
* A curated gazetteer of Saudi + Gulf + major world cities with *all* their
  real-world spellings/aliases (Arabic + English + short forms), each mapped to
  a country and a set of match tokens.
* Country name/ISO normalization.
* Name normalization: strip honorifics (bin/ibn/al/abu ...), split
  given/family, expand each part to its spelling variants.

This module is deliberately data-heavy — that data *is* the intelligence.
"""
from __future__ import annotations

import re
import unicodedata


# --------------------------------------------------------------------------- #
#  Arabic normalization
# --------------------------------------------------------------------------- #
_AR_DIACRITICS = re.compile(r"[\u0610-\u061A\u064B-\u065F\u0670\u06D6-\u06ED\u0640]")

def strip_ar_diacritics(s: str) -> str:
    """Remove tashkeel + tatweel; normalize alef/hamza/teh-marbuta/yeh forms."""
    s = _AR_DIACRITICS.sub("", s)
    trans = {
        "أ": "ا", "إ": "ا", "آ": "ا", "ٱ": "ا",
        "ى": "ي", "ئ": "ي",
        "ؤ": "و",
        "ة": "ه",
        "ﻻ": "لا",
    }
    return "".join(trans.get(c, c) for c in s)


def has_arabic(s: str) -> bool:
    return any("\u0600" <= c <= "\u06FF" or "\u0750" <= c <= "\u077F" for c in s)


def fold(s: str) -> str:
    """Aggressive fold for matching: lowercase, strip accents, collapse spaces,
    drop separators. Works for both Latin and Arabic."""
    s = strip_ar_diacritics(s)
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    s = s.lower()
    s = re.sub(r"[\s._\-]+", "", s)
    return s.strip()


# --------------------------------------------------------------------------- #
#  Arabic -> Latin transliteration (multi-variant)
# --------------------------------------------------------------------------- #
# Each Arabic letter maps to a *list* of plausible Latin renderings; we expand
# the cartesian product but cap it so we don't explode. Long/rare letters keep
# a single common spelling to stay sane.
_AR2LAT = {
    "ا": ["a"], "ب": ["b"], "ت": ["t"], "ث": ["th", "s"],
    "ج": ["j", "g"], "ح": ["h"], "خ": ["kh", "k"], "د": ["d"],
    "ذ": ["th", "z", "d"], "ر": ["r"], "ز": ["z"], "س": ["s"],
    "ش": ["sh"], "ص": ["s"], "ض": ["d"], "ط": ["t"], "ظ": ["z", "th"],
    "ع": ["a", ""], "غ": ["gh", "g"], "ف": ["f"], "ق": ["q", "g", "k"],
    "ك": ["k"], "ل": ["l"], "م": ["m"], "ن": ["n"], "ه": ["h"],
    "و": ["w", "o", "u"], "ي": ["y", "i", "ee"], "ة": ["a", "ah", ""],
    "ء": [""], "ئ": ["e", "i"], "ؤ": ["o", "u"],
    "لا": ["la"],
}

# Hand-curated canonical spellings for the most common Gulf names & tribes.
# Real people almost always spell these in one of these fixed ways, so we seed
# them directly rather than trusting the letter-by-letter engine alone.
CANON_NAME_MAP: dict[str, list[str]] = {
    # given names (male)
    "محمد": ["mohammed", "muhammad", "mohamed", "mohamad", "mohammad", "muhammed"],
    "احمد": ["ahmed", "ahmad"],
    "عبدالله": ["abdullah", "abdallah", "abdulla"],
    "عبدالرحمن": ["abdulrahman", "abdelrahman", "abdurrahman", "abdalrahman"],
    "عبدالعزيز": ["abdulaziz", "abdelaziz", "abdalaziz"],
    "علي": ["ali"], "عمر": ["omar", "umar"], "خالد": ["khaled", "khalid"],
    "سعد": ["saad", "sad"], "سعود": ["saud", "saood"], "فهد": ["fahad", "fahd"],
    "سلطان": ["sultan"], "فيصل": ["faisal", "faysal"], "نايف": ["naif", "nayef"],
    "تركي": ["turki"], "بندر": ["bandar"], "ماجد": ["majed", "majid"],
    "يوسف": ["yousef", "youssef", "yusuf", "yousuf"], "ابراهيم": ["ibrahim", "ebrahim"],
    "حسن": ["hassan", "hasan"], "حسين": ["hussain", "hussein", "husain"],
    "عبدالمجيد": ["abdulmajeed", "abdulmajid"],
    "فراس": ["firas", "feras", "ferras", "firass", "ferass", "fras"],
    "زياد": ["ziad", "zeyad", "ziyad"], "طلال": ["talal"], "وليد": ["waleed", "walid"],
    "ناصر": ["nasser", "naser", "nasir"], "راشد": ["rashed", "rashid"],
    "سامي": ["sami", "samy"], "طارق": ["tariq", "tarek", "tarik"],
    "مازن": ["mazen", "mazin"], "ريان": ["rayan", "rayyan", "raian"],
    "معاذ": ["muath", "moath", "moaz"], "انس": ["anas"], "بدر": ["bader", "badr"],
    # given names (female)
    "نورة": ["noura", "nora", "norah"], "سارة": ["sara", "sarah"],
    "ريم": ["reem", "rim"], "لمى": ["lama", "lamma"], "هند": ["hind", "hend"],
    "منى": ["mona", "muna"], "امل": ["amal", "amel"], "شهد": ["shahad", "shahd"],
    "جواهر": ["jawaher", "jawahir"], "العنود": ["alanoud", "anoud"],
    # tribes / family names
    # NOTE: real Saudi social handles overwhelmingly use the -y / -ee / -ie
    # ending ('Alharby', 'Alharbe') far more than the textbook -i ('Alharbi').
    # We include ALL of them (with and without the 'al' article, with and
    # without a hyphen) because people spell their own tribe name every way.
    "الحربي": ["alharbi", "alharby", "alharbe", "harbi", "harby",
               "al-harbi", "al-harby", "elharbi", "elharby", "alhrbi"],
    "العتيبي": ["alotaibi", "alotaiby", "otaibi", "otaiby", "al-otaibi",
                "aloteibi", "aloteiby", "alutaibi"],
    "القحطاني": ["alqahtani", "alqahtany", "qahtani", "qahtany",
                 "al-qahtani", "alkahtani", "alkahtany"],
    "الغامدي": ["alghamdi", "alghamdy", "ghamdi", "ghamdy", "al-ghamdi"],
    "الشمري": ["alshammari", "alshammary", "shammari", "shammary",
               "al-shammari", "alshamri", "alshamary"],
    "الدوسري": ["aldosari", "aldosary", "dosari", "dosary", "al-dosari",
                "aldossary", "aldossari"],
    "المطيري": ["almutairi", "almutairy", "mutairi", "mutairy",
                "al-mutairi", "almtairi", "almuteiri"],
    "الزهراني": ["alzahrani", "alzahrany", "zahrani", "zahrany", "al-zahrani"],
    "الشهري": ["alshehri", "alshehry", "shehri", "shehry", "al-shehri",
               "alshahri", "alshahry"],
    "العنزي": ["alanazi", "alanazy", "anazi", "anazy", "al-anazi",
               "alenezi", "alenezy", "enezi"],
    "السبيعي": ["alsubaie", "alsubaiy", "subaie", "al-subaie", "alsubaiei",
                "alsbaie"],
    "البقمي": ["albqami", "albqamy", "bqami", "albogami", "albugami", "albogamy"],
    "الجهني": ["aljuhani", "aljuhany", "juhani", "juhany", "al-juhani",
               "aljohani", "aljohany", "johani"],
    "العمري": ["alomari", "alomary", "omari", "omary", "al-omari",
               "alamri", "alamry", "amri"],
    "الرشيدي": ["alrashidi", "alrashidy", "rashidi", "rashidy", "al-rashidi"],
    "الخالدي": ["alkhaldi", "khaldi", "al-khalidi"],
    "الاحمدي": ["alahmadi", "ahmadi", "al-ahmadi"],
    "السلمي": ["alsulami", "sulami", "al-sulami", "alsalmi"],
    "المالكي": ["almalki", "malki", "al-malki"],
    "الثقفي": ["althaqafi", "thaqafi", "al-thaqafi", "althagafi"],
    "الحازمي": ["alhazmi", "hazmi", "al-hazmi"],
}

# Honorifics / connectors to strip when splitting a name.
_STOPWORDS = {
    "bin", "ben", "ibn", "abu", "abo", "um", "umm", "el", "al", "the",
    "بن", "ابن", "ابو", "أبو", "ام", "أم", "آل",
}
# NOTE: "al" as a standalone token is a connector, but "al-harbi" glued is a
# family name — handled in normalize_name().


def _cap(variants: list[str], limit: int = 6) -> list[str]:
    out, seen = [], set()
    for v in variants:
        v = v.strip()
        if v and v not in seen:
            seen.add(v)
            out.append(v)
        if len(out) >= limit:
            break
    return out


def translit_ar_to_latin(word: str, limit: int = 6) -> list[str]:
    """Return up to `limit` plausible Latin spellings of one Arabic word."""
    w = strip_ar_diacritics(word).strip()
    if not w:
        return []
    # 1) canonical map wins (handles ال- prefixed tribes & common names)
    if w in CANON_NAME_MAP:
        return _cap(CANON_NAME_MAP[w], limit)
    # strip leading ال (definite article) and retry the map for family names
    if w.startswith("ال") and w[2:] in CANON_NAME_MAP:
        base = CANON_NAME_MAP[w[2:]]
        return _cap([("al" + b) for b in base] + base, limit)

    # 2) letter-by-letter cartesian expansion (bounded)
    forms = [""]
    for ch in w:
        opts = _AR2LAT.get(ch, [ch])
        new = []
        for pre in forms:
            for o in opts:
                new.append(pre + o)
            if len(new) >= 24:      # keep the product from exploding
                break
        forms = new
    # de-dupe, prefer shorter/cleaner spellings first
    forms = sorted(set(forms), key=lambda x: (len(x), x))
    return _cap(forms, limit)


def latin_variants(word: str, limit: int = 6) -> list[str]:
    """Spelling variants for a Latin-script name part (people mistype/vary)."""
    w = fold(word)
    if not w:
        return []
    out = {w}
    # common Gulf English spelling swaps
    swaps = [
        ("ph", "f"), ("ee", "i"), ("ou", "u"), ("oo", "u"),
        ("aa", "a"), ("y", "i"), ("q", "k"), ("kh", "k"), ("gh", "g"),
        ("mohammed", "mohamed"), ("mohammed", "muhammad"),
    ]
    for a, b in swaps:
        for base in list(out):
            if a in base:
                out.add(base.replace(a, b))
    # trailing-vowel variants: real handles swap the final i<->y<->ee freely
    # ('alharbi' vs 'alharby' vs 'harbee'). generate them for EVERY form so
    # names not in the canonical map still reach the common spelling.
    for base in list(out):
        if base.endswith("i"):
            out.add(base[:-1] + "y")
            out.add(base[:-1] + "ee")
        elif base.endswith("y"):
            out.add(base[:-1] + "i")
        elif base.endswith("ee"):
            out.add(base[:-2] + "i")
            out.add(base[:-2] + "y")
    # al- family prefix handling
    if w.startswith("al") and len(w) > 3:
        out.add(w[2:])           # harbi
    else:
        out.add("al" + w)        # alharbi
    return _cap(sorted(out, key=lambda x: (len(x), x)), limit)


# --------------------------------------------------------------------------- #
#  Name normalization
# --------------------------------------------------------------------------- #
class NormalizedName:
    """A parsed human name with all its cross-language spelling variants."""
    def __init__(self, raw: str):
        self.raw = raw.strip()
        self.is_arabic = has_arabic(self.raw)
        self.parts: list[str] = []            # cleaned parts (source script)
        self.given = ""
        self.family = ""
        # variants[i] = list of spellings for parts[i], across BOTH scripts
        self.part_variants: list[list[str]] = []
        self._parse()

    def _parse(self):
        # glue "al harbi" / "al-harbi" -> keep family prefix attached
        raw = re.sub(r"\bal[\s\-]", "al", self.raw, flags=re.I)
        raw = re.sub(r"\bال\s+", "ال", raw)
        toks = [t for t in re.split(r"[\s،,]+", raw) if t]
        # drop pure connectors (but keep glued al-family)
        cleaned = []
        for t in toks:
            tf = fold(t)
            if tf in _STOPWORDS and len(cleaned) > 0:
                continue
            cleaned.append(t)
        self.parts = cleaned or toks
        if self.parts:
            self.given = self.parts[0]
            self.family = self.parts[-1] if len(self.parts) > 1 else ""
        for p in self.parts:
            self.part_variants.append(self._variants_for(p))

    @staticmethod
    def _variants_for(part: str) -> list[str]:
        if has_arabic(part):
            v = translit_ar_to_latin(part)
            # also keep the folded arabic itself for arabic-native matching
            v = [part] + v
        else:
            v = latin_variants(part)
        # de-dupe preserving order
        seen, out = set(), []
        for x in v:
            k = fold(x)
            if k and k not in seen:
                seen.add(k)
                out.append(x)
        return out

    def all_tokens_folded(self) -> set[str]:
        """Every folded spelling token of every part — used for matching."""
        toks = set()
        for vs in self.part_variants:
            for v in vs:
                f = fold(v)
                if f:
                    toks.add(f)
        return toks

    def display(self) -> str:
        return self.raw

    def __repr__(self):
        return f"<NormalizedName {self.raw!r} parts={self.parts}>"


def normalize_name(raw: str) -> NormalizedName:
    return NormalizedName(raw)


# --------------------------------------------------------------------------- #
#  Gazetteer: cities & countries (Arabic + English + aliases)
# --------------------------------------------------------------------------- #
# country_code -> {"names": [all spellings], "iso2": "SA"}
COUNTRIES: dict[str, dict] = {
    "SA": {"iso2": "SA", "iso3": "SAU", "dial": "+966",
           "names": ["saudi arabia", "saudi", "ksa", "kingdom of saudi arabia",
                     "السعودية", "المملكة العربية السعودية", "السعوديه"]},
    "AE": {"iso2": "AE", "iso3": "ARE", "dial": "+971",
           "names": ["uae", "united arab emirates", "emirates", "الامارات",
                     "الإمارات", "الامارات العربية المتحدة"]},
    "KW": {"iso2": "KW", "iso3": "KWT", "dial": "+965",
           "names": ["kuwait", "الكويت"]},
    "QA": {"iso2": "QA", "iso3": "QAT", "dial": "+974",
           "names": ["qatar", "قطر"]},
    "BH": {"iso2": "BH", "iso3": "BHR", "dial": "+973",
           "names": ["bahrain", "البحرين"]},
    "OM": {"iso2": "OM", "iso3": "OMN", "dial": "+968",
           "names": ["oman", "عمان", "سلطنة عمان"]},
    "EG": {"iso2": "EG", "iso3": "EGY", "dial": "+20",
           "names": ["egypt", "مصر"]},
    "JO": {"iso2": "JO", "iso3": "JOR", "dial": "+962",
           "names": ["jordan", "الاردن", "الأردن"]},
    "US": {"iso2": "US", "iso3": "USA", "dial": "+1",
           "names": ["usa", "united states", "america", "us", "امريكا", "أمريكا"]},
    "GB": {"iso2": "GB", "iso3": "GBR", "dial": "+44",
           "names": ["uk", "united kingdom", "britain", "england", "بريطانيا"]},
}

# city_key -> {"country": "SA", "aliases": [all spellings incl arabic + english]}
CITIES: dict[str, dict] = {
    "al_madinah": {
        "country": "SA",
        "canonical": "Al Madinah Al Munawwarah",
        "aliases": ["al madinah", "al-madinah", "madinah", "medina", "medinah",
                    "al madina", "almadinah", "al madinah al munawwarah",
                    "madina munawwara", "المدينة", "المدينه", "المدينة المنورة",
                    "المدينه المنوره", "طيبة", "طيبه"]},
    "makkah": {
        "country": "SA",
        "canonical": "Makkah Al Mukarramah",
        "aliases": ["makkah", "mecca", "makkah al mukarramah", "makka",
                    "مكة", "مكه", "مكة المكرمة", "مكه المكرمه"]},
    "riyadh": {
        "country": "SA",
        "canonical": "Riyadh",
        "aliases": ["riyadh", "ar riyadh", "al riyadh", "riyad",
                    "الرياض", "الریاض"]},
    "jeddah": {
        "country": "SA",
        "canonical": "Jeddah",
        "aliases": ["jeddah", "jedda", "jiddah", "jaddah",
                    "جدة", "جده"]},
    "dammam": {
        "country": "SA", "canonical": "Dammam",
        "aliases": ["dammam", "ad dammam", "الدمام"]},
    "khobar": {
        "country": "SA", "canonical": "Al Khobar",
        "aliases": ["khobar", "al khobar", "alkhobar", "الخبر"]},
    "dhahran": {
        "country": "SA", "canonical": "Dhahran",
        "aliases": ["dhahran", "الظهران"]},
    "taif": {
        "country": "SA", "canonical": "Taif",
        "aliases": ["taif", "at taif", "الطائف", "الطايف"]},
    "tabuk": {
        "country": "SA", "canonical": "Tabuk",
        "aliases": ["tabuk", "تبوك"]},
    "abha": {
        "country": "SA", "canonical": "Abha",
        "aliases": ["abha", "ابها", "أبها"]},
    "buraidah": {
        "country": "SA", "canonical": "Buraidah",
        "aliases": ["buraidah", "buraydah", "بريدة", "بريده"]},
    "hail": {
        "country": "SA", "canonical": "Hail",
        "aliases": ["hail", "hayil", "حائل"]},
    "najran": {
        "country": "SA", "canonical": "Najran",
        "aliases": ["najran", "نجران"]},
    "jazan": {
        "country": "SA", "canonical": "Jazan",
        "aliases": ["jazan", "jizan", "gizan", "جازان", "جيزان"]},
    "yanbu": {
        "country": "SA", "canonical": "Yanbu",
        "aliases": ["yanbu", "ينبع"]},
    # Gulf / regional
    "dubai": {"country": "AE", "canonical": "Dubai",
              "aliases": ["dubai", "dubayy", "دبي"]},
    "abu_dhabi": {"country": "AE", "canonical": "Abu Dhabi",
                  "aliases": ["abu dhabi", "abudhabi", "ابوظبي", "أبوظبي"]},
    "sharjah": {"country": "AE", "canonical": "Sharjah",
                "aliases": ["sharjah", "الشارقة"]},
    "doha": {"country": "QA", "canonical": "Doha",
             "aliases": ["doha", "الدوحة", "الدوحه"]},
    "kuwait_city": {"country": "KW", "canonical": "Kuwait City",
                    "aliases": ["kuwait city", "kuwait", "الكويت", "مدينة الكويت"]},
    "manama": {"country": "BH", "canonical": "Manama",
               "aliases": ["manama", "المنامة"]},
    "muscat": {"country": "OM", "canonical": "Muscat",
               "aliases": ["muscat", "مسقط"]},
    "cairo": {"country": "EG", "canonical": "Cairo",
              "aliases": ["cairo", "القاهرة", "القاهره"]},
    "amman": {"country": "JO", "canonical": "Amman",
              "aliases": ["amman", "عمان", "عمّان"]},
}


def resolve_country(raw: str) -> str | None:
    """Return ISO2 code for a country typed in any spelling/language."""
    if not raw:
        return None
    f = fold(raw)
    for code, meta in COUNTRIES.items():
        if f == fold(code):
            return code
        for n in meta["names"]:
            if fold(n) == f:
                return code
    # partial contains (e.g. "kingdom of saudi arabia" typed loosely)
    for code, meta in COUNTRIES.items():
        for n in meta["names"]:
            nf = fold(n)
            if nf and (nf in f or f in nf):
                return code
    return None


def resolve_city(raw: str):
    """Return (city_key, city_meta) for a city typed in any spelling/language."""
    if not raw:
        return None, None
    f = fold(raw)
    for key, meta in CITIES.items():
        for a in meta["aliases"]:
            if fold(a) == f:
                return key, meta
    for key, meta in CITIES.items():
        for a in meta["aliases"]:
            af = fold(a)
            if af and (af in f or f in af) and len(af) >= 4:
                return key, meta
    return None, None


def city_match_tokens(city_key: str) -> set[str]:
    """All folded alias tokens for a city — used to detect it inside a bio."""
    meta = CITIES.get(city_key)
    if not meta:
        return set()
    return {fold(a) for a in meta["aliases"] if fold(a)}


def country_dial(code: str) -> str:
    return COUNTRIES.get(code, {}).get("dial", "")
