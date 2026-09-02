<div align="center">

# 🛰️ Argus — OSINT-2026  ·  v2.0.0

```
    ___
   /   |  _________ ___  _______
  / /| | / ___/ __ `/ / / / ___/
 / ___ |/ /  / /_/ / /_/ (__  )
/_/  |_/_/   \__, /\__,_/____/
            /____/   Zero-API OSINT Engine
        The hundred-eyed. It sees everything.
```

**A professional, zero-API-key, deep-passive OSINT framework for Kali Linux.**
Auto-detects the target, runs 50+ native modules & external-tool adapters with **no API keys**,
correlates everything into one intelligence graph, and produces professional reports.

*إطار احترافي لجمع المعلومات مفتوحة المصدر — بدون أي مفاتيح API، سلبي وعميق جداً، مع محرك بحث عن الأشخاص "Persona Hunter".*

</div>

---

## 📌 What's new in v2.0.0 — الجديد في الإصدار الثاني

| المزية · Feature | الوصف · Description |
|---|---|
| 🧭 **Persona Hunter** | ابحث عن **شخص** بالاسم + الدولة + المدينة بأي لغة (عربي/إنجليزي). يجد الحسابات في **المدينة المحددة فقط** ويضع **روابط الحسابات**. Search a **person** by name + country + city in any language and get **direct account links**, locked to that city only. |
| 🌍 **Locale brain** | تحويل تلقائي عربي↔لاتيني للأسماء + قاموس مدن/دول (خليجي + عالمي) بكل التهجئات. Arabic↔Latin transliteration + a gazetteer of Gulf/world cities & countries with all spellings. |
| 🎯 **Geo-Confirmation** | كل حساب يُقيّم 0–100 (اسم × مدينة × إشارات) مع سبب واضح وحكم. قاعدة صارمة: نفس الاسم في مدينة أخرى → **مرفوض**. Every account scored 0–100 with explainable reasons; same name in a *different* city → **REJECTED**. |
| 🔗 **Cross-account fusion** | حسابات نفس الشخص (عربي + إنجليزي، معرّفات مختلفة) تُدمج في **شخصية واحدة**. Same person's accounts fuse into ONE persona. |
| 🧹 **Lean results** | لا مزيد من "ملف عملاق بدون فائدة". النتائج مرتبة بطبقات: مؤكد / محتمل / ملخص. No more giant useless logs — tiered output: confirmed / likely / summary. |
| 🛡️ **Scope Guard** | إصلاح تلوث الكيانات (كان ينتج 18,005 كياناً وهمياً). Eliminated the 15k+ fake-entity contamination. |

---

## 📚 Table of Contents · الفهرس
1. [Requirements · المتطلبات](#-requirements--المتطلبات)
2. [Install · التنزيل والتثبيت](#-install--التنزيل-والتثبيت)
3. [Uninstall / Update · الحذف والتحديث](#-uninstall--update--الحذف-والتحديث)
4. [The 5 canonical commands · الأوامر الخمسة](#-the-5-canonical-commands--الأوامر-الخمسة)
5. [🧭 Persona Hunter · البحث عن شخص](#-persona-hunter--البحث-عن-شخص)
6. [Scan profiles · ملفات الفحص](#-scan-profiles--ملفات-الفحص)
7. [Management commands · أوامر الإدارة](#-management-commands--أوامر-الإدارة)
8. [Architecture · البنية](#-architecture--البنية)
9. [Modules · الوحدات](#-modules--الوحدات)
10. [How Persona Hunter works · كيف يعمل داخلياً](#-how-persona-hunter-works-internally--كيف-يعمل-داخلياً)
11. [Reports · التقارير](#-reports--التقارير)
12. [Project structure · هيكل المشروع](#-project-structure--هيكل-المشروع)
13. [Extending Argus · التوسيع والتطوير](#-extending-argus--التوسيع-والتطوير)
14. [Tests · الاختبارات](#-tests--الاختبارات)
15. [Legal · إخلاء المسؤولية](#-legal--إخلاء-المسؤولية)

---

## 🧱 Requirements · المتطلبات
- **Kali Linux** (or any Debian/Ubuntu). Also works on macOS/WSL.
- **Python 3.9+** (3.11+ recommended).
- `git`, `pip`. External OSINT tools are **optional** — Argus works fully without them (native modules cover the same ground).

---

## 📥 Install · التنزيل والتثبيت

```bash
# 1) Clone
git clone https://github.com/mohammedaljohaniit1-max/OSINT-2026.git
cd OSINT-2026

# 2) Install (creates a venv, installs the Python core, links the `argus` CLI,
#    and installs optional external tools if apt is available)
chmod +x install.sh
./install.sh

# 3) Activate the environment (each new shell)
source .venv/bin/activate

# 4) Verify
argus doctor
argus modules
```

**Minimal install** (Python core only, no external tools):
```bash
./install.sh --minimal
```

**Run without installing** (standalone launcher):
```bash
pip install -r requirements.txt
python3 argus.py scan example.com
```

---

## ♻️ Uninstall / Update · الحذف والتحديث

```bash
./install.sh --uninstall     # removes venv, reports, SearXNG container, entry point
./install.sh --update        # refresh external tools & templates
```

---

## 🎛️ The 5 canonical commands · الأوامر الخمسة

Argus **auto-detects** the target type (domain, IP, email, phone, username, **person**). One command shape for everything:

```bash
argus scan <target> [--profile deep|standard|quick|stealth] [--active]
```

| # | Example · مثال | Detected as |
|---|---|---|
| 1 | `argus scan example.com` | Domain |
| 2 | `argus scan 8.8.8.8` | IP |
| 3 | `argus scan vxxvvxxvv3@gmail.com` | Email |
| 4 | `argus scan 0576365924` | Phone (Saudi local number) |
| 5 | `argus scan "فراس الحربي" --country "Saudi Arabia" --city "Al Madinah Al Munawwarah"` | **Person → Persona Hunter** |

> Default profile is **`deep`** = maximum *passive* depth. Active probing is **never** done unless you pass `--active`.

---

## 🧭 Persona Hunter · البحث عن شخص

Search for a **person** by **name + country + city**, in **any language**. Argus finds every account that carries that name **and belongs to the specified city only** — and prints the **links** to those accounts.

> مثال: ابحث عن `فراس الحربي` في **المدينة المنورة**. لو وُجد "فراس الحربي" في **الرياض** → لا يظهر. ولو كتب اسمه بالإنجليزية "Firas Al-Harbi" → يظهر ويُدمج مع حسابه العربي في **شخصية واحدة**.

### Usage · الاستخدام
```bash
# Arabic name + Arabic city
argus scan "فراس الحربي" --country "السعودية" --city "المدينة المنورة" --profile deep

# English name + English city (same person, still found)
argus scan "Firas Al-Harbi" --country "Saudi Arabia" --city "Al Madinah Al Munawwarah"

# You can also pass the name via --name and use the target as a label
argus scan person --name "فراس الحربي" --country SA --city "Medina"
```

Country and city accept **any spelling**:
`Saudi Arabia` = `السعودية` = `KSA` = `SA` → **SA**  ·  `Al Madinah Al Munawwarah` = `المدينة المنورة` = `Medina` → **al_madinah**.

### What you get · النتيجة
Results are **tiered** so you never get a useless dump:

| Tier · الطبقة | Meaning · المعنى | Output |
|---|---|---|
| ✅ **CONFIRMED** | الاسم + المدينة المحددة مؤكدان | Fused persona(s), **full detail + links** |
| 🟡 **LIKELY** | نفس الاسم لكن المدينة غير مذكورة | ONE grouped bucket (top matches) |
| ⚪ **SUMMARY** | أسماء ضعيفة / **مدينة خاطئة** | عدد فقط + أمثلة قليلة للتدقيق |

Each account row carries: **platform · link · handle · display name · location · score · why (reasons)**.

---

## ⚙️ Scan profiles · ملفات الفحص

| Profile | Depth | Handles/platform (Persona) | Use |
|---|---|---|---|
| `quick` | shallow, fastest | 8 | quick triage |
| `standard` | balanced | 18 | daily use |
| `deep` *(default)* | maximum **passive** depth | 40 | full investigation |
| `stealth` | low-noise, Tor-friendly | 12 | quiet recon |

---

## 🗂️ Management commands · أوامر الإدارة

```bash
argus history                 # list stored scans
argus report [scan_id]        # regenerate reports from a stored scan (default: latest)
argus export [scan_id] -o f   # export raw JSON of a scan
argus diff <target>           # diff two most recent scans of a target
argus clean -k 5              # prune stored scans, keep newest 5
argus doctor                  # environment health check
argus modules                 # list all loaded modules
```

---

## 🏗️ Architecture · البنية

Argus is a **self-orchestrating blackboard engine** built from four components:

1. **Detector** — classifies the raw target (domain / IP / email / phone / username / **person**, incl. Arabic-name detection).
2. **Registry** — auto-discovers every `Module` under `argus/` and reads its `ModuleSpec` (accepts/produces entity types, active flag, priority, tags).
3. **Engine (IntelGraph blackboard)** — seeds the target, then repeatedly picks modules whose *accepts* type is present, runs them, and folds their **Entities / Relationships / Evidence** back into one graph. A **Scope Guard** ensures only in-scope entities cascade — look-alikes and out-of-scope contacts are recorded as *findings* but never expanded (this killed the 15k-entity contamination).
4. **Reporter** — renders the graph into JSON / Markdown / HTML / GEXF, including the **🧭 Persona Investigation** section.

Everything shares a **unified data model**: `Entity`, `Relationship`, `Evidence` inside a single `IntelGraph`.

---

## 🧩 Modules · الوحدات

51 modules load out of the box. Highlights:

| Module | Category | Accepts → Produces | Notes |
|---|---|---|---|
| `persona_hunter` | native | PERSON → PERSONA / SOCIAL_PROFILE / USERNAME | 🧭 the person search engine |
| `whois_rdap` | source | DOMAIN → registrar/org/contacts | passive RDAP |
| `certs` (crt.sh) | source | DOMAIN → SUBDOMAIN | cert transparency |
| `passive_dns` / `dns_records` | source | DOMAIN → IP/records | |
| `deep_passive` | source | DOMAIN → many | aggregated passive |
| `wayback` / `wayback_diff` | source/native | DOMAIN → URLs/changes | |
| `breaches` / `breach_correlation` | source/native | EMAIL → breach findings | |
| `email_enrich` / `email_permutator` | source/native | EMAIL/PERSON → emails | |
| `username` | source | USERNAME → SOCIAL_PROFILE | |
| `phone` | source | PHONE → carrier/region/dorks | handles `0576365924` as Saudi |
| `github_dork` / `js_recon` | source/native | DOMAIN → leaks/endpoints | |
| `typosquat` / `favicon_pivot` / `tracker_pivot` / `asn_sweep` / `bucket_hunter` | native | pivots | genius correlation |

List them live with `argus modules`.

---

## 🧠 How Persona Hunter works internally · كيف يعمل داخلياً

```
raw name (any language)
        │
        ▼
┌───────────────────────┐   COUNTRY/CITY (any spelling)
│  Locale brain          │◄──────────────────────────────┐
│  • strip honorifics    │                                │
│    (bin/ibn/al/abu)    │        ┌──────────────────────┴───┐
│  • ar↔latin translit   │        │  Gazetteer                │
│  • spelling variants   │        │  countries + cities       │
└──────────┬─────────────┘        │  (ar + en + aliases)      │
           │                      └──────────────────────────┘
           ▼
┌───────────────────────┐
│  Name→username engine  │  firas.alharbi, f.alharbi,
│  (ranked real handles) │  alharbi.firas, +year suffixes…
└──────────┬─────────────┘
           ▼
┌───────────────────────┐   probe 18 platforms (passive)
│  Profile extractor     │   OpenGraph / Twitter meta /
│  display,bio,loc,lang  │   JSON-LD Person / <html lang>
└──────────┬─────────────┘
           ▼
┌───────────────────────┐   score = name × city × signals (0–100)
│  Geo-Confirmer         │   HARD RULE: strong name + WRONG city
│  verdict + reasons     │            → REJECTED
└──────────┬─────────────┘
           ▼
┌───────────────────────┐   union-find: cross-link / same bio /
│  Cross-account fusion  │   (confirmed + same gazetteer city +
│  → ONE persona         │    shared handle stem)
└──────────┬─────────────┘
           ▼
┌───────────────────────┐   CONFIRMED → full detail + links
│  Lean tiered emission  │   LIKELY    → one bucket
│                        │   POSSIBLE/REJECTED → count summary
└───────────────────────┘
```

**Platforms probed (18):** GitHub, GitLab, Instagram, TikTok, YouTube, Twitter/X, Reddit, Telegram, Pinterest, Medium, Behance, SoundCloud, About.me, Gravatar, Keybase, Linktree, Snapchat, Threads.

---

## 📄 Reports · التقارير

Every scan writes to `reports/`:
- `*.json` — full machine-readable graph
- `*.md` — Markdown summary
- `*.html` — styled report incl. the **🧭 Persona Investigation** section (personas sorted by verdict, clickable account links, colour-coded confidence, "why" reasons)
- `*.gexf` — graph for Gephi

---

## 🌲 Project structure · هيكل المشروع

```
OSINT-2026/
├── argus.py                 # standalone launcher
├── install.sh               # installer (--minimal/--update/--uninstall)
├── requirements.txt
├── setup.py                 # v2.0.0, `argus` entry point
├── config.yaml
├── argus/
│   ├── __init__.py          # version + banner
│   ├── cli.py               # scan + management commands, --name/--country/--city/--lang
│   ├── core/
│   │   ├── config.py        # + person_name/country/city/langs
│   │   ├── models.py        # Entity/Relationship/Evidence, EntityType.PERSONA
│   │   ├── detector.py      # target classifier (+ Arabic-name → PERSON)
│   │   ├── registry.py      # module auto-discovery
│   │   ├── engine.py        # blackboard engine + Scope Guard
│   │   └── correlator.py
│   ├── persona/             # 🧭 Persona Hunter
│   │   ├── locale.py        # ar↔latin translit + COUNTRIES/CITIES gazetteer
│   │   ├── name_engine.py   # name → ranked usernames + display queries
│   │   ├── geo_confirm.py   # 0–100 scoring + REJECTED hard-rule
│   │   ├── extract.py       # passive profile field extraction
│   │   ├── persona.py       # ProfileHit + fuse() union-find
│   │   └── investigator.py  # PersonaHunter module + lean tiered emission
│   ├── sources/             # passive sources (whois, certs, dns, phone, …)
│   ├── native/              # genius pivots (typosquat, favicon, asn, …)
│   ├── adapters/            # external-tool wrappers (optional)
│   ├── reporting/reporter.py# JSON/MD/HTML/GEXF + persona section
│   └── utils/http.py        # async HTTP client (rate-limited, Tor-capable)
└── tests/                   # test_persona, test_scope_guard, test_truthguards, test_pipeline
```

---

## 🧬 Extending Argus · التوسيع والتطوير

> "أي مشروع ناجح دائماً قابل للتطوير والتوسيع" — Argus is built to grow forever, like the big companies keep growing.

**Add a new module** in 3 steps:
1. Create a file under `argus/native/` (or `argus/sources/`) with a class subclassing `Module`.
2. Give it a `spec = ModuleSpec(name=…, accepts={…}, produces={…}, priority=…, tags={…})`.
3. That's it — the **Registry auto-discovers it**. No wiring needed.

**Add a platform to Persona Hunter:** append one line to `PLATFORMS` in `argus/persona/investigator.py`.
**Add a city/country/name spelling:** extend the dicts in `argus/persona/locale.py` (`CITIES`, `COUNTRIES`, `CANON_NAME_MAP`).
**Tune result volume:** `MAX_LIKELY_ACCOUNTS` / `MAX_REJECTED_EXAMPLES` / `MAX_HANDLES` in `investigator.py`.

---

## ✅ Tests · الاختبارات

```bash
# persona unit + e2e (28 assertions across 7 tests)
python3 -m pytest tests/test_persona.py -q

# scope-guard, truth-guards, pipeline (standalone scripts)
python3 tests/test_scope_guard.py
python3 tests/test_truthguards.py
python3 tests/test_pipeline.py
```
All green: **28 persona + 11 scope-guard + 8 truth-guard + pipeline**.

---

## ⚖️ Legal · إخلاء المسؤولية

Argus performs **passive** OSINT on **publicly available** information only. Active probing is off by default and gated behind `--active`. Use it **only** on targets you are authorised to investigate, and in compliance with all applicable laws. The authors accept no liability for misuse.

*هذه الأداة للاستخدام القانوني والمصرّح به فقط على المعلومات المتاحة للعموم. الفحص سلبي افتراضياً. المسؤولية على المستخدم.*

---

<div align="center">

**Argus — OSINT-2026 · v2.0.0 · The hundred-eyed. It sees everything.**

</div>
