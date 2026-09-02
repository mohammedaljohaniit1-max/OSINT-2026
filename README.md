<div align="center">

# 🛰️ Argus — OSINT-2026  ·  v2.1.0

```
    ___
   /   |  _________ ___  _______
  / /| | / ___/ __ `/ / / / ___/
 / ___ |/ /  / /_/ / /_/ (__  )
/_/  |_/_/   \__, /\__,_/____/
            /____/   Zero-API OSINT Engine
        The hundred-eyed. It sees everything.
```

**An evidence-aware, zero-mandatory-key OSINT orchestration framework for Kali Linux.**
Argus auto-detects targets, runs native sources and optional external-tool adapters,
records source coverage, and separates observed facts, inferred facts, candidates, and
confirmed findings. Optional keys can improve coverage; no paid key is mandatory.

*منصة OSINT مبنية على الدليل ولا تتطلب مفتاح API مدفوعاً إلزامياً. تفصل بين المرشح والنتيجة المؤكدة وتعرض المصادر التي فشلت أو لم تتوفر.*

> **Truth contract:** HTTP 200, a matching username, or the same name+city never proves
> account ownership by itself. Reports explicitly label such output as `candidate`.

</div>

---

## 📌 What's new in v2.1.0 — Evidence-first release

| المزية · Feature | الوصف · Description |
|---|---|
| 🧭 **Persona Hunter** | يكتشف مرشحي الملفات العامة بالاسم والدولة والمدينة وبتهجئات عربية/لاتينية؛ لا يدّعي الملكية بلا دليل ربط مستقل. |
| 🌍 **Locale normalization** | تحويلات عربية↔لاتينية وقاموس aliases للدول والمدن؛ التغطية معلنة وليست شاملة لكل لغات العالم. |
| 🎯 **Explainable identity scoring** | يفصل وجود الصفحة عن تشابه الهوية وملكية الحساب، ويرفض تعارض المدينة المعروف. |
| 🔗 **Conservative fusion** | الدمج يتطلب cross-link أو سيرة متطابقة قوية أو handle+مدينة؛ الاسم والمدينة وحدهما لا يكفيان. |
| 🧹 **Truth states** | `observed`, `candidate`, `inferred`, `confirmed`, `rejected`, `unknown`, و`unavailable`. |
| 🛡️ **False-positive controls** | Negative controls، soft-404/generic-shell detection، deduplication، واستقلال عائلات الأدلة. |
| 📊 **Coverage ledger** | كل وحدة تسجل success/empty/partial/failed/timeout/unavailable/skipped ومدة التنفيذ. |

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
- `git`, `pip`. External tools are optional, but each missing tool reduces coverage and is shown as `unavailable`; native modules do not claim perfect replacement coverage.

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

> Default profile is **`deep`** = maximum *passive* depth. Active probing is **never** done unless you pass `--active`. Use repeatable `--include-module NAME` or `--exclude-module NAME` flags for auditable module selection. Local phone numbers require `--phone-region`, for example `--phone-region SA`.

---

## 🧭 Persona Hunter · البحث عن شخص

Search for a **person** by **name + country + city** across Arabic and Latin variants. Argus discovers public profile candidates, rejects known city conflicts, and prints auditable links. It does **not** claim that every account is discoverable or owned by the target without independent linking evidence.

> مثال: عند البحث عن `فراس الحربي` في **المدينة المنورة**، يُرفض الملف الذي يصرّح بمدينة متعارضة مثل الرياض. التهجئة `Firas Al-Harbi` توسّع الاكتشاف فقط، ولا تُدمج الحسابات إلا عند وجود إشارة ربط قوية.

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
| ✅ **CONFIRMED** | أدلة ربط قوية ومستقلة بين الحسابات | Fused identity with explicit fusion signals |
| 🟡 **CANDIDATE** | تطابق اسم/مدينة أو اسم بلا دليل ملكية كافٍ | Separate candidate cluster; never silently merged |
| ⚪ **FILTERED** | صفحة عامة/404 ناعم/مدينة خاطئة/تحكم سلبي فاشل | Count and audit examples only |

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
argus benchmark               # offline false-positive/identity release gates
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
| `phone` | source | PHONE → allocation metadata/region | local numbers require `--phone-region`; carrier may be stale after portability |
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
┌───────────────────────┐   probe curated platforms (passive)
│  Profile extractor     │   OpenGraph / Twitter meta /
│  display,bio,loc,lang  │   JSON-LD Person / <html lang>
└──────────┬─────────────┘
           ▼
┌───────────────────────┐   score = name × city × signals (0–100)
│  Geo-Confirmer         │   HARD RULE: strong name + WRONG city
│  verdict + reasons     │            → REJECTED
└──────────┬─────────────┘
           ▼
┌───────────────────────┐   conservative fusion: cross-link /
│  Cross-account fusion  │   strong shared biography /
│  with reason ledger    │   same handle + declared same city
└──────────┬─────────────┘
           ▼
┌───────────────────────┐   CONFIRMED → strong linking evidence
│  Truth-state emission  │   CANDIDATE → separate clusters
│                        │   FILTERED → count + audit reason
└───────────────────────┘
```

**Curated validators currently included:** GitHub, GitLab, Reddit, Telegram, Keybase, Dev.to, Medium, About.me, Gravatar, PyPI, npm, Docker Hub, Hacker News, CodePen, Replit, and Chess.com. A platform is added only with explicit presence/absence signals and a negative-control strategy.

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
├── setup.py                 # package metadata + `argus` entry point
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

**Add a platform safely:** add a `SiteCheck` in `argus/sources/username.py` with platform-specific presence, absence, shell, and username-binding rules, then add positive and negative fixtures. Generic HTTP 200 checks are not accepted.
**Add a city/country/name spelling:** extend the normalized aliases in `argus/persona/locale.py` and add multilingual tests.
**Tune result volume:** use scan profiles and budgets; never raise confidence merely to reduce output volume.

---

## ✅ Tests · الاختبارات

```bash
# full deterministic suite
python3 -m pytest -q

# syntax/import validation
python3 -m compileall -q argus tests
```
The evidence-first suite includes regression gates for generic HTTP 200 pages, negative controls, confidence-family independence, serialization, scope guards, and persona fusion.

Run the reproducible offline acceptance benchmark:

```bash
argus benchmark
argus benchmark --json-out reports/benchmark_2026-09-02.json
argus benchmark --dataset /path/to/labeled-corpus.json --min-precision 0.98 --max-fpr 0.01
```

The bundled corpus is a deterministic regression gate, **not** proof of real-world superiority. A public comparison claim requires a larger independently labelled corpus, identical target sets and time budgets, and published tool/version manifests.

---

## ⚖️ Legal · إخلاء المسؤولية

Argus performs **passive** OSINT on **publicly available** information only. Active probing is off by default and gated behind `--active`. Use it **only** on targets you are authorised to investigate, and in compliance with all applicable laws. The authors accept no liability for misuse.

*هذه الأداة للاستخدام القانوني والمصرّح به فقط على المعلومات المتاحة للعموم. الفحص سلبي افتراضياً. المسؤولية على المستخدم.*

---

<div align="center">

**Argus — OSINT-2026 · v2.1.0 · Evidence before claims.**

</div>
