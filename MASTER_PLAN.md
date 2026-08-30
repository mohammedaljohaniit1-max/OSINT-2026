# 🕵️ OSINT-2026 — الخطة العملاقة (Master Plan)

> **الاسم المقترح للأداة:** `OSINT-2026` (اسم كودي داخلي: **`Argus`** — العملاق ذو المئة عين في الأساطير، رمز المراقبة الكاملة)
>
> **الحالة:** خطة (Planning Phase) — لم يبدأ البناء بعد.
> **آخر تحديث:** 2026-08-30
> **الجمهور المستهدف:** محلل/موظف أمن سيبراني يحتاج فحوصات OSINT متكررة (دومين شركة / إيميلات موظفين / أرقام جوالات).

---

## 📑 فهرس الوثيقة

1. [الرؤية والأهداف](#1)
2. [المشكلة الحالية والحل](#2)
3. [المبادئ الحاكمة (Design Principles)](#3)
4. [المعمارية العامة (High-Level Architecture)](#4)
5. [محرك الكشف التلقائي عن نوع الهدف (Target Detection Engine)](#5)
6. [كتالوج الأدوات الخارجية الكامل](#6)
7. [السكربتات الخاصة بنا (Custom Scripts / Native Modules)](#7)
8. [نظام الإدارة والتشغيل (Orchestrator)](#8)
9. [نظام النتائج والتقارير (Reporting Engine)](#9)
10. [نظام التثبيت والتجهيز التلقائي (Installer)](#10)
11. [هيكل المجلدات الكامل](#11)
12. [الأمان والأخلاقيات والقانون (OPSEC & Legal)](#12)
13. [خارطة الطريق المرحلية (Roadmap / Phases)](#13)
14. [معايير النجاح (Definition of Done)](#14)

---

<a name="1"></a>
## 1. الرؤية والأهداف

### 1.1 الرؤية
بناء **إطار عمل OSINT موحّد (Unified OSINT Framework)** احترافي، مفتوح، قابل للتوسّع للأبد، يحوّل عملية جمع المعلومات من "تشغيل عشرات الأدوات يدوياً" إلى **أمر واحد**:

```bash
argus scan example.com
argus scan john.doe@company.com
argus scan +966501234567
argus scan johndoe        # username
```

يتعرّف تلقائياً على نوع الهدف، يشغّل الأدوات والسكربتات المناسبة بالتوازي، يجمّع النتائج، يزيل التكرار، ويخرج تقريراً موحّداً (HTML/JSON/PDF/Markdown).

### 1.2 الأهداف الإلزامية (Hard Requirements)
| # | الهدف | المعيار |
|---|-------|---------|
| G1 | **تغطية كاملة حرفياً** | كل نوع هدف (دومين، إيميل، هاتف، username، IP، اسم شخص، شركة) له تغطية من أدوات + سكربتات خاصة تسدّ الفجوات |
| G2 | **اختصار الوقت فعلياً** | أمر واحد يحل محل تشغيل 10-30 أداة يدوياً؛ تشغيل متوازٍ |
| G3 | **كشف تلقائي للهدف** | لا حاجة لتحديد النوع يدوياً — المحرك يستنتجه |
| G4 | **تثبيت بأمر واحد** | `git clone` ثم تشغيل ملف واحد يجهّز كل شيء ويتحقق منه |
| G5 | **يعمل على Linux (أولوية)** | ودعم Windows/Mac إن أمكن، وإلا Linux فقط مقبول |
| G6 | **قابل للتوسّع للأبد** | إضافة أداة/سكربت جديد = ملف plugin واحد بدون تعديل النواة |

### 1.3 أهداف ثانوية (Nice to Have)
- واجهة ويب محلية اختيارية (Dashboard).
- جدولة فحوصات دورية (monitoring / continuous OSINT).
- مقارنة نتائج بين فحصين (diff — "ماذا تغيّر منذ آخر فحص؟").
- تكامل مع نظام التذاكر/التنبيهات في الشركة.

---

<a name="2"></a>
## 2. المشكلة الحالية والحل

### 2.1 نقاط الألم (Pain Points)
- تشغيل أداة تلو الأخرى يدوياً (theHarvester ثم amass ثم holehe ثم...).
- كل أداة لها صيغة مخرجات مختلفة (JSON/CSV/نص/XML).
- تجميع النتائج ودمجها وإزالة التكرار يدوياً.
- إعادة كتابة التقرير كل مرة.
- إدارة API keys المتناثرة.
- تثبيت وتحديث كل أداة على حدة.

### 2.2 الحل
طبقة تنسيق (Orchestration Layer) واحدة فوق كل الأدوات + محرك تطبيع (Normalization) + محرك ربط (Correlation) + مولّد تقارير موحّد + مُثبِّت ذكي.

```
مدخل واحد  →  كشف النوع  →  اختيار الوحدات  →  تشغيل متوازٍ  →  تطبيع  →  ربط وإزالة تكرار  →  تقرير موحّد
```

---

<a name="3"></a>
## 3. المبادئ الحاكمة (Design Principles)

1. **Plugin-first (كل شيء إضافة):** كل أداة خارجية وكل سكربت خاص = "موديول" يتبع واجهة موحّدة (interface). النواة لا تعرف تفاصيل الأدوات.
2. **Schema موحّد:** كل موديول يُخرج بيانات بصيغة داخلية موحّدة (`Entity` + `Relationship`) مهما كانت أداته الأصلية.
3. **فصل الطبقات (Separation of Concerns):** النواة / الموديولات / التقارير / التثبيت منفصلة تماماً.
4. **آمن افتراضياً (Passive by default):** يبدأ بالفحص السلبي (Passive) الذي لا يلمس الهدف؛ الفحص النشط (Active) يتطلب `--active` صريح.
5. **بدون مفاتيح = يعمل جزئياً:** الأدوات التي لا تحتاج API keys تعمل فوراً؛ التي تحتاج تُفعّل عند إضافة المفتاح، ولا تُعطّل بقية النظام.
6. **قابل للتكرار (Idempotent):** إعادة التشغيل لا تُفسد النتائج؛ نظام cache لتجنّب الاستعلامات المكررة.
7. **شفاف وقابل للتدقيق (Auditable):** كل استعلام يُسجّل (من، متى، ضد ماذا) لأغراض الامتثال القانوني في الشركة.
8. **لا يعيد اختراع العجلة:** نستخدم الأدوات الناضجة كما هي، ونكتب سكربتات خاصة فقط لسدّ الفجوات الحقيقية.

---

<a name="4"></a>
## 4. المعمارية العامة (High-Level Architecture)

```
┌──────────────────────────────────────────────────────────────────────┐
│                             CLI / TUI / (Web UI اختياري)               │
│                          argus scan <target> [flags]                    │
└───────────────────────────────┬──────────────────────────────────────┘
                                 │
┌───────────────────────────────▼──────────────────────────────────────┐
│                          CORE (النواة / Argus Core)                     │
│  ┌────────────────┐ ┌──────────────────┐ ┌───────────────────────┐    │
│  │ Target Detector │ │ Task Planner /   │ │  Module Registry       │    │
│  │ (كشف النوع)     │ │ Scheduler (DAG)  │ │  (سجل الإضافات)         │    │
│  └────────────────┘ └──────────────────┘ └───────────────────────┘    │
│  ┌────────────────┐ ┌──────────────────┐ ┌───────────────────────┐    │
│  │ Executor        │ │ Normalizer       │ │ Correlation Engine     │    │
│  │ (تشغيل متوازٍ)  │ │ (تطبيع المخرجات) │ │ (ربط + إزالة تكرار)    │    │
│  └────────────────┘ └──────────────────┘ └───────────────────────┘    │
│  ┌────────────────┐ ┌──────────────────┐ ┌───────────────────────┐    │
│  │ Cache / Store   │ │ Rate Limiter /   │ │ Secrets/Config Manager │    │
│  │ (SQLite)        │ │ Proxy Manager    │ │ (API keys)             │    │
│  └────────────────┘ └──────────────────┘ └───────────────────────┘    │
└──────┬─────────────────────────┬──────────────────────────┬──────────┘
       │                         │                          │
┌──────▼───────┐   ┌─────────────▼────────────┐   ┌─────────▼──────────┐
│ External Tool │   │  Native Modules          │   │  Reporting Engine   │
│ Adapters      │   │  (سكربتاتنا الخاصة)      │   │  HTML/PDF/JSON/MD   │
│ (محوّلات)     │   │                          │   │  + Graph (Maltego-  │
│ theHarvester  │   │  - custom email intel    │   │    like)            │
│ amass, holehe │   │  - custom phone intel    │   └────────────────────┘
│ sherlock ...  │   │  - custom domain intel   │
└───────────────┘   │  - dork engine, etc.     │
                    └──────────────────────────┘
```

### 4.1 نموذج البيانات الموحّد (Unified Data Model)
كل نتيجة من أي موديول تتحول إلى:

- **Entity (كيان):** `{ id, type, value, confidence, source, first_seen, tags, metadata{} }`
  - أنواع: `domain, subdomain, ip, email, phone, username, person, organization, url, breach, credential, social_profile, file, asn, certificate, geolocation`
- **Relationship (علاقة):** `{ from_entity, to_entity, type, source, confidence }`
  - أنواع: `resolves_to, owned_by, member_of, leaked_in, linked_account, hosts, registered_by`

هذا هو ما يمكّن "الربط" (Correlation) وبناء رسم بياني (Graph) شبيه بـ Maltego.

### 4.2 لغة التنفيذ
- **النواة والسكربتات الخاصة:** **Python 3.11+** (نضج مكتبات OSINT، سهولة، معظم الأدوات بايثون).
- **الأدوات الخارجية:** تُستدعى كما هي (بايثون/Go/غيره) عبر Adapters.
- **إدارة الحزم:** `pipx` للأدوات المعزولة + `venv` للنواة + Go binaries للأدوات المكتوبة بـ Go (amass/subfinder).

---

<a name="5"></a>
## 5. محرك الكشف التلقائي عن نوع الهدف (Target Detection Engine)

الميزة الأهم لتحقيق G3. المنطق تسلسلي بالأولوية:

| الترتيب | النوع | قاعدة الكشف (Heuristic) |
|---------|-------|------------------------|
| 1 | **Email** | يطابق regex بريد `\S+@\S+\.\S+` |
| 2 | **Phone** | يبدأ بـ `+` أو أرقام مع رموز دولية؛ يُتحقق عبر `phonenumbers` (Google libphonenumber) |
| 3 | **IPv4/IPv6** | يطابق صيغة IP صالحة |
| 4 | **CIDR / ASN** | `1.2.3.0/24` أو `ASxxxx` |
| 5 | **Domain** | يطابق صيغة نطاق صالح + له TLD معروف (قائمة IANA) |
| 6 | **URL** | يبدأ بـ `http(s)://` |
| 7 | **Username** | إذا لم يطابق ما سبق ولا يحتوي مسافات/رموز غير مسموحة |
| 8 | **Person / Org name** | يحتوي مسافة أو أكثر → يُعامل كاسم للبحث |
| 9 | **Hash / BTC / crypto** | أنماط hash معروفة أو عناوين محافظ |

- **حالات الغموض:** إن تطابق أكثر من نوع، يُعرض للمستخدم اختيار أو يُشغّل الأنواع المحتملة (`--type` للتجاوز اليدوي).
- **مدخلات متعددة:** ملف يحوي قائمة أهداف (`argus scan -f targets.txt`) → يكتشف كل سطر.
- **قابل للتوسّع:** كاشفات جديدة تُضاف كـ plugins.

---

<a name="6"></a>
## 6. كتالوج الأدوات الخارجية الكامل

> مصنّفة حسب نوع الهدف. **P** = سلبي (Passive)، **A** = نشط (Active)، **K** = يحتاج API key.
> هذه القائمة "للأبد" — قابلة للزيادة. كلها مفتوحة المصدر ومجانية إلا ما يُذكر.

### 6.1 أدوات النطاقات / البنية التحتية (Domain / Infrastructure)
| الأداة | اللغة | الوصف | نوع |
|--------|-------|-------|-----|
| **theHarvester** | Python | جمع إيميلات/نطاقات فرعية/مضيفين من محركات بحث ومصادر عامة | P/K |
| **OWASP Amass** | Go | تعداد نطاقات فرعية شامل (Passive+Active) + خرائط ASN/CIDR | P/A/K |
| **subfinder** | Go | تعداد نطاقات فرعية سلبي سريع (ProjectDiscovery) | P/K |
| **assetfinder** | Go | إيجاد أصول/نطاقات مرتبطة بدومين | P |
| **findomain** | Rust | تعداد نطاقات فرعية سريع | P |
| **dnsx** | Go | استعلامات DNS جماعية سريعة | A |
| **dnsrecon** | Python | فحص DNS، zone transfer، brute force | P/A |
| **massdns** | C | حل DNS جماعي عالي السرعة | A |
| **crt.sh (API)** | — | شفافية الشهادات (Certificate Transparency) | P |
| **whois / python-whois** | Python | معلومات تسجيل النطاق | P |
| **httpx** | Go | فحص خدمات HTTP الحية، عناوين، تقنيات | A |
| **naabu** | Go | فحص منافذ سريع | A |
| **nmap** | C | فحص منافذ/خدمات تفصيلي | A |
| **Shodan (API)** | Python | محرك بحث الأجهزة المتصلة | P/K |
| **Censys (API)** | Python | فحص الأصول والشهادات على الإنترنت | P/K |
| **WhatWeb** | Ruby | بصمة تقنيات المواقع | A |
| **Wappalyzer (CLI)** | JS | كشف تقنيات الموقع | A |
| **wafw00f** | Python | كشف جدار حماية التطبيقات (WAF) | A |
| **waybackurls / gau** | Go | استخراج روابط تاريخية من Wayback/CommonCrawl | P |
| **openSquat** | Python | كشف النطاقات المزيّفة (typosquatting) للعلامة | P |

### 6.2 أدوات البريد الإلكتروني (Email)
| الأداة | اللغة | الوصف | نوع |
|--------|-------|-------|-----|
| **holehe** | Python | يكشف أي مواقع/خدمات مسجّل فيها الإيميل | P |
| **h8mail** | Python | البحث عن الإيميل في تسريبات البيانات + كلمات مرور | P/K |
| **theHarvester** | Python | (مذكور أعلاه) لجمع إيميلات المؤسسة | P/K |
| **Have I Been Pwned (API)** | — | التحقق من ظهور الإيميل/الرقم في اختراقات | P/K |
| **DeHashed / LeakCheck (API)** | — | قواعد تسريبات تجارية (اختياري) | P/K |
| **mosint** | Go | جامع OSINT شامل للإيميل (تسريبات، DNS، مواقع) | P/K |
| **emailrep (API)** | — | سمعة الإيميل ومخاطره | P/K |
| **infoga** | Python | جمع معلومات الإيميل من مصادر عامة | P |
| **email-verify / MX check** | Python | التحقق من صلاحية/تسليم الإيميل (SMTP/MX) | A |

### 6.3 أدوات أرقام الهواتف (Phone)
| الأداة | اللغة | الوصف | نوع |
|--------|-------|-------|-----|
| **PhoneInfoga** | Go | أشهر أداة: مشغّل الشبكة، الدولة، نوع الخط، بحث محركات | P/K |
| **ignorant** | Python | يكشف إن كان الرقم مسجّلاً في مواقع (نظير holehe للهاتف) | P |
| **phonenumbers (libphonenumber)** | Python | تحليل/تحقق/تنسيق دولي + المشغّل والمنطقة | P |
| **Numverify (API)** | — | تحقق من الرقم والمشغّل والموقع | P/K |
| **Truecaller (غير رسمي/حذر)** | — | اسم صاحب الرقم (قيود قانونية) | P/K |

### 6.4 أدوات أسماء المستخدمين / الحسابات (Username / Social)
| الأداة | اللغة | الوصف | نوع |
|--------|-------|-------|-----|
| **Sherlock** | Python | البحث عن username عبر مئات المنصات | P |
| **Maigret** | Python | نسخة موسّعة من Sherlock (3000+ موقع) + استخراج بيانات | P |
| **WhatsMyName** | data/Python | قاعدة بيانات ضخمة لفحص أسماء المستخدمين | P |
| **socialscan** | Python | التحقق من توفر/استخدام username وإيميل على المنصات | P |
| **blackbird** | Python | بحث سريع عن الحسابات بالاسم/username | P |

### 6.5 أدوات شاملة / إطارات (Frameworks & Aggregators)
| الأداة | اللغة | الوصف | نوع |
|--------|-------|-------|-----|
| **SpiderFoot** | Python | أقوى إطار OSINT آلي (200+ موديول) — سنتكامل معه ونستفيد منه | P/A/K |
| **recon-ng** | Python | إطار استطلاع نمطي بأسلوب Metasploit | P/K |
| **Maltego (CE)** | Java | تصوّر العلاقات (اختياري، للتصدير) | P/K |
| **Photon** | Python | زاحف ويب لاستخراج البيانات (إيميلات، روابط، ملفات) | P/A |

### 6.6 أدوات مساندة (Utilities)
| الأداة | الوصف |
|--------|-------|
| **ExifTool** | استخراج بيانات ميتا من الصور/الملفات |
| **metagoofil** | استخراج ميتاداتا من مستندات المؤسسة العامة |
| **GHunt** | OSINT لحسابات Google (يحتاج جلسة) |
| **twint/snscrape** | استخراج من الشبكات الاجتماعية (حسب توفرها) |
| **google dorks DB** | قاعدة استعلامات Google Dorks جاهزة |

---

<a name="7"></a>
## 7. السكربتات الخاصة بنا (Custom / Native Modules)

> هذه هي "قيمتنا المضافة" — تسدّ الفجوات التي لا تغطيها الأدوات الجاهزة. النوع الثاني الذي طلبته.
> كل سكربت = موديول يتبع نفس واجهة الموديولات ويُخرج بنفس الـ Schema الموحّد.

### 7.1 موديولات النطاق (Custom Domain Intelligence)
| الموديول | الفجوة التي يسدّها |
|----------|-------------------|
| `native_email_pattern` | استنتاج نمط إيميلات الشركة (first.last@, f.last@) من الإيميلات المكتشفة، ثم توليد إيميلات محتملة لبقية الموظفين المعروفين بالاسم |
| `native_cert_intel` | تحليل شهادات SSL/TLS (SAN, issuer, تواريخ) لاكتشاف نطاقات/أصول مخفية عبر crt.sh + الاتصال المباشر |
| `native_dns_history` | تجميع سجل DNS التاريخي (SecurityTrails/passive DNS) وربطه بالبنية الحالية |
| `native_tech_fingerprint` | دمج نتائج WhatWeb/Wappalyzer/httpx في بصمة تقنية موحّدة + مطابقتها مع CVEs معروفة |
| `native_cloud_assets` | كشف أصول سحابية (S3 buckets, Azure blobs, GCP) مرتبطة باسم الشركة |
| `native_github_leaks` | البحث في GitHub/GitLab عن تسريبات أسرار/مفاتيح مرتبطة بالنطاق (بأسلوب gitleaks/trufflehog على النتائج العامة) |
| `native_typosquat` | توليد وفحص نطاقات مزيّفة محتملة للعلامة التجارية (phishing detection) |
| `native_email_security` | فحص SPF/DKIM/DMARC/MTA-STS لتقييم نضج أمن البريد للنطاق |

### 7.2 موديولات البريد (Custom Email Intelligence)
| الموديول | الفجوة |
|----------|--------|
| `native_email_correlate` | ربط إيميل واحد بكل ما اكتُشف عنه (تسريبات + حسابات + username محتمل مشتق من الإيميل) في بطاقة واحدة |
| `native_username_from_email` | اشتقاق أسماء مستخدمين محتملة من الإيميل وتمريرها لـ Sherlock/Maigret تلقائياً |
| `native_breach_timeline` | بناء خط زمني للاختراقات التي ظهر فيها الإيميل + تقييم الخطورة (كلمات مرور مكشوفة؟) |
| `native_gravatar` | فحص Gravatar/صور مرتبطة بالإيميل |

### 7.3 موديولات الهاتف (Custom Phone Intelligence)
| الموديول | الفجوة |
|----------|--------|
| `native_phone_enrich` | دمج libphonenumber + المشغّل + المنطقة الزمنية + نوع الخط في بطاقة موحّدة |
| `native_phone_pivot` | استخدام الرقم كنقطة ارتكاز: بحث في محركات/شبكات اجتماعية/تطبيقات المراسلة عن ظهوره |
| `native_phone_format_expand` | توليد كل الصيغ الممكنة للرقم (محلي/دولي/بدون رموز) لتغطية بحث أوسع |

### 7.4 موديولات عامة (Cross-cutting)
| الموديول | الوصف |
|----------|-------|
| `native_dork_engine` | محرك Google/Bing/DuckDuckGo Dorks: يبني ويشغّل استعلامات dork ذكية حسب نوع الهدف (site:, filetype:, intext:) |
| `native_people_search` | تجميع بحث الأشخاص من مصادر عامة (اسم → إيميل/هاتف/حسابات محتملة) |
| `native_pastebin_monitor` | البحث في مواقع اللصق (Pastebin وأشباهه) عن ظهور الهدف |
| `native_darkweb_lite` | فحص خفيف لمصادر مفتوحة تشير لتسريبات dark web (بدون دخول فعلي — روابط/فهارس عامة فقط) |
| `native_wayback_intel` | استخراج صفحات/مسارات/إيميلات من أرشيف Wayback |
| `native_metadata_harvest` | تنزيل مستندات عامة للنطاق واستخراج ميتاداتا (أسماء موظفين، برامج، مسارات) |
| `native_correlation_scorer` | خوارزمية تقييم الثقة والربط بين الكيانات (أي معلومة مؤكدة من مصدرين+؟) |

### 7.5 واجهة الموديول الموحّدة (Module Interface)
كل موديول (خارجي أو خاص) يطبّق:
```python
class Module:
    name: str
    target_types: list[str]      # ["domain", "email", ...]
    requires_keys: list[str]     # ["shodan_api_key", ...] أو []
    mode: str                    # "passive" | "active"
    def is_available(self) -> bool: ...     # هل الأداة/المفتاح متوفر؟
    def run(self, target: Target, ctx: Context) -> list[Entity | Relationship]: ...
```
هذا يضمن G6 (التوسّع للأبد بإضافة ملف واحد).

---

<a name="8"></a>
## 8. نظام الإدارة والتشغيل (Orchestrator) — النوع الأول من السكربتات

> هذا هو "العقل المدبّر" الذي طلبته: يشغّل الأدوات، يحلّل الطلب، يرتّب المهام، يجمع النتائج.

### 8.1 مراحل التنفيذ (Pipeline)
```
1. Parse Input      → قراءة الهدف/الأهداف والأعلام (flags)
2. Detect Type      → محرك الكشف (القسم 5)
3. Plan Tasks       → بناء DAG: أي موديولات تعمل، وترتيبها، وتبعياتها
                      (مثال: theHarvester يجب أن يسبق native_email_pattern)
4. Resolve Deps     → التحقق من توفر الأدوات/المفاتيح؛ تخطّي غير المتوفر مع تحذير
5. Execute          → تشغيل متوازٍ (asyncio + process pool) مع rate limiting
6. Normalize        → تحويل كل مخرجات لـ Entity/Relationship
7. Correlate        → ربط، إزالة تكرار، تقييم ثقة (native_correlation_scorer)
8. Store            → حفظ في SQLite (workspace) + cache
9. Report           → توليد التقارير (القسم 9)
```

### 8.2 مخطّط المهام (Task Planner / DAG)
- يبني رسم تبعيات موجّه (Directed Acyclic Graph): بعض الموديولات تعتمد على مخرجات غيرها.
- **مثال حقيقي (فحص دومين شركة):**
  ```
  domain
   ├─(parallel)─ whois, crt.sh, subfinder, amass(passive), theHarvester, shodan
   │                         │
   │                    subdomains ──► httpx (فحص الحية) ──► tech fingerprint
   │
   ├─ theHarvester → emails ──► holehe + h8mail + native_email_pattern
   │                                  │
   │                          native_username_from_email ──► sherlock + maigret
   │
   └─ native_email_security (SPF/DKIM/DMARC), native_typosquat, native_github_leaks
  ```

### 8.3 أوضاع التشغيل (Profiles)
| البروفايل | الوصف | الاستخدام |
|-----------|-------|-----------|
| `quick` | أدوات سلبية سريعة فقط | فحص أولي سريع |
| `standard` (افتراضي) | كل الأدوات السلبية + الخاصة | الفحص اليومي |
| `deep` | سلبي + نشط + brute force خفيف | فحص معمّق مصرّح به |
| `stealth` | سلبي فقط عبر proxies/tor، معدلات منخفضة | فحص حذر |
| `monitor` | فحص دوري + تنبيه على التغييرات | مراقبة مستمرة |
| `custom` | المستخدم يختار الموديولات | مرن |

### 8.4 إدارة الموارد
- **Rate Limiting:** لكل مصدر/API حد معدّل قابل للضبط.
- **Proxy/Tor Manager:** توجيه الطلبات عبر proxies أو Tor في وضع stealth.
- **Retry & Backoff:** إعادة محاولة ذكية عند الفشل المؤقت.
- **Timeout:** لكل موديول مهلة قصوى حتى لا يعلّق النظام.
- **Cache:** SQLite cache لنتائج الاستعلامات (TTL قابل للضبط) لتوفير الوقت وحصص الـ API.

### 8.5 مساحات العمل (Workspaces)
- كل هدف/تحقيق = workspace مستقل (مجلد + قاعدة SQLite).
- يسمح بحفظ الحالة، الاستئناف، والمقارنة الزمنية (diff).

---

<a name="9"></a>
## 9. نظام النتائج والتقارير (Reporting Engine)

### 9.1 صيغ الإخراج
| الصيغة | الاستخدام |
|--------|-----------|
| **JSON** | آلي/تكامل مع أنظمة أخرى (SIEM/تذاكر) |
| **HTML تفاعلي** | تقرير احترافي بألوان، جداول قابلة للفرز، بحث |
| **PDF** | للإدارة/التوثيق الرسمي |
| **Markdown** | سريع، للمشاركة والـ git |
| **CSV** | للتحليل في Excel |
| **Graph (JSON/GEXF)** | تصوّر العلاقات (استيراد Maltego/Gephi/عرض داخلي) |

### 9.2 محتوى التقرير
1. **ملخص تنفيذي:** الهدف، النوع، عدد الكيانات، أبرز المخاطر (Risk Highlights).
2. **بطاقة الهدف:** كل ما اكتُشف مصنّفاً.
3. **الكيانات:** جداول (نطاقات فرعية، إيميلات، حسابات، تسريبات...).
4. **العلاقات:** رسم بياني + قائمة.
5. **تقييم المخاطر:** تسريبات كلمات مرور؟ أصول مكشوفة؟ منافذ خطرة؟ نطاقات phishing؟
6. **الأدلة (Evidence):** المصدر لكل معلومة (قابل للتدقيق).
7. **التوصيات:** خطوات معالجة مقترحة (مفيد لك كموظف أمن).
8. **سجل الفحص:** الأدوات التي عملت/فشلت/تُخطّيت + التوقيت.

### 9.3 نظام تقييم المخاطر (Risk Scoring)
- كل اكتشاف يُصنّف: `Critical / High / Medium / Low / Info`.
- أمثلة: كلمة مرور مكشوفة في تسريب = Critical؛ نطاق فرعي منسي حيّ = Medium؛ SPF مفقود = Medium.

---

<a name="10"></a>
## 10. نظام التثبيت والتجهيز التلقائي (Installer) — تحقيق G4

### 10.1 السيناريو المطلوب
```bash
git clone https://github.com/mohammedaljohaniit1-max/OSINT-2026.git
cd OSINT-2026
./install.sh          # (أو install.ps1 على ويندوز)
# ... يثبّت ويتحقق من كل شيء ...
argus scan example.com
```

### 10.2 ما يفعله المُثبّت
1. **كشف نظام التشغيل** (Linux/Mac/Windows) والتوزيعة ومدير الحزم.
2. **التحقق من المتطلبات:** Python 3.11+, Go, Git, pip/pipx (يثبّت الناقص إن أمكن).
3. **إنشاء بيئة معزولة** (venv) للنواة.
4. **تثبيت أدوات بايثون** عبر pipx (عزل كل أداة) — theHarvester, holehe, sherlock, maigret, h8mail, ignorant, phoneinfoga(py)...
5. **تنزيل ثنائيات Go** — amass, subfinder, httpx, dnsx, naabu, assetfinder (عبر `go install` أو تنزيل releases مباشرة).
6. **تنزيل قواعد البيانات** — WhatsMyName, dorks DB, wordlists أساسية.
7. **إعداد ملف الإعدادات** `config.yaml` + قالب `secrets.env` لمفاتيح الـ API.
8. **فحص صحة (Health Check):** يشغّل `argus doctor` — يتحقق أن كل أداة تعمل ويطبع تقرير الجاهزية:
   ```
   [✓] theHarvester   ready
   [✓] amass          ready
   [✗] shodan         missing API key (optional)
   [!] nmap           not installed (active scans disabled)
   ```
9. **دعم Docker (بديل):** `docker compose up` — صورة جاهزة فيها كل الأدوات (يحل مشكلة اختلاف الأنظمة نهائياً — خيار قوي لك).

### 10.3 استراتيجية دعم الأنظمة
- **Linux:** دعم كامل أصلي (أولويتك — شغلك عليه).
- **macOS:** دعم عبر Homebrew (معظم الأدوات متوفرة).
- **Windows:** دعم عبر WSL2 موصى به + PowerShell installer للأدوات المتوافقة.
- **الحل الشامل المضمون:** **Docker image** — يعمل على الثلاثة بلا اختلاف. (خطة بديلة قوية لتحقيق G5).

### 10.4 التحديث
```bash
argus update          # يحدّث النواة + كل الأدوات + قواعد البيانات
```

---

<a name="11"></a>
## 11. هيكل المجلدات الكامل (Repository Structure)

```
OSINT-2026/
├── README.md                     # نظرة عامة + دليل البدء السريع
├── MASTER_PLAN.md                # هذه الوثيقة
├── LICENSE                       # رخصة (MIT مقترح)
├── install.sh                    # مُثبّت Linux/Mac
├── install.ps1                   # مُثبّت Windows
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── config/
│   ├── config.yaml               # الإعدادات العامة
│   ├── secrets.env.example       # قالب مفاتيح API
│   ├── modules.yaml              # تفعيل/تعطيل الموديولات
│   └── profiles.yaml             # تعريف البروفايلات
├── argus/                        # النواة (Python package)
│   ├── __init__.py
│   ├── cli.py                    # واجهة الأوامر
│   ├── core/
│   │   ├── detector.py           # كشف نوع الهدف
│   │   ├── planner.py            # مخطّط المهام (DAG)
│   │   ├── executor.py           # التشغيل المتوازي
│   │   ├── normalizer.py         # التطبيع
│   │   ├── correlator.py         # الربط وإزالة التكرار
│   │   ├── registry.py           # سجل الموديولات
│   │   ├── models.py             # Entity / Relationship / Target
│   │   ├── store.py              # SQLite + workspaces
│   │   ├── cache.py
│   │   ├── config.py             # إدارة الإعدادات والأسرار
│   │   ├── ratelimit.py
│   │   └── proxy.py
│   ├── modules/
│   │   ├── base.py               # واجهة Module الأساسية
│   │   ├── external/             # محوّلات الأدوات الخارجية (Adapters)
│   │   │   ├── theharvester.py
│   │   │   ├── amass.py
│   │   │   ├── subfinder.py
│   │   │   ├── holehe.py
│   │   │   ├── h8mail.py
│   │   │   ├── sherlock.py
│   │   │   ├── maigret.py
│   │   │   ├── phoneinfoga.py
│   │   │   ├── ignorant.py
│   │   │   ├── shodan_mod.py
│   │   │   ├── httpx_mod.py
│   │   │   ├── spiderfoot.py
│   │   │   └── ...               # (كل أداة من القسم 6)
│   │   └── native/               # سكربتاتنا الخاصة (القسم 7)
│   │       ├── email_pattern.py
│   │       ├── cert_intel.py
│   │       ├── email_security.py
│   │       ├── github_leaks.py
│   │       ├── typosquat.py
│   │       ├── phone_enrich.py
│   │       ├── dork_engine.py
│   │       ├── correlation_scorer.py
│   │       └── ...
│   ├── reporting/
│   │   ├── html.py
│   │   ├── pdf.py
│   │   ├── json_out.py
│   │   ├── markdown.py
│   │   ├── graph.py
│   │   └── templates/            # قوالب HTML/Jinja2
│   └── utils/
│       ├── logging.py            # سجل التدقيق (audit log)
│       ├── validators.py
│       └── net.py
├── data/
│   ├── tlds.txt                  # قائمة TLDs للكشف
│   ├── dorks/                    # قواعد Google Dorks
│   ├── wordlists/                # قوائم للتعداد
│   └── whatsmyname.json          # قاعدة أسماء المستخدمين
├── workspaces/                   # نتائج الفحوصات (per-target)
├── tests/                        # اختبارات وحدة/تكامل
│   ├── test_detector.py
│   ├── test_modules/
│   └── ...
├── docs/                         # توثيق مفصّل
│   ├── ARCHITECTURE.md
│   ├── ADD_MODULE.md             # كيف تضيف موديول جديد
│   ├── API_KEYS.md               # كيف تحصل على المفاتيح وتضيفها
│   └── USAGE.md
└── scripts/                      # سكربتات صيانة/تحديث
    ├── update_tools.sh
    └── healthcheck.sh
```

---

<a name="12"></a>
## 12. الأمان والأخلاقيات والقانون (OPSEC & Legal)

> بما أنك موظف أمن سيبراني تعمل ضمن نطاق مصرّح به، هذا القسم يحميك ويحمي المشروع.

1. **الاستخدام المصرّح فقط:** الأداة مخصّصة لفحص أصول شركتك أو ما لديك تفويض كتابي بفحصه. رسالة تحذير عند أول تشغيل + إقرار (`--i-have-authorization`).
2. **سجل تدقيق كامل (Audit Log):** كل فحص يُسجّل (الهدف، الوقت، المستخدم، الموديولات) — مهم للامتثال.
3. **Passive-first:** الافتراضي لا يلمس الهدف؛ الفحص النشط يتطلب علماً صريحاً.
4. **احترام حصص الـ API وشروط الخدمة (ToS):** rate limiting افتراضي؛ تحذير من الأدوات التي قد تخالف ToS.
5. **حماية البيانات:** نتائج الفحص قد تحوي بيانات شخصية حسّاسة (تسريبات) → تُخزّن محلياً، تشفير اختياري للـ workspace، لا رفع سحابي.
6. **إخلاء مسؤولية (Disclaimer)** في README واضح.
7. **بيانات دنيا (Data Minimization):** جمع ما يلزم فقط للهدف الأمني.

---

<a name="13"></a>
## 13. خارطة الطريق المرحلية (Roadmap / Phases)

> بناء تدريجي: كل مرحلة تُنتج شيئاً يعمل ويُختبر قبل الانتقال للتالية.

### 🟢 المرحلة 0 — الأساس (Foundation)
- [ ] هيكل المستودع + README + LICENSE + config.
- [ ] نموذج البيانات (`models.py`: Entity/Relationship/Target).
- [ ] `config.py` + إدارة الأسرار + `secrets.env.example`.
- [ ] نظام تسجيل (logging) + audit log.
- [ ] هيكل CLI أساسي (`argus --help`, `argus doctor`).

### 🟢 المرحلة 1 — النواة (Core Engine)
- [ ] محرك الكشف عن نوع الهدف (`detector.py`) + اختباراته.
- [ ] واجهة الموديول (`base.py`) + سجل الموديولات (`registry.py`).
- [ ] المخطّط (`planner.py`) + المنفّذ المتوازي (`executor.py`).
- [ ] المطبّع (`normalizer.py`) + التخزين (`store.py` SQLite + workspaces).

### 🟢 المرحلة 2 — أول تدفّق كامل (First End-to-End: Domain)
- [ ] محوّلات: whois, crt.sh, subfinder, theHarvester, httpx.
- [ ] موديول خاص: `email_pattern`, `email_security`.
- [ ] الربط الأساسي (`correlator.py`).
- [ ] تقرير JSON + Markdown.
- [ ] **إنجاز:** `argus scan example.com` يعمل من البداية للنهاية. ✅

### 🟢 المرحلة 3 — تغطية البريد والهاتف والمستخدم
- [ ] محوّلات: holehe, h8mail, HIBP, sherlock, maigret, phoneinfoga, ignorant, phonenumbers.
- [ ] موديولات خاصة: `email_correlate`, `username_from_email`, `phone_enrich`, `phone_pivot`.
- [ ] **إنجاز:** الكشف التلقائي يعمل لكل الأنواع الأربعة.

### 🟢 المرحلة 4 — التقارير الاحترافية
- [ ] تقرير HTML تفاعلي + PDF + Graph.
- [ ] نظام تقييم المخاطر (Risk Scoring).
- [ ] ملخص تنفيذي + توصيات.

### 🟢 المرحلة 5 — التوسّع (More Coverage)
- [ ] amass(active), shodan, censys, nmap/naabu, dnsx.
- [ ] موديولات خاصة: `cert_intel`, `github_leaks`, `typosquat`, `cloud_assets`, `dork_engine`, `metadata_harvest`, `wayback_intel`.
- [ ] تكامل SpiderFoot + recon-ng.

### 🟢 المرحلة 6 — المُثبّت والتوزيع
- [ ] `install.sh` كامل + `argus doctor` شامل.
- [ ] Docker image + docker-compose.
- [ ] `install.ps1` (Windows) + دليل WSL2.
- [ ] `argus update`.

### 🟢 المرحلة 7 — المميزات المتقدّمة
- [ ] بروفايلات (quick/deep/stealth/monitor).
- [ ] Proxy/Tor manager + cache متقدّم.
- [ ] وضع المراقبة الدورية + diff بين الفحوصات.
- [ ] واجهة ويب محلية (Dashboard) — اختياري.
- [ ] TUI تفاعلي.

### 🟢 المرحلة 8 — الجودة والتوثيق
- [ ] تغطية اختبارات شاملة.
- [ ] توثيق كامل (ARCHITECTURE, ADD_MODULE, API_KEYS, USAGE).
- [ ] CI/CD (GitHub Actions) للاختبار الآلي.

---

<a name="14"></a>
## 14. معايير النجاح (Definition of Done)

المشروع "مكتمل بحسب الرؤية" عندما:
1. ✅ `git clone` + `./install.sh` يجهّز كل شيء على Linux بأمر واحد ويمرّ `argus doctor` بنجاح.
2. ✅ `argus scan <أي هدف>` يكتشف النوع تلقائياً ويشغّل الموديولات المناسبة.
3. ✅ كل نوع هدف (domain/email/phone/username) مغطّى بأدوات + سكربتات خاصة تسدّ الفجوات.
4. ✅ التشغيل متوازٍ ويختصر الوقت فعلياً مقابل التشغيل اليدوي.
5. ✅ تقرير موحّد احترافي (HTML/PDF/JSON) مع تقييم مخاطر وتوصيات.
6. ✅ إضافة أداة/سكربت جديد = ملف plugin واحد بدون لمس النواة.
7. ✅ Docker image يعمل على أي نظام (خطة بديلة مضمونة).
8. ✅ سجل تدقيق + تحذيرات قانونية للاستخدام المصرّح.

---

## 📌 قرارات معلّقة تحتاج رأيك قبل البناء

1. **الاسم الكودي:** أقترح **`argus`** كأمر. توافق؟ أم تفضّل اسماً آخر؟
2. **اللغة:** Python للنواة (موصى به). موافق؟
3. **أولوية التوزيع:** أبني Docker أولاً (يعمل فوراً على كل نظام) أم `install.sh` أصلي لـ Linux أولاً؟
4. **مفاتيح API:** هل لديك مفاتيح (Shodan/HIBP/Censys) الآن أم نبدأ بالأدوات المجانية فقط ونضيفها لاحقاً؟
5. **نطاق المرحلة الأولى:** أبدأ بتدفّق **الدومين** كاملاً (لأنه شغلك الأساسي على موقع الشركة) ثم البريد فالهاتف؟

> بمجرد موافقتك على هذه النقاط، أبدأ **المرحلة 0 + 1** فعلياً.
