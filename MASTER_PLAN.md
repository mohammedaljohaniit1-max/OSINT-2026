# 🕵️ OSINT-2026 — الخطة العملاقة v2 (Master Plan)

> **الاسم الكودي:** `Argus` — العملاق ذو المئة عين (رمز المراقبة الكاملة).
> **الحالة:** خطة (Planning) — v2 مطوّرة بعمق.
> **آخر تحديث:** 2026-08-30
> **الجمهور:** محلل أمن سيبراني بمنصب عالٍ يحتاج فحص OSINT كامل واحترافي معتمد عليه 100%.

---

## 🔑 المبدأ الحاكم الجديد (v2): **صفر مفاتيح API إلزامية (Zero-API-First)**

بناءً على توجيهك: **الأداة يجب أن تعمل بكامل طاقتها بدون أي مفتاح API**. نحقق هذا عبر ثلاث طبقات:

1. **مصادر عامة مفتوحة لا تتطلب مفاتيح** (crt.sh، Wayback، DNS، Ahmia، XposedOrNot، ProxyNova COMB، PGP keyservers، RDAP، محركات بحث بديلة).
2. **كشط ذكي مؤتمت (Smart Scraping)** بأسلوب متصفح حقيقي (Playwright/headless + rotation + تأخير عشوائي) لتجاوز الحظر — للمصادر التي لا توفر API.
3. **محرك بحث محايد ذاتي الاستضافة (SearXNG محلي)** بدل كشط Google مباشرة (Google صار يمنع الكشط بـ CAPTCHA/TLS fingerprint) — يجمع من 70+ محرك بحث دفعة واحدة بلا حظر.

> **المفاتيح تبقى اختيارية 100%:** إن وُجد مفتاح (Shodan مثلاً) يُفعّل مصدراً إضافياً؛ إن لم يوجد، بديل مجاني يقوم بالمهمة. **لا شيء يتعطّل بغياب المفاتيح.**

---

## 📑 الفهرس

1. [الرؤية والأهداف](#s1)
2. [كيف نجمع كل شيء بدون API — الاستراتيجية التقنية](#s2)
3. [المبادئ الحاكمة](#s3)
4. [المعمارية الكاملة](#s4)
5. [محرك الكشف التلقائي عن الهدف](#s5)
6. [التغطية الكاملة — مصفوفة الجوانب (Coverage Matrix)](#s6)
7. [كتالوج الأدوات الخارجية](#s7)
8. [السكربتات الخاصة — الوصفة السرية](#s8)
9. [محرك Google/GitHub/Dark-Web Dorking](#s9)
10. [نظام الإدارة والتشغيل (Orchestrator)](#s10)
11. [نظام التقارير الاحترافي](#s11)
12. [المُثبّت التلقائي + Docker](#s12)
13. [هيكل المجلدات](#s13)
14. [الأمان والقانون (OPSEC)](#s14)
15. [خارطة الطريق المرحلية](#s15)
16. [معايير النجاح](#s16)

---

<a name="s1"></a>
## 1. الرؤية والأهداف

### 1.1 السيناريو المستهدف (حرفياً كما وصفته)
```bash
argus scan company.com
```
تدخل دومين الشركة → تحصل على **كل ما يمكن جمعه** عن: الشركة، الموقع، البنية التحتية، الموظفين، إيميلاتهم، تسريباتهم، حساباتهم، الأصول المخفية، التسريبات على GitHub، ما ظهر في Google Dorks، وما ظهر في الـ Dark Web — **تقرير احترافي مرتب دقيق**، بأمر واحد، بدون تشغيل يدوي ولا مفاتيح.

```bash
argus scan ahmed@company.com     # كل شيء عن الإيميل
argus scan +966501234567         # كل شيء عن الرقم
```

### 1.2 الأهداف الإلزامية
| # | الهدف | المعيار القابل للقياس |
|---|-------|----------------------|
| G1 | **تغطية كل الجوانب حرفياً** | مصفوفة تغطية (القسم 6) — لا جانب واحد مكشوف |
| G2 | **معتمد عليه 100%** | كل نتيجة لها مصدر + درجة ثقة + دليل (evidence) |
| G3 | **بدون API إلزامي** | كل الأنواع تعمل بلا مفتاح واحد |
| G4 | **كشف تلقائي للهدف** | لا تحديد يدوي |
| G5 | **تقرير احترافي مرتب** | HTML/PDF/JSON مع تصنيف ومخاطر وتوصيات |
| G6 | **اختصار وقت فعلي** | أمر واحد = عشرات الأدوات بالتوازي |
| G7 | **تثبيت بأمر واحد** | git clone → install → يعمل |
| G8 | **للأبد / قابل للتوسّع** | إضافة مصدر = ملف plugin واحد |

---

<a name="s2"></a>
## 2. كيف نجمع كل شيء بدون API — الاستراتيجية التقنية (جوهر v2)

> هذا القسم يجيب سؤالك: "مانحتاج API، نقدر نسوي سكربتات تجيب كل شي".

### 2.1 المصادر العامة المجانية بلا مفاتيح (Free Public Sources)
| المصدر | ماذا يعطي | كيف نصل بلا مفتاح |
|--------|-----------|-------------------|
| **crt.sh** | كل النطاقات الفرعية من شهادات SSL | JSON endpoint عام مباشر |
| **Certificate Transparency logs** (Censys CT، Google CT) | شهادات ونطاقات | زحف مباشر |
| **Wayback Machine / CDX API** | كل روابط/مسارات/ملفات الموقع تاريخياً | API عام بلا مفتاح |
| **Common Crawl Index** | فهرس ضخم لصفحات الويب | API عام |
| **DNS مباشر** (A/AAAA/MX/NS/TXT/CNAME/SOA/DNSSEC) | البنية التحتية | استعلام DNS مباشر |
| **RDAP / WHOIS** | مالك النطاق، تواريخ، nameservers | RDAP بروتوكول عام مجاني |
| **PGP keyservers** (keys.openpgp.org) | إيميلات مرتبطة بالنطاق | بحث عام |
| **XposedOrNot API** | فحص تسريب الإيميل | **مجاني بلا مفتاح** |
| **ProxyNova COMB** | بحث في أكبر تجميعة تسريبات | endpoint عام |
| **Ahmia.fi** | فهرس Dark Web (.onion) | بحث عام + عبر Tor |
| **libphonenumber** (offline) | تحليل الهاتف بالكامل | مكتبة محلية بلا نت |
| **GitHub/GitLab code search (web)** | تسريبات أسرار وأكواد | كشط نتائج البحث العام |
| **Gravatar** | صورة/ملف مرتبط بالإيميل | hash عام |
| **HackerTarget (محدود مجاني)** | DNS/subdomain/reverse IP | حد مجاني بلا مفتاح |
| **ThreatCrowd / AlienVault OTX (عام)** | passive DNS، سمعة | endpoints عامة |

### 2.2 الكشط الذكي (Smart Scraping Engine)
لأن بعض المصادر (Google، LinkedIn، Truecaller) تمنع الوصول الآلي، نبني **محرك كشط احترافي**:
- **Headless browser** (Playwright) يحاكي متصفحاً حقيقياً (User-Agent، TLS، cookies، JS rendering) → يتجاوز الحظر البسيط.
- **Rotation:** تدوير User-Agents + proxies (اختياري) + Tor.
- **Human-like:** تأخير عشوائي، حركة، تمرير — لتفادي كشف البوت.
- **Fallback chain:** إن فشل مصدر، ينتقل تلقائياً للبديل.
- **Rate limiting + caching:** لا نضرب نفس المصدر مرتين، ولا نتجاوز الحدود.

### 2.3 محرك البحث المحايد (SearXNG المحلي) — بدل كشط Google
- ننشر **SearXNG** محلياً (حاوية Docker صغيرة) — meta-search يجمع نتائج 70+ محرك (Google, Bing, DuckDuckGo, Brave, Yandex, Mojeek...) عبر واجهته الخاصة.
- **الفائدة:** نحصل على نتائج Google Dorks **بلا CAPTCHA وبلا مفتاح** لأن SearXNG يوزّع الطلبات ويطبّعها.
- بديل احتياطي: كشط مباشر لـ DuckDuckGo HTML / Bing / Brave (أقل حظراً من Google).

### 2.4 خلاصة: لماذا هذا معتمد عليه للأبد؟
- لا نعتمد على مصدر واحد → لكل جانب **3-5 مصادر بديلة** (redundancy).
- لا نعتمد على مفاتيح قد تنتهي أو تُقيّد.
- المصادر العامة (CT logs, DNS, Wayback) **دائمة ومستقرة**.
- عند تعطّل مصدر، الـ fallback chain يغطّي.

---

<a name="s3"></a>
## 3. المبادئ الحاكمة

1. **Zero-API-First:** يعمل كاملاً بلا مفاتيح؛ المفاتيح تحسّن فقط.
2. **Plugin-first:** كل مصدر/أداة = موديول بواجهة موحّدة.
3. **Redundancy:** كل جانب مغطّى بمصادر متعددة (لا نقطة فشل واحدة).
4. **Schema موحّد:** Entity + Relationship لكل النتائج.
5. **Passive-first:** الافتراضي لا يلمس الهدف؛ Active يتطلب `--active`.
6. **Evidence-based:** كل معلومة لها مصدر + ثقة + طابع زمني (قابل للتدقيق).
7. **Idempotent + Cached:** إعادة التشغيل آمنة وسريعة.
8. **Fail-soft:** فشل مصدر لا يوقف الفحص، يُسجّل ويُكمل.

---

<a name="s4"></a>
## 4. المعمارية الكاملة

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    CLI / TUI / Web Dashboard (اختياري)                      │
│                        argus scan <target> [flags]                          │
└───────────────────────────────┬────────────────────────────────────────────┘
                                 │
┌───────────────────────────────▼────────────────────────────────────────────┐
│                              ARGUS CORE                                       │
│  Target Detector · Task Planner (DAG) · Async Executor · Module Registry     │
│  Normalizer · Correlation Engine · Risk Scorer · SQLite Store · Cache        │
│  Config/Secrets (optional) · Rate Limiter · Audit Logger                     │
└───┬──────────────────┬──────────────────────┬───────────────────┬──────────┘
    │                  │                      │                   │
┌───▼──────┐  ┌────────▼─────────┐  ┌─────────▼────────┐  ┌───────▼─────────┐
│ Data     │  │ Smart Scraping   │  │ Native Modules   │  │ Reporting        │
│ Sources  │  │ Engine           │  │ (الوصفة السرية)  │  │ HTML/PDF/JSON/   │
│ (public, │  │ Playwright +     │  │                  │  │ MD/CSV/Graph     │
│ no key)  │  │ SearXNG + Tor    │  │                  │  │                  │
│ crt.sh   │  │ + rotation       │  │ email_pattern    │  │ Executive        │
│ wayback  │  │ + fallback chain │  │ dork_engine      │  │ summary +        │
│ DNS/RDAP │  │                  │  │ github_leaks     │  │ risk + evidence  │
│ Xposed   │  │                  │  │ darkweb_hunter   │  │ + recommend.     │
│ Ahmia    │  │                  │  │ correlation      │  │                  │
└──────────┘  └──────────────────┘  └──────────────────┘  └──────────────────┘
    │                  │                      │                   │
┌───▼──────────────────▼──────────────────────▼───────────────────▼──────────┐
│         External Tools (theHarvester, amass, holehe, sherlock, ...)          │
│                    تُستدعى عبر Adapters بنفس الواجهة                          │
└──────────────────────────────────────────────────────────────────────────────┘
```

### نموذج البيانات الموحّد
- **Entity:** `{id, type, value, confidence(0-1), sources[], first_seen, last_seen, tags[], risk, metadata{}}`
- **Relationship:** `{from, to, type, confidence, sources[]}`
- **Evidence:** `{entity_id, source, url, snapshot, timestamp}` — لكل معلومة دليلها.
- أنواع الكيانات: `domain, subdomain, ip, port, service, tech, cert, email, phone, username, person, org, url, file, credential, breach, paste, social_profile, onion, asn, geolocation, cloud_asset`

---

<a name="s5"></a>
## 5. محرك الكشف التلقائي عن الهدف

| الأولوية | النوع | قاعدة الكشف |
|---------|-------|-------------|
| 1 | Email | regex بريد صالح |
| 2 | Phone | `+`/أرقام دولية → تحقق بـ `phonenumbers` |
| 3 | IP / CIDR | صيغة IPv4/IPv6/CIDR صالحة |
| 4 | ASN | `ASxxxxx` |
| 5 | Domain | نطاق + TLD معروف (قائمة IANA) |
| 6 | URL | يبدأ بـ http(s):// |
| 7 | Hash / Crypto | أنماط hash/محافظ معروفة |
| 8 | Username | نص بلا مسافات لا يطابق ما سبق |
| 9 | Person/Org | نص فيه مسافات → بحث اسم |

- تجاوز يدوي: `--type domain`. مدخلات متعددة: `-f targets.txt`. غموض → يشغّل الأنواع المحتملة أو يسأل.

---

<a name="s6"></a>
## 6. التغطية الكاملة — مصفوفة الجوانب (Coverage Matrix)

> ضمان **G1**: لا جانب واحد مكشوف. كل خلية لها مصدر (أداة أو سكربت خاص).

### 6.1 عند فحص دومين شركة (company.com) — نجمع كل هذا:
| الجانب | كيف نغطّيه |
|--------|-----------|
| معلومات التسجيل (WHOIS/RDAP) | RDAP + whois — المالك، التواريخ، nameservers |
| النطاقات الفرعية (كل شيء) | crt.sh + CT logs + subfinder + amass + assetfinder + wayback + DNS brute (اختياري) |
| سجلات DNS الكاملة | A/AAAA/MX/NS/TXT/SOA/CNAME/SRV/CAA/DNSSEC |
| البنية التحتية / IPs / ASN | reverse DNS، ASN mapping، reverse IP (جيران السيرفر) |
| المنافذ والخدمات | Shodan(بديل مجاني: نتائج عامة) / naabu / nmap (active) |
| التقنيات المستخدمة | httpx + WhatWeb + Wappalyzer → بصمة + مطابقة CVE |
| الخوادم الحية والعناوين | httpx (status, title, tech, screenshots) |
| الشهادات (SSL/TLS) | SAN، issuer، تواريخ، اكتشاف نطاقات مخفية |
| أمن البريد | SPF/DKIM/DMARC/MTA-STS/BIMI ← تقييم النضج |
| الإيميلات (كل الموظفين) | theHarvester + crawl + PGP + dork + **native_email_pattern** |
| أسماء وأدوار الموظفين | LinkedIn/dork + metadata المستندات + web crawl |
| النطاقات المزيّفة (phishing) | **native_typosquat** — توليد وفحص |
| تسريبات GitHub/GitLab | **native_github_leaks** + gitleaks/trufflehog على العام |
| الملفات والمستندات العامة | metagoofil + **native_metadata_harvest** (ExifTool) |
| الأصول السحابية (S3/Azure/GCP) | **native_cloud_assets** |
| Google/Bing Dorks | **native_dork_engine** (عبر SearXNG) |
| Wayback/الأرشيف | **native_wayback_intel** — مسارات وملفات ونقاط دخول |
| Dark Web mentions | **native_darkweb_hunter** (Ahmia + onion index) |
| تسريبات بيانات الموظفين | XposedOrNot + ProxyNova + holehe + h8mail(بلا مفتاح جزئياً) |
| سمعة/تهديدات | OTX/ThreatCrowd العام |

### 6.2 عند فحص إيميل (ahmed@company.com):
تسريبات (Xposed/ProxyNova/HIBP-web) · حسابات مسجّلة (holehe) · usernames مشتقة → (sherlock/maigret) · Gravatar · PGP · dork للإيميل · ظهور في pastes · ظهور في dark web · تحليل النطاق.

### 6.3 عند فحص رقم (+966...):
تحليل كامل (libphonenumber: الدولة، المشغّل، النوع، المنطقة الزمنية) · حسابات مسجّلة (ignorant) · كل الصيغ · dork للرقم · ظهور في تطبيatات المراسلة/الشبكات · ظهور في تسريبات · dark web.

---

<a name="s7"></a>
## 7. كتالوج الأدوات الخارجية

> **P**=سلبي، **A**=نشط، **NoKey**=يعمل بلا مفتاح، **Key?**=مفتاح اختياري يحسّن.

### 7.1 النطاقات والبنية التحتية
| الأداة | يعمل بلا مفتاح؟ | الوظيفة |
|--------|:---:|---------|
| theHarvester | ✅ NoKey (Key? يوسّع) | إيميلات/نطاقات/مضيفين من 50+ مصدر عام |
| OWASP Amass | ✅ NoKey | تعداد نطاقات فرعية شامل + ASN/CIDR |
| subfinder | ✅ NoKey | تعداد سلبي سريع |
| assetfinder | ✅ NoKey | أصول مرتبطة بالدومين |
| findomain | ✅ NoKey | تعداد سريع (Rust) |
| dnsx | ✅ NoKey | استعلامات DNS جماعية |
| dnsrecon | ✅ NoKey | DNS + zone transfer + brute |
| massdns | ✅ NoKey | حل DNS جماعي فائق السرعة |
| httpx | ✅ NoKey | فحص خدمات HTTP حية + تقنيات + screenshots |
| naabu | ✅ NoKey | فحص منافذ سريع (active) |
| nmap | ✅ NoKey | فحص منافذ/خدمات تفصيلي (active) |
| WhatWeb | ✅ NoKey | بصمة تقنيات المواقع |
| wafw00f | ✅ NoKey | كشف WAF |
| waybackurls / gau | ✅ NoKey | روD تاريخية من Wayback/CommonCrawl |
| openSquat | ✅ NoKey | كشف typosquatting للعلامة |
| Shodan | ⚠️ Key? (بديل مجاني موجود) | محرك بحث الأجهزة |
| Censys | ⚠️ Key? (CT logs بديل مجاني) | فحص أصول/شهادات |

### 7.2 البريد
| الأداة | بلا مفتاح؟ | الوظيفة |
|--------|:---:|---------|
| holehe | ✅ NoKey | يكشف المواقع المسجّل فيها الإيميل |
| h8mail | ✅ NoKey (جزئي، Key? يوسّع) | بحث الإيميل في تسريبات |
| mosint | ✅ NoKey (جزئي) | جامع OSINT شامل للإيميل |
| theHarvester | ✅ NoKey | جمع إيميلات المؤسسة |

### 7.3 الهاتف
| الأداة | بلا مفتاح؟ | الوظيفة |
|--------|:---:|---------|
| PhoneInfoga | ✅ NoKey | المشغّل، الدولة، النوع + بحث محركات |
| ignorant | ✅ NoKey | يكشف تسجيل الرقم في مواقع |
| phonenumbers | ✅ NoKey (offline) | تحليل/تحقق/تنسيق دولي كامل |

### 7.4 أسماء المستخدمين / الحسابات
| الأداة | بلا مفتاح؟ | الوظيفة |
|--------|:---:|---------|
| Sherlock | ✅ NoKey | بحث username عبر 400+ منصة |
| Maigret | ✅ NoKey | 3000+ موقع + استخراج بيانات |
| WhatsMyName | ✅ NoKey | قاعدة ضخمة لفحص أسماء المستخدمين |
| socialscan | ✅ NoKey | توفر/استخدام username وإيميل |
| blackbird | ✅ NoKey | بحث سريع عن الحسابات |

### 7.5 إطارات وأدوات مساندة
| الأداة | بلا مفتاح؟ | الوظيفة |
|--------|:---:|---------|
| SpiderFoot | ✅ NoKey (Key? يوسّع) | إطار OSINT آلي 200+ موديول |
| recon-ng | ✅ NoKey (جزئي) | إطار استطلاع نمطي |
| Photon | ✅ NoKey | زاحف ويب لاستخراج البيانات |
| ExifTool | ✅ NoKey | ميتاداتا الصور/الملفات |
| metagoofil | ✅ NoKey | ميتاداتا مستندات المؤسسة العامة |
| gitleaks / trufflehog | ✅ NoKey | كشف الأسرار في المستودعات العامة |
| SearXNG (ذاتي الاستضافة) | ✅ NoKey | meta-search 70+ محرك (لا CAPTCHA) |

---

<a name="s8"></a>
## 8. السكربتات الخاصة — الوصفة السرية (Native Modules)

> النوع الثاني من السكربتات: **تغطي الجوانب التي لا تصل إليها الأدوات الجاهزة**. هذه ميزتنا التنافسية.

### 8.1 موديولات النطاق
| الموديول | الجانب الذي يغطّيه (الفجوة) |
|----------|---------------------------|
| `native_email_pattern` | يستنتج نمط إيميلات الشركة (first.last@ / f.last@ / flast@) من الإيميلات المكتشفة، ثم **يولّد إيميلات كل الموظفين المعروفين بالاسم** حتى لو لم تظهر إيميلاتهم — ويتحقق منها (MX/SMTP) |
| `native_cert_intel` | يزحف CT logs + يحلّل SAN/issuer لاكتشاف **نطاقات وأصول مخفية** لا تظهرها الأدوات |
| `native_dns_deep` | يجمع كل أنواع سجلات DNS + DNSSEC + reverse + zone walk + passive DNS تاريخي |
| `native_tech_cve` | يدمج بصمات التقنيات ويطابقها مع **CVEs معروفة** → تنبيه ثغرات محتملة |
| `native_cloud_assets` | يكشف **S3 buckets / Azure blobs / GCP** مفتوحة مرتبطة باسم الشركة (bucket enumeration) |
| `native_github_leaks` | يبحث في **GitHub/GitLab code search** عن أسرار/مفاتيح/إيميلات/مسارات مرتبطة بالنطاق + يشغّل trufflehog على النتائج |
| `native_typosquat` | يولّد نطاقات مزيّفة (homograph/typo/TLD-swap) ويفحص أيها **مسجّل فعلاً** (كشف phishing) |
| `native_email_security` | فحص SPF/DKIM/DMARC/MTA-STS/BIMI + تقييم النضج + توصيات |
| `native_metadata_harvest` | يزحف مستندات الموقع العامة (PDF/DOCX/XLSX) ويستخرج **أسماء موظفين، برامج، مسارات داخلية، أجهزة** من الميتاداتا |
| `native_wayback_intel` | يستخرج من الأرشيف **مسارات مخفية، endpoints، ملفات نسخ احتياطي، إيميلات** ظهرت تاريخياً |

### 8.2 موديولات البريد
| الموديول | الفجوة |
|----------|--------|
| `native_email_correlate` | يجمع كل ما اكتُشف عن إيميل واحد (تسريبات + حسابات + usernames + صور + PGP) في **بطاقة موحّدة واحدة** |
| `native_username_from_email` | يشتق usernames محتملة من الإيميل ويمرّرها تلقائياً لـ Sherlock/Maigret |
| `native_breach_timeline` | يبني **خط زمني للاختراقات** + هل كُشفت كلمة المرور؟ + شدة الخطورة |
| `native_email_verify` | تحقق SMTP/MX من صلاحية الإيميل بلا إرسال فعلي (catch-all detection) |

### 8.3 موديولات الهاتف
| الموديول | الفجوة |
|----------|--------|
| `native_phone_enrich` | libphonenumber + المشغّل + المنطقة الزمنية + النوع في بطاقة واحدة |
| `native_phone_pivot` | يستخدم الرقم كنقطة ارتكاز: بحث في المحركات/الشبكات/تطبيقات المراسلة عن ظهوره |
| `native_phone_format_expand` | يولّد كل الصيغ (محلي/دولي/بلا رموز) لتوسيع البحث |

### 8.4 موديولات عابرة (الأقوى)
| الموديول | الوصف |
|----------|-------|
| `native_dork_engine` | **محرك Dorks الذكي:** يبني استعلامات Google/Bing/DuckDuckGo (site:, filetype:, intext:, inurl:) حسب نوع الهدف، ينفّذها عبر **SearXNG** (بلا CAPTCHA بلا مفتاح)، ويصنّف النتائج (ملفات حساسة، لوحات دخول، وثائق مسربة) |
| `native_github_dork` | dorks متخصصة لـ GitHub (اسم الشركة + password/api_key/.env/config) |
| `native_darkweb_hunter` | يبحث في **Ahmia + فهارس onion عامة** عن ذكر الهدف؛ (اختياري عبر Tor للوصول المباشر) — يجمع **إشارات تسريب** دون تنزيل محتوى غير قانوني |
| `native_paste_hunter` | يبحث في Pastebin وأشباهه عن ظهور الهدف (إيميلات/كلمات مرور/مفاتيح) |
| `native_people_search` | اسم شخص → إيميلات/حسابات/أرقام محتملة من مصادر عامة |
| `native_correlation_scorer` | **قلب الربط:** يوحّد الكيانات المكررة، يقيّم الثقة (معلومة من 3 مصادر > مصدر واحد)، يبني الرسم البياني للعلاقات |
| `native_scraper_core` | محرك الكشط المشترك (Playwright + rotation + Tor + fallback) الذي تستخدمه بقية الموديولات |

### 8.5 واجهة الموديول الموحّدة
```python
class Module:
    name: str
    target_types: list[str]        # ["domain","email","phone","username",...]
    mode: str                      # "passive" | "active"
    requires_keys: list[str] = []  # اختياري دائماً
    fallbacks: list[str] = []      # مصادر بديلة عند الفشل
    def is_available(self) -> bool: ...
    async def run(self, target, ctx) -> list[Entity | Relationship]: ...
```

---

<a name="s9"></a>
## 9. محرك Google/GitHub/Dark-Web Dorking (تفصيل تقني)

### 9.1 Google/Web Dorking (بلا CAPTCHA بلا مفتاح)
- **الآلية:** SearXNG محلي → يوزّع الاستعلام على Google/Bing/DDG/Brave/Yandex/Mojeek ويعيد نتائج موحّدة JSON.
- **مكتبة Dorks:** قاعدة GHDB (Google Hacking Database) محدّثة + dorks مخصّصة نبنيها:
  - `site:company.com filetype:pdf|xlsx|docx|env|sql|bak|log`
  - `site:company.com intitle:"index of"` (directory listing)
  - `site:company.com inurl:admin|login|portal|vpn`
  - `intext:"@company.com"` (حصاد إيميلات)
  - `site:pastebin.com "company.com"` / `site:trello.com`, `site:s3.amazonaws.com "company"`
- **fallback:** كشط مباشر DuckDuckGo HTML / Bing إن تعذّر SearXNG.

### 9.2 GitHub Dorking (تسريبات الأسرار)
- كشط **GitHub/GitLab code search** للنطاق واسم الشركة مع كلمات: `password, api_key, secret, token, BEGIN RSA, .env, config, aws_access`.
- تشغيل **trufflehog/gitleaks** على المستودعات العامة المطابقة للتحقق من الأسرار الحية.
- كشف commits وملفات محذوفة عبر الأرشيف.

### 9.3 Dark Web (آمن وقانوني)
- **Ahmia.fi** (فهرس onion عبر الويب العادي) للبحث عن ذكر النطاق/الشركة/الإيميل.
- فهارس onion عامة (Tor66, Onion Search) — بحث فقط.
- **عبر Tor** (اختياري): توجيه استعلامات البحث فقط، **دون تنزيل أو شراء بيانات مسروقة** (خط أحمر قانوني).
- الهدف: **إشارات تعرّض** (هل بيانات الشركة مذكورة في سوق تسريبات؟) لإطلاق تنبيه — لا اقتناء بيانات.

---

<a name="s10"></a>
## 10. نظام الإدارة والتشغيل (Orchestrator) — النوع الأول

### 10.1 خط الأنابيب (Pipeline)
```
Parse → Detect Type → Plan DAG → Resolve Sources → Execute (async, parallel)
     → Normalize → Correlate + Dedupe + Score → Store (SQLite) → Report
```

### 10.2 مخطّط المهام (DAG) — مثال فحص دومين
```
company.com
├─(parallel wave 1)─ RDAP/whois · crt.sh · CT logs · subfinder · amass ·
│                    assetfinder · theHarvester · wayback · DNS-deep · dork_engine
│                              │
│                       subdomains ─► httpx (حية) ─► tech_cve ─► naabu/nmap(active)
│                              │
├─(wave 2)─ theHarvester+dork+PGP → emails ─► holehe · xposed · h8mail ·
│                                             native_email_pattern · breach_timeline
│                                                    │
│                                    username_from_email ─► sherlock · maigret
│
├─(wave 3)─ native_email_security · native_typosquat · native_github_leaks ·
│           native_cloud_assets · native_metadata_harvest · darkweb_hunter
│
└─(final)── correlation_scorer ─► risk_scorer ─► report
```

### 10.3 البروفايلات
| البروفايل | الوصف |
|-----------|-------|
| `quick` | مصادر سلبية سريعة فقط (دقائق) |
| `standard` (افتراضي) | كل السلبي + كل السكربتات الخاصة |
| `deep` | + active (naabu/nmap/brute DNS) + كشط موسّع |
| `stealth` | سلبي فقط عبر Tor + معدلات منخفضة |
| `monitor` | فحص دوري + diff + تنبيه على الجديد |

### 10.4 إدارة الموارد
Rate limiting لكل مصدر · Proxy/Tor manager · Retry+backoff · Timeout لكل موديول · SQLite cache (TTL) · Workspaces مستقلة لكل هدف (حفظ/استئناف/مقارنة).

---

<a name="s11"></a>
## 11. نظام التقارير الاحترافي

### 11.1 الصيغ
HTML تفاعلي (بحث/فرز/رسم بياني) · PDF رسمي · JSON للتكامل · Markdown · CSV · Graph (GEXF/JSON لـ Gephi/Maltego).

### 11.2 محتوى التقرير
1. **ملخص تنفيذي:** الهدف، عدد الكيانات، أبرز المخاطر (Critical/High).
2. **بطاقة الهدف** مصنّفة بالكامل.
3. **جداول الكيانات:** نطاقات فرعية، إيميلات، حسابات، تسريبات، منافذ، تقنيات...
4. **الرسم البياني للعلاقات** (من مرتبط بمن).
5. **تقييم المخاطر:** Critical/High/Medium/Low/Info لكل اكتشاف.
6. **الأدلة (Evidence):** المصدر + الرابط + الطابع الزمني لكل معلومة.
7. **التوصيات:** خطوات معالجة (مفيد لك كموظف أمن).
8. **سجل الفحص:** ما عمل/فشل/تُخطّي + التوقيت.

### 11.3 أمثلة تصنيف المخاطر
| الاكتشاف | التصنيف |
|----------|---------|
| كلمة مرور موظف مكشوفة في تسريب | 🔴 Critical |
| مفتاح API في GitHub عام | 🔴 Critical |
| S3 bucket مفتوح | 🔴 Critical |
| نطاق فرعي منسي حيّ (staging/dev) | 🟠 High |
| نطاق phishing مسجّل مشابه | 🟠 High |
| SPF/DMARC مفقود | 🟡 Medium |
| إيميل موظف مكشوف (بلا كلمة مرور) | 🟡 Medium |
| تقنية قديمة بإصدار معلن | 🔵 Low |

---

<a name="s12"></a>
## 12. المُثبّت التلقائي + Docker

### 12.1 السيناريو
```bash
git clone https://github.com/mohammedaljohaniit1-max/OSINT-2026.git
cd OSINT-2026
./install.sh            # ينزّل ويجهّز كل شيء ويتحقق
argus doctor            # تقرير جاهزية كل الأدوات
argus scan company.com  # ابدأ
```

### 12.2 ما يفعله install.sh
1. كشف النظام (Linux/Mac/Win-WSL) ومدير الحزم.
2. تثبيت المتطلبات: Python 3.11+، Go، Tor، Git، pipx، Playwright + متصفح.
3. venv للنواة + pipx لعزل كل أداة بايثون.
4. تنزيل ثنائيات Go (amass/subfinder/httpx/dnsx/naabu/assetfinder).
5. تنزيل قواعد: GHDB dorks، WhatsMyName، TLDs، wordlists.
6. تشغيل حاوية **SearXNG** المحلية (Docker) للبحث بلا CAPTCHA.
7. تجهيز `config.yaml` + `secrets.env` (فارغ — كله اختياري).
8. `argus doctor`: تقرير جاهزية:
   ```
   [✓] theHarvester    ready
   [✓] amass           ready
   [✓] SearXNG         running (localhost:8080)
   [✓] Tor             running
   [✓] Playwright      chromium installed
   [-] shodan          no key (optional — using free fallback)
   ```

### 12.3 دعم الأنظمة
- **Linux:** دعم كامل أصلي (أولويتك).
- **macOS:** Homebrew.
- **Windows:** WSL2 (موصى) + install.ps1.
- **الحل المضمون للكل:** **Docker image** `docker compose up` — كل الأدوات + SearXNG + Tor جاهزة، يعمل على أي نظام بلا اختلاف.

### 12.4 التحديث
`argus update` — النواة + الأدوات + قواعد Dorks + قوائم المصادر.

---

<a name="s13"></a>
## 13. هيكل المجلدات

```
OSINT-2026/
├── README.md                 # الدليل الشامل (كل أداة: وظيفة/فائدة/تحميل/تشغيل)
├── MASTER_PLAN.md            # هذه الوثيقة
├── LICENSE
├── install.sh / install.ps1
├── docker/ (Dockerfile, docker-compose.yml, searxng/)
├── config/ (config.yaml, secrets.env.example, modules.yaml, profiles.yaml)
├── argus/
│   ├── cli.py
│   ├── core/ (detector, planner, executor, normalizer, correlator,
│   │          risk_scorer, registry, models, store, cache, ratelimit,
│   │          proxy, audit)
│   ├── sources/              # مصادر بلا مفتاح
│   │   (crtsh, ct_logs, wayback, commoncrawl, rdap, dns, pgp,
│   │    xposedornot, proxynova, ahmia, hackertarget, otx)
│   ├── scraping/             # محرك الكشط الذكي
│   │   (scraper_core, searxng_client, browser, rotation, tor)
│   ├── modules/
│   │   ├── external/ (theharvester, amass, subfinder, holehe, sherlock,
│   │   │              maigret, phoneinfoga, ignorant, httpx, ... )
│   │   └── native/  (email_pattern, cert_intel, dns_deep, tech_cve,
│   │                 cloud_assets, github_leaks, typosquat, email_security,
│   │                 metadata_harvest, wayback_intel, email_correlate,
│   │                 username_from_email, breach_timeline, phone_enrich,
│   │                 phone_pivot, dork_engine, github_dork, darkweb_hunter,
│   │                 paste_hunter, people_search, correlation_scorer)
│   ├── reporting/ (html, pdf, json_out, markdown, csv_out, graph, templates/)
│   └── utils/ (logging, validators, net)
├── data/ (tlds.txt, dorks/ghdb.json, wordlists/, whatsmyname.json)
├── workspaces/               # نتائج كل فحص
├── tests/
├── docs/ (ARCHITECTURE, ADD_MODULE, SOURCES, USAGE, LEGAL)
└── scripts/ (update_tools.sh, healthcheck.sh)
```

---

<a name="s14"></a>
## 14. الأمان والقانون (OPSEC & Legal)

1. **استخدام مصرّح فقط:** أصول شركتك أو ما لديك تفويض كتابي بفحصه. إقرار عند أول تشغيل.
2. **سجل تدقيق كامل:** كل فحص (الهدف/الوقت/المستخدم/الموديولات) — للامتثال.
3. **Passive-first:** الافتراضي لا يلمس الهدف؛ active صريح.
4. **خط أحمر Dark Web:** بحث عن **إشارات التعرّض** فقط — **ممنوع تنزيل/شراء/حيازة بيانات مسروقة**.
5. **حماية البيانات:** النتائج (قد تحوي بيانات شخصية) تُخزّن محلياً، تشفير اختياري للـ workspace، لا رفع سحابي.
6. **احترام ToS + rate limits:** لتفادي الحظر والمخالفات.
7. **Disclaimer** واضح في README.

---

<a name="s15"></a>
## 15. خارطة الطريق المرحلية

### 🟢 المرحلة 0 — الأساس
هيكل + models + config + audit logging + CLI هيكلي (`argus --help/doctor`).

### 🟢 المرحلة 1 — النواة + محرك الكشط
detector · registry · planner · executor(async) · normalizer · store(SQLite) · **scraper_core + searxng_client + tor**.

### 🟢 المرحلة 2 — تدفّق الدومين كامل (أولويتك)
مصادر: rdap, crtsh, ct_logs, dns, wayback + أدوات: subfinder, amass, theHarvester, httpx + native: email_pattern, email_security, cert_intel, dork_engine + correlator + تقرير JSON/MD.
**إنجاز:** `argus scan company.com` end-to-end.

### 🟢 المرحلة 3 — البريد + الهاتف + المستخدم
holehe, xposed, proxynova, sherlock, maigret, phoneinfoga, ignorant, phonenumbers + native: email_correlate, username_from_email, breach_timeline, phone_enrich, phone_pivot.
**إنجاز:** الكشف التلقائي لكل الأنواع.

### 🟢 المرحلة 4 — Dorking + GitHub + Dark Web
dork_engine (SearXNG) · github_leaks + github_dork (trufflehog) · darkweb_hunter (Ahmia/Tor) · paste_hunter.

### 🟢 المرحلة 5 — التقارير الاحترافية
HTML تفاعلي + PDF + Graph + risk_scorer + ملخص تنفيذي + توصيات.

### 🟢 المرحلة 6 — التوسّع
cloud_assets · metadata_harvest · tech_cve · typosquat · SpiderFoot/recon-ng · Shodan/Censys (اختياري).

### 🟢 المرحلة 7 — المُثبّت والتوزيع
install.sh كامل + Docker (مع SearXNG+Tor) + doctor + install.ps1 + update.

### 🟢 المرحلة 8 — المتقدّم
بروفايلات · monitor+diff · web dashboard · TUI.

### 🟢 المرحلة 9 — الجودة
اختبارات · توثيق كامل · CI/CD.

---

<a name="s16"></a>
## 16. معايير النجاح (Definition of Done)

1. ✅ يعمل **بالكامل بلا أي مفتاح API**.
2. ✅ `argus scan <هدف>` كشف تلقائي + تشغيل متوازٍ.
3. ✅ **مصفوفة التغطية (القسم 6) كلها مغطّاة** — لا جانب مكشوف.
4. ✅ Google/GitHub/Dark-Web dorking يعمل آلياً.
5. ✅ تقرير احترافي (HTML/PDF/JSON) بمخاطر وأدلة وتوصيات.
6. ✅ كل معلومة لها مصدر + ثقة (معتمد عليه 100%).
7. ✅ تثبيت بأمر واحد + Docker يعمل على أي نظام.
8. ✅ إضافة مصدر/أداة = ملف plugin واحد.
9. ✅ سجل تدقيق + ضوابط قانونية.

---

> **جاهز للبناء.** عند موافقتك أبدأ المرحلة 0 + 1 فوراً. لا مفاتيح مطلوبة منك.
