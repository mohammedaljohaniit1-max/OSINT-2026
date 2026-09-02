"""
Argus command-line interface.

  argus scan <target> [--profile standard|quick|deep|stealth]
  argus doctor          # environment & tool health check
  argus modules         # list all loaded modules
  argus update          # update external tools & wordlists
"""
from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import sys

from . import BANNER, __version__
from .core.config import Config
from .core.detector import detect
from .core.engine import Engine
from .core.registry import Registry
from .core.store import Store
from .reporting.reporter import write_reports


def _c(txt, color):
    codes = {"g": 32, "r": 31, "y": 33, "b": 34, "c": 36, "m": 35}
    return f"\033[{codes.get(color,37)}m{txt}\033[0m"


def cmd_scan(args):
    print(BANNER)
    cfg = Config.load(args.config, profile=args.profile)
    if args.tor:
        cfg.use_tor = True
    if args.active:
        cfg.active_scan = True
    if args.smtp:
        cfg.verify_smtp = True
    if args.searxng:
        cfg.searxng_url = args.searxng
    if args.insecure:
        cfg.verify_tls = False
    if args.budget:
        cfg.scan_budget = args.budget
    if args.phone_region:
        cfg.phone_region = args.phone_region.upper()
    if args.output_dir:
        cfg.output_dir = args.output_dir
    if args.include_module:
        cfg.include_modules = set(args.include_module)
    if args.exclude_module:
        cfg.exclude_modules = set(args.exclude_module)
    # ── Persona Hunter context (person search locked to a country + city) ──
    if getattr(args, "name", None):
        cfg.person_name = args.name
    if getattr(args, "country", None):
        cfg.person_country = args.country
    if getattr(args, "city", None):
        cfg.person_city = args.city
    if getattr(args, "lang", None):
        cfg.person_langs = [x.strip() for x in args.lang.split(",") if x.strip()]
    # if the target itself is the name (no --name), treat it as the person name
    if not cfg.person_name and (cfg.person_country or cfg.person_city):
        cfg.person_name = args.target

    det = detect(args.target)
    print(_c(f"[Argus] Target: {det.value}  →  {det.type.value} "
             f"({det.confidence:.0%})", "c"))
    print(_c(f"[Argus] Profile: {cfg.profile} | active={cfg.active_scan} "
             f"| tor={cfg.use_tor} | tls_verify={cfg.verify_tls} "
             f"| budget={cfg.scan_budget or 'profile-default'}s\n", "c"))

    engine = Engine(cfg, quiet=args.quiet)
    graph = asyncio.run(engine.scan(args.target))

    # monitor diff
    if cfg.profile == "monitor":
        store = Store(f"{cfg.output_dir}/argus.db")
        prev = store.previous_entities(det.normalized)
        store.save(graph)
        new = [e for e in graph.entities.values() if e.id not in prev]
        print(_c(f"\n[monitor] {len(new)} NEW findings since last scan", "y"))
    else:
        Store(f"{cfg.output_dir}/argus.db").save(graph)

    st = graph.stats()
    print()
    print(_c("═" * 60, "b"))
    print(_c(f"  RESULTS: {st['total_entities']} entities, "
             f"{st['total_relationships']} relationships", "g"))
    for r in ("critical", "high", "medium", "low", "info"):
        n = st["by_risk"].get(r, 0)
        if n:
            col = {"critical": "r", "high": "y", "medium": "y",
                   "low": "b", "info": "c"}[r]
            print("  " + _c(f"{r.upper():9} {n}", col))
    print(_c("═" * 60, "b"))

    paths = write_reports(graph, cfg.output_dir)
    print(_c("\n[Argus] Reports written:", "g"))
    for k, v in paths.items():
        print(f"   {k:9}: {v}")
    print(_c(f"\n   ▶ Open the HTML report: {paths['html']}", "c"))


def cmd_doctor(args):
    print(BANNER)
    print(_c("Argus Doctor — environment health check\n", "c"))
    # python deps
    deps = ["httpx", "requests", "dns", "phonenumbers", "mmh3", "bs4", "yaml"]
    print(_c("Python libraries:", "b"))
    for d in deps:
        try:
            __import__(d)
            print(f"  {_c('✓', 'g')} {d}")
        except ImportError:
            print(f"  {_c('✗', 'r')} {d}  (pip install)")
    # external tools
    tools = ["subfinder", "amass", "assetfinder", "findomain", "theHarvester",
             "holehe", "sherlock", "maigret", "httpx", "naabu", "nuclei",
             "whatweb", "gau", "trufflehog", "gitleaks", "tor", "nmap"]
    print(_c("\nExternal tools (optional — missing tools reduce declared coverage):", "b"))
    have = 0
    for t in tools:
        if shutil.which(t):
            have += 1
            print(f"  {_c('✓', 'g')} {t}")
        else:
            print(f"  {_c('·', 'y')} {t}  (not installed)")
    print(f"\n  {have}/{len(tools)} external tools present.")
    # searxng
    print(_c("\nServices:", "b"))
    import urllib.request
    for name, url in [("SearXNG", "http://127.0.0.1:8888"),
                      ("Tor SOCKS", "127.0.0.1:9050")]:
        print(f"  · {name}: configured at {url}")
    # modules
    reg = Registry().discover()
    print(_c(f"\nLoaded modules: {len(reg.modules)}", "g"))


def cmd_modules(args):
    reg = Registry().discover()
    print(_c(f"\n{len(reg.modules)} modules loaded\n", "c"))
    by_cat = {}
    for cls in reg.all():
        by_cat.setdefault(cls.spec.category, []).append(cls)
    for cat, mods in by_cat.items():
        print(_c(f"── {cat.upper()} ({len(mods)}) ──", "b"))
        for cls in mods:
            s = cls.spec
            acc = ",".join(sorted(t.value for t in s.accepts))
            flags = []
            if s.active:
                flags.append("active")
            if s.requires_tor:
                flags.append("tor")
            if s.external_bin:
                flags.append(f"bin:{s.external_bin}")
            fl = f" [{','.join(flags)}]" if flags else ""
            print(f"  {_c(s.name, 'g'):30}  ←{acc}{fl}")
            print(f"       {s.description}")
        print()


def cmd_update(args):
    print(_c("Run install.sh --update to reinstall the pinned external toolchain.", "y"))


def cmd_benchmark(args):
    """Run deterministic false-positive and identity-fusion release gates."""
    from pathlib import Path
    from .benchmark import load_cases, run_benchmark

    cases = load_cases(args.dataset)
    result = run_benchmark(
        cases,
        min_precision=args.min_precision,
        max_false_positive_rate=args.max_fpr,
    )
    payload = result.to_dict()
    print(_c("\nArgus evidence benchmark", "c"))
    print(f"  cases:               {result.passed}/{result.total} passed")
    print(f"  precision:           {result.precision:.2%}")
    print(f"  recall:              {result.recall:.2%}")
    print(f"  F1:                  {result.f1:.2%}")
    print(f"  false-positive rate: {result.false_positive_rate:.2%}")
    print(f"  false-merge rate:    {result.false_merge_rate:.2%}")
    print(f"  false-split rate:    {result.false_split_rate:.2%}")
    print(_c(f"  release gate:        {'PASS' if result.gate_passed else 'FAIL'}",
             "g" if result.gate_passed else "r"))
    if result.failures:
        for failure in result.failures:
            print(_c(f"    FAIL {failure['id']}: {failure['actual']}", "r"))
    if args.json_out:
        path = Path(args.json_out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"  JSON: {path}")
    if not result.gate_passed:
        raise SystemExit(2)


# --------------------------------------------------------------------------- #
#  MANAGEMENT COMMANDS (سكربتات الإدارة) — manage stored scans, reports, diffs
# --------------------------------------------------------------------------- #
def _open_store(args):
    outdir = getattr(args, "output_dir", None) or "reports"
    return Store(f"{outdir}/argus.db"), outdir


def _fmt_ts(ts):
    import datetime
    try:
        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


def cmd_history(args):
    """List past scans stored in the local DB."""
    store, _ = _open_store(args)
    scans = store.list_scans(limit=args.limit, target=args.target)
    if not scans:
        print(_c("No scans stored yet. Run 'argus scan <target>' first.", "y"))
        return
    st = store.stats()
    print(_c(f"\nScan history — {st['scans']} scans, {st['distinct_targets']} "
             f"targets, {st['entities']} total entities\n", "c"))
    print(_c(f"  {'ID':<5} {'WHEN':<20} {'TYPE':<10} {'ENTITIES':<9} TARGET", "b"))
    print("  " + "─" * 70)
    for s in scans:
        print(f"  {s['id']:<5} {_fmt_ts(s['ts']):<20} {s['type']:<10} "
              f"{s['entities']:<9} {s['target']}")
    print()


def cmd_report(args):
    """Regenerate reports (JSON/MD/HTML/GEXF) from a stored scan — no re-scan."""
    from .core.models import IntelGraph
    store, outdir = _open_store(args)
    sid = args.scan_id or store.latest_scan_id(args.target)
    if not sid:
        print(_c("No matching scan found.", "r"))
        return
    d = store.get_scan(sid)
    if not d:
        print(_c(f"Scan {sid} not found.", "r"))
        return
    graph = IntelGraph.from_dict(d)
    paths = write_reports(graph, outdir)
    print(_c(f"[Argus] Reports regenerated for scan #{sid} "
             f"({d.get('meta', {}).get('target', '?')}):", "g"))
    for k, v in paths.items():
        print(f"   {k:9}: {v}")


def cmd_export(args):
    """Export a stored scan's raw JSON to a file (or stdout)."""
    import json
    store, _ = _open_store(args)
    sid = args.scan_id or store.latest_scan_id(args.target)
    if not sid:
        print(_c("No matching scan found.", "r"))
        return
    d = store.get_scan(sid)
    if not d:
        print(_c(f"Scan {sid} not found.", "r"))
        return
    payload = json.dumps(d, indent=2, default=str)
    if args.out:
        with open(args.out, "w") as f:
            f.write(payload)
        print(_c(f"Exported scan #{sid} -> {args.out}", "g"))
    else:
        print(payload)


def cmd_diff(args):
    """Diff the two most recent scans of a target (what changed)."""
    store, _ = _open_store(args)
    res = store.diff(args.target)
    if res.get("error"):
        print(_c(res["error"], "y"))
        return
    print(_c(f"\nDiff for {args.target}: scan #{res['old_scan']} → "
             f"#{res['new_scan']}\n", "c"))
    print(_c(f"  + {len(res['added'])} NEW findings", "g"))
    for e in res["added"][:60]:
        print(f"    {_c('+', 'g')} [{e['etype']}] {e['value'][:70]}")
    print(_c(f"\n  - {len(res['removed'])} findings GONE", "y"))
    for e in res["removed"][:60]:
        print(f"    {_c('-', 'y')} [{e['etype']}] {e['value'][:70]}")
    print()


def cmd_clean(args):
    """Prune stored scans (keep the N most recent; optionally per-target)."""
    store, _ = _open_store(args)
    if args.scan_id:
        ok = store.delete_scan(args.scan_id)
        print(_c(f"Deleted scan #{args.scan_id}" if ok
                 else f"Scan #{args.scan_id} not found.",
                 "g" if ok else "y"))
        return
    n = store.clean(keep=args.keep, target=args.target)
    print(_c(f"Removed {n} scan(s). Kept {args.keep} most recent"
             f"{' for ' + args.target if args.target else ''}.", "g"))


def build_parser():
    p = argparse.ArgumentParser(
        prog="argus", description="Argus — Zero-API OSINT Engine")
    p.add_argument("--version", action="version", version=f"argus {__version__}")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="scan a target (auto-detected)")
    s.add_argument("target")
    s.add_argument("-p", "--profile", default="deep",
                   choices=["quick", "standard", "deep", "stealth", "monitor"],
                   help="scan depth (default: deep = maximum passive depth)")
    s.add_argument("--active", action="store_true", help="enable active probing")
    s.add_argument("--tor", action="store_true", help="route via Tor")
    # ── Persona Hunter: person search locked to a country + city ──
    s.add_argument("--name", help="person's full name (ar/en) — enables person search")
    s.add_argument("--country", help="country (any spelling: 'Saudi Arabia', 'SA', 'السعودية')")
    s.add_argument("--city", help="city (any spelling: 'Al Madinah Al Munawwarah', 'المدينة المنورة')")
    s.add_argument("--lang", help="restrict languages, comma-sep (default: auto ar+en+all)")
    s.add_argument("--smtp", action="store_true", help="SMTP email verification")
    s.add_argument("--searxng", help="SearXNG base URL")
    s.add_argument("--phone-region", help="ISO region for local phone numbers, e.g. SA")
    s.add_argument("--budget", type=int, help="total scan budget in seconds")
    s.add_argument("--insecure", action="store_true",
                   help="disable TLS verification (isolated labs only; recorded in report)")
    s.add_argument("--output-dir", help="report/database output directory")
    s.add_argument("--include-module", action="append", default=[], metavar="NAME",
                   help="run only named module(s); repeatable")
    s.add_argument("--exclude-module", action="append", default=[], metavar="NAME",
                   help="skip named module(s); repeatable")
    s.add_argument("--config", default="config.yaml")
    s.add_argument("-q", "--quiet", action="store_true")
    s.set_defaults(func=cmd_scan)

    sub.add_parser("doctor", help="health check").set_defaults(func=cmd_doctor)
    sub.add_parser("modules", help="list modules").set_defaults(func=cmd_modules)
    sub.add_parser("update", help="update pinned tools").set_defaults(func=cmd_update)

    b = sub.add_parser("benchmark", help="run deterministic truth-quality gates")
    b.add_argument("--dataset", help="optional JSON benchmark corpus")
    b.add_argument("--json-out", help="write machine-readable benchmark result")
    b.add_argument("--min-precision", type=float, default=0.98)
    b.add_argument("--max-fpr", type=float, default=0.01,
                   help="maximum false-positive rate (default: 0.01)")
    b.set_defaults(func=cmd_benchmark)

    # ---------------- management commands (سكربتات الإدارة) ---------------- #
    h = sub.add_parser("history", help="list stored scans")
    h.add_argument("-t", "--target", help="filter by target")
    h.add_argument("-n", "--limit", type=int, default=50)
    h.add_argument("--output-dir", default="reports")
    h.set_defaults(func=cmd_history)

    r = sub.add_parser("report", help="regenerate reports from a stored scan")
    r.add_argument("scan_id", nargs="?", type=int, help="scan id (default: latest)")
    r.add_argument("-t", "--target", help="use latest scan of this target")
    r.add_argument("--output-dir", default="reports")
    r.set_defaults(func=cmd_report)

    x = sub.add_parser("export", help="export a stored scan's raw JSON")
    x.add_argument("scan_id", nargs="?", type=int, help="scan id (default: latest)")
    x.add_argument("-t", "--target", help="use latest scan of this target")
    x.add_argument("-o", "--out", help="output file (default: stdout)")
    x.add_argument("--output-dir", default="reports")
    x.set_defaults(func=cmd_export)

    d = sub.add_parser("diff", help="diff two most recent scans of a target")
    d.add_argument("target")
    d.add_argument("--output-dir", default="reports")
    d.set_defaults(func=cmd_diff)

    c = sub.add_parser("clean", help="prune stored scans")
    c.add_argument("scan_id", nargs="?", type=int, help="delete one scan id")
    c.add_argument("-t", "--target", help="restrict to a target")
    c.add_argument("-k", "--keep", type=int, default=5,
                   help="keep the N most recent (default 5)")
    c.add_argument("--output-dir", default="reports")
    c.set_defaults(func=cmd_clean)
    return p


def main(argv=None):
    p = build_parser()
    args = p.parse_args(argv)
    if not getattr(args, "cmd", None):
        p.print_help()
        return 0
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
