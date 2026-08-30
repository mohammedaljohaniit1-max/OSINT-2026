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

    det = detect(args.target)
    print(_c(f"[Argus] Target: {det.value}  →  {det.type.value} "
             f"({det.confidence:.0%})", "c"))
    print(_c(f"[Argus] Profile: {cfg.profile} | active={cfg.active_scan} "
             f"| tor={cfg.use_tor}\n", "c"))

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
    print(_c("\nExternal tools (optional — native modules cover gaps):", "b"))
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
    print(_c("Run install.sh --update to refresh external tools & wordlists.", "y"))


def build_parser():
    p = argparse.ArgumentParser(
        prog="argus", description="Argus — Zero-API OSINT Engine")
    p.add_argument("--version", action="version", version=f"argus {__version__}")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="scan a target (auto-detected)")
    s.add_argument("target")
    s.add_argument("-p", "--profile", default="standard",
                   choices=["quick", "standard", "deep", "stealth", "monitor"])
    s.add_argument("--active", action="store_true", help="enable active probing")
    s.add_argument("--tor", action="store_true", help="route via Tor")
    s.add_argument("--smtp", action="store_true", help="SMTP email verification")
    s.add_argument("--searxng", help="SearXNG base URL")
    s.add_argument("--config", default="config.yaml")
    s.add_argument("-q", "--quiet", action="store_true")
    s.set_defaults(func=cmd_scan)

    sub.add_parser("doctor", help="health check").set_defaults(func=cmd_doctor)
    sub.add_parser("modules", help="list modules").set_defaults(func=cmd_modules)
    sub.add_parser("update", help="update tools").set_defaults(func=cmd_update)
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
