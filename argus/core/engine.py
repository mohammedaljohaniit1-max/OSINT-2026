"""
The Orchestrator - Argus's brain.

Pipeline:
  Parse -> Detect -> seed graph -> Plan (which modules) -> Execute (async
  waves, respecting accepts/produces so newly-found entities feed the next
  wave) -> Correlate/Score -> Report.

Cascading is the killer feature: a domain produces subdomains + emails, those
emails feed the breach & holehe modules, employee names feed permutation +
social modules, discovered IPs feed ASN/CIDR sweeps... all automatically.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

from .config import Config
from .detector import detect
from .models import Entity, EntityType, IntelGraph, Evidence, FindingState
from .registry import Registry
from ..utils.http import HttpClient


@dataclass
class RunContext:
    config: Config
    http: HttpClient
    graph: IntelGraph
    registry: Registry
    log: "Logger" = None


class Logger:
    def __init__(self, quiet=False):
        self.quiet = quiet
        self.lines: list[str] = []

    def info(self, msg):
        self.lines.append(msg)
        if not self.quiet:
            print(f"  \033[36m[*]\033[0m {msg}")

    def good(self, msg):
        self.lines.append(msg)
        if not self.quiet:
            print(f"  \033[32m[+]\033[0m {msg}")

    def warn(self, msg):
        self.lines.append(msg)
        if not self.quiet:
            print(f"  \033[33m[!]\033[0m {msg}")


class Engine:
    def __init__(self, config: Config, quiet=False):
        self.cfg = config
        self.log = Logger(quiet)
        self.graph = IntelGraph()
        self.http = HttpClient(config)
        self.registry = Registry().discover()
        self.ctx = RunContext(config, self.http, self.graph, self.registry, self.log)
        # cascade control — deeper profiles cascade through more waves so a
        # domain fully unfolds: domain→subs→emails→breaches→usernames→social→…
        self.max_waves = {"quick": 2, "standard": 4, "deep": 6,
                          "stealth": 5, "monitor": 4}.get(config.profile, 4)
        self._processed: set[str] = set()   # entity ids already fed to modules
        # scan budgets / throttling so cascades never explode
        profile_budget = {"quick": 120, "standard": 420, "deep": 2400,
                          "stealth": 1200, "monitor": 420}.get(config.profile, 420)
        self._total_budget = config.scan_budget if config.scan_budget > 0 else profile_budget
        # how many freshly-discovered entities of each type we bother to expand
        # (seed + a bounded sample; prevents "run wayback on 900 subdomains")
        self._expand_cap = {
            "quick":    {"subdomain": 0,   "ip": 5,   "email": 15, "username": 5,
                         "person": 8,  "tracker_id": 5, "asn": 2, "cidr": 0},
            "standard": {"subdomain": 25,  "ip": 25,  "email": 60, "username": 15,
                         "person": 25, "tracker_id": 15, "asn": 3, "cidr": 2},
            "deep":     {"subdomain": 150, "ip": 100, "email": 300, "username": 40,
                         "person": 80, "tracker_id": 40, "asn": 5, "cidr": 10},
        }.get(config.profile, None)
        self._expanded_count: dict[str, int] = {}
        self.graph.run_meta["module_runs"] = []

    # entities tagged with any of these are FINDINGS, not scan scope: the
    # engine must never cascade modules into them (prevents the typosquat /
    # registrar-contact contamination that produced fake breaches & subdomains).
    NO_EXPAND_TAGS = {"no-expand", "out-of-scope", "lookalike",
                      "registrar-contact", "abuse-contact"}

    @staticmethod
    def _registrable(host: str) -> str:
        """Best-effort registrable domain (eTLD+1) without external deps.
        Handles common 2-level public suffixes (co.uk, com.sa, ...)."""
        host = host.lower().strip(".").lstrip("*.")
        parts = host.split(".")
        if len(parts) <= 2:
            return host
        two_level = {"co", "com", "net", "org", "gov", "edu", "ac"}
        if parts[-2] in two_level and len(parts) >= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    def _in_scope(self, ent) -> bool:
        """Is this entity within the seed target's scope (safe to cascade)?"""
        from .models import EntityType
        if "seed" in ent.tags:
            return True
        if ent.tags & self.NO_EXPAND_TAGS:
            return False
        # domain-rooted scope: only expand domains/subdomains that belong to the
        # seed registrable domain (x.com), never sibling look-alikes (x.vip).
        root = self.graph.run_meta.get("root_domain")
        if root and ent.type in (EntityType.DOMAIN, EntityType.SUBDOMAIN):
            v = ent.value.lower()
            if not (v == root or v.endswith("." + root)):
                return False
        # PERSON/PHONE/EMAIL/USERNAME-rooted scope guard: when we're investigating
        # a *person* (not a domain), a discovered ORG or GEO is almost always a
        # generic FACT (phone carrier, country, an employer name) — NOT an asset
        # that belongs to the target. Expanding it drags in a whole corporation's
        # infrastructure (the "carrier Lebara -> 615 entities" contamination).
        # So for non-domain investigations we never cascade ORG/GEO.
        seed_type = self.graph.run_meta.get("target_type")
        if seed_type in ("person", "phone", "email", "username"):
            if ent.type in (EntityType.ORG, EntityType.GEO):
                return False
        return True

    def _select_pending(self):
        """Return [(entity, [module_classes])] to run this wave, applying
        per-type expansion caps, an in-scope guard, and skipping heavy
        recursive modules on low-value fan-out entities."""
        from .models import EntityType
        out = []
        # process high-risk / high-confidence entities first
        candidates = sorted(
            [e for e in self.graph.entities.values() if e.id not in self._processed],
            key=lambda e: (-e.risk.score, -e.confidence),
        )
        for ent in candidates:
            tname = ent.type.value
            # SCOPE GUARD: findings (look-alikes, registrar contacts, out-of-scope
            # domains) are recorded but never expanded/cascaded.
            if not self._in_scope(ent):
                self._processed.add(ent.id)
                continue
            # apply expansion cap (None = unlimited)
            if self._expand_cap is not None:
                cap = self._expand_cap.get(tname, 10)
                used = self._expanded_count.get(tname, 0)
                is_seed = "seed" in ent.tags
                if not is_seed and used >= cap:
                    self._processed.add(ent.id)   # mark done, don't expand
                    continue
                self._expanded_count[tname] = used + 1
            matching = [m for m in self.registry.all() if ent.type in m.spec.accepts]
            mods = []
            for mod in matching:
                if self.cfg.include_modules and mod.spec.name not in self.cfg.include_modules:
                    self._record_run(mod.spec, ent, "skipped",
                                     detail="not selected by include_modules")
                    continue
                if mod.spec.name in self.cfg.exclude_modules:
                    self._record_run(mod.spec, ent, "skipped",
                                     detail="disabled by exclude_modules")
                    continue
                if mod.spec.active and not self.cfg.active_scan:
                    self._record_run(mod.spec, ent, "skipped",
                                     detail="active module disabled")
                    continue
                if mod.spec.requires_tor and not self.cfg.use_tor:
                    self._record_run(mod.spec, ent, "skipped",
                                     detail="Tor required but disabled")
                    continue
                mods.append(mod)
            # on fan-out subdomains, drop the most expensive recursive modules
            if ent.type == EntityType.SUBDOMAIN and "seed" not in ent.tags:
                heavy = {"wayback", "commoncrawl", "js_recon", "wayback_diff",
                         "gau", "leakix", "favicon_pivot"}
                mods = [m for m in mods if m.spec.name not in heavy]
            if mods:
                out.append((ent, mods))
        return out

    async def scan(self, raw_target: str) -> IntelGraph:
        det = detect(raw_target)
        self.log.good(f"Target detected: {det.value} -> {det.type.value} "
                      f"({det.confidence:.0%}, {det.note})")
        self.graph.run_meta.update({
            "target": det.value,
            "target_type": det.type.value,
            "profile": self.cfg.profile,
            "started": time.time(),
        })
        # establish the registrable root domain so the scope guard can keep the
        # cascade on the target and reject sibling look-alikes.
        if det.type in (EntityType.DOMAIN, EntityType.SUBDOMAIN):
            self.graph.run_meta["root_domain"] = self._registrable(det.normalized)
        seed = self.graph.add(det.type, det.normalized, confidence=det.confidence,
                              state=FindingState.CONFIRMED, tags={"seed"})
        seed.add_evidence(Evidence(
            source="detector", source_family="local-input",
            independence_key="operator-input", method="derivation",
            reliability=det.confidence, snippet=det.note))

        # cascading waves
        overall_start = time.time()
        for wave in range(1, self.max_waves + 1):
            if time.time() - overall_start > self._total_budget:
                self.log.warn(f"Total scan budget ({self._total_budget}s) reached "
                              f"— stopping cascade at wave {wave}")
                break
            pending = self._select_pending()
            if not pending:
                break
            self.log.info(f"── Wave {wave}: expanding {len(pending)} entit"
                          f"{'y' if len(pending)==1 else 'ies'} ──")
            tasks = []
            for ent, mod_classes in pending:
                self._processed.add(ent.id)
                for cls in mod_classes:
                    inst = cls(self.ctx)
                    if not inst.available():
                        self._record_run(
                            inst.spec, ent, "unavailable",
                            detail=f"missing binary: {inst.spec.external_bin}")
                        continue
                    tasks.append(self._safe_run(inst, ent))
            if not tasks:
                break
            sem = asyncio.Semaphore(self.cfg.concurrency)

            async def bounded(coro):
                async with sem:
                    return await coro
            await asyncio.gather(*[bounded(t) for t in tasks])

        self.graph.run_meta["http"] = {
            "status_counts": dict(getattr(self.http, "status_counts", {})),
            "notable_events": list(getattr(self.http, "events", [])),
            "tls_verified": bool(self.cfg.verify_tls),
        }
        await self.http.close()
        self._finalize()
        return self.graph

    def _record_run(self, spec, ent, status: str, *, started: float | None = None,
                    before_entities: int = 0, before_relationships: int = 0,
                    detail: str = "", error_class: str = "", timeout: int = 0,
                    http_event_start: int = 0):
        now = time.time()
        run = {
            "module": spec.name,
            "category": spec.category,
            "source_family": spec.source_family,
            "target_id": ent.id,
            "target_type": ent.type.value,
            "target": ent.value,
            "status": status,
            "started": started or now,
            "finished": now,
            "duration": round(now - started, 3) if started else 0.0,
            "entities_added": max(0, len(self.graph.entities) - before_entities)
                if started else 0,
            "relationships_added": max(0, len(self.graph.relationships) - before_relationships)
                if started else 0,
            "timeout": timeout,
            "detail": detail,
            "error_class": error_class,
            "http_events": len(getattr(self.http, "events", [])) - http_event_start if started else 0,
        }
        self.graph.run_meta.setdefault("module_runs", []).append(run)

    async def _safe_run(self, inst, ent):
        name = inst.spec.name
        budget = inst.spec.timeout or self.cfg.module_timeout
        if inst.spec.active:
            budget = max(budget, 120)
        started = time.time()
        before_ids = set(self.graph.entities)
        before_entities = len(before_ids)
        before_relationships = len(self.graph.relationships)
        http_event_start = len(getattr(self.http, "events", []))
        try:
            await asyncio.wait_for(inst.run(ent, self.graph), timeout=budget)
            new_from_me = [
                e for eid, e in self.graph.entities.items()
                if eid not in before_ids and name in e.sources
            ]
            rel_added = len(self.graph.relationships) - before_relationships
            had_http_failures = len(getattr(self.http, "events", [])) > http_event_start
            if new_from_me:
                self.log.good(f"{name}: +{len(new_from_me)} new "
                              f"from {ent.value[:40]}")
            status = "partial" if had_http_failures and (new_from_me or rel_added) else (
                "empty" if not new_from_me and rel_added <= 0 else "success")
            self._record_run(
                inst.spec, ent, status, started=started,
                before_entities=before_entities,
                before_relationships=before_relationships,
                http_event_start=http_event_start,
                timeout=budget,
                detail="completed with source errors" if status == "partial" else "")
        except asyncio.TimeoutError:
            self._record_run(
                inst.spec, ent, "timeout", started=started,
                before_entities=before_entities,
                before_relationships=before_relationships,
                timeout=budget, error_class="TimeoutError",
                detail=f"hard timeout after {budget}s",
                http_event_start=http_event_start)
            self.log.warn(f"{name} timed out ({budget}s) on {ent.value[:30]}")
        except Exception as exc:
            self._record_run(
                inst.spec, ent, "failed", started=started,
                before_entities=before_entities,
                before_relationships=before_relationships,
                timeout=budget, error_class=type(exc).__name__,
                detail=str(exc)[:500], http_event_start=http_event_start)
            self.log.warn(f"{name} failed on {ent.value[:30]}: {exc}")

    def _finalize(self):
        from .correlator import correlate
        correlate(self.graph)
        runs = self.graph.run_meta.get("module_runs", [])
        coverage: dict[str, int] = {}
        for run in runs:
            coverage[run["status"]] = coverage.get(run["status"], 0) + 1
        self.graph.run_meta["module_coverage"] = coverage
        self.graph.run_meta["finished"] = time.time()
        self.graph.run_meta["duration"] = round(
            self.graph.run_meta["finished"] - self.graph.run_meta["started"], 1
        )
