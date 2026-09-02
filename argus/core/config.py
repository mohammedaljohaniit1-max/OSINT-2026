"""
Argus configuration.

Everything works with ZERO API keys out of the box. Keys are purely optional
enhancers - if present they unlock higher rate limits, but nothing REQUIRES
them. Config is loaded from (in order): defaults -> config.yaml -> env vars.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

try:
    import yaml  # optional
except ImportError:
    yaml = None


DEFAULT_UAS = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
]


@dataclass
class Config:
    # profiles: quick | standard | deep | stealth | monitor
    # DEEP is the default: maximum PASSIVE depth (never intrusive unless --active).
    profile: str = "deep"
    concurrency: int = 16
    timeout: int = 25
    retries: int = 3
    rate_limit_per_host: float = 3.0        # req/sec per host

    # networking
    user_agents: list[str] = field(default_factory=lambda: list(DEFAULT_UAS))
    use_tor: bool = False
    tor_socks: str = "socks5h://127.0.0.1:9050"
    proxies: list[str] = field(default_factory=list)
    searxng_url: str = os.environ.get("ARGUS_SEARXNG", "http://127.0.0.1:8888")

    # behavior
    active_scan: bool = False                # port scan, live probing
    verify_smtp: bool = False                # SMTP RCPT verification
    max_subdomains_resolve: int = 5000
    output_dir: str = "reports"

    # ── PERSONA HUNTER: person-search geo context ──────────────────────────
    # When set (via `argus scan "<name>" --country .. --city ..`) the engine
    # runs a person investigation locked to this locale: only accounts whose
    # name matches AND whose location resolves to this city are ranked as the
    # target; everything else is recorded as a low-confidence finding.
    person_name: str = ""                    # raw name as the user typed it
    person_country: str = ""                 # e.g. "Saudi Arabia" / "SA"
    person_city: str = ""                    # e.g. "Al Madinah Al Munawwarah"
    person_langs: list[str] = field(default_factory=list)  # [] = auto (ar+en)

    # optional keys (NONE required)
    keys: dict = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | None = None, profile: str | None = None) -> "Config":
        cfg = cls()
        if path and yaml and os.path.exists(path):
            with open(path) as f:
                data = yaml.safe_load(f) or {}
            for k, v in data.items():
                if hasattr(cfg, k):
                    setattr(cfg, k, v)
        # env overrides for keys
        for env, key in [
            ("SHODAN_API_KEY", "shodan"),
            ("GITHUB_TOKEN", "github"),
            ("HUNTER_API_KEY", "hunter"),
        ]:
            if os.environ.get(env):
                cfg.keys[key] = os.environ[env]
        # always materialize the profile's settings (default = deep)
        cfg.apply_profile(profile or cfg.profile)
        return cfg

    def apply_profile(self, profile: str):
        self.profile = profile
        if profile == "quick":
            self.concurrency = 20
            self.max_subdomains_resolve = 500
            self.active_scan = False
        elif profile == "standard":
            self.concurrency = 14
            self.active_scan = False
            self.max_subdomains_resolve = 5000
        elif profile == "deep":
            # DEFAULT: maximum PASSIVE depth. Active probing stays OFF unless the
            # user explicitly passes --active (keeps the scan non-intrusive).
            self.concurrency = 16
            self.active_scan = False
            self.verify_smtp = False
            self.max_subdomains_resolve = 30000
            self.retries = 3
        elif profile == "stealth":
            self.use_tor = True
            self.concurrency = 4
            self.rate_limit_per_host = 0.5
            self.active_scan = False
        elif profile == "monitor":
            self.active_scan = False
