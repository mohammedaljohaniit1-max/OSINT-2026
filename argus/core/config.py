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
    profile: str = "standard"
    concurrency: int = 12
    timeout: int = 25
    retries: int = 2
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
        if profile:
            cfg.apply_profile(profile)
        return cfg

    def apply_profile(self, profile: str):
        self.profile = profile
        if profile == "quick":
            self.concurrency = 20
            self.max_subdomains_resolve = 500
            self.active_scan = False
        elif profile == "deep":
            self.concurrency = 16
            self.active_scan = True
            self.verify_smtp = True
            self.max_subdomains_resolve = 20000
        elif profile == "stealth":
            self.use_tor = True
            self.concurrency = 4
            self.rate_limit_per_host = 0.5
            self.active_scan = False
        elif profile == "monitor":
            self.active_scan = False
