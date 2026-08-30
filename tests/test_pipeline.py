"""
Offline pipeline test — mocks HttpClient so we validate ALL engine logic
(detection, cascading, correlation, scoring, reporting) deterministically
without hitting the network.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from argus.core.config import Config
from argus.core.engine import Engine
from argus.core.models import EntityType
from argus.reporting.reporter import write_reports


# ---- fake HTTP responses keyed by URL substring ---------------------------- #
FAKE = {
    "crt.sh": [
        {"name_value": "www.acme-test.com\nmail.acme-test.com\nvpn.acme-test.com"},
        {"common_name": "admin.acme-test.com"},
    ],
    "hostsearch": "www.acme-test.com,93.184.216.34\napi.acme-test.com,93.184.216.35",
    "xposedornot": {"breaches": [["LinkedIn", "Adobe", "Canva"]]},
    "proxynova": {"lines": ["ceo@acme-test.com:Summer2023!", "hr@acme-test.com:Welcome1"]},
    "favicon": b"\x00" * 400,   # fake favicon bytes
}


class FakeHttp:
    def __init__(self, cfg):
        self.cfg = cfg

    async def get(self, url, params=None, headers=None, expect="text"):
        u = url.lower()
        if "crt.sh" in u:
            return FAKE["crt.sh"] if expect == "json" else str(FAKE["crt.sh"])
        if "hostsearch" in u:
            return FAKE["hostsearch"]
        if "xposedornot" in u:
            return FAKE["xposedornot"]
        if "proxynova" in u:
            return FAKE["proxynova"]
        if "favicon" in u:
            return FAKE["favicon"] if expect == "bytes" else ""
        if expect == "json":
            return {} if "list" not in u else []
        if expect == "bytes":
            return b""
        if expect == "response":
            class R:
                status_code = 404
                text = ""
            return R()
        return ""

    async def post(self, *a, **k):
        return ""

    async def close(self):
        pass


def test_full_pipeline():
    cfg = Config.load(None, "quick")
    eng = Engine(cfg, quiet=True)
    eng.http = FakeHttp(cfg)
    eng.ctx.http = eng.http
    # disable DNS-dependent + external modules for determinism
    for name in list(eng.registry.modules):
        s = eng.registry.modules[name].spec
        if s.external_bin or s.requires_tor:
            del eng.registry.modules[name]

    graph = asyncio.run(eng.scan("acme-test.com"))
    stats = graph.stats()
    print("STATS:", stats)

    # assertions
    subs = [e.value for e in graph.by_type(EntityType.SUBDOMAIN)]
    assert "www.acme-test.com" in subs, "crtsh subdomain missing"
    assert "vpn.acme-test.com" in subs, "vpn subdomain missing"
    breaches = graph.by_type(EntityType.BREACH)
    creds = graph.by_type(EntityType.CREDENTIAL)
    print(f"subdomains={len(subs)} breaches={len(breaches)} creds={len(creds)}")

    # correlation should have produced an org-exposure vulnerability if creds exist
    vulns = [v.value for v in graph.by_type(EntityType.VULNERABILITY)]
    print("VULNS:", vulns)

    paths = write_reports(graph, "reports")
    assert os.path.exists(paths["html"])
    assert os.path.exists(paths["json"])
    print("REPORTS:", paths)
    print("\n✅ pipeline test passed")


if __name__ == "__main__":
    test_full_pipeline()
