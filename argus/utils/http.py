"""
Resilient HTTP client for Argus.

Features that make no-key scraping actually work in 2026:
  - User-Agent rotation
  - Optional Tor (socks5h) and proxy-list rotation
  - Per-host rate limiting (polite, avoids bans)
  - Automatic retries with backoff
  - Async (httpx) with sync fallback (requests)
  - Transparent JSON / text / bytes helpers
"""
from __future__ import annotations

import asyncio
import random
import time
from collections import defaultdict
from email.utils import parsedate_to_datetime
from typing import Any, Optional

try:
    import httpx
    HAVE_HTTPX = True
except ImportError:
    HAVE_HTTPX = False

import requests


class RateLimiter:
    def __init__(self, per_sec: float):
        self.min_interval = 1.0 / per_sec if per_sec > 0 else 0
        self._last: dict[str, float] = defaultdict(float)
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def wait(self, host: str):
        async with self._locks[host]:
            elapsed = time.time() - self._last[host]
            if elapsed < self.min_interval:
                await asyncio.sleep(self.min_interval - elapsed)
            self._last[host] = time.time()


class HttpClient:
    def __init__(self, config):
        self.cfg = config
        self.rl = RateLimiter(config.rate_limit_per_host)
        self._client: Optional["httpx.AsyncClient"] = None
        self.events: list[dict[str, Any]] = []
        self.status_counts: dict[str, int] = defaultdict(int)

    def _headers(self, extra: dict | None = None) -> dict:
        h = {
            "User-Agent": random.choice(self.cfg.user_agents),
            "Accept": "text/html,application/json,*/*",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if extra:
            h.update(extra)
        return h

    def _proxy(self) -> str | None:
        if self.cfg.use_tor:
            return self.cfg.tor_socks
        if self.cfg.proxies:
            return random.choice(self.cfg.proxies)
        return None

    async def _ensure(self):
        if not HAVE_HTTPX:
            return
        if self._client is None:
            proxy = self._proxy()
            self._client = httpx.AsyncClient(
                headers=self._headers(),
                timeout=self.cfg.timeout,
                follow_redirects=True,
                proxy=proxy,
                verify=self.cfg.verify_tls,
            )

    @staticmethod
    def _host(url: str) -> str:
        try:
            return url.split("/")[2]
        except IndexError:
            return url

    def _record(self, method: str, url: str, *, status: int = 0,
                error: str = "", attempt: int = 0, elapsed: float = 0.0):
        key = str(status) if status else "error"
        self.status_counts[key] += 1
        # Keep a bounded audit trail. Successful 2xx requests are summarized by
        # status_counts; non-success events retain enough context to diagnose gaps.
        if error or status in (403, 408, 429) or status >= 500:
            self.events.append({
                "method": method, "host": self._host(url), "status": status,
                "error": error[:300], "attempt": attempt,
                "elapsed": round(elapsed, 3), "timestamp": time.time(),
            })
            if len(self.events) > 500:
                del self.events[:100]

    @staticmethod
    def _retry_after(response, fallback: float) -> float:
        value = getattr(response, "headers", {}).get("Retry-After", "")
        if not value:
            return fallback
        try:
            return min(60.0, max(0.0, float(value)))
        except (TypeError, ValueError):
            try:
                return min(60.0, max(0.0,
                    parsedate_to_datetime(value).timestamp() - time.time()))
            except Exception:
                return fallback

    def _too_large(self, response) -> bool:
        raw = getattr(response, "content", b"") or b""
        return len(raw) > int(self.cfg.max_response_bytes)

    async def get(self, url: str, *, params=None, headers=None, expect="text") -> Any:
        await self.rl.wait(self._host(url))
        for attempt in range(self.cfg.retries + 1):
            started = time.monotonic()
            try:
                if HAVE_HTTPX:
                    await self._ensure()
                    r = await self._client.get(
                        url, params=params, headers=self._headers(headers)
                    )
                else:
                    r = await asyncio.to_thread(
                        requests.get, url, params=params,
                        headers=self._headers(headers), timeout=self.cfg.timeout,
                        verify=self.cfg.verify_tls, proxies=self._req_proxies(),
                    )
                status = int(getattr(r, "status_code", 0))
                self._record("GET", url, status=status, attempt=attempt,
                             elapsed=time.monotonic() - started)
                if self._too_large(r):
                    self._record("GET", url, status=status, attempt=attempt,
                                 error="response exceeds configured size limit")
                    return None
                if status == 429 or status >= 500:
                    if attempt >= self.cfg.retries:
                        return self._decode(r, expect) if expect == "response" else None
                    await asyncio.sleep(self._retry_after(
                        r, 1.5 * (attempt + 1) + random.random()))
                    continue
                return self._decode(r, expect)
            except Exception as exc:
                self._record("GET", url, error=f"{type(exc).__name__}: {exc}",
                             attempt=attempt, elapsed=time.monotonic() - started)
                if attempt >= self.cfg.retries:
                    return None
                await asyncio.sleep(1.5 * (attempt + 1) + random.random())
        return None

    async def post(self, url, *, data=None, json=None, headers=None, expect="text"):
        await self.rl.wait(self._host(url))
        for attempt in range(self.cfg.retries + 1):
            started = time.monotonic()
            try:
                if HAVE_HTTPX:
                    await self._ensure()
                    r = await self._client.post(
                        url, data=data, json=json, headers=self._headers(headers)
                    )
                else:
                    r = await asyncio.to_thread(
                        requests.post, url, data=data, json=json,
                        headers=self._headers(headers), timeout=self.cfg.timeout,
                        verify=self.cfg.verify_tls, proxies=self._req_proxies(),
                    )
                status = int(getattr(r, "status_code", 0))
                self._record("POST", url, status=status, attempt=attempt,
                             elapsed=time.monotonic() - started)
                if self._too_large(r):
                    self._record("POST", url, status=status,
                                 error="response exceeds configured size limit")
                    return None
                if status == 429 or status >= 500:
                    if attempt >= self.cfg.retries:
                        return self._decode(r, expect) if expect == "response" else None
                    await asyncio.sleep(self._retry_after(r, 1.5 * (attempt + 1)))
                    continue
                return self._decode(r, expect)
            except Exception as exc:
                self._record("POST", url, error=f"{type(exc).__name__}: {exc}",
                             attempt=attempt, elapsed=time.monotonic() - started)
                if attempt >= self.cfg.retries:
                    return None
                await asyncio.sleep(1.5 * (attempt + 1))
        return None

    def _req_proxies(self):
        p = self._proxy()
        return {"http": p, "https": p} if p else None

    @staticmethod
    def _decode(r, expect):
        try:
            if expect == "json":
                return r.json()
            if expect == "bytes":
                return r.content
            if expect == "response":
                return r
            return r.text
        except Exception:
            return r.text if expect != "bytes" else r.content

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None


# convenience sync wrapper for simple scripts / testing
def sync_get(url, **kw):
    """Small secure-by-default sync helper used by maintenance scripts."""
    import requests as _r
    verify = kw.pop("verify", True)
    return _r.get(url, timeout=20, verify=verify,
                  headers={"User-Agent": random.choice(
                      __import__("argus.core.config", fromlist=["DEFAULT_UAS"]).DEFAULT_UAS)}, **kw)
