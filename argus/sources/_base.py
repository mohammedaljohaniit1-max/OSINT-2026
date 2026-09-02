"""Shared helpers for source modules."""
from __future__ import annotations

import re

from ..core.models import Evidence

RE_EMAIL_EXTRACT = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
RE_SUBDOMAIN = re.compile(r"(?:[A-Za-z0-9_\-]+\.)+[A-Za-z]{2,}")


def ev(source, url="", snippet="", **raw):
    """Build evidence while keeping provenance fields out of opaque raw data."""
    provenance = {
        key: raw.pop(key) for key in (
            "source_family", "independence_key", "method", "reliability"
        ) if key in raw
    }
    return Evidence(source=source, url=url, snippet=snippet, raw=raw, **provenance)


def extract_emails(text: str, domain: str | None = None) -> set[str]:
    out = set()
    for m in RE_EMAIL_EXTRACT.findall(text or ""):
        m = m.lower()
        if domain and not m.endswith("@" + domain):
            continue
        out.add(m)
    return out


def clean_sub(s: str) -> str:
    return s.strip().lower().lstrip("*.").rstrip(".")
