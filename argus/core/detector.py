"""
Target Auto-Detection Engine
============================
Give Argus ANYTHING and it figures out what it is - no flags needed.

  argus scan example.com          -> domain
  argus scan john@example.com     -> email
  argus scan +14155552671         -> phone
  argus scan 8.8.8.8              -> ip
  argus scan 8.8.8.0/24           -> cidr
  argus scan AS15169              -> asn
  argus scan johndoe              -> username
  argus scan "Acme Corp"          -> org
  argus scan bc1qxy...            -> crypto wallet
  argus scan d41d8cd98f00b204...  -> hash
  argus scan http://xyz.onion     -> onion

Detection is ordered by specificity (most-specific regex first) so the
engine never mistakes an email for a domain, or an IP for an ASN.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from .models import EntityType

# --------------------------------------------------------------------------- #
#  Regex library (compiled once)
# --------------------------------------------------------------------------- #
RE_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
RE_ONION = re.compile(r"^(https?://)?[a-z2-7]{16}\.onion$|^(https?://)?[a-z2-7]{56}\.onion$", re.I)
RE_URL = re.compile(r"^https?://", re.I)
RE_ASN = re.compile(r"^AS\d{1,10}$", re.I)
RE_PHONE = re.compile(r"^\+?[0-9][0-9\s().\-]{6,18}[0-9]$")
RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
RE_BTC = re.compile(r"^(bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")
RE_ETH = re.compile(r"^0x[a-fA-F0-9]{40}$")
RE_USERNAME = re.compile(r"^[A-Za-z0-9_.\-]{2,40}$")
# a domain: at least one dot, valid label chars, TLD >= 2 alpha
RE_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?!-)([A-Za-z0-9\-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$"
)


@dataclass
class Detection:
    type: EntityType
    value: str
    normalized: str
    confidence: float
    note: str = ""


def _clean(raw: str) -> str:
    return raw.strip().strip('"').strip("'")


def detect(raw: str) -> Detection:
    """Return the single best-guess Detection for a raw target string."""
    t = _clean(raw)

    # 1. Email (most specific - has @)
    if RE_EMAIL.match(t):
        return Detection(EntityType.EMAIL, t, t.lower(), 0.99, "matched email regex")

    # 2. Onion (before URL/domain)
    if RE_ONION.match(t):
        host = re.sub(r"^https?://", "", t, flags=re.I).lower()
        return Detection(EntityType.ONION, t, host, 0.98, "tor hidden service")

    # 3. URL
    if RE_URL.match(t):
        return Detection(EntityType.URL, t, t, 0.97, "http(s) url")

    # 4. ASN
    if RE_ASN.match(t):
        return Detection(EntityType.ASN, t, t.upper(), 0.98, "autonomous system number")

    # 5. IP / CIDR
    try:
        if "/" in t:
            net = ipaddress.ip_network(t, strict=False)
            return Detection(EntityType.CIDR, t, str(net), 0.99, f"ipv{net.version} network")
        ip = ipaddress.ip_address(t)
        return Detection(EntityType.IP, t, str(ip), 0.99, f"ipv{ip.version} address")
    except ValueError:
        pass

    # 6. Hashes
    if RE_MD5.match(t):
        return Detection(EntityType.HASH, t, t.lower(), 0.9, "md5")
    if RE_SHA1.match(t):
        return Detection(EntityType.HASH, t, t.lower(), 0.9, "sha1")
    if RE_SHA256.match(t):
        return Detection(EntityType.HASH, t, t.lower(), 0.9, "sha256")

    # 7. Crypto wallets
    if RE_ETH.match(t):
        return Detection(EntityType.CRYPTO_WALLET, t, t.lower(), 0.95, "ethereum")
    if RE_BTC.match(t):
        return Detection(EntityType.CRYPTO_WALLET, t, t, 0.9, "bitcoin")

    # 8. Phone (validate with libphonenumber if available)
    if RE_PHONE.match(t) and sum(c.isdigit() for c in t) >= 7:
        norm = _normalize_phone(t)
        if norm:
            return Detection(EntityType.PHONE, t, norm, 0.9, "valid phone (libphonenumber)")
        # digit-only strings that look like phones
        if t.startswith("+") or sum(c.isdigit() for c in t) >= 10:
            return Detection(EntityType.PHONE, t, re.sub(r"[^\d+]", "", t), 0.6, "heuristic phone")

    # 9. Domain (must contain dot + valid TLD)
    if "." in t and RE_DOMAIN.match(t):
        return Detection(EntityType.DOMAIN, t, t.lower(), 0.9, "valid domain")

    # 10. Org (has space or multiple words / capitalized)
    if " " in t:
        return Detection(EntityType.ORG, t, t, 0.55, "multi-word -> organization/person")

    # 11. Username fallback
    if RE_USERNAME.match(t):
        return Detection(EntityType.USERNAME, t, t, 0.5, "single token -> username")

    return Detection(EntityType.UNKNOWN, t, t, 0.2, "could not classify")


def _normalize_phone(t: str) -> str | None:
    try:
        import phonenumbers  # optional dependency

        num = phonenumbers.parse(t, None)
        if phonenumbers.is_valid_number(num):
            return phonenumbers.format_number(
                num, phonenumbers.PhoneNumberFormat.E164
            )
    except Exception:
        return None
    return None


def detect_all(raw: str) -> list[Detection]:
    """Return primary detection (kept for future multi-hypothesis use)."""
    return [detect(raw)]
