"""
existence.py — does this profile page describe a REAL account?
==============================================================

The #1 source of false positives in passive person-search is treating any
HTTP-200 response as "the account exists". Reality on the platforms people
actually use:

  * Snapchat  /add/<handle>  returns 200 for ANY string (generic
    "‎<x> أصبح متاحًا على سناب شات / now available on Snapchat" landing page).
  * Instagram / Threads / TikTok serve a login-wall whose <title> is literally
    "Instagram" / "Threads" with NO profile fields — 200 for missing users too.
  * Reddit's shell renders "Reddit" for suspended / non-existent users.
  * Many sites return a soft-404 (200 status, "page not found" body).

So a 200 alone is worthless. This module inspects the extracted profile fields
+ raw body and returns an EXISTENCE verdict the scorer can trust:

    "real"      — a genuine profile (has a personal display name / bio / avatar
                  / follower text that is NOT just the site name).
    "shell"     — a login-wall / generic landing page (exists for every handle;
                  useless as evidence — do NOT count it).
    "absent"    — an explicit not-found / suspended / soft-404 page.
    "unknown"   — couldn't tell (kept, but at reduced confidence).

Pure heuristics, zero keys, defensive.
"""
from __future__ import annotations

import re

from . import locale as L

# platform display-name/title strings that mean "this is just the site chrome,
# not a person's profile" (login walls / generic landing pages).
_GENERIC_TITLES = {
    "instagram", "instagram photos and videos", "threads", "reddit",
    "tiktok", "tiktok - make your day", "pinterest", "x", "twitter",
    "youtube", "facebook", "log in", "login", "sign up", "snapchat",
}

# Snapchat's public /add/ page shows this for EVERY handle — so its presence
# means nothing about whether the person exists.
_SNAP_GENERIC = [
    "أصبح متاحًا على سناب شات", "على سناب شات", "now available on snapchat",
    "add me on snapchat", "snapchatter",
]

# explicit "this user does not exist" markers (soft-404 in a 200 body)
_ABSENT_MARKERS = [
    "page not found", "sorry, this page isn", "user not found",
    "this account doesn", "isn't available", "content isn't available",
    "account suspended", "user may have been banned", "no existe",
    "الصفحة غير موجودة", "هذا الحساب غير متوفر", "الحساب غير موجود",
    "couldn't find this account", "page isn't available",
    "the page you requested was not found", "404",
]

# login-wall / consent-wall markers → shell (exists for anyone)
_WALL_MARKERS = [
    "log in to see", "sign up to see", "login • instagram",
    "see photos and videos from", "to see photos and videos",
    "you must log in", "please log in", "create an account",
    "سجّل الدخول", "تسجيل الدخول لمشاهدة",
]


def _fold(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "")).strip().lower()


def classify(platform: str, handle: str, prof: dict, body: str) -> tuple[str, str]:
    """Return (verdict, reason). verdict ∈ real|shell|absent|unknown."""
    low = _fold(body)[:20000]
    disp = _fold(prof.get("display_name", ""))
    bio = _fold(prof.get("bio", ""))
    hfold = L.fold(handle)

    # 1) explicit not-found
    for m in _ABSENT_MARKERS:
        if m in low:
            return "absent", f"page reports not-found ('{m}')"

    # 2) Snapchat /add generic landing → shell unless a REAL name is present
    if platform.lower() == "snapchat":
        if any(g in low for g in _SNAP_GENERIC):
            # a real snap profile still shows the person's display name; the
            # generic page's display name is just "<x> على سناب شات". If the
            # only thing we have is that boilerplate, it's a shell.
            stripped = disp
            for g in _SNAP_GENERIC:
                stripped = stripped.replace(_fold(g), "")
            stripped = stripped.strip(" .•-")
            if len(stripped) < 2:
                return "shell", "snapchat generic /add landing (no real name)"

    # 3) login/consent wall
    if any(m in low for m in _WALL_MARKERS):
        # walls sometimes still leak "See photos from <Real Name> (@handle)" —
        # if a real name distinct from the handle is present, keep it.
        if not _has_real_name(disp, bio, hfold):
            return "shell", "login/consent wall (generic, exists for any handle)"

    # 4) display name == bare site chrome (Instagram/Threads/Reddit …)
    if disp in _GENERIC_TITLES and not bio:
        return "shell", f"generic site title '{prof.get('display_name','')}' (no profile)"
    if not disp and not bio and not prof.get("location"):
        # nothing personal extracted at all
        # (could be a JS-only SPA; mark unknown, not real)
        return "unknown", "no profile fields exposed in static HTML"

    # 5) does the page carry a genuine personal signal?
    if _has_real_name(disp, bio, hfold) or _has_person_signal(low):
        return "real", "profile exposes a real display name / bio / person signal"

    return "unknown", "ambiguous page (kept at reduced confidence)"


def _has_real_name(disp: str, bio: str, hfold: str) -> bool:
    """A real display name is human text that isn't just the platform name or a
    verbatim echo of the handle."""
    if not disp:
        return False
    if disp in _GENERIC_TITLES:
        return False
    # strip site suffixes like " on x", " • instagram", "(@handle) on x"
    core = re.split(r"[•|(]| on | \| ", disp)[0].strip()
    core = core.strip(" .-")
    if len(core) < 2:
        return False
    # a name that is literally the handle folded (e.g. 'firasalharbi') is weak,
    # but a spaced/real name ('Firas Alharbi', 'فراس الحربي') is a real signal.
    if L.fold(core) == hfold and " " not in core and not L.has_arabic(core):
        return False
    return True


# follower/following counts, join dates, post counts → a live profile
_PERSON_SIGNALS = [
    re.compile(r"\bfollowers?\b"), re.compile(r"\bfollowing\b"),
    re.compile(r"\bposts?\b"), re.compile(r"joined \w+ \d{4}"),
    re.compile(r"متابع"), re.compile(r"يتابع"), re.compile(r"منشور"),
    re.compile(r'"userinteractioncount"'), re.compile(r'"follower'),
]


def _has_person_signal(low: str) -> bool:
    return any(rx.search(low) for rx in _PERSON_SIGNALS)
