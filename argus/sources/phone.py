"""
Phone-number intelligence - NO KEY.

Robust against LOCAL numbers with no country code (the common real-world case,
e.g. Saudi "0576365924"). Strategy:
  1. Try parsing as-is (E.164 with +).
  2. If that fails, try a list of likely default regions (SA, AE, EG, US, GB,
     ...) and accept the first VALID interpretation.
  3. Derive country / region / carrier / line-type / timezone offline
     (libphonenumber - no network).
  4. Emit the parsed facts + a web-pivot dork so the number's footprint
     (WhatsApp, Telegram, listings, leaks) can be found.
Never returns an empty scan silently - it always records what it could parse.
"""
from __future__ import annotations

from ..core.models import EntityType, IntelGraph
from ..core.module import Module, ModuleSpec
from ._base import ev

# regions to try when the number has no + country code (ordered by MENA focus)
DEFAULT_REGIONS = ["SA", "AE", "EG", "KW", "QA", "BH", "OM", "JO", "US", "GB",
                   "IN", "TR", "FR", "DE"]

LINE_TYPES = {0: "FIXED_LINE", 1: "MOBILE", 2: "FIXED_LINE_OR_MOBILE",
              3: "TOLL_FREE", 4: "PREMIUM_RATE", 5: "SHARED_COST",
              6: "VOIP", 7: "PERSONAL_NUMBER", 8: "PAGER", 9: "UAN",
              10: "VOICEMAIL", -1: "UNKNOWN", 27: "UNKNOWN"}


class PhoneIntel(Module):
    spec = ModuleSpec(
        name="phone_intel", category="source",
        accepts={EntityType.PHONE},
        produces={EntityType.GEO, EntityType.ORG},
        description="Offline phone parse (country/carrier/type) w/ local-number fallback",
        priority=15, tags={"passive", "phone", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        try:
            import phonenumbers
            from phonenumbers import carrier, geocoder, timezone
        except ImportError:
            target.metadata["note"] = "install 'phonenumbers' for phone parsing"
            return

        raw = target.value
        num = None
        used_region = None

        # 1) as-is (handles +CC numbers)
        try:
            cand = phonenumbers.parse(raw, None)
            if phonenumbers.is_valid_number(cand):
                num = cand
        except Exception:
            pass

        # 2) local-number fallback: try likely regions
        if num is None:
            for region in DEFAULT_REGIONS:
                try:
                    cand = phonenumbers.parse(raw, region)
                    if phonenumbers.is_valid_number(cand):
                        num, used_region = cand, region
                        break
                except Exception:
                    continue

        if num is None:
            # still record best-effort possibility, mark low confidence
            target.tags.add("phone-unparseable")
            target.metadata["parse_note"] = (
                "Could not validate as E.164 or any common region. "
                "Provide with country code (e.g. +966...) for full parsing.")
            return

        e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
        intl = phonenumbers.format_number(
            num, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        region = geocoder.description_for_number(num, "en")
        carr = carrier.name_for_number(num, "en")
        tzs = list(timezone.time_zones_for_number(num))
        ltype = LINE_TYPES.get(phonenumbers.number_type(num), "UNKNOWN")
        region_code = phonenumbers.region_code_for_number(num)

        target.metadata.update({
            "e164": e164,
            "international": intl,
            "country_code": num.country_code,
            "region_code": region_code,
            "geographic_area": region,
            "carrier": carr,
            "timezones": tzs,
            "line_type": ltype,
            "assumed_region": used_region,
        })
        target.confidence = max(target.confidence, 0.85)
        target.tags.add("phone-parsed")

        # NOTE: geo + carrier are FACTS ABOUT THE NUMBER, not assets owned by
        # the person we're investigating. They must be recorded but NEVER
        # expanded — otherwise the engine cascades the carrier's global corporate
        # infrastructure (e.g. carrier "Lebara" -> mobile.lebara.com -> 100s of
        # IPs/CIDRs/URLs in another country). That is pure contamination.
        if region:
            graph.add(EntityType.GEO, f"{region} ({region_code})", confidence=0.85,
                      tags={"phone-geo", "no-expand"},
                      evidence=ev("phone_intel", snippet=f"{e164} -> {region}"))
        if carr:
            graph.add(EntityType.ORG, carr, confidence=0.8,
                      tags={"carrier", "no-expand", "phone-fact"},
                      evidence=ev("phone_intel",
                                  snippet=f"{e164} carrier {carr} "
                                          f"(carrier name — not the subscriber)"))

        # feed the dork engine: normalize to searchable variants so the web
        # pivot (WhatsApp/Telegram/listings/leaks) actually runs on the number.
        digits = "".join(c for c in e164 if c.isdigit())
        target.metadata["search_variants"] = [
            e164, intl, digits, raw,
            f"+{num.country_code} {phonenumbers.national_significant_number(num)}",
        ]
