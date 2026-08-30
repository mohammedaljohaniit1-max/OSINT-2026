"""
Phone-number intelligence - NO KEY.

Uses libphonenumber (phonenumbers) offline to derive:
  - country, region, carrier, line type, timezone
Then pivots the number through public search / dork engine to find where it's
posted (forums, leaks, business listings, WhatsApp/Telegram footprints).
"""
from __future__ import annotations

from ..core.models import EntityType, IntelGraph
from ..core.module import Module, ModuleSpec
from ._base import ev


class PhoneIntel(Module):
    spec = ModuleSpec(
        name="phone_intel", category="source",
        accepts={EntityType.PHONE},
        produces={EntityType.GEO, EntityType.ORG, EntityType.DORK_HIT},
        description="Offline phone parse (country/carrier/type) + web pivot",
        priority=15, tags={"passive", "phone", "nokey"},
    )

    async def run(self, target, graph: IntelGraph):
        try:
            import phonenumbers
            from phonenumbers import carrier, geocoder, timezone
        except ImportError:
            return
        try:
            num = phonenumbers.parse(target.value, None)
        except Exception:
            return
        if not phonenumbers.is_valid_number(num):
            target.tags.add("invalid-phone")
            return
        region = geocoder.description_for_number(num, "en")
        carr = carrier.name_for_number(num, "en")
        tzs = timezone.time_zones_for_number(num)
        ltype = phonenumbers.number_type(num)
        target.metadata.update({
            "country_code": num.country_code,
            "region": region,
            "carrier": carr,
            "timezones": list(tzs),
            "line_type": str(ltype),
        })
        if region:
            graph.add(EntityType.GEO, region, confidence=0.8,
                      evidence=ev("phone_intel", snippet="phone region"))
        if carr:
            graph.add(EntityType.ORG, carr, confidence=0.7, tags={"carrier"},
                      evidence=ev("phone_intel", snippet="carrier"))
        target.tags.add("phone-parsed")
