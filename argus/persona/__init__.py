"""
PERSONA HUNTER — Argus's person-investigation subsystem.

Turns a plain human name + a country + a city into a locked-scope investigation:
find every online account belonging to *that* person in *that* city, in any
language (Arabic + Latin + transliterations), rank each hit by an explainable
confidence score, and fuse duplicates into one unified persona.

Public surface:
  - locale.py        : Arabic<->Latin transliteration, KSA/Gulf/world city &
                       country gazetteer, name normalization/variants.
  - name_engine.py   : genius Name -> username / handle generator.
  - geo_confirm.py   : geo & identity confirmation scoring for a profile.
  - persona.py       : Persona dataclass + cross-account fusion.
"""
