"""
Module registry + auto-discovery.

Walks argus.sources / argus.adapters / argus.native, imports every module,
and registers any subclass of Module that defines a `spec`. New modules are
picked up automatically - no central list to maintain.
"""
from __future__ import annotations

import importlib
import inspect
import pkgutil

from .module import Module


class Registry:
    def __init__(self):
        self.modules: dict[str, type[Module]] = {}

    def discover(self):
        import argus.sources
        import argus.adapters
        import argus.native
        import argus.persona

        for pkg in (argus.sources, argus.adapters, argus.native, argus.persona):
            for _, modname, _ in pkgutil.iter_modules(pkg.__path__):
                full = f"{pkg.__name__}.{modname}"
                try:
                    mod = importlib.import_module(full)
                except Exception as e:  # pragma: no cover
                    print(f"[registry] skip {full}: {e}")
                    continue
                for _, obj in inspect.getmembers(mod, inspect.isclass):
                    if (
                        issubclass(obj, Module)
                        and obj is not Module
                        and getattr(obj, "spec", None) is not None
                    ):
                        self.modules[obj.spec.name] = obj
        return self

    def for_type(self, etype, active_ok: bool, tor_ok: bool) -> list[type[Module]]:
        out = []
        for cls in self.modules.values():
            s = cls.spec
            if etype not in s.accepts:
                continue
            if s.active and not active_ok:
                continue
            if s.requires_tor and not tor_ok:
                continue
            out.append(cls)
        return sorted(out, key=lambda c: c.spec.priority)

    def all(self) -> list[type[Module]]:
        return sorted(self.modules.values(), key=lambda c: c.spec.priority)
