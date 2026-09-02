"""
The Module contract.

EVERYTHING is a Module - a free data source, an external-tool adapter, or a
genius native script. The orchestrator only knows this interface. This is what
makes Argus infinitely extensible: drop a new file in sources/ adapters/ or
native/, declare what it accepts and produces, and the planner wires it in.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field

from .models import EntityType, IntelGraph


@dataclass
class ModuleSpec:
    name: str                                  # unique id, e.g. "crtsh"
    category: str                              # source | adapter | native
    accepts: set[EntityType]                   # entity types it can consume
    produces: set[EntityType]                  # entity types it may emit
    needs_key: bool = False                    # ALWAYS False for core coverage
    active: bool = False                       # True = touches target directly
    requires_tor: bool = False
    external_bin: str | None = None            # e.g. "subfinder" (adapter)
    description: str = ""
    priority: int = 50                         # lower runs earlier
    tags: set[str] = field(default_factory=set)
    source_family: str = ""                    # shared backend/tool lineage
    timeout: int | None = None                 # explicit runtime ceiling
    reliability: float = 0.5                   # baseline source quality

    def __post_init__(self):
        if not self.source_family:
            self.source_family = self.external_bin or self.name
        self.reliability = max(0.0, min(1.0, float(self.reliability)))


class Module(abc.ABC):
    spec: ModuleSpec

    def __init__(self, ctx):
        self.ctx = ctx                          # RunContext (config, http, graph)

    def available(self) -> bool:
        """Can this module run in the current environment?"""
        if self.spec.external_bin:
            import shutil
            return shutil.which(self.spec.external_bin) is not None
        return True

    @abc.abstractmethod
    async def run(self, target, graph: IntelGraph) -> None:
        """Consume `target` entity, emit findings into `graph`."""
        raise NotImplementedError
