"""
Argus - Evidence-first OSINT Orchestrator
==========================================
A self-orchestrating OSINT framework that distinguishes observations,
candidates, inferences, confirmations, and unavailable coverage. It can use
public no-key sources and optional external tools without claiming that a
page response or matching handle proves identity ownership.

Codename: Argus (the hundred-eyed giant of Greek myth - all-seeing).
"""

__version__ = "2.1.0"
__codename__ = "Argus"
__author__ = "OSINT-2026"

BANNER = r"""
    ___                           
   /   |  _________ ___  _______  
  / /| | / ___/ __ `/ / / / ___/  
 / ___ |/ /  / /_/ / /_/ (__  )   
/_/  |_/_/   \__, /\__,_/____/    
            /____/   Evidence-first OSINT  v{version}
        The hundred-eyed. Evidence before claims.
""".format(version=__version__)
