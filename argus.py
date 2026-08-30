#!/usr/bin/env python3
"""Standalone launcher so you can run `python3 argus.py scan <target>`
without installing (handy when the entry point isn't on PATH)."""
import sys
from argus.cli import main

if __name__ == "__main__":
    sys.exit(main())
