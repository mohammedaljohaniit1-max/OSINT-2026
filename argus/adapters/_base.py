"""
Base for external-tool adapters.

Adapters wrap best-of-breed OSS tools. They ONLY run if the binary is present
(install.sh installs them). If a tool is missing, Argus silently skips it and
the native modules still cover the ground - so the framework works even on a
bare box, and gets MORE powerful as tools are installed.
"""
from __future__ import annotations

import asyncio
import json
import shutil

from ..core.module import Module


async def run_cmd(args: list[str], timeout: int = 300) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return 124, "", "timeout"
    return proc.returncode, out.decode(errors="ignore"), err.decode(errors="ignore")


def which(binary: str) -> bool:
    return shutil.which(binary) is not None
