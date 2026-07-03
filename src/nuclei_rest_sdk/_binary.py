"""Utilities for locating the nuclei binary."""

from __future__ import annotations

import os
import shutil
from typing import Sequence

from nuclei_rest_sdk.exceptions import NucleiNotFoundError

_DEFAULT_NAMES: tuple[str, ...] = ("nuclei", "nuclei.exe")


def find_binary(
    binary: str | None = None,
    *,
    search_paths: Sequence[str] | None = None,
) -> str:
    """Locate the nuclei executable.

    Resolution order:
    1. Explicit ``binary`` argument
    2. ``NUCLEI_BINARY`` environment variable
    3. ``PATH`` lookup (plus optional ``search_paths``)
    """
    candidates: list[str] = []
    if binary:
        candidates.append(binary)
    env_binary = os.environ.get("NUCLEI_BINARY")
    if env_binary:
        candidates.append(env_binary)

    for candidate in candidates:
        resolved = _resolve_candidate(candidate)
        if resolved:
            return resolved

    paths = list(search_paths or ())
    path_env = os.environ.get("PATH", "")
    if path_env:
        paths.extend(path_env.split(os.pathsep))

    for directory in paths:
        for name in _DEFAULT_NAMES:
            candidate = os.path.join(directory, name)
            resolved = _resolve_candidate(candidate)
            if resolved:
                return resolved

    for name in _DEFAULT_NAMES:
        resolved = shutil.which(name)
        if resolved:
            return resolved

    raise NucleiNotFoundError(
        "Could not find the nuclei binary. Install Nuclei from "
        "https://github.com/projectdiscovery/nuclei and ensure it is on PATH, "
        "or set NUCLEI_BINARY to the executable path."
    )


def _resolve_candidate(path: str) -> str | None:
    if not path:
        return None
    expanded = os.path.expanduser(path)
    if os.path.isfile(expanded) and os.access(expanded, os.X_OK):
        return expanded
    resolved = shutil.which(expanded)
    if resolved:
        return resolved
    if os.path.isfile(expanded):
        return expanded
    return None
