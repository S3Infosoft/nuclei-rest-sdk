"""Exceptions raised by the Nuclei SDK."""

from __future__ import annotations


class NucleiError(Exception):
    """Base exception for all nuclei-rest-sdk errors."""


class NucleiNotFoundError(NucleiError):
    """Raised when the nuclei binary cannot be located on the system."""


class NucleiScanError(NucleiError):
    """Raised when a nuclei scan exits with a non-zero status."""

    def __init__(self, message: str, *, returncode: int, stderr: str = "") -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


class NucleiParseError(NucleiError):
    """Raised when nuclei JSONL output cannot be parsed."""
