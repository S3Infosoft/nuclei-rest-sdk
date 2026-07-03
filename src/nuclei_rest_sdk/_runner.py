"""Subprocess execution and JSONL parsing for Nuclei."""

from __future__ import annotations

import asyncio
import json
import subprocess
from collections.abc import AsyncIterator, Iterator
from typing import IO

from nuclei_rest_sdk.exceptions import NucleiParseError, NucleiScanError
from nuclei_rest_sdk.models import Finding


def parse_jsonl_line(line: str) -> Finding | None:
    """Parse a single JSONL line into a :class:`Finding`."""
    stripped = line.strip()
    if not stripped:
        return None
    if not stripped.startswith("{"):
        return None
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise NucleiParseError(f"Invalid JSONL from nuclei: {exc}") from exc
    if not isinstance(payload, dict):
        raise NucleiParseError("Expected JSON object in nuclei JSONL output")
    return Finding.from_dict(payload)


def iter_findings(stream: IO[str]) -> Iterator[Finding]:
    """Yield findings from a nuclei JSONL stream."""
    for line in stream:
        finding = parse_jsonl_line(line)
        if finding is not None:
            yield finding


async def async_iter_findings(stream: asyncio.StreamReader) -> AsyncIterator[Finding]:
    """Yield findings from an async nuclei JSONL stream."""
    while True:
        line = await stream.readline()
        if not line:
            break
        text = line.decode("utf-8", errors="replace")
        finding = parse_jsonl_line(text)
        if finding is not None:
            yield finding


def run_sync(
    command: list[str],
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run nuclei synchronously and return the completed process."""
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        cwd=cwd,
        env=env,
        check=False,
    )
    if check and result.returncode != 0:
        raise NucleiScanError(
            f"nuclei exited with status {result.returncode}",
            returncode=result.returncode,
            stderr=result.stderr,
        )
    return result


async def run_async(
    command: list[str],
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    """Run nuclei asynchronously and capture stdout/stderr."""
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
        env=env,
    )
    stdout_bytes, stderr_bytes = await process.communicate()
    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")
    returncode = process.returncode if process.returncode is not None else 1
    return returncode, stdout, stderr


async def stream_async(
    command: list[str],
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> tuple[asyncio.subprocess.Process, asyncio.StreamReader]:
    """Start nuclei asynchronously with streaming stdout."""
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
        env=env,
    )
    if process.stdout is None:
        raise NucleiScanError("Failed to open nuclei stdout pipe", returncode=1)
    return process, process.stdout
