"""High-level client for running Nuclei scans from Python."""

from __future__ import annotations

import asyncio
import os
import subprocess
from collections.abc import AsyncIterator, Iterator, Sequence
from typing import overload

from nuclei_rest_sdk._binary import find_binary
from nuclei_rest_sdk._runner import (
    async_iter_findings,
    iter_findings,
    run_async,
    run_sync,
    stream_async,
)
from nuclei_rest_sdk.exceptions import NucleiScanError
from nuclei_rest_sdk.models import Finding
from nuclei_rest_sdk.options import ScanOptions

__all__ = ["NucleiClient"]


class NucleiClient:
    """Python client for the ProjectDiscovery Nuclei CLI.

    This SDK wraps the official ``nuclei`` binary. You must install Nuclei
    separately — see https://github.com/projectdiscovery/nuclei#installation.

    Example::

        from nuclei_rest_sdk import NucleiClient, ScanOptions

        client = NucleiClient()
        findings = client.scan(
            targets=["https://example.com"],
            tags=["cve"],
            severities=["high", "critical"],
        )
        for finding in findings:
            print(finding.template_id, finding.severity, finding.matched_at)
    """

    def __init__(
        self,
        binary: str | None = None,
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        search_paths: Sequence[str] | None = None,
    ) -> None:
        self._binary_override = binary
        self.cwd = cwd
        self.env = env
        self.search_paths = list(search_paths) if search_paths else None
        self._resolved_binary: str | None = None

    @property
    def binary(self) -> str:
        if self._resolved_binary is None:
            self._resolved_binary = find_binary(
                self._binary_override,
                search_paths=self.search_paths,
            )
        return self._resolved_binary

    def _command(self, options: ScanOptions, *, jsonl: bool = True) -> list[str]:
        if options.requires_targets() and not options.targets and not options.target_list:
            raise ValueError("At least one target or target_list is required for scans")
        args = [self.binary]
        args.extend(options.build_args())
        if jsonl and not options.list_templates and not options.list_tags:
            args.append("-jsonl")
        return args

    def _merged_env(self) -> dict[str, str] | None:
        if self.env is None:
            return None
        merged = os.environ.copy()
        merged.update(self.env)
        return merged

    def version(self) -> str:
        """Return the installed nuclei version string."""
        result = run_sync(
            [self.binary, "-version"],
            cwd=self.cwd,
            env=self._merged_env(),
            check=True,
        )
        return result.stdout.strip() or result.stderr.strip()

    def templates_version(self) -> str:
        """Return the installed nuclei-templates version string."""
        result = run_sync(
            [self.binary, "-templates-version"],
            cwd=self.cwd,
            env=self._merged_env(),
            check=True,
        )
        return result.stdout.strip() or result.stderr.strip()

    def health_check(self) -> str:
        """Run nuclei diagnostic health check."""
        result = run_sync(
            [self.binary, "-health-check"],
            cwd=self.cwd,
            env=self._merged_env(),
            check=True,
        )
        return result.stdout.strip() or result.stderr.strip()

    @overload
    def scan(self, *, options: ScanOptions) -> list[Finding]: ...

    @overload
    def scan(
        self,
        *,
        targets: Sequence[str] | None = None,
        target_list: str | None = None,
        templates: Sequence[str] | None = None,
        tags: Sequence[str] | None = None,
        severities: Sequence[str] | None = None,
        **kwargs: object,
    ) -> list[Finding]: ...

    def scan(
        self,
        *,
        options: ScanOptions | None = None,
        targets: Sequence[str] | None = None,
        target_list: str | None = None,
        templates: Sequence[str] | None = None,
        tags: Sequence[str] | None = None,
        severities: Sequence[str] | None = None,
        **kwargs: object,
    ) -> list[Finding]:
        """Run a scan and collect all findings."""
        return list(self.scan_iter(
            options=options,
            targets=targets,
            target_list=target_list,
            templates=templates,
            tags=tags,
            severities=severities,
            **kwargs,
        ))

    def scan_iter(
        self,
        *,
        options: ScanOptions | None = None,
        targets: Sequence[str] | None = None,
        target_list: str | None = None,
        templates: Sequence[str] | None = None,
        tags: Sequence[str] | None = None,
        severities: Sequence[str] | None = None,
        **kwargs: object,
    ) -> Iterator[Finding]:
        """Run a scan and stream findings as they are emitted."""
        opts = self._resolve_options(
            options,
            targets=targets,
            target_list=target_list,
            templates=templates,
            tags=tags,
            severities=severities,
            **kwargs,
        )
        command = self._command(opts)
        process = run_sync(
            command,
            cwd=self.cwd,
            env=self._merged_env(),
            check=False,
        )
        if process.returncode != 0:
            raise NucleiScanError(
                f"nuclei exited with status {process.returncode}",
                returncode=process.returncode,
                stderr=process.stderr,
            )
        yield from iter_findings(_StringIterator(process.stdout))

    async def async_scan(
        self,
        *,
        options: ScanOptions | None = None,
        targets: Sequence[str] | None = None,
        target_list: str | None = None,
        templates: Sequence[str] | None = None,
        tags: Sequence[str] | None = None,
        severities: Sequence[str] | None = None,
        **kwargs: object,
    ) -> list[Finding]:
        """Run a scan asynchronously and collect all findings."""
        return [finding async for finding in self.async_scan_iter(
            options=options,
            targets=targets,
            target_list=target_list,
            templates=templates,
            tags=tags,
            severities=severities,
            **kwargs,
        )]

    async def async_scan_iter(
        self,
        *,
        options: ScanOptions | None = None,
        targets: Sequence[str] | None = None,
        target_list: str | None = None,
        templates: Sequence[str] | None = None,
        tags: Sequence[str] | None = None,
        severities: Sequence[str] | None = None,
        **kwargs: object,
    ) -> AsyncIterator[Finding]:
        """Run a scan asynchronously and stream findings."""
        opts = self._resolve_options(
            options,
            targets=targets,
            target_list=target_list,
            templates=templates,
            tags=tags,
            severities=severities,
            **kwargs,
        )
        command = self._command(opts)
        process, stdout = await stream_async(
            command,
            cwd=self.cwd,
            env=self._merged_env(),
        )
        async for finding in async_iter_findings(stdout):
            yield finding
        return_code = await process.wait()
        if return_code != 0:
            stderr = ""
            if process.stderr is not None:
                stderr_bytes = await process.stderr.read()
                stderr = stderr_bytes.decode("utf-8", errors="replace")
            raise NucleiScanError(
                f"nuclei exited with status {return_code}",
                returncode=return_code,
                stderr=stderr,
            )

    def validate_templates(self, templates: Sequence[str]) -> str:
        """Validate templates using nuclei's built-in validator."""
        opts = ScanOptions(templates=templates, validate_templates=True)
        result = run_sync(
            self._command(opts, jsonl=False),
            cwd=self.cwd,
            env=self._merged_env(),
            check=True,
        )
        return result.stdout.strip() or result.stderr.strip()

    def list_templates(self, **kwargs: object) -> str:
        """List templates matching the given filters."""
        opts = self._resolve_options(None, **kwargs)
        opts.list_templates = True
        result = run_sync(
            self._command(opts, jsonl=False),
            cwd=self.cwd,
            env=self._merged_env(),
            check=True,
        )
        return result.stdout

    def list_tags(self) -> str:
        """List all available template tags."""
        opts = ScanOptions(list_tags=True)
        result = run_sync(
            self._command(opts, jsonl=False),
            cwd=self.cwd,
            env=self._merged_env(),
            check=True,
        )
        return result.stdout

    def run(
        self,
        options: ScanOptions,
        *,
        jsonl: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        """Run nuclei with full control and return the raw completed process.

        This escape hatch exposes the underlying subprocess result for advanced
        use cases (custom exports, stats JSON, etc.).
        """
        return run_sync(
            self._command(options, jsonl=jsonl),
            cwd=self.cwd,
            env=self._merged_env(),
            check=False,
        )

    async def async_run(
        self,
        options: ScanOptions,
        *,
        jsonl: bool = True,
    ) -> tuple[int, str, str]:
        """Async variant of :meth:`run`."""
        return await run_async(
            self._command(options, jsonl=jsonl),
            cwd=self.cwd,
            env=self._merged_env(),
        )

    def _resolve_options(
        self,
        options: ScanOptions | None,
        *,
        targets: Sequence[str] | None = None,
        target_list: str | None = None,
        templates: Sequence[str] | None = None,
        tags: Sequence[str] | None = None,
        severities: Sequence[str] | None = None,
        **kwargs: object,
    ) -> ScanOptions:
        if options is not None:
            return options
        data: dict[str, object] = {}
        if targets is not None:
            data["targets"] = list(targets)
        if target_list is not None:
            data["target_list"] = target_list
        if templates is not None:
            data["templates"] = list(templates)
        if tags is not None:
            data["tags"] = list(tags)
        if severities is not None:
            data["severities"] = list(severities)
        data.update(kwargs)
        return ScanOptions(**data)  # type: ignore[arg-type]


class _StringIterator:
    """Minimal IO[str] adapter for in-memory stdout."""

    def __init__(self, text: str) -> None:
        self._lines = text.splitlines(keepends=True)
        self._index = 0

    def readline(self) -> str:
        if self._index >= len(self._lines):
            return ""
        line = self._lines[self._index]
        self._index += 1
        return line

    def __iter__(self) -> Iterator[str]:
        for line in self._lines:
            yield line
