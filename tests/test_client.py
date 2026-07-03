"""Tests for NucleiClient with mocked subprocess."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nuclei_rest_sdk import NucleiClient, ScanOptions
from nuclei_rest_sdk.exceptions import NucleiScanError


@patch("nuclei_rest_sdk.client.find_binary", return_value="/usr/bin/nuclei")
@patch("nuclei_rest_sdk.client.run_sync")
def test_scan_collects_findings(mock_run_sync: MagicMock, _mock_find: MagicMock) -> None:
    mock_run_sync.return_value = MagicMock(
        returncode=0,
        stdout='{"template-id":"a","type":"http","info":{"severity":"low"}}\n',
        stderr="",
    )
    client = NucleiClient()
    findings = client.scan(targets=["https://example.com"])
    assert len(findings) == 1
    assert findings[0].template_id == "a"
    command = mock_run_sync.call_args.args[0]
    assert command[0] == "/usr/bin/nuclei"
    assert "-jsonl" in command
    assert "-target" in command


@patch("nuclei_rest_sdk.client.find_binary", return_value="/usr/bin/nuclei")
@patch("nuclei_rest_sdk.client.run_sync")
def test_scan_raises_on_nonzero_exit(mock_run_sync: MagicMock, _mock_find: MagicMock) -> None:
    mock_run_sync.return_value = MagicMock(returncode=1, stdout="", stderr="boom")
    client = NucleiClient()
    with pytest.raises(NucleiScanError) as exc:
        client.scan(targets=["https://example.com"])
    assert exc.value.returncode == 1


@patch("nuclei_rest_sdk.client.find_binary", return_value="/usr/bin/nuclei")
@patch("nuclei_rest_sdk.client.run_sync")
def test_version(mock_run_sync: MagicMock, _mock_find: MagicMock) -> None:
    mock_run_sync.return_value = MagicMock(returncode=0, stdout="v3.10.0\n", stderr="")
    assert NucleiClient().version() == "v3.10.0"


@patch("nuclei_rest_sdk.client.find_binary", return_value="/usr/bin/nuclei")
@patch("nuclei_rest_sdk.client.stream_async")
@pytest.mark.asyncio
async def test_async_scan_iter(mock_stream: AsyncMock, _mock_find: MagicMock) -> None:
    process = AsyncMock()
    process.wait = AsyncMock(return_value=0)
    process.stderr = None

    class Reader:
        def __init__(self) -> None:
            self._lines = [
                b'{"template-id":"b","type":"dns","info":{"severity":"info"}}\n',
                b"",
            ]
            self._index = 0

        async def readline(self) -> bytes:
            if self._index >= len(self._lines):
                return b""
            line = self._lines[self._index]
            self._index += 1
            return line

    mock_stream.return_value = (process, Reader())
    client = NucleiClient()
    findings = [f async for f in client.async_scan_iter(targets=["example.com"])]
    assert len(findings) == 1
    assert findings[0].template_id == "b"


def test_scan_requires_targets() -> None:
    client = NucleiClient(binary="/usr/bin/nuclei")
    with pytest.raises(ValueError):
        client.scan()
