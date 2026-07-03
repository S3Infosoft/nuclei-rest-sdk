"""Tests for JSONL parsing."""

import pytest

from nuclei_rest_sdk._runner import parse_jsonl_line
from nuclei_rest_sdk.exceptions import NucleiParseError


def test_parse_jsonl_line_returns_none_for_blank_or_non_json() -> None:
    assert parse_jsonl_line("") is None
    assert parse_jsonl_line("scan complete") is None


def test_parse_jsonl_line_parses_finding() -> None:
    finding = parse_jsonl_line('{"template-id":"x","type":"http"}')
    assert finding is not None
    assert finding.template_id == "x"


def test_parse_jsonl_line_raises_on_invalid_json() -> None:
    with pytest.raises(NucleiParseError):
        parse_jsonl_line("{not json")
