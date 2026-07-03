"""Tests for ScanOptions CLI argument building."""

from nuclei_rest_sdk.options import ScanOptions


def test_build_args_includes_targets_and_filters() -> None:
    options = ScanOptions(
        targets=["https://example.com"],
        templates=["http/cves/"],
        tags=["cve", "exposure"],
        severities=["high", "critical"],
        rate_limit=50,
        no_interactsh=True,
        restrict_local_network_access=True,
    )
    args = options.build_args()
    assert args == [
        "-target", "https://example.com",
        "-templates", "http/cves/",
        "-tags", "cve,exposure",
        "-severity", "high,critical",
        "-rate-limit", "50",
        "-no-interactsh",
        "-silent",
        "-restrict-local-network-access",
        "-disable-update-check",
    ]


def test_requires_targets_for_scans() -> None:
    assert ScanOptions(targets=["x"]).requires_targets() is True
    assert ScanOptions(validate_templates=True).requires_targets() is False
    assert ScanOptions(list_templates=True).requires_targets() is False
