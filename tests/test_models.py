"""Tests for Finding and TemplateInfo models."""

from nuclei_rest_sdk.models import Finding, TemplateInfo


def test_template_info_from_dict_normalizes_scalars() -> None:
    info = TemplateInfo.from_dict({
        "name": "Test Template",
        "author": "alice",
        "tags": "cve,exposure",
        "severity": "high",
        "reference": "https://example.com",
    })
    assert info.name == "Test Template"
    assert info.author == ["alice"]
    assert info.tags == ["cve", "exposure"]
    assert info.severity == "high"
    assert info.reference == ["https://example.com"]


def test_finding_from_dict_maps_nuclei_fields() -> None:
    payload = {
        "template-id": "tech-detect",
        "type": "http",
        "matched-at": "https://example.com",
        "host": "example.com",
        "matcher-status": True,
        "timestamp": "2026-01-15T10:30:00Z",
        "info": {
            "name": "Technology Detection",
            "severity": "info",
            "tags": ["tech"],
        },
        "extracted-results": ["nginx"],
    }
    finding = Finding.from_dict(payload)
    assert finding.template_id == "tech-detect"
    assert finding.matched_at == "https://example.com"
    assert finding.severity == "info"
    assert finding.extracted_results == ["nginx"]
    assert finding.timestamp is not None
    assert finding.raw["template-id"] == "tech-detect"
