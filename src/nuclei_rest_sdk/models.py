"""Typed models for Nuclei scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class TemplateInfo:
    """Metadata embedded in a nuclei template."""

    name: str = ""
    author: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    description: str = ""
    severity: str = ""
    classification: dict[str, Any] = field(default_factory=dict)
    reference: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TemplateInfo:
        author = data.get("author", [])
        if isinstance(author, str):
            author = [author]
        tags = data.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        reference = data.get("reference", [])
        if isinstance(reference, str):
            reference = [reference]
        classification = data.get("classification", {})
        if not isinstance(classification, dict):
            classification = {}
        metadata = data.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
        return cls(
            name=str(data.get("name", "")),
            author=list(author),
            tags=list(tags),
            description=str(data.get("description", "")),
            severity=str(data.get("severity", "")),
            classification=classification,
            reference=list(reference),
            metadata=metadata,
        )


@dataclass
class Finding:
    """A single vulnerability finding emitted by Nuclei."""

    template_id: str
    type: str
    matched_at: str = ""
    host: str = ""
    url: str = ""
    ip: str = ""
    port: str = ""
    scheme: str = ""
    path: str = ""
    template: str = ""
    template_path: str = ""
    template_url: str = ""
    matcher_name: str = ""
    extractor_name: str = ""
    extracted_results: list[str] = field(default_factory=list)
    request: str = ""
    response: str = ""
    curl_command: str = ""
    matcher_status: bool = False
    timestamp: datetime | None = None
    info: TemplateInfo = field(default_factory=TemplateInfo)
    metadata: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        info_data = data.get("info", {})
        if not isinstance(info_data, dict):
            info_data = {}
        timestamp_raw = data.get("timestamp")
        timestamp: datetime | None = None
        if isinstance(timestamp_raw, str) and timestamp_raw:
            normalized = timestamp_raw.replace("Z", "+00:00")
            try:
                timestamp = datetime.fromisoformat(normalized)
            except ValueError:
                timestamp = None
        meta = data.get("meta", {})
        if not isinstance(meta, dict):
            meta = {}
        extracted = data.get("extracted-results", [])
        if not isinstance(extracted, list):
            extracted = []
        return cls(
            template_id=str(data.get("template-id", "")),
            type=str(data.get("type", "")),
            matched_at=str(data.get("matched-at", "")),
            host=str(data.get("host", "")),
            url=str(data.get("url", "")),
            ip=str(data.get("ip", "")),
            port=str(data.get("port", "")),
            scheme=str(data.get("scheme", "")),
            path=str(data.get("path", "")),
            template=str(data.get("template", "")),
            template_path=str(data.get("template-path", "")),
            template_url=str(data.get("template-url", "")),
            matcher_name=str(data.get("matcher-name", "")),
            extractor_name=str(data.get("extractor-name", "")),
            extracted_results=[str(item) for item in extracted],
            request=str(data.get("request", "")),
            response=str(data.get("response", "")),
            curl_command=str(data.get("curl-command", "")),
            matcher_status=bool(data.get("matcher-status", False)),
            timestamp=timestamp,
            info=TemplateInfo.from_dict(info_data),
            metadata=meta,
            raw=dict(data),
        )

    @property
    def severity(self) -> str:
        return self.info.severity
