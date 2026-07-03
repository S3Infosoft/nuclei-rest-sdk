"""Scan configuration and CLI argument building."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence


@dataclass
class ScanOptions:
    """Options passed to a Nuclei scan.

    Maps to common Nuclei CLI flags. See the upstream documentation for the
    full list of supported flags: https://docs.projectdiscovery.io/tools/nuclei/running
    """

    targets: Sequence[str] = field(default_factory=list)
    target_list: str | None = None
    templates: Sequence[str] = field(default_factory=list)
    template_urls: Sequence[str] = field(default_factory=list)
    workflows: Sequence[str] = field(default_factory=list)
    tags: Sequence[str] = field(default_factory=list)
    exclude_tags: Sequence[str] = field(default_factory=list)
    template_ids: Sequence[str] = field(default_factory=list)
    exclude_template_ids: Sequence[str] = field(default_factory=list)
    severities: Sequence[str] = field(default_factory=list)
    exclude_severities: Sequence[str] = field(default_factory=list)
    protocol_types: Sequence[str] = field(default_factory=list)
    exclude_protocol_types: Sequence[str] = field(default_factory=list)
    authors: Sequence[str] = field(default_factory=list)
    headers: Sequence[str] = field(default_factory=list)
    vars: Sequence[str] = field(default_factory=list)
    rate_limit: int | None = None
    bulk_size: int | None = None
    concurrency: int | None = None
    timeout: int | None = None
    retries: int | None = None
    follow_redirects: bool = False
    disable_redirects: bool = False
    max_redirects: int | None = None
    no_interactsh: bool = False
    silent: bool = True
    omit_raw: bool = False
    omit_template: bool = False
    restrict_local_network_access: bool = True
    disable_update_check: bool = True
    automatic_scan: bool = False
    new_templates: bool = False
    validate_templates: bool = False
    list_templates: bool = False
    list_tags: bool = False
    dast: bool = False
    config: str | None = None
    profile: str | None = None
    output: str | None = None
    json_export: str | None = None
    sarif_export: str | None = None
    markdown_export: str | None = None
    extra_args: Sequence[str] = field(default_factory=list)

    def build_args(self) -> list[str]:
        """Convert options into nuclei CLI arguments."""
        args: list[str] = []

        if self.validate_templates:
            args.append("-validate")
        if self.list_templates:
            args.append("-tl")
        if self.list_tags:
            args.append("-tgl")

        for target in self.targets:
            args.extend(["-target", target])
        if self.target_list:
            args.extend(["-list", self.target_list])

        for template in self.templates:
            args.extend(["-templates", template])
        for url in self.template_urls:
            args.extend(["-template-url", url])
        for workflow in self.workflows:
            args.extend(["-workflows", workflow])

        if self.tags:
            args.extend(["-tags", ",".join(self.tags)])
        if self.exclude_tags:
            args.extend(["-exclude-tags", ",".join(self.exclude_tags)])
        if self.template_ids:
            args.extend(["-template-id", ",".join(self.template_ids)])
        if self.exclude_template_ids:
            args.extend(["-exclude-id", ",".join(self.exclude_template_ids)])
        if self.severities:
            args.extend(["-severity", ",".join(self.severities)])
        if self.exclude_severities:
            args.extend(["-exclude-severity", ",".join(self.exclude_severities)])
        if self.protocol_types:
            args.extend(["-type", ",".join(self.protocol_types)])
        if self.exclude_protocol_types:
            args.extend(["-exclude-type", ",".join(self.exclude_protocol_types)])
        if self.authors:
            args.extend(["-author", ",".join(self.authors)])

        for header in self.headers:
            args.extend(["-header", header])
        for var in self.vars:
            args.extend(["-var", var])

        if self.rate_limit is not None:
            args.extend(["-rate-limit", str(self.rate_limit)])
        if self.bulk_size is not None:
            args.extend(["-bulk-size", str(self.bulk_size)])
        if self.concurrency is not None:
            args.extend(["-concurrency", str(self.concurrency)])
        if self.timeout is not None:
            args.extend(["-timeout", str(self.timeout)])
        if self.retries is not None:
            args.extend(["-retries", str(self.retries)])

        if self.follow_redirects:
            args.append("-follow-redirects")
        if self.disable_redirects:
            args.append("-disable-redirects")
        if self.max_redirects is not None:
            args.extend(["-max-redirects", str(self.max_redirects)])
        if self.no_interactsh:
            args.append("-no-interactsh")
        if self.silent:
            args.append("-silent")
        if self.omit_raw:
            args.append("-omit-raw")
        if self.omit_template:
            args.append("-omit-template")
        if self.restrict_local_network_access:
            args.append("-restrict-local-network-access")
        if self.disable_update_check:
            args.append("-disable-update-check")
        if self.automatic_scan:
            args.append("-automatic-scan")
        if self.new_templates:
            args.append("-new-templates")
        if self.dast:
            args.append("-dast")

        if self.config:
            args.extend(["-config", self.config])
        if self.profile:
            args.extend(["-profile", self.profile])
        if self.output:
            args.extend(["-output", self.output])
        if self.json_export:
            args.extend(["-json-export", self.json_export])
        if self.sarif_export:
            args.extend(["-sarif-export", self.sarif_export])
        if self.markdown_export:
            args.extend(["-markdown-export", self.markdown_export])

        args.extend(self.extra_args)
        return args

    def requires_targets(self) -> bool:
        return not (
            self.validate_templates
            or self.list_templates
            or self.list_tags
        )
