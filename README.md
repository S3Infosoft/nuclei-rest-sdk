# nuclei-rest-sdk

Community-maintained Python SDK for the [ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei) vulnerability scanner.

> **PyPI package name:** `nuclei-rest-sdk` (import as `nuclei_rest_sdk`)

## Disclaimer

**Community-maintained SDK.** This project is independently maintained and is **not affiliated with, endorsed by, or sponsored by** ProjectDiscovery, Nuclei, or any third-party organization, project, or its contributors.

**Trademarks.** Any product names, logos, or brands mentioned (including "Nuclei" and "ProjectDiscovery") are the property of their respective owners. Their use is solely for identification and interoperability purposes and does not imply any affiliation, sponsorship, or endorsement.

**Disclaimer.** This software is provided **"as is"**, without any warranties, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, or non-infringement. The authors and copyright holders are not liable for any claims, damages, or other liabilities arising from the use of this software.

**Security notice.** Nuclei is a powerful offensive-security tool. Only scan targets you are authorized to test. Running Nuclei as a service may pose security risks — see the [upstream documentation](https://github.com/projectdiscovery/nuclei) for guidance.

## Requirements

- Python 3.9+
- The [Nuclei CLI](https://github.com/projectdiscovery/nuclei#installation) installed and available on `PATH`, or set `NUCLEI_BINARY` to its path

## Installation

```bash
pip install nuclei-rest-sdk
```

Development install:

```bash
pip install -e ".[dev]"
```

## Quick start

```python
from nuclei_rest_sdk import NucleiClient, ScanOptions

client = NucleiClient()

# Simple scan
findings = client.scan(
    targets=["https://example.com"],
    tags=["cve"],
    severities=["high", "critical"],
)

for finding in findings:
    print(finding.template_id, finding.severity, finding.matched_at)
```

### Streaming results

```python
for finding in client.scan_iter(targets=["https://example.com"], tags=["exposure"]):
    print(finding.template_id, finding.matched_at)
```

### Async API

```python
import asyncio
from nuclei_rest_sdk import NucleiClient

async def main():
    client = NucleiClient()
    async for finding in client.async_scan_iter(targets=["https://example.com"]):
        print(finding.template_id)

asyncio.run(main())
```

### Full control with ScanOptions

```python
from nuclei_rest_sdk import NucleiClient, ScanOptions

options = ScanOptions(
    targets=["https://example.com"],
    templates=["http/cves/"],
    rate_limit=100,
    no_interactsh=True,
    restrict_local_network_access=True,
    json_export="results.json",
)

client = NucleiClient()
findings = client.scan(options=options)
```

### Utility methods

```python
client = NucleiClient(binary="/usr/local/bin/nuclei")  # optional explicit path

print(client.version())
print(client.templates_version())
print(client.health_check())
client.validate_templates(["/path/to/template.yaml"])
```

### CLI helper

```bash
nuclei-rest-sdk --target https://example.com --tags cve --severity high,critical
nuclei-rest-sdk --nuclei-version
```

## Configuration

| Variable | Description |
|----------|-------------|
| `NUCLEI_BINARY` | Path to the nuclei executable |

By default, scans enable `-restrict-local-network-access` and `-disable-update-check`. Override via `ScanOptions` or `extra_args`.

## Publishing to PyPI

```bash
pip install build twine
python -m build
twine upload dist/*
```

## Development

```bash
pytest
ruff check src tests
mypy src
```

## License

MIT — see [LICENSE](LICENSE).

## Related projects

- [Nuclei](https://github.com/projectdiscovery/nuclei) — upstream scanner (Go)
- [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) — community template library

This SDK is a thin Python wrapper around the Nuclei CLI. For embedded Go integration, see the [official Nuclei library](https://github.com/projectdiscovery/nuclei/tree/dev/lib).
