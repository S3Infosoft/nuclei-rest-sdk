"""Optional CLI helpers for nuclei-rest-sdk."""

from __future__ import annotations

import argparse
import json
import sys

from nuclei_rest_sdk import NucleiClient, ScanOptions, __version__
from nuclei_rest_sdk.exceptions import NucleiError


def main(argv: list[str] | None = None) -> int:
    """Run a nuclei scan from the command line."""
    parser = argparse.ArgumentParser(
        prog="nuclei-rest-sdk",
        description=(
            "Community-maintained Python wrapper for the Nuclei scanner. "
            "Requires the nuclei binary to be installed separately."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-t", "--target", action="append", dest="targets", default=[])
    parser.add_argument("-l", "--list", dest="target_list")
    parser.add_argument("--templates", action="append", default=[])
    parser.add_argument("--tags", default="")
    parser.add_argument("--severity", dest="severities", default="")
    parser.add_argument("--binary")
    parser.add_argument("--nuclei-version", action="store_true", help="Print nuclei version")
    args = parser.parse_args(argv)

    try:
        client = NucleiClient(binary=args.binary)
        if args.nuclei_version:
            print(client.version())
            return 0

        if not args.targets and not args.target_list:
            parser.error("At least one --target or --list is required")

        options = ScanOptions(
            targets=args.targets,
            target_list=args.target_list,
            templates=args.templates,
            tags=[t.strip() for t in args.tags.split(",") if t.strip()],
            severities=[s.strip() for s in args.severities.split(",") if s.strip()],
        )
        for finding in client.scan_iter(options=options):
            print(json.dumps(finding.raw, default=str))
        return 0
    except NucleiError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
