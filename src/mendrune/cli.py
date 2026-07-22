"""Command-line interface for MendRune."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from mendrune import __version__
from mendrune.errors import ConfigurationError, ExitCode
from mendrune.verify import verify_campaign


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mendrune",
        description="Verify ordered security remediation campaigns.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify campaign configuration without executing repository code.",
    )
    verify_parser.add_argument("campaign", help="Path to campaign YAML.")

    run_parser = subparsers.add_parser("run", help="Run a remediation campaign.")
    run_parser.add_argument("campaign", help="Path to campaign YAML.")

    status_parser = subparsers.add_parser("status", help="Read the state of a stored run.")
    status_parser.add_argument("run_id", help="Run identifier.")

    report_parser = subparsers.add_parser("report", help="Render a stored run report.")
    report_parser.add_argument("run_id", help="Run identifier.")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return ExitCode.SUCCESS

    if args.command == "verify":
        try:
            verified = verify_campaign(Path(args.campaign))
        except ConfigurationError as exc:
            print(f"{exc.reason_code}: {exc}", file=sys.stderr)
            return ExitCode.CONFIGURATION_ERROR
        print(
            f"verified campaign {verified.config.campaign_id} "
            f"at base commit {verified.repository.base_commit}"
        )
        return ExitCode.SUCCESS

    print(f"{args.command!r} is not implemented yet", file=sys.stderr)
    return ExitCode.CONFIGURATION_ERROR
