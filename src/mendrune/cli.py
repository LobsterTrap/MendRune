"""Command-line interface for MendRune."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from mendrune import __version__
from mendrune.errors import ConfigurationError, ExitCode, MendRuneError
from mendrune.orchestrator import run_campaign
from mendrune.reporting import report, status
from mendrune.verify import verify_campaign


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mendrune",
        description="Verify ordered security remediation campaigns.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--runs-root",
        type=Path,
        default=Path("runs"),
        help="Stored run directory (default: runs).",
    )

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

    if args.command == "run":
        try:
            verdict = run_campaign(Path(args.campaign))
        except ConfigurationError as exc:
            print(f"{exc.reason_code}: {exc}", file=sys.stderr)
            return ExitCode.CONFIGURATION_ERROR
        except MendRuneError as exc:
            print(f"{exc.reason_code}: {exc}", file=sys.stderr)
            infrastructure = {
                "rootless_required",
                "podman_unavailable",
                "runtime_unavailable",
                "runtime_unqualified",
                "image_digest_mismatch",
                "isolation_control_unavailable",
                "container_launch_failed",
                "cleanup_uncertain",
            }
            internal = {
                "illegal_state_transition",
                "unexpected_exception",
                "unexpected_internal_error",
                "atomic_write_failed",
            }
            if exc.reason_code in infrastructure:
                return ExitCode.INFRASTRUCTURE_ERROR
            if exc.reason_code in internal:
                return ExitCode.INTERNAL_ERROR
            return ExitCode.VERIFICATION_FAILURE
        except Exception as exc:
            print(f"unexpected_exception: {exc}", file=sys.stderr)
            return ExitCode.INTERNAL_ERROR
        print(f"accepted run {verdict['run_id']}")
        return ExitCode.SUCCESS

    if args.command in {"status", "report"}:
        try:
            rendered = (
                status(args.runs_root, args.run_id)
                if args.command == "status"
                else report(args.runs_root, args.run_id)
            )
        except MendRuneError as exc:
            print(f"{exc.reason_code}: {exc}", file=sys.stderr)
            return ExitCode.CONFIGURATION_ERROR
        print(rendered, end="")
        return ExitCode.SUCCESS

    print(f"{args.command!r} is not implemented yet", file=sys.stderr)
    return ExitCode.CONFIGURATION_ERROR
