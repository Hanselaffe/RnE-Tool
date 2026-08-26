from __future__ import annotations

import argparse
import json
from pathlib import Path

from rne_core.orchestrator import OrchestrationOptions, run_assessment
from rne_core.scope import ScopePolicy
from rne_core.tools import mirror_exploit, toolchain_status


def _write_report(path: str | Path, report: dict[str, object]) -> Path:
    output = Path(path).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rne",
        description="RnE mini-Legion: authorized reconnaissance, correlation and tool orchestration",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    status = subparsers.add_parser("status", help="show availability of external tool adapters")
    status.set_defaults(handler=_handle_status)

    scan = subparsers.add_parser("scan", help="run an authorized assessment pipeline for one literal IP")
    scan.add_argument("target", help="literal IPv4 or IPv6 target")
    scan.add_argument("--authorized", action="store_true", help="confirm authorization for active assessment")
    scan.add_argument("--allow-public", action="store_true", help="allow a public IP after authorization")
    scan.add_argument("--profile", choices=("quick", "standard", "deep"), default="standard")
    scan.add_argument(
        "--nse-vuln",
        action="store_true",
        help="add Nmap's vuln NSE category to the selected profile; use only when explicitly in scope",
    )
    scan.add_argument("--no-exploit-db", action="store_true", help="skip SearchSploit correlation")
    scan.add_argument("--no-nvd", action="store_true", help="skip NVD CVE correlation")
    scan.add_argument("--web-enum", action="store_true", help="run bounded Gobuster enumeration on discovered web services")
    scan.add_argument("--wordlist", help="wordlist used only with --web-enum")
    scan.add_argument("--max-triage-services", type=int, default=50)
    scan.add_argument("--max-cves", type=int, default=5)
    scan.add_argument("--max-exploits", type=int, default=20)
    scan.add_argument("--nmap-timeout", type=int, default=900)
    scan.add_argument("--web-timeout", type=int, default=180)
    scan.add_argument("--output", default="rne_report.json")
    scan.set_defaults(handler=_handle_scan)

    mirror = subparsers.add_parser(
        "mirror",
        help="copy one explicitly selected Exploit-DB entry into a local workspace; does not execute it",
    )
    mirror.add_argument("--edb-id", required=True, help="numeric Exploit-DB ID")
    mirror.add_argument("--workspace", default="exploit_workspace", help="destination directory")
    mirror.add_argument(
        "--confirm-mirror",
        action="store_true",
        help="confirm that you intentionally want to copy the selected public exploit into the workspace",
    )
    mirror.set_defaults(handler=_handle_mirror)
    return parser


def _handle_status(args: argparse.Namespace) -> int:
    del args
    for name, available in toolchain_status().items():
        print(f"{name}: {'available' if available else 'missing'}")
    return 0


def _handle_scan(args: argparse.Namespace) -> int:
    policy = ScopePolicy(authorized=args.authorized, allow_public=args.allow_public)
    options = OrchestrationOptions(
        profile=args.profile,
        nse_vuln=args.nse_vuln,
        use_exploit_db=not args.no_exploit_db,
        use_nvd=not args.no_nvd,
        web_enum=args.web_enum,
        wordlist=args.wordlist,
        max_triage_services=args.max_triage_services,
        max_cves_per_service=args.max_cves,
        max_exploits_per_service=args.max_exploits,
        nmap_timeout=args.nmap_timeout,
        gobuster_timeout=args.web_timeout,
    )
    try:
        report = run_assessment(args.target, policy=policy, options=options)
        output = _write_report(args.output, report.to_dict())
    except (RuntimeError, ValueError) as exc:
        print(f"RnE error: {exc}")
        return 2

    print(f"Target: {report.target}")
    print(f"Profile: {report.profile}")
    print(f"Open services: {len(report.services)}")
    print(f"Report: {output}")
    if report.warnings:
        print("Warnings:")
        for warning in report.warnings:
            print(f"- {warning}")
    return 0


def _handle_mirror(args: argparse.Namespace) -> int:
    if not args.confirm_mirror:
        print("Refusing mirror: pass --confirm-mirror after reviewing the selected EDB-ID.")
        return 2
    try:
        copied, _command = mirror_exploit(args.edb_id, args.workspace)
    except (RuntimeError, ValueError) as exc:
        print(f"RnE error: {exc}")
        return 2
    print(f"Mirrored Exploit-DB entry to: {copied}")
    print("No exploit was executed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
