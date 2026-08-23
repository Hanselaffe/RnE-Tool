"""RnE - read-only reconnaissance and CVE triage.

The 2026 maintenance refresh intentionally removes exploit execution and
automated exploit materialization. Active scanning requires explicit operator
acknowledgement and uses conservative fixed Nmap arguments.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import subprocess
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass(frozen=True)
class ServiceFinding:
    port: int
    protocol: str
    service: str
    product: str
    version: str


def validate_target(target: str, *, allow_public: bool = False) -> str:
    """Validate a literal IP target and fail closed on public addresses by default."""
    try:
        address = ipaddress.ip_address(target.strip())
    except ValueError as exc:
        raise ValueError("target must be a literal IPv4 or IPv6 address") from exc

    if address.is_unspecified or address.is_multicast:
        raise ValueError("unspecified and multicast targets are not supported")
    if address.is_global and not allow_public:
        raise ValueError("public targets require --allow-public in addition to --authorized")
    return str(address)


def parse_nmap_xml(xml_text: str) -> list[ServiceFinding]:
    """Parse open TCP/UDP services from Nmap XML output."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"invalid Nmap XML: {exc}") from exc

    findings: list[ServiceFinding] = []
    for port in root.findall(".//port"):
        state = port.find("state")
        if state is None or state.attrib.get("state") != "open":
            continue
        service = port.find("service")
        findings.append(
            ServiceFinding(
                port=int(port.attrib["portid"]),
                protocol=port.attrib.get("protocol", "unknown"),
                service=(service.attrib.get("name", "unknown") if service is not None else "unknown"),
                product=(service.attrib.get("product", "") if service is not None else ""),
                version=(service.attrib.get("version", "") if service is not None else ""),
            )
        )
    return sorted(findings, key=lambda item: (item.protocol, item.port))


def run_nmap_scan(target: str, *, allow_public: bool = False, timeout: int = 300) -> list[ServiceFinding]:
    """Run a conservative read-only service inventory against an authorized target."""
    normalized_target = validate_target(target, allow_public=allow_public)
    command = [
        "nmap",
        "-sV",
        "--version-light",
        "-T3",
        "--top-ports",
        "100",
        "-oX",
        "-",
        normalized_target,
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("nmap executable was not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"nmap timed out after {timeout} seconds") from exc

    if completed.returncode != 0:
        message = completed.stderr.strip() or f"nmap exited with code {completed.returncode}"
        raise RuntimeError(message)
    return parse_nmap_xml(completed.stdout)


def _english_description(cve: dict[str, Any]) -> str:
    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            return str(item.get("value", ""))
    return ""


def parse_nvd_response(payload: dict[str, Any], *, limit: int = 5) -> list[dict[str, str]]:
    """Extract a compact read-only CVE summary from an NVD API 2.0 response."""
    results: list[dict[str, str]] = []
    for wrapper in payload.get("vulnerabilities", []):
        cve = wrapper.get("cve", {})
        cve_id = str(cve.get("id", "")).strip()
        if not cve_id:
            continue
        results.append({"id": cve_id, "description": _english_description(cve)})
        if len(results) >= limit:
            break
    return results


def search_nvd(service: str, version: str, *, limit: int = 5, timeout: int = 15) -> list[dict[str, str]]:
    """Query NVD API 2.0 for a small keyword-based CVE triage result."""
    if not 1 <= limit <= 10:
        raise ValueError("limit must be between 1 and 10")
    keyword = " ".join(part for part in (service.strip(), version.strip()) if part)
    if not keyword:
        return []

    query = urllib.parse.urlencode({"keywordSearch": keyword, "resultsPerPage": limit})
    request = urllib.request.Request(
        f"{NVD_CVE_API}?{query}",
        headers={"User-Agent": "RnE-Tool/2026-maintenance"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.load(response)
    except Exception as exc:  # network/library errors are normalized for the CLI boundary
        raise RuntimeError(f"NVD request failed: {exc}") from exc
    return parse_nvd_response(payload, limit=limit)


def build_report(
    target: str,
    findings: list[ServiceFinding],
    cve_results: dict[str, list[dict[str, str]]],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "target": target,
        "services": [asdict(item) for item in findings],
        "cve_triage": cve_results,
        "note": "Read-only reconnaissance/CVE triage. No exploit execution or exploitation claim.",
    }


def save_report(path: str | Path, report: dict[str, Any]) -> Path:
    output = Path(path).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Authorized read-only service inventory and NVD CVE triage")
    parser.add_argument("target", help="literal IPv4 or IPv6 address")
    parser.add_argument("--authorized", action="store_true", help="confirm you are authorized to scan the target")
    parser.add_argument("--allow-public", action="store_true", help="permit a public IP target after authorization")
    parser.add_argument("--max-cves", type=int, default=5, help="maximum NVD results per detected service (1-10)")
    parser.add_argument("--output", default="scan_results.json", help="JSON output path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.authorized:
        print("Refusing active scan: pass --authorized only when you have permission for the target.")
        return 2

    try:
        target = validate_target(args.target, allow_public=args.allow_public)
        findings = run_nmap_scan(target, allow_public=args.allow_public)
        cve_results: dict[str, list[dict[str, str]]] = {}
        for finding in findings:
            key = f"{finding.protocol}/{finding.port} {finding.service}".strip()
            try:
                cve_results[key] = search_nvd(finding.product or finding.service, finding.version, limit=args.max_cves)
            except RuntimeError as exc:
                cve_results[key] = [{"id": "NVD_LOOKUP_FAILED", "description": str(exc)}]
        output = save_report(args.output, build_report(target, findings, cve_results))
    except (RuntimeError, ValueError) as exc:
        print(f"RnE error: {exc}")
        return 2

    print(f"Saved read-only report to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
