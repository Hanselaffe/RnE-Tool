from __future__ import annotations

import json
import shutil
import subprocess
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from .models import CveCandidate, ExploitCandidate, ServiceFinding, WebFinding

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_MAX_OUTPUT_CHARS = 2_000_000

NMAP_PROFILES: dict[str, list[str]] = {
    "quick": ["-sV", "--version-light", "-T3", "--top-ports", "100"],
    "standard": ["-sV", "-T3", "--top-ports", "1000"],
    "deep": ["-sV", "-T3", "-p-"],
}


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def toolchain_status() -> dict[str, bool]:
    return {name: tool_available(name) for name in ("nmap", "searchsploit", "gobuster")}


def _run(command: list[str], *, timeout: int, cwd: str | Path | None = None) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd) if cwd is not None else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"required tool was not found: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"tool timed out after {timeout} seconds: {command[0]}") from exc

    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    if len(stdout) > _MAX_OUTPUT_CHARS or len(stderr) > _MAX_OUTPUT_CHARS:
        raise RuntimeError(f"tool output exceeded the {_MAX_OUTPUT_CHARS}-character safety bound: {command[0]}")
    if completed.returncode != 0:
        message = stderr.strip() or stdout.strip() or f"exit code {completed.returncode}"
        raise RuntimeError(f"{command[0]} failed: {message[:1000]}")
    return completed


def build_nmap_command(target: str, profile: str, *, nse_vuln: bool = False) -> list[str]:
    if profile not in NMAP_PROFILES:
        raise ValueError(f"unknown Nmap profile: {profile}")
    command = ["nmap", *NMAP_PROFILES[profile]]
    if nse_vuln:
        command.extend(["--script", "vuln"])
    command.extend(["-oX", "-", target])
    return command


def parse_nmap_xml(xml_text: str) -> list[ServiceFinding]:
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
                state="open",
                service=service.attrib.get("name", "unknown") if service is not None else "unknown",
                product=service.attrib.get("product", "") if service is not None else "",
                version=service.attrib.get("version", "") if service is not None else "",
                tunnel=service.attrib.get("tunnel", "") if service is not None else "",
            )
        )
    return sorted(findings, key=lambda item: (item.protocol, item.port))


def run_nmap(target: str, profile: str, *, nse_vuln: bool = False, timeout: int = 900) -> tuple[list[ServiceFinding], list[str]]:
    command = build_nmap_command(target, profile, nse_vuln=nse_vuln)
    completed = _run(command, timeout=timeout)
    return parse_nmap_xml(completed.stdout), command


def _searchsploit_rows(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    rows: list[dict[str, Any]] = []
    for key in ("RESULTS_EXPLOIT", "RESULTS_SHELLCODE"):
        value = payload.get(key, [])
        if isinstance(value, list):
            rows.extend(item for item in value if isinstance(item, dict))
    return rows


def search_exploit_db(service: str, version: str, *, timeout: int = 30, limit: int = 20) -> tuple[list[ExploitCandidate], list[str]]:
    if not 1 <= limit <= 100:
        raise ValueError("exploit result limit must be between 1 and 100")
    terms = [part.strip() for part in (service, version) if part and part.strip()]
    if not terms:
        return [], []
    command = ["searchsploit", "-j", *terms]
    completed = _run(command, timeout=timeout)
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("searchsploit returned invalid JSON") from exc

    candidates: list[ExploitCandidate] = []
    for row in _searchsploit_rows(payload)[:limit]:
        edb_id = str(row.get("EDB-ID") or row.get("EDB_ID") or "").strip()
        title = str(row.get("Title") or row.get("TITLE") or "").strip()
        path = str(row.get("Path") or row.get("PATH") or "").strip()
        if not edb_id and path:
            stem = Path(path).stem
            edb_id = stem if stem.isdigit() else ""
        if not edb_id and not title:
            continue
        candidates.append(
            ExploitCandidate(
                edb_id=edb_id,
                title=title,
                path=path,
                type=str(row.get("Type") or row.get("TYPE") or ""),
                platform=str(row.get("Platform") or row.get("PLATFORM") or ""),
            )
        )
    return candidates, command


def mirror_exploit(edb_id: str, workspace: str | Path, *, timeout: int = 30) -> tuple[Path, list[str]]:
    normalized_id = edb_id.strip()
    if not normalized_id.isdigit() or not 1 <= len(normalized_id) <= 10:
        raise ValueError("EDB-ID must be a numeric Exploit-DB identifier")
    destination = Path(workspace).expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    before = {path.name for path in destination.iterdir() if path.is_file()}
    command = ["searchsploit", "-m", normalized_id]
    _run(command, timeout=timeout, cwd=destination)
    created = [path for path in destination.iterdir() if path.is_file() and path.name not in before]
    if len(created) != 1:
        raise RuntimeError("searchsploit mirror did not create exactly one new file in the workspace")
    return created[0], command


def _english_description(cve: dict[str, Any]) -> str:
    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            return str(item.get("value", ""))
    return ""


def parse_nvd_response(payload: dict[str, Any], *, limit: int = 5) -> list[CveCandidate]:
    results: list[CveCandidate] = []
    for wrapper in payload.get("vulnerabilities", []):
        if not isinstance(wrapper, dict):
            continue
        cve = wrapper.get("cve", {})
        if not isinstance(cve, dict):
            continue
        cve_id = str(cve.get("id", "")).strip()
        if not cve_id:
            continue
        results.append(
            CveCandidate(
                cve_id=cve_id,
                description=_english_description(cve),
                published=str(cve.get("published", "")),
                last_modified=str(cve.get("lastModified", "")),
            )
        )
        if len(results) >= limit:
            break
    return results


def search_nvd(service: str, version: str, *, limit: int = 5, timeout: int = 15) -> list[CveCandidate]:
    if not 1 <= limit <= 10:
        raise ValueError("NVD result limit must be between 1 and 10")
    keyword = " ".join(part.strip() for part in (service, version) if part and part.strip())
    if not keyword:
        return []
    query = urllib.parse.urlencode({"keywordSearch": keyword, "resultsPerPage": limit})
    request = urllib.request.Request(
        f"{NVD_CVE_API}?{query}",
        headers={"User-Agent": "RnE-Tool/2026-mini-legion-r2"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.load(response)
    except Exception as exc:
        raise RuntimeError("NVD lookup failed") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("NVD returned an unexpected response")
    return parse_nvd_response(payload, limit=limit)


def build_web_url(target: str, finding: ServiceFinding) -> str:
    secure = finding.service.lower() == "https" or finding.tunnel.lower() == "ssl" or finding.port in {443, 8443}
    scheme = "https" if secure else "http"
    default_port = 443 if secure else 80
    suffix = "" if finding.port == default_port else f":{finding.port}"
    host = f"[{target}]" if ":" in target else target
    return f"{scheme}://{host}{suffix}/"


def run_gobuster(url: str, wordlist: str | Path, *, timeout: int = 180, threads: int = 5) -> tuple[list[WebFinding], list[str]]:
    if not 1 <= threads <= 10:
        raise ValueError("gobuster threads must be between 1 and 10")
    wordlist_path = Path(wordlist).expanduser().resolve()
    if not wordlist_path.is_file():
        raise ValueError("web wordlist does not exist")
    command = [
        "gobuster",
        "dir",
        "-u",
        url,
        "-w",
        str(wordlist_path),
        "--threads",
        str(threads),
        "--timeout",
        "10s",
        "--no-progress",
        "--no-error",
        "--quiet",
    ]
    completed = _run(command, timeout=timeout)
    findings = [WebFinding(url=url, output_line=line.strip()) for line in completed.stdout.splitlines() if line.strip()]
    return findings[:500], command
