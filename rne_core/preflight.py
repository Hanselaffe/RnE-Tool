"""Local, non-network toolchain preflight for RnE external adapters."""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Iterable

_PROBE_TIMEOUT_SECONDS = 8
_MAX_PROBE_CHARS = 200_000


@dataclass(frozen=True)
class ToolDiagnostic:
    name: str
    installed: bool
    path: str = ""
    version: str = "unknown"
    ready: bool = False
    capabilities: dict[str, bool] = field(default_factory=dict)
    issues: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _probe(command: list[str], *, timeout: int = _PROBE_TIMEOUT_SECONDS) -> tuple[int, str]:
    """Run one local metadata/help probe without invoking a shell."""
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, f"{type(exc).__name__}: {exc}"

    output = "\n".join(part for part in (completed.stdout or "", completed.stderr or "") if part)
    if len(output) > _MAX_PROBE_CHARS:
        output = output[:_MAX_PROBE_CHARS]
    return int(completed.returncode), output


def _contains_all(output: str, tokens: Iterable[str]) -> dict[str, bool]:
    return {token: token in output for token in tokens}


def _extract_version(output: str, patterns: Iterable[str]) -> str:
    for pattern in patterns:
        match = re.search(pattern, output, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return "unknown"


def _missing_issues(capabilities: dict[str, bool]) -> tuple[str, ...]:
    missing = [name for name, available in capabilities.items() if not available]
    if not missing:
        return ()
    return ("missing required CLI capabilities: " + ", ".join(missing),)


def diagnose_nmap() -> ToolDiagnostic:
    path = shutil.which("nmap")
    if not path:
        return ToolDiagnostic(name="nmap", installed=False, issues=("executable not found on PATH",))

    version_rc, version_output = _probe([path, "--version"])
    help_rc, help_output = _probe([path, "--help"])
    capabilities = {
        "service_detection_-sV": "-sV" in help_output,
        "version_light_--version-light": "--version-light" in help_output,
        "top_ports_--top-ports": "--top-ports" in help_output,
        "xml_stdout_-oX": "-oX" in help_output,
        "ipv6_-6": "-6" in help_output,
        "nse_--script": "--script" in help_output,
    }
    issues = list(_missing_issues(capabilities))
    if version_rc != 0:
        issues.append("nmap --version probe failed")
    if help_rc != 0:
        issues.append("nmap --help probe failed")
    version = _extract_version(version_output, (r"Nmap version\s+([^\s]+)",))
    return ToolDiagnostic(
        name="nmap",
        installed=True,
        path=path,
        version=version,
        ready=not issues,
        capabilities=capabilities,
        issues=tuple(issues),
    )


def diagnose_searchsploit() -> ToolDiagnostic:
    path = shutil.which("searchsploit")
    if not path:
        return ToolDiagnostic(name="searchsploit", installed=False, issues=("executable not found on PATH",))

    help_rc, help_output = _probe([path, "-h"])
    capabilities = {
        "json_-j": "-j" in help_output or "--json" in help_output,
        "mirror_-m": "-m" in help_output or "--mirror" in help_output,
    }
    issues = list(_missing_issues(capabilities))
    if help_rc != 0:
        issues.append("searchsploit -h probe failed")
    version = _extract_version(
        help_output,
        (
            r"SearchSploit(?:\s+version|\s+v)?\s*([0-9]+(?:\.[0-9]+)+)",
            r"Exploit-DB[^\n]*?([0-9]+(?:\.[0-9]+)+)",
        ),
    )
    return ToolDiagnostic(
        name="searchsploit",
        installed=True,
        path=path,
        version=version,
        ready=not issues,
        capabilities=capabilities,
        issues=tuple(issues),
    )


def diagnose_gobuster() -> ToolDiagnostic:
    path = shutil.which("gobuster")
    if not path:
        return ToolDiagnostic(name="gobuster", installed=False, issues=("executable not found on PATH",))

    version_rc, version_output = _probe([path, "version"])
    help_rc, help_output = _probe([path, "dir", "--help"])
    capabilities = {
        "dir_subcommand": "Usage:" in help_output or "dir" in help_output.lower(),
        "url_-u": "-u" in help_output or "--url" in help_output,
        "wordlist_-w": "-w" in help_output or "--wordlist" in help_output,
        "threads_--threads": "--threads" in help_output,
        "timeout_--timeout": "--timeout" in help_output,
        "no_progress_--no-progress": "--no-progress" in help_output,
        "no_error_--no-error": "--no-error" in help_output,
        "quiet_--quiet": "--quiet" in help_output,
    }
    issues = list(_missing_issues(capabilities))
    if version_rc != 0:
        issues.append("gobuster version probe failed")
    if help_rc != 0:
        issues.append("gobuster dir --help probe failed")
    version = _extract_version(
        version_output,
        (
            r"gobuster(?:\s+version|\s+v)?\s*([0-9]+(?:\.[0-9]+)+)",
            r"v([0-9]+(?:\.[0-9]+)+)",
        ),
    )
    return ToolDiagnostic(
        name="gobuster",
        installed=True,
        path=path,
        version=version,
        ready=not issues,
        capabilities=capabilities,
        issues=tuple(issues),
    )


def toolchain_diagnostics() -> dict[str, ToolDiagnostic]:
    """Return detailed local readiness information for every external adapter."""
    diagnostics = (diagnose_nmap(), diagnose_searchsploit(), diagnose_gobuster())
    return {item.name: item for item in diagnostics}
