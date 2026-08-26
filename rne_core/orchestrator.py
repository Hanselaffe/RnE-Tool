from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .models import RunReport
from .scope import ScopePolicy, validate_target
from .tools import (
    build_web_url,
    run_gobuster,
    run_nmap,
    search_exploit_db,
    search_nvd,
    toolchain_status,
)


@dataclass(frozen=True)
class OrchestrationOptions:
    profile: str = "standard"
    nse_vuln: bool = False
    use_exploit_db: bool = True
    use_nvd: bool = True
    web_enum: bool = False
    wordlist: str | Path | None = None
    max_triage_services: int = 50
    max_cves_per_service: int = 5
    max_exploits_per_service: int = 20
    nmap_timeout: int = 900
    gobuster_timeout: int = 180

    def validate(self) -> None:
        if self.profile not in {"quick", "standard", "deep"}:
            raise ValueError("profile must be quick, standard, or deep")
        if not 1 <= self.max_triage_services <= 100:
            raise ValueError("max_triage_services must be between 1 and 100")
        if not 1 <= self.max_cves_per_service <= 10:
            raise ValueError("max_cves_per_service must be between 1 and 10")
        if not 1 <= self.max_exploits_per_service <= 100:
            raise ValueError("max_exploits_per_service must be between 1 and 100")
        if not 30 <= self.nmap_timeout <= 3600:
            raise ValueError("nmap_timeout must be between 30 and 3600 seconds")
        if not 30 <= self.gobuster_timeout <= 600:
            raise ValueError("gobuster_timeout must be between 30 and 600 seconds")
        if self.web_enum and self.wordlist is None:
            raise ValueError("--web-enum requires --wordlist")


def run_assessment(
    target: str,
    *,
    policy: ScopePolicy,
    options: OrchestrationOptions,
) -> RunReport:
    """Run the bounded RnE orchestration pipeline for one authorized IP target."""
    options.validate()
    normalized_target = validate_target(target, policy)
    report = RunReport(target=normalized_target, profile=options.profile)
    report.tool_status = toolchain_status()

    services, nmap_command = run_nmap(
        normalized_target,
        options.profile,
        nse_vuln=options.nse_vuln,
        timeout=options.nmap_timeout,
    )
    report.executed_commands.append(nmap_command)
    report.services = services

    triage_services = services[: options.max_triage_services]
    if len(services) > len(triage_services):
        report.warnings.append(
            f"triage limited to the first {len(triage_services)} of {len(services)} discovered services"
        )

    searchsploit_available = report.tool_status.get("searchsploit", False)
    gobuster_available = report.tool_status.get("gobuster", False)
    if options.use_exploit_db and not searchsploit_available:
        report.warnings.append("SearchSploit not available; Exploit-DB correlation skipped")
    if options.web_enum and not gobuster_available:
        report.warnings.append("Gobuster not available; requested web enumeration skipped")

    for finding in triage_services:
        key = finding.label
        search_name = finding.product or finding.service

        if options.use_exploit_db and searchsploit_available:
            try:
                candidates, command = search_exploit_db(
                    search_name,
                    finding.version,
                    limit=options.max_exploits_per_service,
                )
                report.executed_commands.append(command)
                report.exploits[key] = candidates
            except RuntimeError as exc:
                report.exploits[key] = []
                report.warnings.append(f"SearchSploit failed for {key}: {exc}")

        if options.use_nvd:
            try:
                report.cves[key] = search_nvd(
                    search_name,
                    finding.version,
                    limit=options.max_cves_per_service,
                )
            except RuntimeError as exc:
                report.cves[key] = []
                report.warnings.append(f"NVD lookup failed for {key}: {exc}")

        if options.web_enum and finding.is_web and gobuster_available:
            url = build_web_url(normalized_target, finding)
            try:
                web_findings, command = run_gobuster(
                    url,
                    options.wordlist or "",
                    timeout=options.gobuster_timeout,
                )
                report.executed_commands.append(command)
                report.web_findings[key] = web_findings
            except (RuntimeError, ValueError) as exc:
                report.web_findings[key] = []
                report.warnings.append(f"web enumeration failed for {key}: {exc}")

    report.warnings = list(dict.fromkeys(report.warnings))
    return report
