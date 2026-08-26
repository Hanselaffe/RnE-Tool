from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class ServiceFinding:
    port: int
    protocol: str
    state: str
    service: str
    product: str
    version: str
    tunnel: str = ""

    @property
    def label(self) -> str:
        product = self.product or self.service or "unknown"
        version = f" {self.version}" if self.version else ""
        return f"{self.protocol}/{self.port} {product}{version}".strip()

    @property
    def is_web(self) -> bool:
        name = (self.service or "").lower()
        tunnel = (self.tunnel or "").lower()
        return name in {"http", "https", "http-proxy", "ssl/http"} or "http" in name or tunnel == "ssl"


@dataclass(frozen=True)
class ExploitCandidate:
    edb_id: str
    title: str
    path: str = ""
    type: str = ""
    platform: str = ""


@dataclass(frozen=True)
class CveCandidate:
    cve_id: str
    description: str
    published: str = ""
    last_modified: str = ""


@dataclass(frozen=True)
class WebFinding:
    url: str
    output_line: str


@dataclass
class RunReport:
    target: str
    profile: str
    services: list[ServiceFinding] = field(default_factory=list)
    exploits: dict[str, list[ExploitCandidate]] = field(default_factory=dict)
    cves: dict[str, list[CveCandidate]] = field(default_factory=dict)
    web_findings: dict[str, list[WebFinding]] = field(default_factory=dict)
    tool_status: dict[str, bool] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    executed_commands: list[list[str]] = field(default_factory=list)
    schema_version: int = 2

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
