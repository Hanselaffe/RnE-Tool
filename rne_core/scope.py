from __future__ import annotations

import ipaddress
from dataclasses import dataclass


@dataclass(frozen=True)
class ScopePolicy:
    authorized: bool
    allow_public: bool = False

    def require_active_authorization(self) -> None:
        if not self.authorized:
            raise ValueError("active assessment requires explicit --authorized confirmation")


def validate_target(target: str, policy: ScopePolicy) -> str:
    """Return a normalized literal IP after applying the active-scope policy."""
    policy.require_active_authorization()
    try:
        address = ipaddress.ip_address(target.strip())
    except ValueError as exc:
        raise ValueError("target must be a literal IPv4 or IPv6 address") from exc

    if address.is_unspecified or address.is_multicast:
        raise ValueError("unspecified and multicast targets are not supported")
    if address.is_global and not policy.allow_public:
        raise ValueError("public targets require --allow-public in addition to --authorized")
    return str(address)
