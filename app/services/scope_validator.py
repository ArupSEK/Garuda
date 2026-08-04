"""Authorization scope validation and expansion."""

import ipaddress
from collections.abc import Iterable

from app.core.exceptions import ScopeValidationError


def parse_public_network(value: str, *, max_cidr_prefix: int = 24) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ScopeValidationError(f"Malformed IPv4 address or CIDR: {value}") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise ScopeValidationError("Version 1 accepts public IPv4 targets only")
    if network.prefixlen < max_cidr_prefix:
        raise ScopeValidationError(f"CIDR is larger than the configured maximum /{max_cidr_prefix}")
    for address in (network.network_address, network.broadcast_address):
        blocked = (
            not address.is_global
            or address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
        )
        if blocked:
            raise ScopeValidationError(f"Non-public network is not allowed: {value}")
    return network


def expand_targets(values: Iterable[str], *, max_cidr_prefix: int = 24, max_targets: int = 256) -> list[str]:
    targets: set[ipaddress.IPv4Address] = set()
    for raw in values:
        for item in raw.replace(",", "\n").splitlines():
            item = item.strip()
            if not item or item.startswith("#"):
                continue
            network = parse_public_network(item, max_cidr_prefix=max_cidr_prefix)
            addresses = [network.network_address] if network.prefixlen == 32 else list(network.hosts())
            targets.update(addresses)
            if len(targets) > max_targets:
                raise ScopeValidationError(f"Target count exceeds configured maximum of {max_targets}")
    if not targets:
        raise ScopeValidationError("At least one public IPv4 target is required")
    return [str(address) for address in sorted(targets)]


def enforce_engagement_scope(
    targets: Iterable[str],
    approved_scope: Iterable[str],
    exclusions: Iterable[str] = (),
    *,
    max_cidr_prefix: int = 24,
) -> None:
    approved = [parse_public_network(item, max_cidr_prefix=max_cidr_prefix) for item in approved_scope]
    excluded = [ipaddress.ip_network(item.strip(), strict=False) for item in exclusions if item.strip()]
    for target in targets:
        address = ipaddress.ip_address(target)
        if not any(address in network for network in approved):
            raise ScopeValidationError(f"Target is outside the approved engagement scope: {target}")
        if any(address in network for network in excluded):
            raise ScopeValidationError(f"Target is explicitly excluded from the engagement: {target}")
