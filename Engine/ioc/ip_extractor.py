
"""IP address extraction utilities for BlueSentinel XDR."""

import ipaddress
import re

# Match candidate IPv4 and IPv6 strings; validate them afterward.
IP_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_.])"
    r"(?:[0-9A-Fa-f:.]{3,45})"
    r"(?![A-Za-z0-9_.])"
)


def is_private_ip(value: str) -> bool:
    """Return True for private, loopback, link-local, or reserved IPs."""
    try:
        address = ipaddress.ip_address(value.strip())
        return (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
        )
    except ValueError:
        return False


def extract_ips(
    text: str,
    include_private: bool = True,
) -> list[str]:
    """
    Extract valid IPv4 and IPv6 addresses from text.

    Args:
        text: Text from a normalized security event.
        include_private: Whether to retain private/internal addresses.

    Returns:
        Unique IP addresses in their original order.
    """
    if not isinstance(text, str) or not text:
        return []

    results: list[str] = []
    seen: set[str] = set()

    for match in IP_PATTERN.finditer(text):
        candidate = match.group(0).strip("[](),;")
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue

        normalized = str(address)

        if not include_private and is_private_ip(normalized):
            continue

        if normalized not in seen:
            seen.add(normalized)
            results.append(normalized)

    return results
