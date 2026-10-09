
"""Extract domain names from security-event text."""

import ipaddress
import re

DOMAIN_PATTERN = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])"
    r"(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+"
    r"[A-Z]{2,63}\.?"
    r"(?![A-Za-z0-9_-])"
)


def extract_domains(text: str) -> list[str]:
    """Return unique domain names in their original order."""
    if not isinstance(text, str) or not text:
        return []

    results = []
    seen = set()

    for match in DOMAIN_PATTERN.finditer(text):
        domain = match.group(0).rstrip(".").lower()

        try:
            ipaddress.ip_address(domain)
            continue
        except ValueError:
            pass

        if len(domain) > 253:
            continue

        if domain not in seen:
            seen.add(domain)
            results.append(domain)

    return results
