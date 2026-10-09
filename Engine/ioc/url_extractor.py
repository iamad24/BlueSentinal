
"""Extract HTTP and HTTPS URLs from security-event text."""

import re

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"'`]+",
    re.IGNORECASE,
)


def extract_urls(text: str) -> list[str]:
    """Return unique HTTP/HTTPS URLs without trailing punctuation."""
    if not isinstance(text, str) or not text:
        return []

    results = []
    seen = set()

    for match in URL_PATTERN.finditer(text):
        url = match.group(0).rstrip(".,;:!?)]}")

        if not url:
            continue

        normalized = url.lower()

        if normalized not in seen:
            seen.add(normalized)
            results.append(url)

    return results
