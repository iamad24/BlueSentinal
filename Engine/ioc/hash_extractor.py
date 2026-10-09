
"""Extract MD5, SHA-1, and SHA-256 hash candidates."""

import re

HASH_PATTERN = re.compile(
    r"(?i)(?<![0-9a-f])"
    r"(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})"
    r"(?![0-9a-f])"
)


def extract_hashes(text: str) -> dict[str, list[str]]:
    """
    Extract hexadecimal hash candidates from text.

    Returns:
        {
            "md5": [...],
            "sha1": [...],
            "sha256": [...]
        }

    Note: Hash length identifies a candidate format, not
    proof of which algorithm generated the value.
    """
    results = {
        "md5": [],
        "sha1": [],
        "sha256": [],
    }

    if not isinstance(text, str) or not text:
        return results

    seen = {
        "md5": set(),
        "sha1": set(),
        "sha256": set(),
    }

    for match in HASH_PATTERN.finditer(text):
        value = match.group(0).lower()

        if len(value) == 32:
            algorithm = "md5"
        elif len(value) == 40:
            algorithm = "sha1"
        else:
            algorithm = "sha256"

        if value not in seen[algorithm]:
            seen[algorithm].add(value)
            results[algorithm].append(value)

    return results
