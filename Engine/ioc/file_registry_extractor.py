
"""Extract file paths, registry keys, and email addresses."""

import re


EMAIL_PATTERN = re.compile(
    r"(?i)(?<![A-Z0-9._%+-])"
    r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}"
    r"(?![A-Z0-9_-])"
)

WINDOWS_PATH_PATTERN = re.compile(
    r"(?i)(?<![A-Z0-9_])"
    r"(?:[A-Z]:\\|\\\\)"
    r"""[^\s<>"|?*]+"""
)

UNIX_PATH_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"/(?:[A-Za-z0-9._@+-]+/)*"
    r"[A-Za-z0-9._@+-]+"
)

REGISTRY_PATTERN = re.compile(
    r"(?i)\b(?:"
    r"HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|"
    r"HKEY_CLASSES_ROOT|HKEY_USERS|"
    r"HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC"
    r")\\[^\s,;\"']+"
)


def _unique(values: list[str]) -> list[str]:
    """Remove duplicate values while preserving order."""
    output = []
    seen = set()

    for value in values:
        value = value.strip().rstrip(".,;:!?)")

        if value and value.lower() not in seen:
            seen.add(value.lower())
            output.append(value)

    return output


def extract_file_paths(text: str) -> list[str]:
    """Extract candidate Windows and Unix file paths."""
    if not isinstance(text, str) or not text:
        return []

    paths = WINDOWS_PATH_PATTERN.findall(text)
    paths.extend(UNIX_PATH_PATTERN.findall(text))

    return _unique(paths)


def extract_registry_keys(text: str) -> list[str]:
    """Extract common Windows registry key paths."""
    if not isinstance(text, str) or not text:
        return []

    return _unique(REGISTRY_PATTERN.findall(text))


def extract_emails(text: str) -> list[str]:
    """Extract email address candidates."""
    if not isinstance(text, str) or not text:
        return []

    return _unique(EMAIL_PATTERN.findall(text))
