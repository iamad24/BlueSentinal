
"""
BlueSentinel XDR - IOC Extraction Engine

Extracts indicators from normalized security events.
It identifies indicators; it does not determine whether they
are malicious. Threat Intelligence handles reputation enrichment.
"""

from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import date, datetime
from typing import Any

from .ip_extractor import extract_ips
from .domain_extractor import extract_domains
from .url_extractor import extract_urls
from .hash_extractor import extract_hashes
from .file_registry_extractor import (
    extract_file_paths,
    extract_registry_keys,
    extract_emails,
)


@dataclass
class IOCResult:
    """Indicators extracted from a single security event."""

    event_host: str | None = None
    event_user: str | None = None
    event_timestamp: str | None = None

    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)

    md5_hashes: list[str] = field(default_factory=list)
    sha1_hashes: list[str] = field(default_factory=list)
    sha256_hashes: list[str] = field(default_factory=list)

    file_paths: list[str] = field(default_factory=list)
    registry_keys: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        """Return True if no indicators were found."""
        return not any(
            (
                self.ips,
                self.domains,
                self.urls,
                self.md5_hashes,
                self.sha1_hashes,
                self.sha256_hashes,
                self.file_paths,
                self.registry_keys,
                self.emails,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly dictionary."""
        return asdict(self)


def _event_to_dict(event: Any) -> dict[str, Any]:
    """Accept a Pydantic model, dataclass, or dictionary."""

    if isinstance(event, dict):
        return event

    # Pydantic v2
    if hasattr(event, "model_dump"):
        result = event.model_dump(mode="json")
        if isinstance(result, dict):
            return result

    # Pydantic v1
    if hasattr(event, "dict") and callable(event.dict):
        result = event.dict()
        if isinstance(result, dict):
            return result

    if is_dataclass(event) and not isinstance(event, type):
        return asdict(event)

    if hasattr(event, "to_dict") and callable(event.to_dict):
        result = event.to_dict()
        if isinstance(result, dict):
            return result

    raise TypeError(
        "event must be a dictionary, Pydantic model, or dataclass"
    )


def _flatten_values(value: Any) -> list[str]:
    """Collect searchable text from nested dictionaries and lists."""

    if value is None:
        return []

    if isinstance(value, dict):
        output: list[str] = []
        for item in value.values():
            output.extend(_flatten_values(item))
        return output

    if isinstance(value, (list, tuple, set)):
        output = []
        for item in value:
            output.extend(_flatten_values(item))
        return output

    if isinstance(value, (str, int, float)):
        return [str(value)]

    return []


def _unique(values: list[str]) -> list[str]:
    """Remove duplicates while preserving order."""
    result: list[str] = []
    seen: set[str] = set()

    for value in values:
        if not isinstance(value, str):
            continue

        value = value.strip()
        if value and value not in seen:
            seen.add(value)
            result.append(value)

    return result


def _timestamp_to_string(value: Any) -> str | None:
    """Convert common timestamp types to a serializable string."""

    if value is None:
        return None

    if isinstance(value, (datetime, date)):
        return value.isoformat()

    return str(value)


def _collect_text(event: dict[str, Any]) -> str:
    """
    Collect relevant text from normalized fields and raw telemetry.

    Supports the current SecurityEvent field names, including
    command_line, parent_process, script_block_text and file_hash.
    """

    fields = (
        "process",
        "parent_process",
        "command_line",
        "script_block_text",
        "file_path",
        "file_hash",
        "registry_key",
        "registry_value",
        "source_ip",
        "destination_ip",
        "protocol",
        "raw_event",
    )

    parts: list[str] = []

    for field_name in fields:
        parts.extend(_flatten_values(event.get(field_name)))

    return " ".join(parts)


class IOCExtractor:
    """
    Extract IOCs from BlueSentinel normalized security events.

    Args:
        include_private_ips: Whether private IP addresses should
            be retained by the IP extraction helper.
    """

    def __init__(self, include_private_ips: bool = True):
        self.include_private_ips = include_private_ips

    def extract(self, event: Any) -> IOCResult:
        """Extract indicators from one security event."""

        event_dict = _event_to_dict(event)
        text = _collect_text(event_dict)

        ips = extract_ips(
            text,
            include_private=self.include_private_ips,
        )
        domains = extract_domains(text)
        urls = extract_urls(text)
        hashes = extract_hashes(text)
        file_paths = extract_file_paths(text)
        registry_keys = extract_registry_keys(text)
        emails = extract_emails(text)

        # Preserve indicators already parsed into structured fields.
        for field_name in ("source_ip", "destination_ip"):
            value = event_dict.get(field_name)
            if isinstance(value, str) and value.strip():
                ips.append(value.strip())

        # The current SecurityEvent model has one generic file_hash.
        # Algorithm-specific fields are also supported if supplied by
        # a future telemetry source.
        hash_fields = {
            "md5": ("file_hash_md5",),
            "sha1": ("file_hash_sha1",),
            "sha256": ("file_hash_sha256",),
        }

        generic_hash = event_dict.get("file_hash")
        if isinstance(generic_hash, str):
            candidate = generic_hash.strip()
            if len(candidate) in (32, 40, 64):
                algorithm = {
                    32: "md5",
                    40: "sha1",
                    64: "sha256",
                }[len(candidate)]

                if all(c in "0123456789abcdefABCDEF" for c in candidate):
                    hashes.setdefault(algorithm, []).append(candidate)

        for algorithm, field_names in hash_fields.items():
            for field_name in field_names:
                value = event_dict.get(field_name)
                if isinstance(value, str) and value.strip():
                    hashes.setdefault(algorithm, []).append(value.strip())

        # Keep explicit file and registry fields even if a helper's
        # pattern does not recognize their formatting.
        file_path = event_dict.get("file_path")
        if isinstance(file_path, str) and file_path.strip():
            file_paths.append(file_path.strip())

        registry_key = event_dict.get("registry_key")
        if isinstance(registry_key, str) and registry_key.strip():
            registry_keys.append(registry_key.strip())

        return IOCResult(
            event_host=event_dict.get("host"),
            event_user=event_dict.get("user"),
            event_timestamp=_timestamp_to_string(
                event_dict.get("timestamp")
            ),
            ips=_unique(ips),
            domains=_unique(domains),
            urls=_unique(urls),
            md5_hashes=_unique(hashes.get("md5", [])),
            sha1_hashes=_unique(hashes.get("sha1", [])),
            sha256_hashes=_unique(hashes.get("sha256", [])),
            file_paths=_unique(file_paths),
            registry_keys=_unique(registry_keys),
            emails=_unique(emails),
        )

    def extract_batch(self, events: list[Any]) -> list[IOCResult]:
        """Extract indicators from multiple events."""
        return [self.extract(event) for event in events]
