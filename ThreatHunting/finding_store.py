
"""In-memory storage for threat hunting findings."""

from copy import deepcopy
from threading import RLock
from typing import Any


class FindingStore:
    """Thread-safe in-memory finding store."""

    def __init__(self) -> None:
        self._findings: dict[str, dict[str, Any]] = {}
        self._lock = RLock()

    def add(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Add or replace a finding by ID."""
        if not isinstance(finding, dict):
            raise TypeError("finding must be a dictionary")

        finding_id = finding.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id.strip():
            raise ValueError("finding must contain a non-empty finding_id")

        saved = deepcopy(finding)

        with self._lock:
            self._findings[finding_id] = saved
            return deepcopy(saved)

    def get(self, finding_id: str) -> dict[str, Any] | None:
        """Return a finding, or None if it does not exist."""
        with self._lock:
            finding = self._findings.get(finding_id)
            return deepcopy(finding) if finding is not None else None

    def list_all(self) -> list[dict[str, Any]]:
        """Return all findings, newest inserted first."""
        with self._lock:
            return [
                deepcopy(finding)
                for finding in reversed(list(self._findings.values()))
            ]

    def list_by_severity(self, severity: str) -> list[dict[str, Any]]:
        """Filter findings by severity, case-insensitively."""
        normalized = severity.strip().lower()
        return [
            finding
            for finding in self.list_all()
            if str(finding.get("severity", "")).lower() == normalized
        ]

    def update_status(
        self,
        finding_id: str,
        status: str,
    ) -> dict[str, Any] | None:
        """Update the investigation status of an existing finding."""
        if not status or not status.strip():
            raise ValueError("status must not be empty")

        with self._lock:
            finding = self._findings.get(finding_id)
            if finding is None:
                return None

            finding["status"] = status.strip()
            return deepcopy(finding)

    def delete(self, finding_id: str) -> bool:
        """Delete a finding. Return False if it does not exist."""
        with self._lock:
            return self._findings.pop(finding_id, None) is not None

    def clear(self) -> None:
        """Remove all stored findings."""
        with self._lock:
            self._findings.clear()
