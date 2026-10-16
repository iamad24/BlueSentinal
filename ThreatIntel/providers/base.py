
from abc import ABC, abstractmethod
from typing import Any


class ThreatIntelProvider(ABC):
    """Common interface for BlueSentinel threat-intelligence providers."""

    def __init__(self, config: Any):
        self.config = config

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the provider's name."""
        raise NotImplementedError

    @abstractmethod
    def lookup(self, indicator: str, indicator_type: str) -> dict:
        """Look up an indicator and return a normalized result."""
        raise NotImplementedError

    def result(
        self,
        indicator: str,
        indicator_type: str,
        verdict: str = "unknown",
        score: int | None = None,
        details: dict | None = None,
        error: str | None = None,
    ) -> dict:
        """Create a consistent result format for all providers."""
        return {
            "provider": self.name,
            "indicator": indicator,
            "indicator_type": indicator_type,
            "verdict": verdict,
            "score": score,
            "details": details or {},
            "error": error,
        }

    @staticmethod
    def normalize_verdict(malicious: bool, suspicious: bool = False) -> str:
        if malicious:
            return "malicious"
        if suspicious:
            return "suspicious"
        return "clean"
