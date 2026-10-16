
import hashlib
import ipaddress
import threading
import time
from urllib.parse import urlparse

from ThreatIntel.config import TIConfig
from ThreatIntel.providers.abuseipdb import AbuseIPDBProvider
from ThreatIntel.providers.otx import OTXProvider
from ThreatIntel.providers.virustotal import VirusTotalProvider


class ThreatIntelEnricher:
    """Enrich indicators with external threat-intelligence sources."""

    def __init__(self, config: TIConfig | None = None):
        self.config = config or TIConfig()

        self.providers = [
            VirusTotalProvider(self.config),
            AbuseIPDBProvider(self.config),
            OTXProvider(self.config),
        ]

        self._cache = {}
        self._cache_lock = threading.Lock()

    @staticmethod
    def normalize_indicator(indicator: str, indicator_type: str) -> str:
        value = indicator.strip()
        kind = indicator_type.lower().strip()

        if not value:
            raise ValueError("Indicator cannot be empty.")

        if kind == "ip":
            return str(ipaddress.ip_address(value))

        if kind == "domain":
            value = value.rstrip(".").lower()
            if not value or "/" in value or " " in value:
                raise ValueError("Invalid domain indicator.")
            return value

        if kind == "url":
            parsed = urlparse(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("URL must be an absolute HTTP or HTTPS URL.")
            return value

        if kind == "hash":
            normalized = value.lower()
            if len(normalized) not in {32, 40, 64}:
                raise ValueError("Hash must be an MD5, SHA-1, or SHA-256 hash.")
            if any(char not in "0123456789abcdef" for char in normalized):
                raise ValueError("Hash contains invalid hexadecimal characters.")
            return normalized

        raise ValueError("Indicator type must be ip, domain, url, or hash.")

    def _cache_key(self, indicator: str, indicator_type: str) -> str:
        raw = f"{indicator_type}:{indicator}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def enrich(self, indicator: str, indicator_type: str) -> dict:
        """Query all configured providers and return combined results."""
        indicator_type = indicator_type.lower().strip()
        indicator = self.normalize_indicator(indicator, indicator_type)
        cache_key = self._cache_key(indicator, indicator_type)
        now = time.time()

        with self._cache_lock:
            cached = self._cache.get(cache_key)
            if cached and now - cached["timestamp"] < self.config.cache_ttl_seconds:
                result = dict(cached["result"])
                result["cached"] = True
                return result

        results = [
            provider.lookup(indicator, indicator_type)
            for provider in self.providers
        ]

        successful = [
            result for result in results
            if result.get("error") is None
        ]

        verdicts = [result["verdict"] for result in successful]
        if "malicious" in verdicts:
            overall_verdict = "malicious"
        elif "suspicious" in verdicts:
            overall_verdict = "suspicious"
        elif "clean" in verdicts:
            overall_verdict = "clean"
        else:
            overall_verdict = "unknown"

        numeric_scores = [
            result["score"]
            for result in successful
            if isinstance(result.get("score"), (int, float))
        ]

        combined = {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "verdict": overall_verdict,
            "score": max(numeric_scores) if numeric_scores else None,
            "providers_queried": len(results),
            "providers_successful": len(successful),
            "provider_results": results,
            "cached": False,
        }

        # Cache results only when at least one provider returned data.
        if successful and self.config.cache_ttl_seconds > 0:
            with self._cache_lock:
                self._cache[cache_key] = {
                    "timestamp": time.time(),
                    "result": combined,
                }

        return combined

    def enrich_many(self, indicators: list[dict]) -> list[dict]:
        """Enrich a list such as [{'type': 'ip', 'value': '1.2.3.4'}]."""
        results = []

        for item in indicators:
            value = item.get("value")
            kind = item.get("type")

            if not isinstance(value, str) or not isinstance(kind, str):
                results.append({
                    "indicator": value,
                    "indicator_type": kind,
                    "verdict": "unknown",
                    "error": "Each item must contain string 'value' and 'type'.",
                })
                continue

            try:
                results.append(self.enrich(value, kind))
            except ValueError as exc:
                results.append({
                    "indicator": value,
                    "indicator_type": kind,
                    "verdict": "unknown",
                    "error": str(exc),
                })

        return results

    def clear_cache(self) -> None:
        """Clear the in-memory cache."""
        with self._cache_lock:
            self._cache.clear()
