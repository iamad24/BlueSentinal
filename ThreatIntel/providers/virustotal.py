
import base64
import hashlib
import ipaddress
from urllib.parse import urlparse

import requests

from ThreatIntel.providers.base import ThreatIntelProvider


class VirusTotalProvider(ThreatIntelProvider):
    BASE_URL = "https://www.virustotal.com/api/v3"

    @property
    def name(self) -> str:
        return "VirusTotal"

    def lookup(self, indicator: str, indicator_type: str) -> dict:
        api_key = self.config.virustotal_api_key

        if not api_key:
            return self.result(
                indicator, indicator_type,
                error="VirusTotal API key is not configured."
            )

        indicator = indicator.strip()
        indicator_type = indicator_type.lower().strip()

        try:
            if indicator_type == "ip":
                endpoint = f"/ip_addresses/{indicator}"
            elif indicator_type == "domain":
                endpoint = f"/domains/{indicator}"
            elif indicator_type == "hash":
                endpoint = f"/files/{indicator}"
            elif indicator_type == "url":
                # URL identifier is URL-safe base64 without padding.
                encoded = base64.urlsafe_b64encode(
                    indicator.encode("utf-8")
                ).decode("ascii").rstrip("=")
                endpoint = f"/urls/{encoded}"
            else:
                return self.result(
                    indicator, indicator_type,
                    error="Unsupported indicator type."
                )

            response = requests.get(
                self.BASE_URL + endpoint,
                headers={"x-apikey": api_key},
                timeout=self.config.request_timeout,
            )

            if response.status_code == 404:
                return self.result(
                    indicator, indicator_type,
                    verdict="unknown",
                    details={"message": "Indicator not found in VirusTotal."},
                )

            if response.status_code == 429:
                return self.result(
                    indicator, indicator_type,
                    error="VirusTotal rate limit reached."
                )

            response.raise_for_status()
            payload = response.json()
            attributes = payload.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            total = sum(int(value or 0) for value in stats.values())

            verdict = self.normalize_verdict(
                malicious=malicious >= self.config.vt_malicious_engines,
                suspicious=malicious > 0 or suspicious > 0,
            )

            return self.result(
                indicator,
                indicator_type,
                verdict=verdict,
                score=round((malicious / total) * 100) if total else None,
                details={
                    "malicious_engines": malicious,
                    "suspicious_engines": suspicious,
                    "harmless_engines": int(stats.get("harmless", 0)),
                    "undetected_engines": int(stats.get("undetected", 0)),
                    "analysis_stats": stats,
                },
            )

        except requests.RequestException as exc:
            return self.result(
                indicator, indicator_type,
                error=f"VirusTotal request failed: {type(exc).__name__}"
            )
        except (ValueError, TypeError):
            return self.result(
                indicator, indicator_type,
                error="VirusTotal returned an invalid response."
            )
