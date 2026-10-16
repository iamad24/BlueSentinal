
import ipaddress

import requests

from ThreatIntel.providers.base import ThreatIntelProvider


class AbuseIPDBProvider(ThreatIntelProvider):
    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    @property
    def name(self) -> str:
        return "AbuseIPDB"

    def lookup(self, indicator: str, indicator_type: str) -> dict:
        if indicator_type.lower() != "ip":
            return self.result(
                indicator, indicator_type,
                error="AbuseIPDB supports IP addresses only."
            )

        api_key = self.config.abuseipdb_api_key
        if not api_key:
            return self.result(
                indicator, indicator_type,
                error="AbuseIPDB API key is not configured."
            )

        try:
            address = str(ipaddress.ip_address(indicator.strip()))

            response = requests.get(
                self.BASE_URL,
                headers={
                    "Key": api_key,
                    "Accept": "application/json",
                },
                params={
                    "ipAddress": address,
                    "maxAgeInDays": self.config.abuseipdb_max_age_days,
                },
                timeout=self.config.request_timeout,
            )

            if response.status_code == 429:
                return self.result(
                    address, "ip",
                    error="AbuseIPDB rate limit reached."
                )

            response.raise_for_status()
            data = response.json().get("data", {})
            score = int(data.get("abuseConfidenceScore", 0))

            if score >= self.config.abuse_malicious_score:
                verdict = "malicious"
            elif score >= self.config.abuse_suspicious_score:
                verdict = "suspicious"
            else:
                verdict = "clean"

            return self.result(
                address,
                "ip",
                verdict=verdict,
                score=score,
                details={
                    "country_code": data.get("countryCode"),
                    "usage_type": data.get("usageType"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "total_reports": data.get("totalReports", 0),
                    "last_reported_at": data.get("lastReportedAt"),
                    "is_public": data.get("isPublic"),
                },
            )

        except ValueError:
            return self.result(
                indicator, "ip",
                error="Invalid IP address."
            )
        except requests.RequestException as exc:
            return self.result(
                indicator, "ip",
                error=f"AbuseIPDB request failed: {type(exc).__name__}"
            )
