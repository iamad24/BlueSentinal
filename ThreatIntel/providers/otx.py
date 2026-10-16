
import ipaddress

import requests

from ThreatIntel.providers.base import ThreatIntelProvider


class OTXProvider(ThreatIntelProvider):
    BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

    @property
    def name(self) -> str:
        return "AlienVault OTX"

    def lookup(self, indicator: str, indicator_type: str) -> dict:
        api_key = self.config.otx_api_key

        if not api_key:
            return self.result(
                indicator, indicator_type,
                error="OTX API key is not configured."
            )

        indicator = indicator.strip()
        indicator_type = indicator_type.lower().strip()

        paths = {
            "ip": "IPv4",
            "domain": "domain",
            "url": "url",
            "hash": "file",
        }

        if indicator_type not in paths:
            return self.result(
                indicator, indicator_type,
                error="Unsupported indicator type."
            )

        try:
            if indicator_type == "ip":
                indicator = str(ipaddress.ip_address(indicator))

            response = requests.get(
                f"{self.BASE_URL}/{paths[indicator_type]}/{indicator}/general",
                headers={"X-OTX-API-KEY": api_key},
                timeout=self.config.request_timeout,
            )

            if response.status_code == 404:
                return self.result(
                    indicator, indicator_type,
                    verdict="unknown",
                    details={"message": "Indicator not found in OTX."},
                )

            if response.status_code == 429:
                return self.result(
                    indicator, indicator_type,
                    error="OTX rate limit reached."
                )

            response.raise_for_status()
            payload = response.json()

            pulse_info = payload.get("pulse_info", {})
            count = int(pulse_info.get("count", 0))
            pulses = pulse_info.get("pulses", [])

            if count >= self.config.otx_malicious_pulses:
                verdict = "malicious"
            elif count >= self.config.otx_suspicious_pulses:
                verdict = "suspicious"
            else:
                verdict = "clean"

            return self.result(
                indicator,
                indicator_type,
                verdict=verdict,
                score=None,
                details={
                    "pulse_count": count,
                    "pulses": [
                        {
                            "name": pulse.get("name"),
                            "created": pulse.get("created"),
                            "tags": pulse.get("tags", []),
                        }
                        for pulse in pulses[:10]
                    ],
                },
            )

        except ValueError:
            return self.result(
                indicator, indicator_type,
                error="Invalid indicator value."
            )
        except requests.RequestException as exc:
            return self.result(
                indicator, indicator_type,
                error=f"OTX request failed: {type(exc).__name__}"
            )
