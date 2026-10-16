import os
from dotenv import load_dotenv
from dataclasses import dataclass, field

load_dotenv()


@dataclass
class TIConfig:
    """Configuration for external threat-intelligence providers."""

    virustotal_api_key: str | None = field(
        default_factory=lambda: os.getenv("VIRUSTOTAL_API_KEY")
    )

    abuseipdb_api_key: str | None = field(
        default_factory=lambda: os.getenv("ABUSEIPDB_API_KEY")
    )

    otx_api_key: str | None = field(
        default_factory=lambda: os.getenv("OTX_API_KEY")
    )

    request_timeout: int = 10
    cache_ttl_seconds: int = 3600
    abuseipdb_max_age_days: int = 90

    # VirusTotal verdict threshold
    vt_malicious_engines: int = 3

    # AbuseIPDB confidence thresholds
    abuse_malicious_score: int = 75
    abuse_suspicious_score: int = 25

    # AlienVault OTX pulse thresholds
    otx_malicious_pulses: int = 5
    otx_suspicious_pulses: int = 1

    def __post_init__(self):
        if self.request_timeout <= 0:
            raise ValueError("request_timeout must be positive.")

        if self.cache_ttl_seconds < 0:
            raise ValueError("cache_ttl_seconds cannot be negative.")

        if not 1 <= self.abuseipdb_max_age_days <= 365:
            raise ValueError(
                "abuseipdb_max_age_days must be between 1 and 365."
            )

        if not 0 <= self.abuse_malicious_score <= 100:
            raise ValueError(
                "abuse_malicious_score must be between 0 and 100."
            )

        if not 0 <= self.abuse_suspicious_score <= 100:
            raise ValueError(
                "abuse_suspicious_score must be between 0 and 100."
            )
