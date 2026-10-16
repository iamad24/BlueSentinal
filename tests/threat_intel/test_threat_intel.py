
from unittest.mock import patch

import pytest

from ThreatIntel.config import TIConfig
from ThreatIntel.enricher import ThreatIntelEnricher
from ThreatIntel.providers.abuseipdb import AbuseIPDBProvider
from ThreatIntel.providers.otx import OTXProvider
from ThreatIntel.providers.virustotal import VirusTotalProvider


def test_invalid_ip_is_rejected():
    enricher = ThreatIntelEnricher(TIConfig())

    with pytest.raises(ValueError):
        enricher.enrich("999.999.999.999", "ip")


def test_invalid_hash_is_rejected():
    enricher = ThreatIntelEnricher(TIConfig())

    with pytest.raises(ValueError):
        enricher.enrich("not-a-hash", "hash")


def test_domain_is_normalized():
    enricher = ThreatIntelEnricher(TIConfig())

    assert enricher.normalize_indicator(
        "Example.COM.", "domain"
    ) == "example.com"


def test_missing_virustotal_key():
    config = TIConfig(virustotal_api_key=None)
    provider = VirusTotalProvider(config)

    result = provider.lookup("8.8.8.8", "ip")

    assert result["error"] is not None
    assert result["verdict"] == "unknown"


def test_abuseipdb_rejects_domains():
    provider = AbuseIPDBProvider(TIConfig())

    result = provider.lookup("example.com", "domain")

    assert result["error"] is not None


def test_missing_otx_key():
    provider = OTXProvider(TIConfig(otx_api_key=None))

    result = provider.lookup("8.8.8.8", "ip")

    assert result["error"] is not None


def test_malicious_result_from_one_provider():
    enricher = ThreatIntelEnricher(TIConfig())

    fake_results = [
        {
            "provider": "VirusTotal",
            "indicator": "8.8.8.8",
            "indicator_type": "ip",
            "verdict": "malicious",
            "score": 80,
            "details": {},
            "error": None,
        },
        {
            "provider": "AbuseIPDB",
            "indicator": "8.8.8.8",
            "indicator_type": "ip",
            "verdict": "clean",
            "score": 0,
            "details": {},
            "error": None,
        },
        {
            "provider": "AlienVault OTX",
            "indicator": "8.8.8.8",
            "indicator_type": "ip",
            "verdict": "unknown",
            "score": None,
            "details": {},
            "error": "Not found",
        },
    ]

    for provider, fake_result in zip(enricher.providers, fake_results):
        with patch.object(provider, "lookup", return_value=fake_result):
            pass

    with patch.object(
        enricher.providers[0], "lookup", return_value=fake_results[0]
    ), patch.object(
        enricher.providers[1], "lookup", return_value=fake_results[1]
    ), patch.object(
        enricher.providers[2], "lookup", return_value=fake_results[2]
    ):
        result = enricher.enrich("8.8.8.8", "ip")

    assert result["verdict"] == "malicious"
    assert result["providers_successful"] == 2


def test_cache_returns_previous_result():
    enricher = ThreatIntelEnricher(TIConfig(cache_ttl_seconds=60))

    fake = {
        "provider": "Test",
        "indicator": "8.8.8.8",
        "indicator_type": "ip",
        "verdict": "clean",
        "score": 0,
        "details": {},
        "error": None,
    }

    with patch.object(
        enricher.providers[0], "lookup", return_value=fake
    ) as first, patch.object(
        enricher.providers[1], "lookup", return_value=fake
    ), patch.object(
        enricher.providers[2], "lookup", return_value=fake
    ):
        first_result = enricher.enrich("8.8.8.8", "ip")
        second_result = enricher.enrich("8.8.8.8", "ip")

    assert first_result["cached"] is False
    assert second_result["cached"] is True


def test_enrich_many_handles_invalid_indicator():
    enricher = ThreatIntelEnricher(TIConfig())

    results = enricher.enrich_many([
        {"type": "ip", "value": "invalid-ip"}
    ])

    assert len(results) == 1
    assert results[0]["verdict"] == "unknown"
    assert "error" in results[0]


def test_unsupported_indicator_type():
    enricher = ThreatIntelEnricher(TIConfig())

    with pytest.raises(ValueError):
        enricher.enrich("sample", "email")
