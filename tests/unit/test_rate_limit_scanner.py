"""Unit tests for RateLimitScanner."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent_security_scanner.modules.misconfig_submodules.rate_limit_scanner import (
    RateLimitScanner,
    RateLimitScannerConfig,
)
from agent_security_scanner.modules.base import Finding, ScanResult, Severity


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------


class TestRateLimitScannerConfig:
    def test_default_values(self):
        config = RateLimitScannerConfig()
        assert config.enabled is True
        assert config.test_rate_limiting_headers is True
        assert config.test_429_responses is True
        assert config.test_rate_limit_bypass is True
        assert config.test_token_bucket is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = RateLimitScannerConfig(
            enabled=False,
            test_rate_limiting_headers=False,
            test_429_responses=False,
            test_rate_limit_bypass=False,
            test_token_bucket=False,
            compliance_threshold=0.8,
            request_delay=1.0,
        )
        assert config.enabled is False
        assert config.test_rate_limiting_headers is False
        assert config.compliance_threshold == 0.8
        assert config.request_delay == 1.0

    def test_no_dead_check_flags(self):
        """Ensure no legacy check_* flags exist."""
        config = RateLimitScannerConfig()
        for attr in dir(config):
            if attr.startswith("check_"):
                pytest.fail(f"Dead config flag found: {attr}")


# ---------------------------------------------------------------------------
# Scanner init tests
# ---------------------------------------------------------------------------


class TestRateLimitScanner:
    def test_init_default_config(self):
        scanner = RateLimitScanner()
        assert isinstance(scanner.config, RateLimitScannerConfig)
        assert scanner.config.enabled is True

    def test_init_custom_config(self):
        config = RateLimitScannerConfig(enabled=False)
        scanner = RateLimitScanner(config=config)
        assert scanner.config.enabled is False

    def test_module_name(self):
        scanner = RateLimitScanner()
        assert scanner.module_name == "rate_limit"


# ---------------------------------------------------------------------------
# Per-check method tests
# ---------------------------------------------------------------------------


class TestRateLimitHeaders:
    @pytest.mark.asyncio
    async def test_missing_headers_creates_finding(self):
        scanner = RateLimitScanner(config=RateLimitScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        mock_response = {
            "status": 200,
            "headers": {"Content-Type": "application/json"},
            "body": "OK",
        }

        with patch.object(scanner, "_fetch_url", return_value=mock_response):
            await scanner._check_rate_limit_headers(
                "http://test.com", MagicMock(), result
            )

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.MEDIUM
        assert result.findings[0].cwe == "CWE-770"
        assert result.findings[0].owasp_ref == "OWASP API4:2019 - Lack of Resources & Rate Limiting"
        assert result.findings[0].mitre_ref == "MITRE ATLAS - TA0045 LLM Attack"

    @pytest.mark.asyncio
    async def test_headers_present_no_finding(self):
        scanner = RateLimitScanner(config=RateLimitScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        mock_response = {
            "status": 200,
            "headers": {
                "X-RateLimit-Limit": "100",
                "X-RateLimit-Remaining": "99",
            },
            "body": "OK",
        }

        with patch.object(scanner, "_fetch_url", return_value=mock_response):
            await scanner._check_rate_limit_headers(
                "http://test.com", MagicMock(), result
            )

        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_skip_when_disabled(self):
        scanner = RateLimitScanner(
            config=RateLimitScannerConfig(test_rate_limiting_headers=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_rate_limit_headers(
            "http://test.com", MagicMock(), result
        )

        assert len(result.findings) == 0


class Test429Responses:
    @pytest.mark.asyncio
    async def test_no_rate_limiting_creates_finding(self):
        scanner = RateLimitScanner(config=RateLimitScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        # All 10 requests return 200 (no rate limiting)
        mock_response = {
            "status": 200,
            "headers": {},
            "body": "OK",
        }

        with patch.object(scanner, "_fetch_url", return_value=mock_response):
            await scanner._check_429_responses(
                "http://test.com", MagicMock(), result
            )

        assert len(result.findings) == 1
        assert result.findings[0].cwe == "CWE-770"
        assert result.findings[0].owasp_ref == "OWASP API4:2019 - Lack of Resources & Rate Limiting"
        assert result.findings[0].mitre_ref == "MITRE ATLAS - TA0045 LLM Attack"

    @pytest.mark.asyncio
    async def test_skip_when_disabled(self):
        scanner = RateLimitScanner(
            config=RateLimitScannerConfig(test_429_responses=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_429_responses(
            "http://test.com", MagicMock(), result
        )

        assert len(result.findings) == 0


class TestRateLimitBypass:
    @pytest.mark.asyncio
    async def test_bypass_success_creates_finding(self):
        scanner = RateLimitScanner(config=RateLimitScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        mock_response = {
            "status": 200,
            "headers": {},
            "body": "OK",
        }

        with patch.object(scanner, "_fetch_url", return_value=mock_response):
            await scanner._check_rate_limit_bypass(
                "http://test.com", MagicMock(), result
            )

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.LOW
        assert result.findings[0].cwe == "CWE-770"
        assert result.findings[0].owasp_ref == "OWASP API4:2019 - Lack of Resources & Rate Limiting"
        assert result.findings[0].mitre_ref == "MITRE ATLAS - TA0045 LLM Attack"

    @pytest.mark.asyncio
    async def test_skip_when_disabled(self):
        scanner = RateLimitScanner(
            config=RateLimitScannerConfig(test_rate_limit_bypass=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_rate_limit_bypass(
            "http://test.com", MagicMock(), result
        )

        assert len(result.findings) == 0


class TestTokenBucketWeakness:
    @pytest.mark.asyncio
    async def test_skip_when_disabled(self):
        scanner = RateLimitScanner(
            config=RateLimitScannerConfig(test_token_bucket=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_token_bucket_weakness(
            "http://test.com", MagicMock(), result
        )

        assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# Scan method tests
# ---------------------------------------------------------------------------


class TestScanMethod:
    def test_scan_disabled(self):
        scanner = RateLimitScanner(config=RateLimitScannerConfig(enabled=False))
        result = scanner.scan("http://test.com")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        scanner = RateLimitScanner(config=RateLimitScannerConfig(request_delay=0))
        with patch.object(scanner, "_check_rate_limit_headers", new_callable=AsyncMock):
            with patch.object(scanner, "_check_429_responses", new_callable=AsyncMock):
                with patch.object(scanner, "_check_rate_limit_bypass", new_callable=AsyncMock):
                    with patch.object(scanner, "_check_token_bucket_weakness", new_callable=AsyncMock):
                        result = scanner.scan("http://test.com")
        assert "test_rate_limiting_headers" in result.metadata


# ---------------------------------------------------------------------------
# Finding creation test
# ---------------------------------------------------------------------------


class TestFindingCreation:
    def test_finding_has_required_fields(self):
        scanner = RateLimitScanner()
        finding = scanner._create_finding(
            severity=Severity.MEDIUM,
            title="Test",
            description="Test description",
            cwe="CWE-770",
            owasp_ref="OWASP API4:2019 - Lack of Resources & Rate Limiting",
            mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
        )
        assert finding.cwe == "CWE-770"
        assert finding.owasp_ref == "OWASP API4:2019 - Lack of Resources & Rate Limiting"
        assert finding.mitre_ref == "MITRE ATLAS - TA0045 LLM Attack"
        assert finding.category == scanner.module_name