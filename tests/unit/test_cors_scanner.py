"""Unit tests for CORSScanner."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from singularity.modules.misconfig_submodules.cors_scanner import (
    CORSScanner,
    CORSScannerConfig,
)
from singularity.modules.base import Finding, ScanResult, Severity


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------


class TestCORSScannerConfig:
    def test_default_values(self):
        config = CORSScannerConfig()
        assert config.enabled is True
        assert config.test_wildcard_origin is True
        assert config.test_credentials_with_wildcard is True
        assert config.test_preflight is True
        assert config.test_allowed_methods is True
        assert config.test_allowed_headers is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = CORSScannerConfig(
            enabled=False,
            test_wildcard_origin=False,
            test_credentials_with_wildcard=False,
            test_preflight=False,
            test_allowed_methods=False,
            test_allowed_headers=False,
            compliance_threshold=0.8,
            request_delay=1.0,
        )
        assert config.enabled is False
        assert config.test_wildcard_origin is False
        assert config.compliance_threshold == 0.8
        assert config.request_delay == 1.0

    def test_no_dead_check_flags(self):
        """Ensure no legacy check_* flags exist."""
        config = CORSScannerConfig()
        for attr in dir(config):
            if attr.startswith("check_"):
                pytest.fail(f"Dead config flag found: {attr}")


# ---------------------------------------------------------------------------
# Scanner init tests
# ---------------------------------------------------------------------------


class TestCORSScanner:
    def test_init_default_config(self):
        scanner = CORSScanner()
        assert isinstance(scanner.config, CORSScannerConfig)
        assert scanner.config.enabled is True

    def test_init_custom_config(self):
        config = CORSScannerConfig(enabled=False)
        scanner = CORSScanner(config=config)
        assert scanner.config.enabled is False

    def test_module_name(self):
        scanner = CORSScanner()
        assert scanner.module_name == "cors"


# ---------------------------------------------------------------------------
# Per-check method tests
# ---------------------------------------------------------------------------


class TestWildcardOrigin:
    @pytest.mark.asyncio
    async def test_wildcard_with_credentials_finds_critical(self):
        scanner = CORSScanner(config=CORSScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        mock_response = {
            "status": 200,
            "headers": {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
            "body": "OK",
        }

        with patch.object(scanner, "_fetch_url", return_value=mock_response):
            await scanner._check_wildcard_origin(
                "http://test.com", MagicMock(), result
            )

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.CRITICAL
        assert result.findings[0].cwe == "CWE-942"
        assert result.findings[0].owasp_ref is not None
        assert result.findings[0].mitre_ref is not None

    @pytest.mark.asyncio
    async def test_wildcard_without_credentials_finds_low(self):
        scanner = CORSScanner(config=CORSScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        mock_response = {
            "status": 200,
            "headers": {
                "Access-Control-Allow-Origin": "*",
            },
            "body": "OK",
        }

        with patch.object(scanner, "_fetch_url", return_value=mock_response):
            await scanner._check_wildcard_origin(
                "http://test.com", MagicMock(), result
            )

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.LOW

    @pytest.mark.asyncio
    async def test_skip_when_disabled(self):
        scanner = CORSScanner(
            config=CORSScannerConfig(test_wildcard_origin=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_wildcard_origin(
            "http://test.com", MagicMock(), result
        )

        assert len(result.findings) == 0


class TestCredentialsWithWildcard:
    @pytest.mark.asyncio
    async def test_credentials_with_wildcard_creates_finding(self):
        scanner = CORSScanner(config=CORSScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        mock_preflight = {
            "url": "http://test.com",
            "status": 200,
            "headers": {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
        }

        with patch.object(scanner, "_preflight_request", return_value=mock_preflight):
            await scanner._check_credentials_with_wildcard(
                "http://test.com", MagicMock(), result
            )

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.CRITICAL
        assert result.findings[0].cwe == "CWE-942"
        assert result.findings[0].mitre_ref is not None

    @pytest.mark.asyncio
    async def test_skip_when_disabled(self):
        scanner = CORSScanner(
            config=CORSScannerConfig(test_credentials_with_wildcard=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_credentials_with_wildcard(
            "http://test.com", MagicMock(), result
        )

        assert len(result.findings) == 0


class TestPreflightManipulation:
    @pytest.mark.asyncio
    async def test_origin_reflection_creates_finding(self):
        scanner = CORSScanner(config=CORSScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        reflected_origin = "https://example.com"
        mock_preflight = {
            "url": "http://test.com",
            "status": 200,
            "headers": {
                "Access-Control-Allow-Origin": reflected_origin,
            },
        }

        with patch.object(scanner, "_preflight_request", return_value=mock_preflight):
            await scanner._check_preflight_manipulation(
                "http://test.com", MagicMock(), result
            )

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.MEDIUM
        assert result.findings[0].cwe == "CWE-942"
        assert result.findings[0].owasp_ref is not None
        assert result.findings[0].mitre_ref is not None

    @pytest.mark.asyncio
    async def test_skip_when_disabled(self):
        scanner = CORSScanner(
            config=CORSScannerConfig(test_preflight=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_preflight_manipulation(
            "http://test.com", MagicMock(), result
        )

        assert len(result.findings) == 0


class TestOverlyPermissiveMethods:
    @pytest.mark.asyncio
    async def test_delete_allowed_creates_finding(self):
        scanner = CORSScanner(config=CORSScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        mock_preflight = {
            "url": "http://test.com",
            "status": 200,
            "headers": {
                "Access-Control-Allow-Methods": "GET, POST, DELETE",
            },
        }

        with patch.object(scanner, "_preflight_request", return_value=mock_preflight):
            await scanner._check_overly_permissive_methods(
                "http://test.com", MagicMock(), result
            )

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH
        assert result.findings[0].cwe == "CWE-942"
        assert result.findings[0].mitre_ref is not None

    @pytest.mark.asyncio
    async def test_skip_when_disabled(self):
        scanner = CORSScanner(
            config=CORSScannerConfig(test_allowed_methods=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_overly_permissive_methods(
            "http://test.com", MagicMock(), result
        )

        assert len(result.findings) == 0


class TestMissingCORSHeaders:
    @pytest.mark.asyncio
    async def test_missing_cors_creates_finding(self):
        scanner = CORSScanner(config=CORSScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        mock_response = {
            "status": 200,
            "headers": {"Content-Type": "text/html"},
            "body": "OK",
        }

        with patch.object(scanner, "_fetch_url", return_value=mock_response):
            await scanner._check_missing_cors_headers(
                "http://test.com", MagicMock(), result
            )

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.INFO
        assert result.findings[0].cwe == "CWE-942"
        assert result.findings[0].owasp_ref is not None
        assert result.findings[0].mitre_ref is not None

    @pytest.mark.asyncio
    async def test_skip_when_disabled(self):
        scanner = CORSScanner(
            config=CORSScannerConfig(test_allowed_headers=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_missing_cors_headers(
            "http://test.com", MagicMock(), result
        )

        assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# Scan method tests
# ---------------------------------------------------------------------------


class TestScanMethod:
    def test_scan_disabled(self):
        scanner = CORSScanner(config=CORSScannerConfig(enabled=False))
        result = scanner.scan("http://test.com")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        scanner = CORSScanner(config=CORSScannerConfig(request_delay=0))
        with patch.object(scanner, "_check_wildcard_origin", new_callable=AsyncMock):
            with patch.object(scanner, "_check_credentials_with_wildcard", new_callable=AsyncMock):
                with patch.object(scanner, "_check_preflight_manipulation", new_callable=AsyncMock):
                    with patch.object(scanner, "_check_overly_permissive_methods", new_callable=AsyncMock):
                        with patch.object(scanner, "_check_missing_cors_headers", new_callable=AsyncMock):
                            result = scanner.scan("http://test.com")
        assert "test_wildcard_origin" in result.metadata


# ---------------------------------------------------------------------------
# Finding creation test
# ---------------------------------------------------------------------------


class TestFindingCreation:
    def test_finding_has_required_fields(self):
        scanner = CORSScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH,
            title="Test",
            description="Test description",
            cwe="CWE-942",
            owasp_ref="OWASP API8:2019 - Security Misconfiguration",
            mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
        )
        assert finding.cwe == "CWE-942"
        assert finding.owasp_ref == "OWASP API8:2019 - Security Misconfiguration"
        assert finding.mitre_ref == "MITRE ATLAS - TA0045 LLM Attack"
        assert finding.category == scanner.module_name