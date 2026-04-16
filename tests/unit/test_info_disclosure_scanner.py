"""Unit tests for InfoDisclosureScanner."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent_security_scanner.modules.misconfig_submodules.info_disclosure_scanner import (
    InfoDisclosureScanner,
    InfoDisclosureScannerConfig,
)
from agent_security_scanner.modules.base import Finding, ScanResult, Severity


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------


class TestInfoDisclosureScannerConfig:
    def test_default_values(self):
        config = InfoDisclosureScannerConfig()
        assert config.enabled is True
        assert config.test_stack_traces is True
        assert config.test_debug_mode is True
        assert config.test_version_info is True
        assert config.test_internal_paths is True
        assert config.test_server_banner is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = InfoDisclosureScannerConfig(
            enabled=False,
            test_stack_traces=False,
            test_debug_mode=False,
            test_version_info=False,
            test_internal_paths=False,
            test_server_banner=False,
            compliance_threshold=0.8,
            request_delay=1.0,
        )
        assert config.enabled is False
        assert config.test_stack_traces is False
        assert config.compliance_threshold == 0.8
        assert config.request_delay == 1.0

    def test_no_dead_check_flags(self):
        """Ensure no legacy check_* flags exist."""
        config = InfoDisclosureScannerConfig()
        for attr in dir(config):
            if attr.startswith("check_"):
                pytest.fail(f"Dead config flag found: {attr}")


# ---------------------------------------------------------------------------
# Scanner init tests
# ---------------------------------------------------------------------------


class TestInfoDisclosureScanner:
    def test_init_default_config(self):
        scanner = InfoDisclosureScanner()
        assert isinstance(scanner.config, InfoDisclosureScannerConfig)
        assert scanner.config.enabled is True

    def test_init_custom_config(self):
        config = InfoDisclosureScannerConfig(enabled=False)
        scanner = InfoDisclosureScanner(config=config)
        assert scanner.config.enabled is False

    def test_module_name(self):
        scanner = InfoDisclosureScanner()
        assert scanner.module_name == "info_disclosure"


# ---------------------------------------------------------------------------
# Per-check method tests
# ---------------------------------------------------------------------------


class TestCheckStackTraces:
    @pytest.mark.asyncio
    async def test_stack_trace_creates_finding(self):
        scanner = InfoDisclosureScanner(config=InfoDisclosureScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        mock_response = {
            "status": 500,
            "headers": {},
            "body": "Traceback (most recent call last):\nFile \"app.py\", line 42",
        }

        with patch.object(scanner, "_fetch_url", return_value=mock_response):
            await scanner._check_stack_traces(
                "http://test.com", MagicMock(), result
            )

        assert len(result.findings) >= 1
        assert result.findings[0].severity == Severity.HIGH
        assert result.findings[0].cwe == "CWE-209"
        assert result.findings[0].mitre_ref is not None

    @pytest.mark.asyncio
    async def test_stack_trace_skip_when_disabled(self):
        scanner = InfoDisclosureScanner(
            config=InfoDisclosureScannerConfig(test_stack_traces=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_stack_traces(
            "http://test.com", MagicMock(), result
        )

        assert len(result.findings) == 0


class TestCheckDebugMode:
    @pytest.mark.asyncio
    async def test_debug_mode_creates_finding(self):
        scanner = InfoDisclosureScanner(config=InfoDisclosureScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        mock_response = {
            "status": 200,
            "headers": {},
            "body": "DEBUG mode is enabled for this application",
        }

        with patch.object(scanner, "_fetch_url", return_value=mock_response):
            await scanner._check_debug_mode(
                "http://test.com", MagicMock(), result
            )

        assert len(result.findings) >= 1
        assert result.findings[0].severity == Severity.MEDIUM
        assert result.findings[0].cwe == "CWE-489"
        assert result.findings[0].mitre_ref is not None

    @pytest.mark.asyncio
    async def test_debug_mode_skip_when_disabled(self):
        scanner = InfoDisclosureScanner(
            config=InfoDisclosureScannerConfig(test_debug_mode=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_debug_mode(
            "http://test.com", MagicMock(), result
        )

        assert len(result.findings) == 0


class TestCheckVersionInfo:
    @pytest.mark.asyncio
    async def test_version_info_creates_finding(self):
        scanner = InfoDisclosureScanner(config=InfoDisclosureScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        mock_response = {
            "status": 200,
            "headers": {},
            "body": "version 2.1.0 build 1234",
        }

        with patch.object(scanner, "_fetch_url", return_value=mock_response):
            await scanner._check_version_info(
                "http://test.com", MagicMock(), result
            )

        assert len(result.findings) >= 1
        assert result.findings[0].severity == Severity.LOW
        assert result.findings[0].cwe == "CWE-200"
        assert result.findings[0].mitre_ref is not None

    @pytest.mark.asyncio
    async def test_version_info_skip_when_disabled(self):
        scanner = InfoDisclosureScanner(
            config=InfoDisclosureScannerConfig(test_version_info=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_version_info(
            "http://test.com", MagicMock(), result
        )

        assert len(result.findings) == 0


class TestCheckInternalPaths:
    @pytest.mark.asyncio
    async def test_internal_paths_creates_finding(self):
        scanner = InfoDisclosureScanner(config=InfoDisclosureScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        mock_response = {
            "status": 200,
            "headers": {},
            "body": "DB_PASSWORD=secret",
        }

        with patch.object(scanner, "_fetch_url", return_value=mock_response):
            await scanner._check_internal_paths(
                "http://test.com", MagicMock(), result
            )

        assert len(result.findings) >= 1
        assert result.findings[0].severity == Severity.HIGH
        assert result.findings[0].cwe == "CWE-200"
        assert result.findings[0].mitre_ref is not None

    @pytest.mark.asyncio
    async def test_internal_paths_skip_when_disabled(self):
        scanner = InfoDisclosureScanner(
            config=InfoDisclosureScannerConfig(test_internal_paths=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_internal_paths(
            "http://test.com", MagicMock(), result
        )

        assert len(result.findings) == 0


class TestCheckServerBanner:
    @pytest.mark.asyncio
    async def test_server_banner_creates_finding(self):
        scanner = InfoDisclosureScanner(config=InfoDisclosureScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        mock_response = {
            "status": 200,
            "headers": {"Server": "Apache/2.4.41", "X-Powered-By": "PHP/7.4.3"},
            "body": "OK",
        }

        with patch.object(scanner, "_fetch_url", return_value=mock_response):
            await scanner._check_server_banner(
                "http://test.com", MagicMock(), result
            )

        assert len(result.findings) >= 1
        assert result.findings[0].severity == Severity.LOW
        assert result.findings[0].cwe == "CWE-200"
        assert result.findings[0].mitre_ref is not None

    @pytest.mark.asyncio
    async def test_server_banner_skip_when_disabled(self):
        scanner = InfoDisclosureScanner(
            config=InfoDisclosureScannerConfig(test_server_banner=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_server_banner(
            "http://test.com", MagicMock(), result
        )

        assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# Scan method tests
# ---------------------------------------------------------------------------


class TestScanMethod:
    def test_scan_disabled(self):
        scanner = InfoDisclosureScanner(config=InfoDisclosureScannerConfig(enabled=False))
        result = scanner.scan("http://test.com")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        scanner = InfoDisclosureScanner(config=InfoDisclosureScannerConfig(request_delay=0))
        with patch.object(scanner, "_check_stack_traces", new_callable=AsyncMock):
            with patch.object(scanner, "_check_debug_mode", new_callable=AsyncMock):
                with patch.object(scanner, "_check_version_info", new_callable=AsyncMock):
                    with patch.object(scanner, "_check_internal_paths", new_callable=AsyncMock):
                        with patch.object(scanner, "_check_server_banner", new_callable=AsyncMock):
                            result = scanner.scan("http://test.com")
        assert "test_stack_traces" in result.metadata


# ---------------------------------------------------------------------------
# Finding creation test
# ---------------------------------------------------------------------------


class TestFindingCreation:
    def test_finding_has_required_fields(self):
        scanner = InfoDisclosureScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH,
            title="Test",
            description="Test description",
            cwe="CWE-209",
            owasp_ref="OWASP API5:2019 - Security Misconfiguration",
            mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
        )
        assert finding.cwe == "CWE-209"
        assert finding.owasp_ref == "OWASP API5:2019 - Security Misconfiguration"
        assert finding.mitre_ref == "MITRE ATLAS - TA0045 LLM Attack"
        assert finding.category == scanner.module_name