"""Unit tests for SandboxScanner."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent_security_scanner.modules.tool_boundaries_submodules.sandbox_scanner import (
    SandboxScanner,
    SandboxScannerConfig,
)
from agent_security_scanner.modules.base import Finding, ScanResult, Severity


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------


class TestSandboxScannerConfig:
    def test_default_values(self):
        config = SandboxScannerConfig()
        assert config.enabled is True
        assert config.test_no_sandbox is True
        assert config.test_root_access is True
        assert config.test_resource_limits is True
        assert config.test_network_isolation is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = SandboxScannerConfig(
            enabled=False,
            test_no_sandbox=False,
            test_root_access=False,
            test_resource_limits=False,
            test_network_isolation=False,
            compliance_threshold=0.8,
            request_delay=1.0,
        )
        assert config.enabled is False
        assert config.test_no_sandbox is False
        assert config.compliance_threshold == 0.8
        assert config.request_delay == 1.0

    def test_no_dead_check_flags(self):
        """Ensure no legacy check_* flags exist."""
        config = SandboxScannerConfig()
        for attr in dir(config):
            if attr.startswith("check_"):
                pytest.fail(f"Dead config flag found: {attr}")


# ---------------------------------------------------------------------------
# Scanner init tests
# ---------------------------------------------------------------------------


class TestSandboxScanner:
    def test_init_default_config(self):
        scanner = SandboxScanner()
        assert isinstance(scanner.config, SandboxScannerConfig)
        assert scanner.config.enabled is True

    def test_init_custom_config(self):
        config = SandboxScannerConfig(enabled=False)
        scanner = SandboxScanner(config=config)
        assert scanner.config.enabled is False

    def test_module_name(self):
        scanner = SandboxScanner()
        assert scanner.module_name == "sandbox"


# ---------------------------------------------------------------------------
# Per-check method tests
# ---------------------------------------------------------------------------


class TestNoSandbox:
    @pytest.mark.asyncio
    async def test_no_sandbox_finds_issue(self):
        scanner = SandboxScanner(config=SandboxScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        mock_response = {
            "status": 200,
            "headers": {},
            "body": '{"environment": "production"}',
        }

        with patch.object(scanner, "_fetch_url", return_value=mock_response):
            await scanner._check_no_sandbox(
                "http://test.com", MagicMock(), result, mock_response
            )

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH
        assert result.findings[0].cwe == "CWE-284"
        assert result.findings[0].mitre_ref is not None
        assert result.findings[0].owasp_ref is not None

    @pytest.mark.asyncio
    async def test_no_sandbox_skip_when_disabled(self):
        scanner = SandboxScanner(
            config=SandboxScannerConfig(test_no_sandbox=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_no_sandbox(
            "http://test.com", MagicMock(), result, {"some": "config"}
        )

        assert len(result.findings) == 0


class TestRootAccess:
    @pytest.mark.asyncio
    async def test_root_access_finds_issue(self):
        scanner = SandboxScanner(config=SandboxScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        mock_response = {
            "status": 200,
            "headers": {},
            "body": '{"root": true, "access": "granted"}',
        }

        with patch.object(scanner, "_fetch_url", return_value=mock_response):
            await scanner._check_root_access(
                "http://test.com", MagicMock(), result, mock_response
            )

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH
        assert result.findings[0].cwe == "CWE-284"
        assert result.findings[0].mitre_ref is not None
        assert result.findings[0].owasp_ref is not None

    @pytest.mark.asyncio
    async def test_root_access_skip_when_disabled(self):
        scanner = SandboxScanner(
            config=SandboxScannerConfig(test_root_access=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_root_access(
            "http://test.com", MagicMock(), result, {"root": True, "access": "granted"}
        )

        assert len(result.findings) == 0


class TestResourceLimits:
    @pytest.mark.asyncio
    async def test_resource_limits_finds_issue(self):
        scanner = SandboxScanner(config=SandboxScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        mock_response = {
            "status": 200,
            "headers": {},
            "body": '{"unlimited_memory": true, "unlimited_cpu": true}',
        }

        with patch.object(scanner, "_fetch_url", return_value=mock_response):
            await scanner._check_resource_limits(
                "http://test.com", MagicMock(), result, mock_response
            )

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.MEDIUM
        assert result.findings[0].cwe == "CWE-770"
        assert result.findings[0].mitre_ref is not None
        assert result.findings[0].owasp_ref is not None

    @pytest.mark.asyncio
    async def test_resource_limits_skip_when_disabled(self):
        scanner = SandboxScanner(
            config=SandboxScannerConfig(test_resource_limits=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_resource_limits(
            "http://test.com", MagicMock(), result, {"unlimited_memory": True}
        )

        assert len(result.findings) == 0


class TestNetworkIsolation:
    @pytest.mark.asyncio
    async def test_network_isolation_finds_issue(self):
        scanner = SandboxScanner(config=SandboxScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        mock_response = {
            "status": 200,
            "headers": {},
            "body": '{"network_enabled": true}',
        }

        with patch.object(scanner, "_fetch_url", return_value=mock_response):
            await scanner._check_network_isolation(
                "http://test.com", MagicMock(), result, mock_response
            )

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.MEDIUM
        assert result.findings[0].cwe == "CWE-284"
        assert result.findings[0].mitre_ref is not None
        assert result.findings[0].owasp_ref is not None

    @pytest.mark.asyncio
    async def test_network_isolation_skip_when_disabled(self):
        scanner = SandboxScanner(
            config=SandboxScannerConfig(test_network_isolation=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_network_isolation(
            "http://test.com", MagicMock(), result, {"network_enabled": True}
        )

        assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# Scan method tests
# ---------------------------------------------------------------------------


class TestScanMethod:
    def test_scan_disabled(self):
        scanner = SandboxScanner(config=SandboxScannerConfig(enabled=False))
        result = scanner.scan("http://test.com")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        scanner = SandboxScanner(config=SandboxScannerConfig(request_delay=0))
        with patch.object(scanner, "_check_no_sandbox", new_callable=AsyncMock):
            with patch.object(scanner, "_check_root_access", new_callable=AsyncMock):
                with patch.object(scanner, "_check_resource_limits", new_callable=AsyncMock):
                    with patch.object(scanner, "_check_network_isolation", new_callable=AsyncMock):
                        with patch.object(scanner, "_fetch_url", return_value={"status": 200}):
                            result = scanner.scan("http://test.com")
        assert "test_no_sandbox" in result.metadata


# ---------------------------------------------------------------------------
# Finding creation test
# ---------------------------------------------------------------------------


class TestFindingCreation:
    def test_finding_has_required_fields(self):
        scanner = SandboxScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH,
            title="Test",
            description="Test description",
            cwe="CWE-284",
            owasp_ref="OWASP LLM08:2025 - Excessive Agency",
            mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
        )
        assert finding.cwe == "CWE-284"
        assert finding.owasp_ref == "OWASP LLM08:2025 - Excessive Agency"
        assert finding.mitre_ref == "MITRE ATLAS - TA0045 LLM Attack"
        assert finding.category == scanner.module_name