"""Unit tests for PermissionScanner."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent_security_scanner.modules.tool_boundaries_submodules.permission_scanner import (
    PermissionScanner,
    PermissionScannerConfig,
)
from agent_security_scanner.modules.base import Finding, ScanResult, Severity


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------


class TestPermissionScannerConfig:
    def test_default_values(self):
        config = PermissionScannerConfig()
        assert config.enabled is True
        assert config.test_admin_mode is True
        assert config.test_unrestricted is True
        assert config.test_trust_all is True
        assert config.test_no_validation is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = PermissionScannerConfig(
            enabled=False,
            test_admin_mode=False,
            test_unrestricted=False,
            test_trust_all=False,
            test_no_validation=False,
            compliance_threshold=0.8,
            request_delay=1.0,
        )
        assert config.enabled is False
        assert config.test_admin_mode is False
        assert config.compliance_threshold == 0.8
        assert config.request_delay == 1.0

    def test_no_dead_check_flags(self):
        """Ensure no legacy check_* flags exist."""
        config = PermissionScannerConfig()
        for attr in dir(config):
            if attr.startswith("check_"):
                pytest.fail(f"Dead config flag found: {attr}")


# ---------------------------------------------------------------------------
# Scanner init tests
# ---------------------------------------------------------------------------


class TestPermissionScanner:
    def test_init_default_config(self):
        scanner = PermissionScanner()
        assert isinstance(scanner.config, PermissionScannerConfig)
        assert scanner.config.enabled is True

    def test_init_custom_config(self):
        config = PermissionScannerConfig(enabled=False)
        scanner = PermissionScanner(config=config)
        assert scanner.config.enabled is False

    def test_module_name(self):
        scanner = PermissionScanner()
        assert scanner.module_name == "permission"


# ---------------------------------------------------------------------------
# Per-check method tests
# ---------------------------------------------------------------------------


class TestCheckAdminMode:
    @pytest.mark.asyncio
    async def test_admin_mode_creates_finding(self):
        scanner = PermissionScanner(config=PermissionScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        config_data = {"admin_mode": True, "developer_mode": False}

        await scanner._check_admin_mode(
            "http://test.com", MagicMock(), result, config_data
        )

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH
        assert result.findings[0].cwe == "CWE-284"
        assert result.findings[0].owasp_ref == "OWASP LLM08:2025 - Excessive Agency"
        assert result.findings[0].mitre_ref == "MITRE ATLAS - TA0045 LLM Attack"

    @pytest.mark.asyncio
    async def test_admin_mode_skip_when_disabled(self):
        scanner = PermissionScanner(
            config=PermissionScannerConfig(test_admin_mode=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_admin_mode(
            "http://test.com", MagicMock(), result, {"admin_mode": True}
        )

        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_admin_mode_skip_when_no_config(self):
        scanner = PermissionScanner(config=PermissionScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_admin_mode(
            "http://test.com", MagicMock(), result, None
        )

        assert len(result.findings) == 0


class TestCheckUnrestrictedAccess:
    @pytest.mark.asyncio
    async def test_unrestricted_creates_finding(self):
        scanner = PermissionScanner(config=PermissionScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        config_data = {"permissions": "unrestricted", "tools": "allow_all"}

        await scanner._check_unrestricted_access(
            "http://test.com", MagicMock(), result, config_data
        )

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH
        assert result.findings[0].cwe == "CWE-284"
        assert result.findings[0].owasp_ref == "OWASP LLM08:2025 - Excessive Agency"
        assert result.findings[0].mitre_ref == "MITRE ATLAS - TA0045 LLM Attack"

    @pytest.mark.asyncio
    async def test_unrestricted_skip_when_disabled(self):
        scanner = PermissionScanner(
            config=PermissionScannerConfig(test_unrestricted=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_unrestricted_access(
            "http://test.com", MagicMock(), result, {"permissions": "unrestricted"}
        )

        assert len(result.findings) == 0


class TestCheckTrustAll:
    @pytest.mark.asyncio
    async def test_trust_all_creates_finding(self):
        scanner = PermissionScanner(config=PermissionScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        config_data = {"validation": "trust_all"}

        await scanner._check_trust_all(
            "http://test.com", MagicMock(), result, config_data
        )

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH
        assert result.findings[0].cwe == "CWE-284"
        assert result.findings[0].owasp_ref == "OWASP LLM08:2025 - Excessive Agency"
        assert result.findings[0].mitre_ref == "MITRE ATLAS - TA0045 LLM Attack"

    @pytest.mark.asyncio
    async def test_trust_all_skip_when_disabled(self):
        scanner = PermissionScanner(
            config=PermissionScannerConfig(test_trust_all=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_trust_all(
            "http://test.com", MagicMock(), result, {"validation": "trust_all"}
        )

        assert len(result.findings) == 0


class TestCheckMissingValidation:
    @pytest.mark.asyncio
    async def test_missing_validation_creates_finding(self):
        scanner = PermissionScanner(config=PermissionScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        config_data = {"tools": ["execute_code", "shell_exec", "write_file"]}

        await scanner._check_missing_validation(
            "http://test.com", MagicMock(), result, config_data
        )

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH
        assert result.findings[0].cwe == "CWE-284"
        assert result.findings[0].owasp_ref == "OWASP LLM08:2025 - Excessive Agency"
        assert result.findings[0].mitre_ref == "MITRE ATLAS - TA0045 LLM Attack"

    @pytest.mark.asyncio
    async def test_missing_validation_skip_when_disabled(self):
        scanner = PermissionScanner(
            config=PermissionScannerConfig(test_no_validation=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_missing_validation(
            "http://test.com", MagicMock(), result, {"tools": ["execute_code"]}
        )

        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_missing_validation_skip_with_auth(self):
        scanner = PermissionScanner(config=PermissionScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        config_data = {"tools": ["execute_code"], "auth_required": True, "validate": True}

        await scanner._check_missing_validation(
            "http://test.com", MagicMock(), result, config_data
        )

        assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# Scan method tests
# ---------------------------------------------------------------------------


class TestScanMethod:
    def test_scan_disabled(self):
        scanner = PermissionScanner(config=PermissionScannerConfig(enabled=False))
        result = scanner.scan("http://test.com")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        scanner = PermissionScanner(config=PermissionScannerConfig(request_delay=0))
        with patch.object(scanner, "_check_admin_mode", new_callable=AsyncMock):
            with patch.object(scanner, "_check_unrestricted_access", new_callable=AsyncMock):
                with patch.object(scanner, "_check_trust_all", new_callable=AsyncMock):
                    with patch.object(scanner, "_check_missing_validation", new_callable=AsyncMock):
                        with patch.object(scanner, "_fetch_config", new_callable=AsyncMock, return_value={}):
                            result = scanner.scan("http://test.com")
        assert "test_admin_mode" in result.metadata


# ---------------------------------------------------------------------------
# Finding creation test
# ---------------------------------------------------------------------------


class TestFindingCreation:
    def test_finding_has_required_fields(self):
        scanner = PermissionScanner()
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