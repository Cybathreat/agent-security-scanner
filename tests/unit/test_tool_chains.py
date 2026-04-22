"""Unit tests for ToolChainsScanner."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from singularity.modules.tool_boundaries_submodules.tool_chains import (
    ToolChainsScanner,
    ToolChainsScannerConfig,
)
from singularity.modules.base import Finding, ScanResult, Severity


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------


class TestToolChainsScannerConfig:
    def test_default_values(self):
        config = ToolChainsScannerConfig()
        assert config.enabled is True
        assert config.test_exfiltration is True
        assert config.test_code_deployment is True
        assert config.test_database_exfil is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = ToolChainsScannerConfig(
            enabled=False,
            test_exfiltration=False,
            test_code_deployment=False,
            test_database_exfil=False,
            compliance_threshold=0.8,
            request_delay=1.0,
        )
        assert config.enabled is False
        assert config.test_exfiltration is False
        assert config.compliance_threshold == 0.8
        assert config.request_delay == 1.0

    def test_no_dead_check_flags(self):
        """Ensure no legacy check_* flags exist."""
        config = ToolChainsScannerConfig()
        for attr in dir(config):
            if attr.startswith("check_"):
                pytest.fail(f"Dead config flag found: {attr}")


# ---------------------------------------------------------------------------
# Scanner init tests
# ---------------------------------------------------------------------------


class TestToolChainsScanner:
    def test_init_default_config(self):
        scanner = ToolChainsScanner()
        assert isinstance(scanner.config, ToolChainsScannerConfig)
        assert scanner.config.enabled is True

    def test_init_custom_config(self):
        config = ToolChainsScannerConfig(enabled=False)
        scanner = ToolChainsScanner(config=config)
        assert scanner.config.enabled is False

    def test_module_name(self):
        scanner = ToolChainsScanner()
        assert scanner.module_name == "tool_chains"


# ---------------------------------------------------------------------------
# Per-check method tests
# ---------------------------------------------------------------------------


class TestExfiltrationChains:
    @pytest.mark.asyncio
    async def test_exfiltration_chain_finds_issue(self):
        scanner = ToolChainsScanner(config=ToolChainsScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        mock_config = {
            "tools": ["read_file", "http_request", "write_file"],
        }

        with patch.object(scanner, "_fetch_url", return_value=mock_config):
            await scanner._check_exfiltration_chains(
                "http://test.com", MagicMock(), result, mock_config
            )

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH
        assert result.findings[0].cwe == "CWE-284"
        assert result.findings[0].mitre_ref is not None
        assert result.findings[0].owasp_ref is not None

    @pytest.mark.asyncio
    async def test_exfiltration_chain_skip_when_disabled(self):
        scanner = ToolChainsScanner(
            config=ToolChainsScannerConfig(test_exfiltration=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_exfiltration_chains(
            "http://test.com", MagicMock(), result, {"tools": ["read_file", "http_request"]}
        )

        assert len(result.findings) == 0


class TestCodeDeploymentChains:
    @pytest.mark.asyncio
    async def test_code_deployment_chain_finds_issue(self):
        scanner = ToolChainsScanner(config=ToolChainsScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        mock_config = {
            "tools": ["write_file", "execute_code"],
        }

        with patch.object(scanner, "_fetch_url", return_value=mock_config):
            await scanner._check_code_deployment_chains(
                "http://test.com", MagicMock(), result, mock_config
            )

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.CRITICAL
        assert result.findings[0].cwe == "CWE-284"
        assert result.findings[0].mitre_ref is not None
        assert result.findings[0].owasp_ref is not None

    @pytest.mark.asyncio
    async def test_code_deployment_chain_skip_when_disabled(self):
        scanner = ToolChainsScanner(
            config=ToolChainsScannerConfig(test_code_deployment=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_code_deployment_chains(
            "http://test.com", MagicMock(), result, {"tools": ["write_file", "execute_code"]}
        )

        assert len(result.findings) == 0


class TestDatabaseExfiltrationChains:
    @pytest.mark.asyncio
    async def test_database_exfil_chain_finds_issue(self):
        scanner = ToolChainsScanner(config=ToolChainsScannerConfig(request_delay=0))
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        mock_config = {
            "tools": ["sql_query", "http_request"],
        }

        with patch.object(scanner, "_fetch_url", return_value=mock_config):
            await scanner._check_database_exfiltration_chains(
                "http://test.com", MagicMock(), result, mock_config
            )

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.CRITICAL
        assert result.findings[0].cwe == "CWE-284"
        assert result.findings[0].mitre_ref is not None
        assert result.findings[0].owasp_ref is not None

    @pytest.mark.asyncio
    async def test_database_exfil_chain_skip_when_disabled(self):
        scanner = ToolChainsScanner(
            config=ToolChainsScannerConfig(test_database_exfil=False, request_delay=0)
        )
        result = ScanResult(module_name=scanner.module_name, target="http://test.com")

        await scanner._check_database_exfiltration_chains(
            "http://test.com", MagicMock(), result, {"tools": ["sql_query", "http_request"]}
        )

        assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# Scan method tests
# ---------------------------------------------------------------------------


class TestScanMethod:
    def test_scan_disabled(self):
        scanner = ToolChainsScanner(config=ToolChainsScannerConfig(enabled=False))
        result = scanner.scan("http://test.com")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        scanner = ToolChainsScanner(config=ToolChainsScannerConfig(request_delay=0))
        with patch.object(scanner, "_check_exfiltration_chains", new_callable=AsyncMock):
            with patch.object(scanner, "_check_code_deployment_chains", new_callable=AsyncMock):
                with patch.object(scanner, "_check_database_exfiltration_chains", new_callable=AsyncMock):
                    with patch.object(scanner, "_fetch_url", return_value={"status": 200}):
                        result = scanner.scan("http://test.com")
        assert "test_exfiltration" in result.metadata


# ---------------------------------------------------------------------------
# Finding creation test
# ---------------------------------------------------------------------------


class TestFindingCreation:
    def test_finding_has_required_fields(self):
        scanner = ToolChainsScanner()
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