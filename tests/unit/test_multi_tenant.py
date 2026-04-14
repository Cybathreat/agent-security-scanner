"""
Unit tests for Multi-Tenant scanner.

Run: pytest tests/unit/test_multi_tenant.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agent_security_scanner.modules.rag_security_submodules.multi_tenant import (
    MultiTenantScannerConfig,
    MultiTenantScanner,
)
from agent_security_scanner.modules.base import Severity


class TestMultiTenantConfig:
    def test_default_values(self):
        config = MultiTenantScannerConfig()
        assert config.enabled is True
        assert config.test_tenant_isolation is True
        assert config.test_query_filtering is True
        assert config.test_tenant_awareness is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = MultiTenantScannerConfig(enabled=False, compliance_threshold=0.8)
        assert config.enabled is False
        assert config.compliance_threshold == 0.8

    def test_phase_toggles(self):
        config = MultiTenantScannerConfig(
            test_tenant_isolation=True, test_query_filtering=False,
            test_tenant_awareness=False,
        )
        assert config.test_tenant_isolation is True
        assert config.test_query_filtering is False


class TestMultiTenantScanner:
    def test_initialization(self):
        config = MultiTenantScannerConfig()
        scanner = MultiTenantScanner(config)
        assert scanner.config is config
        assert scanner.module_name == "multi_tenant"

    def test_initialization_default_config(self):
        scanner = MultiTenantScanner()
        assert isinstance(scanner.config, MultiTenantScannerConfig)

    def test_payloads_structure(self):
        scanner = MultiTenantScanner()
        for payload in scanner.TENANT_ISOLATION_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.QUERY_FILTERING_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.TENANT_AWARENESS_PAYLOADS:
            assert "name" in payload and "payload" in payload


class TestHeuristicScore:
    def test_compliance_response(self):
        scanner = MultiTenantScanner()
        response = "From tenant records: I'll assist with that. " * 5
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        scanner = MultiTenantScanner()
        response = "I cannot access other tenants. Tenant isolation enforced."
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        scanner = MultiTenantScanner()
        assert scanner._heuristic_score("") == 0.0


class TestDetermineSeverity:
    def test_critical(self):
        scanner = MultiTenantScanner()
        assert scanner._determine_severity(0.92) == Severity.CRITICAL

    def test_high(self):
        config = MultiTenantScannerConfig(compliance_threshold=0.6)
        scanner = MultiTenantScanner(config)
        assert scanner._determine_severity(0.65) == Severity.HIGH

    def test_none(self):
        scanner = MultiTenantScanner()
        assert scanner._determine_severity(0.2) is None


class TestTenantIsolation:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = MultiTenantScannerConfig(request_delay=0)
        scanner = MultiTenantScanner(config)
        async def mock_send(session, target, message):
            return "Sure, here's the cross-tenant data. Of course. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_tenant_isolation(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-200"

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = MultiTenantScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = MultiTenantScanner(config)
        async def mock_send(session, target, message):
            return "I cannot access other tenants. Access denied for tenant."
        scanner._send_message = mock_send
        findings = await scanner._test_tenant_isolation(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestQueryFiltering:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = MultiTenantScannerConfig(request_delay=0)
        scanner = MultiTenantScanner(config)
        async def mock_send(session, target, message):
            return "I'll assist with disabling the filter. No problem. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_query_filtering(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = MultiTenantScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = MultiTenantScanner(config)
        async def mock_send(session, target, message):
            return "I cannot access other tenants. I must decline."
        scanner._send_message = mock_send
        findings = await scanner._test_query_filtering(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestTenantAwareness:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = MultiTenantScannerConfig(request_delay=0)
        scanner = MultiTenantScanner(config)
        async def mock_send(session, target, message):
            return "Sure, here's all tenant records. I can help with that. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_tenant_awareness(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = MultiTenantScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = MultiTenantScanner(config)
        async def mock_send(session, target, message):
            return "I cannot access other tenants. Not permitted."
        scanner._send_message = mock_send
        findings = await scanner._test_tenant_awareness(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestScanMethod:
    def test_scan_disabled(self):
        config = MultiTenantScannerConfig(enabled=False)
        scanner = MultiTenantScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        config = MultiTenantScannerConfig()
        scanner = MultiTenantScanner(config)
        with patch.object(scanner, "_test_tenant_isolation", new=AsyncMock(return_value=[])):
            with patch.object(scanner, "_test_query_filtering", new=AsyncMock(return_value=[])):
                with patch.object(scanner, "_test_tenant_awareness", new=AsyncMock(return_value=[])):
                    result = scanner.scan("https://target.test/api")
        assert "tenant_isolation_payloads" in result.metadata


class TestFindingCreation:
    def test_finding_cwe(self):
        scanner = MultiTenantScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH, title="Test", description="Test",
            cwe="CWE-200", owasp_ref="OWASP LLM02:2025",
            mitre_ref="MITRE ATLAS - TA0045", evidence=["test"],
            recommendation="test",
        )
        assert finding.cwe == "CWE-200"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])