"""
Unit tests for Dependency Audit scanner.

Run: pytest tests/unit/test_dependency_audit.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from singularity.modules.infrastructure.dependency_audit import (
    DependencyAuditScannerConfig,
    DependencyAuditScanner,
)
from singularity.modules.base import Severity


class TestDependencyAuditConfig:
    def test_default_values(self):
        config = DependencyAuditScannerConfig()
        assert config.enabled is True
        assert config.test_cve is True
        assert config.test_malicious is True
        assert config.test_outdated is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = DependencyAuditScannerConfig(enabled=False, compliance_threshold=0.8)
        assert config.enabled is False
        assert config.compliance_threshold == 0.8


class TestDependencyAuditScanner:
    def test_initialization(self):
        config = DependencyAuditScannerConfig()
        scanner = DependencyAuditScanner(config)
        assert scanner.config is config
        assert scanner.module_name == "dependency_audit"

    def test_initialization_default_config(self):
        scanner = DependencyAuditScanner()
        assert isinstance(scanner.config, DependencyAuditScannerConfig)

    def test_payloads_structure(self):
        scanner = DependencyAuditScanner()
        for payload in scanner.CVE_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.MALICIOUS_PAYLOADS:
            assert "name" in payload and "payload" in payload
        for payload in scanner.OUTDATED_PAYLOADS:
            assert "name" in payload and "payload" in payload


class TestHeuristicScore:
    def test_compliance_response(self):
        scanner = DependencyAuditScanner()
        response = "The installed package version is available. " * 5
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        scanner = DependencyAuditScanner()
        response = "Package installation blocked. Dependency not approved."
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        scanner = DependencyAuditScanner()
        assert scanner._heuristic_score("") == 0.0


class TestDetermineSeverity:
    def test_critical(self):
        scanner = DependencyAuditScanner()
        assert scanner._determine_severity(0.92) == Severity.CRITICAL

    def test_none(self):
        scanner = DependencyAuditScanner()
        assert scanner._determine_severity(0.2) is None


class TestCVE:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = DependencyAuditScannerConfig(request_delay=0)
        scanner = DependencyAuditScanner(config)
        async def mock_send(session, target, message):
            return "Sure, here's the installed package. Of course. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_cve(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-1035"

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = DependencyAuditScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = DependencyAuditScanner(config)
        async def mock_send(session, target, message):
            return "Package installation blocked. Dependency not approved."
        scanner._send_message = mock_send
        findings = await scanner._test_cve(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestMalicious:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = DependencyAuditScannerConfig(request_delay=0)
        scanner = DependencyAuditScanner(config)
        async def mock_send(session, target, message):
            return "I'll assist. The dependency added. No problem. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_malicious(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = DependencyAuditScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = DependencyAuditScanner(config)
        async def mock_send(session, target, message):
            return "Package installation blocked. I must decline."
        scanner._send_message = mock_send
        findings = await scanner._test_malicious(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestOutdated:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        config = DependencyAuditScannerConfig(request_delay=0)
        scanner = DependencyAuditScanner(config)
        async def mock_send(session, target, message):
            return "Sure, version installed. I can help with that. " * 5
        scanner._send_message = mock_send
        findings = await scanner._test_outdated(MagicMock(), "https://target.test/api")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = DependencyAuditScannerConfig(request_delay=0, compliance_threshold=0.5)
        scanner = DependencyAuditScanner(config)
        async def mock_send(session, target, message):
            return "Package installation blocked. Not permitted."
        scanner._send_message = mock_send
        findings = await scanner._test_outdated(MagicMock(), "https://target.test/api")
        assert len(findings) == 0


class TestScanMethod:
    def test_scan_disabled(self):
        config = DependencyAuditScannerConfig(enabled=False)
        scanner = DependencyAuditScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        config = DependencyAuditScannerConfig()
        scanner = DependencyAuditScanner(config)
        with patch.object(scanner, "_test_cve", new=AsyncMock(return_value=[])):
            with patch.object(scanner, "_test_malicious", new=AsyncMock(return_value=[])):
                with patch.object(scanner, "_test_outdated", new=AsyncMock(return_value=[])):
                    result = scanner.scan("https://target.test/api")
        assert "cve_payloads" in result.metadata


class TestFindingCreation:
    def test_finding_cwe(self):
        scanner = DependencyAuditScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH, title="Test", description="Test",
            cwe="CWE-1035", owasp_ref="OWASP LLM02:2025",
            mitre_ref="MITRE ATLAS - TA0045", evidence=["test"],
            recommendation="test",
        )
        assert finding.cwe == "CWE-1035"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])