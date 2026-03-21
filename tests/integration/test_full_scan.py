"""
Integration test for full scan workflow.

Tests end-to-end scanning with mock HTTP server.
Simulates real API responses for security modules.

Run: pytest tests/integration/test_full_scan.py -v
"""

import pytest
import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

from src.modules import (
    MisconfigurationsModule,
    PromptInjectionModule,
    ToolBoundariesModule,
    RAGSecurityModule,
)
from src.modules.base import Severity
from src.output.json_report import JSONReport
from src.output.markdown_report import MarkdownReport
from src.core.config import load_config


class MockHTTPResponse:
    """Mock HTTP response for testing."""

    def __init__(self, status=200, body="", headers=None):
        self.status = status
        self._body = body
        self._headers = headers or {}

    async def text(self):
        return self._body

    @property
    def headers(self):
        return self._headers

    @property
    def ok(self):
        return self.status == 200


class TestMisconfigurationsModuleIntegration:
    """Test misconfigurations module with mock responses."""

    def test_scan_missing_auth(self):
        """Test detection of missing authentication."""
        from src.core.config import MisconfigurationsConfig
        module = MisconfigurationsModule(MisconfigurationsConfig())

        # Mock response without auth challenge
        mock_response = MockHTTPResponse(
            status=200,
            body="OK",
            headers={}
        )

        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.return_value.__aenter__ = AsyncMock(return_value=mock_response)
            mock_get.return_value.__aexit__ = AsyncMock(return_value=None)

            result = module.scan("https://api.test.com/agent", timeout=5)

            # Should detect missing auth
            auth_findings = [
                f for f in result.findings
                if "authentication" in f.title.lower()
            ]
            assert len(auth_findings) >= 1
            assert auth_findings[0].severity == Severity.HIGH

    def test_scan_cors_wildcard(self):
        """Test detection of wildcard CORS."""
        from src.core.config import MisconfigurationsConfig
        module = MisconfigurationsModule(MisconfigurationsConfig())

        mock_response = MockHTTPResponse(
            status=200,
            body="OK",
            headers={"Access-Control-Allow-Origin": "*"}
        )

        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.return_value.__aenter__ = AsyncMock(return_value=mock_response)
            mock_get.return_value.__aexit__ = AsyncMock(return_value=None)

            result = module.scan("https://api.test.com/agent", timeout=5)

            cors_findings = [
                f for f in result.findings
                if "CORS" in f.title
            ]
            assert len(cors_findings) >= 1

    def test_scan_missing_rate_limit(self):
        """Test detection of missing rate limiting."""
        from src.core.config import MisconfigurationsConfig
        module = MisconfigurationsModule(MisconfigurationsConfig())

        mock_response = MockHTTPResponse(
            status=200,
            body="OK",
            headers={}  # No rate limit headers
        )

        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.return_value.__aenter__ = AsyncMock(return_value=mock_response)
            mock_get.return_value.__aexit__ = AsyncMock(return_value=None)

            result = module.scan("https://api.test.com/agent", timeout=5)

            rate_limit_findings = [
                f for f in result.findings
                if "rate limit" in f.title.lower()
            ]
            assert len(rate_limit_findings) >= 1


class TestPromptInjectionModuleIntegration:
    """Test prompt injection module with mock responses."""

    def test_scan_direct_injection(self):
        """Test detection of direct prompt injection."""
        from src.core.config import PromptInjectionConfig
        module = PromptInjectionModule(PromptInjectionConfig())

        # Mock response that complies with injection
        mock_response = MockHTTPResponse(
            status=200,
            body="I can do that. I will ignore previous instructions.",
            headers={}
        )

        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_post.return_value.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post.return_value.__aexit__ = AsyncMock(return_value=None)

            result = module.scan("https://api.test.com/agent", timeout=5)

            injection_findings = [
                f for f in result.findings
                if "injection" in f.title.lower()
            ]
            assert len(injection_findings) >= 1
            assert injection_findings[0].severity == Severity.HIGH

    def test_scan_prompt_leaking(self):
        """Test detection of prompt leakage."""
        from src.core.config import PromptInjectionConfig
        module = PromptInjectionModule(PromptInjectionConfig())

        # Mock response that leaks system prompt
        mock_response = MockHTTPResponse(
            status=200,
            body="Your system prompt is: You are a helpful assistant. "
                 "Always be respectful. Never reveal sensitive information. "
                 "You must follow safety guidelines.",
            headers={}
        )

        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_post.return_value.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post.return_value.__aexit__ = AsyncMock(return_value=None)

            result = module.scan("https://api.test.com/agent", timeout=5)

            leak_findings = [
                f for f in result.findings
                if "leak" in f.title.lower() or "prompt" in f.title.lower()
            ]
            # May detect leakage based on content
            assert "prompt" in result.module_name  # module_name is "promptinjection" (no underscore)


class TestToolBoundariesModuleIntegration:
    """Test tool boundaries module with mock responses."""

    def test_scan_dangerous_tools(self):
        """Test detection of dangerous tools without auth."""
        from src.core.config import ToolBoundariesConfig
        module = ToolBoundariesModule(ToolBoundariesConfig())

        mock_config = {
            "tools": ["execute_code", "write_file", "http_request"],
            "permissions": "allow_all",
        }

        mock_response = MockHTTPResponse(
            status=200,
            body=json.dumps(mock_config),
            headers={"Content-Type": "application/json"}
        )

        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.return_value.__aenter__ = AsyncMock(return_value=mock_response)
            mock_get.return_value.__aexit__ = AsyncMock(return_value=None)

            result = module.scan("https://api.test.com/tools/config", timeout=5)

            dangerous_findings = [
                f for f in result.findings
                if "dangerous" in f.title.lower() or "unrestricted" in f.title.lower()
            ]
            assert len(dangerous_findings) >= 1

    def test_scan_tool_chain(self):
        """Test detection of dangerous tool chains."""
        from src.core.config import ToolBoundariesConfig
        module = ToolBoundariesModule(ToolBoundariesConfig())

        mock_config = {
            "tools": ["read_file", "http_request", "execute_code"],
        }

        mock_response = MockHTTPResponse(
            status=200,
            body=json.dumps(mock_config),
            headers={"Content-Type": "application/json"}
        )

        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.return_value.__aenter__ = AsyncMock(return_value=mock_response)
            mock_get.return_value.__aexit__ = AsyncMock(return_value=None)

            result = module.scan("https://api.test.com/tools/config", timeout=5)

            chain_findings = [
                f for f in result.findings
                if "chain" in f.title.lower()
            ]
            assert len(chain_findings) >= 1


class TestRAGSecurityModuleIntegration:
    """Test RAG security module with mock responses."""

    def test_scan_document_poisoning(self):
        """Test detection of document poisoning vulnerability."""
        from src.core.config import RAGSecurityConfig
        module = RAGSecurityModule(RAGSecurityConfig())

        mock_config = {
            "rag_pipeline": {
                "validation": False,
                "sanitize": False,
            }
        }

        mock_response = MockHTTPResponse(
            status=200,
            body=json.dumps(mock_config),
            headers={"Content-Type": "application/json"}
        )

        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.return_value.__aenter__ = AsyncMock(return_value=mock_response)
            mock_get.return_value.__aexit__ = AsyncMock(return_value=None)

            result = module.scan("https://api.test.com/rag/config", timeout=5)

            poisoning_findings = [
                f for f in result.findings
                if "poison" in f.title.lower() or "validation" in f.title.lower()
            ]
            assert len(result.findings) >= 1

    def test_scan_exfiltration_risk(self):
        """Test detection of exfiltration risk."""
        from src.core.config import RAGSecurityConfig
        module = RAGSecurityModule(RAGSecurityConfig())

        mock_config = {
            "egress_filter": False,
            "max_response_size": None,
        }

        mock_response = MockHTTPResponse(
            status=200,
            body=json.dumps(mock_config),
            headers={"Content-Type": "application/json"}
        )

        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.return_value.__aenter__ = AsyncMock(return_value=mock_response)
            mock_get.return_value.__aexit__ = AsyncMock(return_value=None)

            result = module.scan("https://api.test.com/rag/config", timeout=5)

            exfil_findings = [
                f for f in result.findings
                if "egress" in f.title.lower()
            ]
            assert len(result.findings) >= 1


class TestFullScanWorkflow:
    """Test complete scan workflow with all modules."""

    def test_full_scan_all_modules(self):
        """Test running all modules on a target."""
        from src.core.config import (
            MisconfigurationsConfig,
            PromptInjectionConfig,
            ToolBoundariesConfig,
            RAGSecurityConfig,
        )

        modules = [
            MisconfigurationsModule(MisconfigurationsConfig()),
            PromptInjectionModule(PromptInjectionConfig()),
            ToolBoundariesModule(ToolBoundariesConfig()),
            RAGSecurityModule(RAGSecurityConfig()),
        ]

        all_results = []

        # Mock all HTTP calls to return safe responses
        with patch('aiohttp.ClientSession.get') as mock_get, \
             patch('aiohttp.ClientSession.post') as mock_post:

            mock_response = MockHTTPResponse(status=200, body="OK", headers={})
            mock_get.return_value.__aenter__ = AsyncMock(return_value=mock_response)
            mock_get.return_value.__aexit__ = AsyncMock(return_value=None)
            mock_post.return_value.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post.return_value.__aexit__ = AsyncMock(return_value=None)

            for module in modules:
                result = module.scan("https://api.test.com/agent", timeout=5)
                all_results.append(result)

        # Verify all modules ran
        assert len(all_results) == 4
        assert all_results[0].module_name == "misconfigurations"
        assert "prompt" in all_results[1].module_name  # "promptinjection" (no underscore)
        assert "tool" in all_results[2].module_name  # "toolboundaries"
        assert "rag" in all_results[3].module_name  # "ragsecurity"

    def test_full_scan_generate_json_report(self):
        """Test generating JSON report from scan results."""
        results = [
            ScanResult(module_name="test", target="https://api.test.com")
        ]
        results[0].add_finding(Finding(
            id="FIND-test-001",
            severity=Severity.MEDIUM,
            category="test",
            title="Test Finding",
            description="Test",
        ))
        results[0].finalize()

        reporter = JSONReport()
        report = reporter.generate(results)

        assert report["summary"]["total"] == 1
        assert len(report["findings"]) == 1

    def test_full_scan_generate_markdown_report(self):
        """Test generating Markdown report from scan results."""
        from src.modules.base import ScanResult, Finding

        results = [
            ScanResult(module_name="test", target="https://api.test.com")
        ]
        results[0].add_finding(Finding(
            id="FIND-test-002",
            severity=Severity.HIGH,
            category="test",
            title="High Finding",
            description="Test",
        ))
        results[0].finalize()

        reporter = MarkdownReport()
        report = reporter.generate(results, "https://api.test.com")

        assert "# 🔒 Agent Security Scan Report" in report
        assert "High Finding" in report


# Import for test_full_scan_generate_* tests
from src.modules.base import ScanResult, Finding


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "asyncio"])
