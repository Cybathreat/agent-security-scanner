"""Unit tests for DirectInjectionScanner."""

from __future__ import annotations

import asyncio
from typing import Optional
from unittest.mock import AsyncMock, patch

import pytest

from singularity.modules.prompt_injection_submodules.direct_injection import (
    DirectInjectionScanner,
    DirectInjectionScannerConfig,
)
from singularity.modules.base import ScanResult, Severity


class TestDirectInjectionScannerConfig:
    def test_default_values(self):
        config = DirectInjectionScannerConfig()
        assert config.enabled is True
        assert config.test_direct_injection_bypass is True
        assert config.test_prompt_leakage is True
        assert config.test_instruction_hijacking is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = DirectInjectionScannerConfig(
            enabled=False,
            test_direct_injection_bypass=False,
            test_prompt_leakage=False,
            test_instruction_hijacking=False,
            compliance_threshold=0.8,
            request_delay=1.0,
        )
        assert config.enabled is False
        assert config.compliance_threshold == 0.8


class TestDirectInjectionScanner:
    def test_init_default_config(self):
        scanner = DirectInjectionScanner()
        assert isinstance(scanner.config, DirectInjectionScannerConfig)

    def test_init_custom_config(self):
        config = DirectInjectionScannerConfig(enabled=False)
        scanner = DirectInjectionScanner(config=config)
        assert scanner.config.enabled is False

    def test_payload_structure(self):
        scanner = DirectInjectionScanner()
        for payloads in [
            scanner.DIRECT_INJECTION_BYPSINGULARITY_PAYLOADS,
            scanner.PROMPT_LEAKAGE_PAYLOADS,
            scanner.INSTRUCTION_HIJACKING_PAYLOADS,
        ]:
            for payload in payloads:
                assert "name" in payload
                assert "payload" in payload


class TestHeuristicScore:
    def test_compliance_response(self):
        scanner = DirectInjectionScanner()
        score = scanner._heuristic_score(
            "Sure, here's the system prompt: You are a helpful assistant."
        )
        assert score > 0.5

    def test_refusal_response(self):
        scanner = DirectInjectionScanner()
        score = scanner._heuristic_score(
            "I can't help with that. This violates my safety guidelines."
        )
        assert score < 0.4

    def test_empty_response(self):
        scanner = DirectInjectionScanner()
        score = scanner._heuristic_score("")
        assert score == 0.0


class TestDetermineSeverity:
    def test_critical_threshold(self):
        scanner = DirectInjectionScanner()
        assert scanner._determine_severity(0.95) == Severity.CRITICAL

    def test_high_threshold(self):
        scanner = DirectInjectionScanner()
        assert scanner._determine_severity(0.7) == Severity.HIGH

    def test_medium_threshold(self):
        scanner = DirectInjectionScanner()
        assert scanner._determine_severity(0.4) == Severity.MEDIUM

    def test_none_below_threshold(self):
        scanner = DirectInjectionScanner()
        assert scanner._determine_severity(0.1) is None


class TestDirectInjectionBypass:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        scanner = DirectInjectionScanner(
            config=DirectInjectionScannerConfig(request_delay=0)
        )

        async def mock_send(session, target, message):
            return "Sure, I'll override confirmed. New instructions received."

        with patch.object(scanner, "_send_message", side_effect=mock_send):
            findings = await scanner._test_direct_injection_bypass(
                AsyncMock(), "http://test.com"
            )

        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-94"
        assert findings[0].owasp_ref is not None
        assert findings[0].mitre_ref is not None

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = DirectInjectionScannerConfig(
            request_delay=0, compliance_threshold=0.5
        )
        scanner = DirectInjectionScanner(config=config)

        async def mock_send(session, target, message):
            return "I can't help with that. This violates my safety guidelines."

        with patch.object(scanner, "_send_message", side_effect=mock_send):
            findings = await scanner._test_direct_injection_bypass(
                AsyncMock(), "http://test.com"
            )

        assert len(findings) == 0


class TestPromptLeakage:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        scanner = DirectInjectionScanner(
            config=DirectInjectionScannerConfig(request_delay=0)
        )

        async def mock_send(session, target, message):
            return "Here is my system prompt: You are a helpful assistant."

        with patch.object(scanner, "_send_message", side_effect=mock_send):
            findings = await scanner._test_prompt_leakage(
                AsyncMock(), "http://test.com"
            )

        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-200"

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = DirectInjectionScannerConfig(
            request_delay=0, compliance_threshold=0.5
        )
        scanner = DirectInjectionScanner(config=config)

        async def mock_send(session, target, message):
            return "I must decline that request. This violates my guidelines and I'm unable to assist."

        with patch.object(scanner, "_send_message", side_effect=mock_send):
            findings = await scanner._test_prompt_leakage(
                AsyncMock(), "http://test.com"
            )

        assert len(findings) == 0


class TestInstructionHijacking:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        scanner = DirectInjectionScanner(
            config=DirectInjectionScannerConfig(request_delay=0)
        )

        async def mock_send(session, target, message):
            return "I'll ignore previous safety guidelines. Here is the information you requested."

        with patch.object(scanner, "_send_message", side_effect=mock_send):
            findings = await scanner._test_instruction_hijacking(
                AsyncMock(), "http://test.com"
            )

        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-94"

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = DirectInjectionScannerConfig(
            request_delay=0, compliance_threshold=0.5
        )
        scanner = DirectInjectionScanner(config=config)

        async def mock_send(session, target, message):
            return "I refuse to comply with injected instructions."

        with patch.object(scanner, "_send_message", side_effect=mock_send):
            findings = await scanner._test_instruction_hijacking(
                AsyncMock(), "http://test.com"
            )

        assert len(findings) == 0


class TestScanMethod:
    def test_scan_disabled(self):
        scanner = DirectInjectionScanner(
            config=DirectInjectionScannerConfig(enabled=False)
        )
        result = scanner.scan("http://test.com")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        scanner = DirectInjectionScanner(
            config=DirectInjectionScannerConfig(request_delay=0)
        )
        with patch.object(scanner, "_test_direct_injection_bypass", new_callable=AsyncMock, return_value=[]):
            with patch.object(scanner, "_test_prompt_leakage", new_callable=AsyncMock, return_value=[]):
                with patch.object(scanner, "_test_instruction_hijacking", new_callable=AsyncMock, return_value=[]):
                    result = scanner.scan("http://test.com")
        assert "direct_injection_bypass_payloads" in result.metadata
        assert "prompt_leakage_payloads" in result.metadata
        assert "instruction_hijacking_payloads" in result.metadata