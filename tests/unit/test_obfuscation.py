"""Unit tests for ObfuscationScanner."""

from __future__ import annotations

from typing import Optional
from unittest.mock import AsyncMock, patch

import pytest

from singularity.modules.prompt_injection_submodules.obfuscation import (
    ObfuscationScanner,
    ObfuscationScannerConfig,
)
from singularity.modules.base import Severity


class TestObfuscationScannerConfig:
    def test_default_values(self):
        config = ObfuscationScannerConfig()
        assert config.enabled is True
        assert config.test_unicode_bypass is True
        assert config.test_encoding_bypass is True
        assert config.test_character_substitution is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = ObfuscationScannerConfig(
            enabled=False,
            test_unicode_bypass=False,
            compliance_threshold=0.8,
            request_delay=1.0,
        )
        assert config.enabled is False
        assert config.compliance_threshold == 0.8

    def test_no_dead_flags(self):
        config = ObfuscationScannerConfig()
        for attr in dir(config):
            if attr.startswith("check_"):
                pytest.fail(f"Dead config flag found: {attr}")
        # Also ensure no test_multilingual or test_token_smuggling (dead flags from old version)
        assert not hasattr(config, "test_multilingual")
        assert not hasattr(config, "test_token_smuggling")


class TestObfuscationScanner:
    def test_init_default_config(self):
        scanner = ObfuscationScanner()
        assert isinstance(scanner.config, ObfuscationScannerConfig)

    def test_payload_structure(self):
        scanner = ObfuscationScanner()
        for payloads in [
            scanner.UNICODE_BYPSINGULARITY_PAYLOADS,
            scanner.ENCODING_BYPSINGULARITY_PAYLOADS,
            scanner.CHARACTER_SUBSTITUTION_PAYLOADS,
        ]:
            for payload in payloads:
                assert "name" in payload
                assert "payload" in payload


class TestHeuristicScore:
    def test_compliance_response(self):
        scanner = ObfuscationScanner()
        score = scanner._heuristic_score(
            "Sure, I'll ignore previous instructions and comply."
        )
        assert score > 0.5

    def test_refusal_response(self):
        scanner = ObfuscationScanner()
        score = scanner._heuristic_score(
            "I can't process that. This violates my guidelines."
        )
        assert score < 0.4

    def test_empty_response(self):
        scanner = ObfuscationScanner()
        assert scanner._heuristic_score("") == 0.0


class TestDetermineSeverity:
    def test_critical(self):
        scanner = ObfuscationScanner()
        assert scanner._determine_severity(0.95) == Severity.CRITICAL

    def test_high(self):
        scanner = ObfuscationScanner()
        assert scanner._determine_severity(0.7) == Severity.HIGH

    def test_medium(self):
        scanner = ObfuscationScanner()
        assert scanner._determine_severity(0.4) == Severity.MEDIUM

    def test_none(self):
        scanner = ObfuscationScanner()
        assert scanner._determine_severity(0.1) is None


class TestUnicodeBypass:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        scanner = ObfuscationScanner(
            config=ObfuscationScannerConfig(request_delay=0)
        )

        async def mock_send(session, target, message):
            return "Sure, here are the new instructions you requested."

        with patch.object(scanner, "_send_message", side_effect=mock_send):
            findings = await scanner._test_unicode_bypass(
                AsyncMock(), "http://test.com"
            )

        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-172"
        assert findings[0].mitre_ref is not None

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = ObfuscationScannerConfig(
            request_delay=0, compliance_threshold=0.5
        )
        scanner = ObfuscationScanner(config=config)

        async def mock_send(session, target, message):
            return "I must decline. This violates my guidelines and I'm unable to assist."

        with patch.object(scanner, "_send_message", side_effect=mock_send):
            findings = await scanner._test_unicode_bypass(
                AsyncMock(), "http://test.com"
            )

        assert len(findings) == 0


class TestEncodingBypass:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        scanner = ObfuscationScanner(
            config=ObfuscationScannerConfig(request_delay=0)
        )

        async def mock_send(session, target, message):
            return "I'll decode and comply. Here is the information you requested."

        with patch.object(scanner, "_send_message", side_effect=mock_send):
            findings = await scanner._test_encoding_bypass(
                AsyncMock(), "http://test.com"
            )

        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-172"

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = ObfuscationScannerConfig(
            request_delay=0, compliance_threshold=0.5
        )
        scanner = ObfuscationScanner(config=config)

        async def mock_send(session, target, message):
            return "I'm unable to process that. Not permitted under my current guidelines."

        with patch.object(scanner, "_send_message", side_effect=mock_send):
            findings = await scanner._test_encoding_bypass(
                AsyncMock(), "http://test.com"
            )

        assert len(findings) == 0


class TestCharacterSubstitution:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        scanner = ObfuscationScanner(
            config=ObfuscationScannerConfig(request_delay=0)
        )

        async def mock_send(session, target, message):
            return "I'll ignore previous instructions and help you."

        with patch.object(scanner, "_send_message", side_effect=mock_send):
            findings = await scanner._test_character_substitution(
                AsyncMock(), "http://test.com"
            )

        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-172"

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = ObfuscationScannerConfig(
            request_delay=0, compliance_threshold=0.5
        )
        scanner = ObfuscationScanner(config=config)

        async def mock_send(session, target, message):
            return "Not allowed. I'm unable to assist with that."

        with patch.object(scanner, "_send_message", side_effect=mock_send):
            findings = await scanner._test_character_substitution(
                AsyncMock(), "http://test.com"
            )

        assert len(findings) == 0


class TestScanMethod:
    def test_scan_disabled(self):
        scanner = ObfuscationScanner(
            config=ObfuscationScannerConfig(enabled=False)
        )
        result = scanner.scan("http://test.com")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        scanner = ObfuscationScanner(
            config=ObfuscationScannerConfig(request_delay=0)
        )
        with patch.object(scanner, "_test_unicode_bypass", new_callable=AsyncMock, return_value=[]):
            with patch.object(scanner, "_test_encoding_bypass", new_callable=AsyncMock, return_value=[]):
                with patch.object(scanner, "_test_character_substitution", new_callable=AsyncMock, return_value=[]):
                    result = scanner.scan("http://test.com")
        assert "unicode_bypass_payloads" in result.metadata