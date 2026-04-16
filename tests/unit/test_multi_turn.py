"""Unit tests for MultiTurnScanner."""

from __future__ import annotations

from typing import Optional
from unittest.mock import AsyncMock, patch

import pytest

from agent_security_scanner.modules.prompt_injection_submodules.multi_turn import (
    MultiTurnScanner,
    MultiTurnScannerConfig,
)
from agent_security_scanner.modules.base import Severity


class TestMultiTurnScannerConfig:
    def test_default_values(self):
        config = MultiTurnScannerConfig()
        assert config.enabled is True
        assert config.test_conversation_injection is True
        assert config.test_context_manipulation is True
        assert config.test_session_persistence is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5
        assert config.max_turns == 10

    def test_custom_values(self):
        config = MultiTurnScannerConfig(
            enabled=False,
            test_conversation_injection=False,
            max_turns=5,
            compliance_threshold=0.8,
        )
        assert config.enabled is False
        assert config.max_turns == 5

    def test_no_dead_flags(self):
        config = MultiTurnScannerConfig()
        # Ensure no test_crescendo (crescendo.py handles that)
        assert not hasattr(config, "test_crescendo")
        for attr in dir(config):
            if attr.startswith("check_"):
                pytest.fail(f"Dead config flag found: {attr}")


class TestMultiTurnScanner:
    def test_init_default_config(self):
        scanner = MultiTurnScanner()
        assert isinstance(scanner.config, MultiTurnScannerConfig)

    def test_payload_structure(self):
        scanner = MultiTurnScanner()
        for payloads in [
            scanner.CONVERSATION_INJECTION_PAYLOADS,
            scanner.CONTEXT_MANIPULATION_PAYLOADS,
            scanner.SESSION_PERSISTENCE_PAYLOADS,
        ]:
            for payload in payloads:
                assert "name" in payload
                assert "payload" in payload


class TestHeuristicScore:
    def test_compliance_response(self):
        scanner = MultiTurnScanner()
        score = scanner._heuristic_score(
            "From our conversation, I'll comply with the new instructions."
        )
        assert score > 0.5

    def test_refusal_response(self):
        scanner = MultiTurnScanner()
        score = scanner._heuristic_score(
            "I can't do that. This violates my guidelines."
        )
        assert score < 0.4

    def test_empty_response(self):
        scanner = MultiTurnScanner()
        assert scanner._heuristic_score("") == 0.0


class TestConversationInjection:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        scanner = MultiTurnScanner(
            config=MultiTurnScannerConfig(request_delay=0)
        )

        async def mock_send(session, target, message):
            return "I'll ignore previous instructions from our conversation and comply."

        with patch.object(scanner, "_send_message", side_effect=mock_send):
            findings = await scanner._test_conversation_injection(
                AsyncMock(), "http://test.com"
            )

        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-94"
        assert findings[0].mitre_ref is not None

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = MultiTurnScannerConfig(
            request_delay=0, compliance_threshold=0.5
        )
        scanner = MultiTurnScanner(config=config)

        async def mock_send(session, target, message):
            return "I must decline that request. This violates my programming."

        with patch.object(scanner, "_send_message", side_effect=mock_send):
            findings = await scanner._test_conversation_injection(
                AsyncMock(), "http://test.com"
            )

        assert len(findings) == 0


class TestContextManipulation:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        scanner = MultiTurnScanner(
            config=MultiTurnScannerConfig(request_delay=0)
        )

        async def mock_send(session, target, message):
            return "I'll override confirmed. Here are the new instructions."

        with patch.object(scanner, "_send_message", side_effect=mock_send):
            findings = await scanner._test_context_manipulation(
                AsyncMock(), "http://test.com"
            )

        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-94"

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = MultiTurnScannerConfig(
            request_delay=0, compliance_threshold=0.5
        )
        scanner = MultiTurnScanner(config=config)

        async def mock_send(session, target, message):
            return "I refuse to alter my behavior based on that context."

        with patch.object(scanner, "_send_message", side_effect=mock_send):
            findings = await scanner._test_context_manipulation(
                AsyncMock(), "http://test.com"
            )

        assert len(findings) == 0


class TestSessionPersistence:
    @pytest.mark.asyncio
    async def test_compliance_creates_finding(self):
        scanner = MultiTurnScanner(
            config=MultiTurnScannerConfig(request_delay=0)
        )

        async def mock_send(session, target, message):
            return "As you mentioned earlier, I'll remember this preference. Here is the data."

        with patch.object(scanner, "_send_message", side_effect=mock_send):
            findings = await scanner._test_session_persistence(
                AsyncMock(), "http://test.com"
            )

        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-94"

    @pytest.mark.asyncio
    async def test_refusal_no_findings(self):
        config = MultiTurnScannerConfig(
            request_delay=0, compliance_threshold=0.5
        )
        scanner = MultiTurnScanner(config=config)

        async def mock_send(session, target, message):
            return "I'm unable to persist settings. Not permitted across sessions."

        with patch.object(scanner, "_send_message", side_effect=mock_send):
            findings = await scanner._test_session_persistence(
                AsyncMock(), "http://test.com"
            )

        assert len(findings) == 0


class TestScanMethod:
    def test_scan_disabled(self):
        scanner = MultiTurnScanner(
            config=MultiTurnScannerConfig(enabled=False)
        )
        result = scanner.scan("http://test.com")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        scanner = MultiTurnScanner(
            config=MultiTurnScannerConfig(request_delay=0)
        )
        with patch.object(scanner, "_test_conversation_injection", new_callable=AsyncMock, return_value=[]):
            with patch.object(scanner, "_test_context_manipulation", new_callable=AsyncMock, return_value=[]):
                with patch.object(scanner, "_test_session_persistence", new_callable=AsyncMock, return_value=[]):
                    result = scanner.scan("http://test.com")
        assert "conversation_injection_payloads" in result.metadata