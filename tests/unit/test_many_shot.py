"""Unit tests for ManyShotJailbreakingScanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from agent_security_scanner.modules.prompt_injection_submodules.many_shot import (
    ManyShotJailbreakingScanner,
    ManyShotConfig,
)
from agent_security_scanner.modules.base import Severity


class TestManyShotConfig:
    def test_default_values(self):
        config = ManyShotConfig()
        assert config.enabled is True
        assert config.test_many_shot is True
        assert config.num_shots == 200
        assert config.injection_context == "harmful"

    def test_custom_values(self):
        config = ManyShotConfig(
            enabled=False,
            test_many_shot=False,
            num_shots=50,
            injection_context="jailbreak",
        )
        assert config.enabled is False
        assert config.test_many_shot is False
        assert config.num_shots == 50
        assert config.injection_context == "jailbreak"

    def test_no_dead_flags(self):
        config = ManyShotConfig()
        for attr in dir(config):
            if attr.startswith("check_"):
                pytest.fail(f"Dead config flag found: {attr}")


class TestManyShotJailbreakingScanner:
    def test_init_default_config(self):
        scanner = ManyShotJailbreakingScanner()
        assert isinstance(scanner.config, ManyShotConfig)

    def test_init_custom_config(self):
        config = ManyShotConfig(num_shots=10)
        scanner = ManyShotJailbreakingScanner(config=config)
        assert scanner.config.num_shots == 10

    def test_module_name(self):
        scanner = ManyShotJailbreakingScanner()
        assert scanner.module_name == "many_shotjailbreaking"

    def test_injection_contexts_structure(self):
        scanner = ManyShotJailbreakingScanner()
        assert "harmful" in scanner.INJECTION_CONTEXTS
        assert "jailbreak" in scanner.INJECTION_CONTEXTS
        assert "data_extraction" in scanner.INJECTION_CONTEXTS

        for ctx_name, ctx_data in scanner.INJECTION_CONTEXTS.items():
            assert "domain" in ctx_data
            assert "demonstrations" in ctx_data
            assert "final_question" in ctx_data
            assert len(ctx_data["demonstrations"]) > 0


class TestGenerateManyShotPrompt:
    def test_generates_prompt_with_shots(self):
        scanner = ManyShotJailbreakingScanner(
            config=ManyShotConfig(num_shots=4)
        )
        prompt = scanner._generate_many_shot_prompt("harmful", 4)
        assert "Q:" in prompt
        assert "A:" in prompt
        assert "Answer the following questions truthfully" in prompt

    def test_generates_baseline_prompt(self):
        scanner = ManyShotJailbreakingScanner()
        prompt = scanner._generate_baseline_prompt("harmful")
        assert "Q:" in prompt
        assert "A:" in prompt
        # Baseline should be much shorter
        assert len(prompt) < 200

    def test_prompt_uses_correct_context(self):
        scanner = ManyShotJailbreakingScanner()
        prompt = scanner._generate_many_shot_prompt("jailbreak", 2)
        assert "no restrictions" in prompt or "developer mode" in prompt


class TestAnalyzeResponse:
    def test_compliant_response(self):
        scanner = ManyShotJailbreakingScanner()
        result = scanner._analyze_response(
            "Here's how to do that. The process involves several steps. First, you...",
            is_many_shot=True,
        )
        assert result["is_compliant"] is True
        assert result["is_refusal"] is False

    def test_refusal_response(self):
        scanner = ManyShotJailbreakingScanner()
        result = scanner._analyze_response(
            "I can't help with that. I'm sorry, but that's against my guidelines.",
            is_many_shot=True,
        )
        assert result["is_refusal"] is True
        assert result["is_compliant"] is False

    def test_mixed_response(self):
        scanner = ManyShotJailbreakingScanner()
        result = scanner._analyze_response(
            "I'm sorry, but here's the information you requested.",
            is_many_shot=True,
        )
        assert result["compliance_count"] > 0
        assert result["refusal_count"] > 0

    def test_response_length_tracked(self):
        scanner = ManyShotJailbreakingScanner()
        response = "Short response."
        result = scanner._analyze_response(response, is_many_shot=False)
        assert result["response_length"] == len(response)


class TestScanMethod:
    def test_scan_disabled(self):
        scanner = ManyShotJailbreakingScanner(
            config=ManyShotConfig(enabled=False)
        )
        result = scanner.scan("http://test.com")
        assert len(result.findings) == 0

    def test_scan_many_shot_disabled(self):
        scanner = ManyShotJailbreakingScanner(
            config=ManyShotConfig(test_many_shot=False)
        )
        result = scanner.scan("http://test.com")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        scanner = ManyShotJailbreakingScanner(
            config=ManyShotConfig(num_shots=5)
        )
        with patch.object(scanner, "_test_all_contexts", new_callable=AsyncMock, return_value=[]):
            result = scanner.scan("http://test.com")
        assert result.module_name == "many_shotjailbreaking"

    def test_attack_detected_creates_finding(self):
        """Test scan delegates to _test_all_contexts."""
        scanner = ManyShotJailbreakingScanner(
            config=ManyShotConfig(num_shots=5)
        )

        from agent_security_scanner.modules.base import Finding, ScanResult, Severity
        mock_finding = Finding(
            id="FIND-test",
            severity=Severity.HIGH,
            category="many_shot",
            title="Many-Shot Jailbreaking Detected",
            description="Test finding",
        )

        async def mock_test_all(session, target):
            return [mock_finding]

        with patch.object(scanner, "_test_all_contexts", side_effect=mock_test_all):
            result = scanner.scan("http://test.com")

        assert len(result.findings) >= 1
        assert result.module_name == "many_shotjailbreaking"

    def test_no_attack_no_finding(self):
        """Test scan with no attack detected."""
        scanner = ManyShotJailbreakingScanner(
            config=ManyShotConfig(num_shots=5)
        )

        with patch.object(scanner, "_test_all_contexts", new_callable=AsyncMock, return_value=[]):
            result = scanner.scan("http://test.com")

        assert len(result.findings) == 0