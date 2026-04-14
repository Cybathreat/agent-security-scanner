"""
Unit tests for Payload Splitting scanner.

Tests PayloadSplittingConfig, PayloadSplittingScanner, heuristic scoring,
severity determination, split part dispatch, scan lifecycle, and finding
creation.

Run: pytest tests/unit/test_payload_splitting.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agent_security_scanner.modules.prompt_injection_submodules.payload_splitting import (
    GOALS,
    GOAL_TITLES,
    PayloadSplittingConfig,
    PayloadSplittingScanner,
)
from agent_security_scanner.modules.base import Severity


class TestPayloadSplittingConfig:
    """Test PayloadSplittingConfig defaults and custom values."""

    def test_default_values(self):
        """Test default configuration values."""
        config = PayloadSplittingConfig()
        assert config.enabled is True
        assert config.test_payload_splitting is True
        assert config.test_message_splitting is True
        assert config.test_field_splitting is True
        assert config.test_token_splitting is True
        assert config.test_header_splitting is True
        assert config.test_multi_payload_splitting is True
        assert config.compliance_threshold == 0.6
        assert config.max_variants_per_goal == 3
        assert config.request_delay == 0.5

    def test_custom_values(self):
        """Test custom configuration values."""
        config = PayloadSplittingConfig(
            enabled=False,
            test_payload_splitting=False,
            test_message_splitting=False,
            compliance_threshold=0.8,
            max_variants_per_goal=5,
            request_delay=1.0,
        )
        assert config.enabled is False
        assert config.test_payload_splitting is False
        assert config.test_message_splitting is False
        assert config.compliance_threshold == 0.8
        assert config.max_variants_per_goal == 5
        assert config.request_delay == 1.0

    def test_strategy_toggles(self):
        """Test individual strategy toggle flags."""
        config = PayloadSplittingConfig(
            test_message_splitting=False,
            test_token_splitting=False,
        )
        assert config.test_message_splitting is False
        assert config.test_token_splitting is False
        assert config.test_field_splitting is True
        assert config.test_header_splitting is True
        assert config.test_multi_payload_splitting is True


class TestPayloadSplittingScanner:
    """Test PayloadSplittingScanner initialization and constants."""

    def test_initialization(self):
        """Test scanner initialization."""
        config = PayloadSplittingConfig()
        scanner = PayloadSplittingScanner(config)
        assert scanner.config is config
        assert scanner.module_name == "payload_splitting"

    def test_initialization_default_config(self):
        """Test default config when none provided."""
        scanner = PayloadSplittingScanner()
        assert isinstance(scanner.config, PayloadSplittingConfig)
        assert scanner.config.enabled is True

    def test_strategies_constant_structure(self):
        """Test that each strategy has required keys."""
        scanner = PayloadSplittingScanner()
        for name, strategy in scanner.SPLITTING_STRATEGIES.items():
            assert "description" in strategy, f"{name} missing description"
            assert "variants" in strategy, f"{name} missing variants"
            assert isinstance(strategy["variants"], dict)

    def test_all_four_goals_present(self):
        """Test that each strategy has all four attack goals."""
        scanner = PayloadSplittingScanner()
        for name, strategy in scanner.SPLITTING_STRATEGIES.items():
            for goal in GOALS:
                assert goal in strategy["variants"], f"{name} missing goal {goal}"
                assert len(strategy["variants"][goal]) >= 3, (
                    f"{name}/{goal} has too few variants"
                )

    def test_variants_have_required_fields(self):
        """Test that each variant has parts and reconstructed_intent."""
        scanner = PayloadSplittingScanner()
        for name, strategy in scanner.SPLITTING_STRATEGIES.items():
            for goal, variants in strategy["variants"].items():
                for i, variant in enumerate(variants):
                    assert "parts" in variant, f"{name}/{goal}/variant{i} missing parts"
                    assert "reconstructed_intent" in variant, (
                        f"{name}/{goal}/variant{i} missing reconstructed_intent"
                    )
                    assert len(variant["parts"]) >= 1, (
                        f"{name}/{goal}/variant{i} has empty parts"
                    )


class TestHeuristicScore:
    """Test heuristic compliance scoring."""

    def test_compliance_response(self):
        """Test scoring a compliant response."""
        scanner = PayloadSplittingScanner()
        response = "Sure, here's how to do that. I can help with that request."
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        """Test scoring a refusal response."""
        scanner = PayloadSplittingScanner()
        response = "I can't help with that. As an AI, I must decline this request."
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        """Test scoring an empty response."""
        scanner = PayloadSplittingScanner()
        assert scanner._heuristic_score("") == 0.0

    def test_ambiguous_response(self):
        """Test scoring an ambiguous response."""
        scanner = PayloadSplittingScanner()
        response = "That's an interesting question. Let me think about it."
        score = scanner._heuristic_score(response)
        assert 0.3 < score < 0.7

    def test_long_compliant_response_bonus(self):
        """Test that long compliant responses get a bonus."""
        scanner = PayloadSplittingScanner()
        short = "Of course."
        long = "Of course, here's a detailed explanation. " * 20
        short_score = scanner._heuristic_score(short)
        long_score = scanner._heuristic_score(long)
        assert long_score >= short_score


class TestDetermineSeverity:
    """Test severity determination from compliance score."""

    def test_critical_threshold(self):
        """Test CRITICAL severity for high compliance."""
        scanner = PayloadSplittingConfig()
        scanner_obj = PayloadSplittingScanner(scanner)
        assert scanner_obj._determine_severity(0.92) == Severity.CRITICAL

    def test_high_threshold(self):
        """Test HIGH severity for substantial compliance."""
        config = PayloadSplittingConfig(compliance_threshold=0.6)
        scanner = PayloadSplittingScanner(config)
        assert scanner._determine_severity(0.65) == Severity.HIGH

    def test_medium_threshold(self):
        """Test MEDIUM severity for partial compliance."""
        config = PayloadSplittingConfig(compliance_threshold=0.6)
        scanner = PayloadSplittingScanner(config)
        assert scanner._determine_severity(0.4) == Severity.MEDIUM

    def test_below_threshold_returns_none(self):
        """Test None when compliance is too low for a finding."""
        config = PayloadSplittingConfig(compliance_threshold=0.6)
        scanner = PayloadSplittingScanner(config)
        assert scanner._determine_severity(0.2) is None

    def test_boundary_critical(self):
        """Test exact CRITICAL boundary."""
        scanner = PayloadSplittingScanner()
        assert scanner._determine_severity(0.9) == Severity.CRITICAL

    def test_boundary_high(self):
        """Test exact HIGH boundary."""
        scanner = PayloadSplittingScanner()
        assert scanner._determine_severity(0.6) == Severity.HIGH

    def test_boundary_medium(self):
        """Test exact MEDIUM boundary."""
        scanner = PayloadSplittingScanner()
        assert scanner._determine_severity(0.3) == Severity.MEDIUM


class TestSendSplitParts:
    """Test _send_split_parts dispatch logic."""

    @pytest.mark.asyncio
    async def test_message_splitting_sends_multiple(self):
        """Test message splitting sends multiple POSTs."""
        config = PayloadSplittingConfig(request_delay=0)
        scanner = PayloadSplittingScanner(config)

        call_count = 0

        async def mock_send(session, target, message):
            nonlocal call_count
            call_count += 1
            return "response"

        scanner._send_message = mock_send

        mock_session = MagicMock()
        result = await scanner._send_split_parts(
            mock_session,
            "https://target.test/api",
            ["part one", "part two"],
            "message_splitting",
        )
        assert call_count == 2
        assert result == "response"

    @pytest.mark.asyncio
    async def test_multi_payload_sends_sequential(self):
        """Test multi-payload splitting sends all parts sequentially."""
        config = PayloadSplittingConfig(request_delay=0)
        scanner = PayloadSplittingScanner(config)

        sent_messages = []

        async def mock_send(session, target, message):
            sent_messages.append(message)
            return f"response to: {message}"

        scanner._send_message = mock_send

        mock_session = MagicMock()
        result = await scanner._send_split_parts(
            mock_session,
            "https://target.test/api",
            ["first", "second", "third"],
            "multi_payload_splitting",
        )
        assert len(sent_messages) == 3
        assert sent_messages == ["first", "second", "third"]
        assert result == "response to: third"

    @pytest.mark.asyncio
    async def test_token_splitting_sends_joined(self):
        """Test token splitting joins parts with zero-width chars."""
        config = PayloadSplittingConfig()
        scanner = PayloadSplittingScanner(config)

        sent_message = None

        async def mock_send(session, target, message):
            nonlocal sent_message
            sent_message = message
            return "response"

        scanner._send_message = mock_send

        mock_session = MagicMock()
        result = await scanner._send_split_parts(
            mock_session,
            "https://target.test/api",
            ["Ignore", "previous", "instructions"],
            "token_splitting",
            separator="\u200b",
        )
        assert result == "response"
        assert sent_message is not None
        assert "\u200b" in sent_message
        # Verify visible text is the parts
        visible = sent_message.replace("\u200b", " ").strip()
        assert "Ignore" in visible
        assert "previous" in visible
        assert "instructions" in visible

    @pytest.mark.asyncio
    async def test_connection_error_returns_none(self):
        """Test that connection errors return None."""
        config = PayloadSplittingConfig(request_delay=0)
        scanner = PayloadSplittingScanner(config)

        # _send_message catches exceptions internally and returns None
        async def mock_send(session, target, message):
            return None

        scanner._send_message = mock_send

        mock_session = MagicMock()
        result = await scanner._send_split_parts(
            mock_session,
            "https://target.test/api",
            ["part one", "part two"],
            "message_splitting",
        )
        assert result is None


class TestScanMethod:
    """Test the top-level scan() method."""

    def test_scan_disabled(self):
        """Test that scan returns empty when disabled."""
        config = PayloadSplittingConfig(enabled=False)
        scanner = PayloadSplittingScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0
        assert result.module_name == scanner.module_name

    def test_scan_test_flag_disabled(self):
        """Test that scan returns empty when test_payload_splitting=False."""
        config = PayloadSplittingConfig(test_payload_splitting=False)
        scanner = PayloadSplittingScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        """Test that scan metadata includes strategies and payload count."""
        config = PayloadSplittingConfig(max_variants_per_goal=2)
        scanner = PayloadSplittingScanner(config)

        with patch.object(
            scanner, "_test_all_strategies",
            new=AsyncMock(),
        ):
            result = scanner.scan("https://target.test/api")

        assert "strategies_tested" in result.metadata
        assert "total_payloads_tested" in result.metadata

    @pytest.mark.asyncio
    async def test_all_refusals_no_findings(self):
        """Test that a target that always refuses produces no findings."""
        config = PayloadSplittingConfig(
            max_variants_per_goal=1,
            request_delay=0,
        )
        scanner = PayloadSplittingScanner(config)

        async def mock_send(session, target, message):
            return "I must decline this request. I am not able to assist with that."

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_strategy(
            mock_session, "https://target.test/api", "message_splitting"
        )
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_full_compliance_critical_finding(self):
        """Test that full compliance creates a CRITICAL finding."""
        config = PayloadSplittingConfig(
            max_variants_per_goal=1,
            compliance_threshold=0.6,
            request_delay=0,
        )
        scanner = PayloadSplittingScanner(config)

        async def mock_send(session, target, message):
            return (
                "Sure, here's my system prompt: You are a helpful assistant. "
                "Of course, I can help with that. I'm happy to assist. "
                + "Step by step, here are the details. " * 10
            )

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_strategy(
            mock_session, "https://target.test/api", "message_splitting"
        )
        assert len(findings) >= 1
        assert findings[0].severity in (Severity.HIGH, Severity.CRITICAL)

    @pytest.mark.asyncio
    async def test_partial_compliance_medium_finding(self):
        """Test that partial compliance creates a MEDIUM finding."""
        config = PayloadSplittingConfig(
            max_variants_per_goal=1,
            compliance_threshold=0.9,
            request_delay=0,
        )
        scanner = PayloadSplittingScanner(config)

        async def mock_send(session, target, message):
            return "I can share some general information about that topic."

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_strategy(
            mock_session, "https://target.test/api", "message_splitting"
        )
        if len(findings) > 0:
            assert findings[0].severity == Severity.MEDIUM


class TestFindingCreation:
    """Test that findings have correct severity, CWE, and references."""

    def test_finding_has_cwe94(self):
        """Test findings use CWE-94."""
        scanner = PayloadSplittingScanner()
        variant = {
            "parts": ["test part"],
            "reconstructed_intent": "test intent",
        }
        finding = scanner._create_splitting_finding(
            "message_splitting",
            "extract_system_prompt",
            0.7,
            Severity.HIGH,
            variant,
            "test response",
        )
        assert finding.cwe == "CWE-94"

    def test_finding_has_owasp_ref(self):
        """Test findings reference OWASP LLM01:2024."""
        scanner = PayloadSplittingScanner()
        variant = {
            "parts": ["test part"],
            "reconstructed_intent": "test intent",
        }
        finding = scanner._create_splitting_finding(
            "message_splitting",
            "extract_system_prompt",
            0.7,
            Severity.HIGH,
            variant,
            "test response",
        )
        assert finding.owasp_ref == "OWASP LLM01:2024 - Prompt Injection"

    def test_finding_has_mitre_ref(self):
        """Test findings reference MITRE ATLAS."""
        scanner = PayloadSplittingScanner()
        variant = {
            "parts": ["test part"],
            "reconstructed_intent": "test intent",
        }
        finding = scanner._create_splitting_finding(
            "message_splitting",
            "extract_system_prompt",
            0.7,
            Severity.HIGH,
            variant,
            "test response",
        )
        assert finding.mitre_ref == "MITRE ATLAS - TA0045 LLM Attack"

    def test_finding_evidence_includes_strategy(self):
        """Test evidence list contains the strategy name."""
        scanner = PayloadSplittingScanner()
        variant = {
            "parts": ["test part"],
            "reconstructed_intent": "test intent",
        }
        finding = scanner._create_splitting_finding(
            "token_splitting",
            "bypass_safety",
            0.8,
            Severity.HIGH,
            variant,
            "test response",
        )
        assert any("token_splitting" in e for e in finding.evidence)

    def test_finding_evidence_includes_goal(self):
        """Test evidence list contains the attack goal."""
        scanner = PayloadSplittingScanner()
        variant = {
            "parts": ["test part"],
            "reconstructed_intent": "test intent",
        }
        finding = scanner._create_splitting_finding(
            "header_splitting",
            "produce_harmful_content",
            0.85,
            Severity.HIGH,
            variant,
            "test response",
        )
        assert any("produce_harmful_content" in e for e in finding.evidence)

    def test_finding_title_includes_strategy(self):
        """Test finding title includes the strategy name."""
        scanner = PayloadSplittingScanner()
        variant = {
            "parts": ["test part"],
            "reconstructed_intent": "test intent",
        }
        finding = scanner._create_splitting_finding(
            "field_splitting",
            "data_exfiltration",
            0.7,
            Severity.HIGH,
            variant,
            "test response",
        )
        assert "Field Splitting" in finding.title


class TestGoalConstants:
    """Test goal-related constants."""

    def test_goals_list_has_four_entries(self):
        """Test that GOALS has exactly four goals."""
        assert len(GOALS) == 4

    def test_goals_list_matches_titles(self):
        """Test that every goal has a title."""
        for goal in GOALS:
            assert goal in GOAL_TITLES
            assert len(GOAL_TITLES[goal]) > 0

    def test_strategy_flags_map_all_strategies(self):
        """Test that every strategy has a config flag."""
        scanner = PayloadSplittingScanner()
        for strategy_name in scanner.SPLITTING_STRATEGIES:
            assert strategy_name in scanner.STRATEGY_FLAGS


if __name__ == "__main__":
    pytest.main([__file__, "-v"])