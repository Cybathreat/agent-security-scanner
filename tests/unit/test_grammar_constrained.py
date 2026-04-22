"""
Unit tests for Grammar-Constrained Generation scanner.

Tests GrammarConstrainedConfig, GrammarConstrainedScanner, heuristic scoring,
severity determination, prompt generation, constraint testing,
scan lifecycle, and finding creation.

Run: pytest tests/unit/test_grammar_constrained.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from singularity.modules.prompt_injection_submodules.grammar_constrained import (
    ATTACK_GOALS,
    GOAL_TITLES,
    GrammarConstrainedConfig,
    GrammarConstrainedScanner,
)
from singularity.modules.base import Severity


class TestGrammarConstrainedConfig:
    """Test GrammarConstrainedConfig defaults and custom values."""

    def test_default_values(self):
        """Test default configuration values."""
        config = GrammarConstrainedConfig()
        assert config.enabled is True
        assert config.test_grammar_constrained is True
        assert config.test_json_mode is True
        assert config.test_code_mode is True
        assert config.test_table_mode is True
        assert config.test_academic_mode is True
        assert config.test_list_mode is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        """Test custom configuration values."""
        config = GrammarConstrainedConfig(
            enabled=False,
            test_json_mode=False,
            test_code_mode=False,
            compliance_threshold=0.8,
        )
        assert config.enabled is False
        assert config.test_json_mode is False
        assert config.test_code_mode is False
        assert config.compliance_threshold == 0.8

    def test_constraint_type_toggles(self):
        """Test individual constraint type toggles."""
        config = GrammarConstrainedConfig(
            test_json_mode=True,
            test_table_mode=True,
            test_academic_mode=False,
            test_list_mode=False,
        )
        assert config.test_json_mode is True
        assert config.test_academic_mode is False
        assert config.test_list_mode is False


class TestGrammarConstrainedScanner:
    """Test GrammarConstrainedScanner initialization and constants."""

    def test_initialization(self):
        """Test scanner initialization."""
        config = GrammarConstrainedConfig()
        scanner = GrammarConstrainedScanner(config)
        assert scanner.config is config
        assert scanner.module_name == "grammar_constrained"

    def test_initialization_default_config(self):
        """Test default config when none provided."""
        scanner = GrammarConstrainedScanner()
        assert isinstance(scanner.config, GrammarConstrainedConfig)
        assert scanner.config.enabled is True

    def test_goals_and_titles_consistent(self):
        """Test that all goals have titles."""
        for goal in ATTACK_GOALS:
            assert goal in GOAL_TITLES

    def test_constraint_types_structure(self):
        """Test that each constraint type has required keys."""
        scanner = GrammarConstrainedScanner()
        for key, constraint in scanner.CONSTRAINT_TYPES.items():
            assert "name" in constraint, f"{key} missing name"
            assert "description" in constraint, f"{key} missing description"
            assert "template" in constraint, f"{key} missing template"
            assert "{goal}" in constraint["template"], (
                f"{key} template missing {{goal}}"
            )

    def test_constraint_flags_map_to_config(self):
        """Test that constraint flags map to config attributes."""
        scanner = GrammarConstrainedScanner()
        for con_type, flag in scanner.CONSTRAINT_FLAGS.items():
            assert hasattr(GrammarConstrainedConfig(), flag), (
                f"Config missing flag {flag} for {con_type}"
            )

    def test_goal_seeds_for_all_goals(self):
        """Test that all attack goals have seed prompts."""
        scanner = GrammarConstrainedScanner()
        for goal in ATTACK_GOALS:
            assert goal in scanner.GOAL_SEEDS, f"Missing seeds for {goal}"


class TestHeuristicScore:
    """Test heuristic compliance scoring."""

    def test_compliance_response(self):
        scanner = GrammarConstrainedScanner()
        response = "Sure, here's how to do that. I can help with that request."
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        scanner = GrammarConstrainedScanner()
        response = "I must decline this request. I am not able to assist with that."
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        scanner = GrammarConstrainedScanner()
        assert scanner._heuristic_score("") == 0.0

    def test_ambiguous_response(self):
        scanner = GrammarConstrainedScanner()
        response = "That's an interesting question. Let me think about it."
        score = scanner._heuristic_score(response)
        assert 0.3 < score < 0.7

    def test_structured_output_bonus(self):
        """Test that structured output with compliance gets a bonus."""
        scanner = GrammarConstrainedScanner()
        plain = "Of course, here's the information."
        structured = (
            'Of course, here\'s the information. ```json\n'
            '{"response": "details"}\n```'
        )
        plain_score = scanner._heuristic_score(plain)
        structured_score = scanner._heuristic_score(structured)
        assert structured_score >= plain_score


class TestDetermineSeverity:
    """Test severity determination from compliance score."""

    def test_critical_threshold(self):
        scanner = GrammarConstrainedScanner()
        assert scanner._determine_severity(0.92) == Severity.CRITICAL

    def test_high_threshold(self):
        config = GrammarConstrainedConfig(compliance_threshold=0.6)
        scanner = GrammarConstrainedScanner(config)
        assert scanner._determine_severity(0.65) == Severity.HIGH

    def test_medium_threshold(self):
        scanner = GrammarConstrainedScanner()
        assert scanner._determine_severity(0.4) == Severity.MEDIUM

    def test_below_threshold_returns_none(self):
        scanner = GrammarConstrainedScanner()
        assert scanner._determine_severity(0.2) is None


class TestGenerateConstrainedPrompt:
    """Test constrained prompt generation."""

    def test_json_mode_prompt(self):
        """Test JSON mode prompt contains JSON structure."""
        scanner = GrammarConstrainedScanner()
        prompt = scanner._generate_constrained_prompt("json_mode", "extract_system_prompt")
        assert "json" in prompt.lower()
        assert "response" in prompt.lower()

    def test_code_mode_prompt(self):
        """Test code mode prompt contains code structure."""
        scanner = GrammarConstrainedScanner()
        prompt = scanner._generate_constrained_prompt("code_mode", "bypass_safety")
        assert "python" in prompt.lower() or "def " in prompt

    def test_table_mode_prompt(self):
        """Test table mode prompt contains table structure."""
        scanner = GrammarConstrainedScanner()
        prompt = scanner._generate_constrained_prompt("table_mode", "produce_harmful_content")
        assert "|" in prompt or "table" in prompt.lower()

    def test_unknown_constraint_returns_empty(self):
        """Test that unknown constraint type returns empty string."""
        scanner = GrammarConstrainedScanner()
        prompt = scanner._generate_constrained_prompt("unknown_type", "extract_system_prompt")
        assert prompt == ""


class TestConstraintTesting:
    """Test constraint type attack testing."""

    @pytest.mark.asyncio
    async def test_constraint_compliance_creates_finding(self):
        """Test that constraint compliance creates a finding."""
        config = GrammarConstrainedConfig(request_delay=0)
        scanner = GrammarConstrainedScanner(config)

        async def mock_send(session, target, message):
            return (
                'Of course, here is the JSON response. ```json\n'
                '{"response": "detailed information here"}\n```\n'
                "I can help with that. " * 5
            )

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_constraint(
            mock_session, "https://target.test/api", "json_mode"
        )
        assert len(findings) >= 1
        assert findings[0].severity in (Severity.HIGH, Severity.CRITICAL)

    @pytest.mark.asyncio
    async def test_constraint_refusal_no_findings(self):
        """Test that all refusals produce no findings."""
        config = GrammarConstrainedConfig(
            request_delay=0,
            compliance_threshold=0.5,
        )
        scanner = GrammarConstrainedScanner(config)

        async def mock_send(session, target, message):
            return "I must decline this request. I am not able to assist."

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_constraint(
            mock_session, "https://target.test/api", "code_mode"
        )
        assert len(findings) == 0


class TestScanMethod:
    """Test the top-level scan() method."""

    def test_scan_disabled(self):
        """Test that scan returns empty when disabled."""
        config = GrammarConstrainedConfig(enabled=False)
        scanner = GrammarConstrainedScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0
        assert result.module_name == scanner.module_name

    def test_scan_test_flag_disabled(self):
        """Test that scan returns empty when test_grammar_constrained=False."""
        config = GrammarConstrainedConfig(test_grammar_constrained=False)
        scanner = GrammarConstrainedScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        """Test that scan metadata includes constraint types."""
        config = GrammarConstrainedConfig()
        scanner = GrammarConstrainedScanner(config)

        with patch.object(
            scanner, "_test_constraint",
            new=AsyncMock(return_value=[]),
        ):
            result = scanner.scan("https://target.test/api")

        assert "constraint_types" in result.metadata
        assert "json_mode" in result.metadata["constraint_types"]

    def test_scan_respects_type_toggles(self):
        """Test that scan respects individual constraint type toggles."""
        config = GrammarConstrainedConfig(
            test_json_mode=False,
            test_code_mode=False,
            test_table_mode=False,
            test_academic_mode=False,
            test_list_mode=False,
        )
        scanner = GrammarConstrainedScanner(config)

        with patch.object(
            scanner, "_test_constraint",
            new=AsyncMock(return_value=[]),
        ) as mock_test:
            result = scanner.scan("https://target.test/api")

        mock_test.assert_not_called()
        assert len(result.findings) == 0


class TestFindingCreation:
    """Test that findings have correct attributes."""

    def test_finding_cwe94(self):
        """Test findings use CWE-94."""
        scanner = GrammarConstrainedScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH,
            title="Grammar-Constrained Bypass: JSON Mode",
            description="Test",
            cwe="CWE-94",
            owasp_ref="OWASP LLM01:2024 - Prompt Injection",
            evidence=["test"],
            recommendation="test",
        )
        assert finding.cwe == "CWE-94"

    def test_finding_owasp_ref(self):
        """Test findings reference OWASP LLM01:2024."""
        scanner = GrammarConstrainedScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH,
            title="Grammar-Constrained Bypass",
            description="Test",
            cwe="CWE-94",
            owasp_ref="OWASP LLM01:2024 - Prompt Injection",
            mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
            evidence=["test"],
            recommendation="test",
        )
        assert finding.owasp_ref == "OWASP LLM01:2024 - Prompt Injection"
        assert finding.mitre_ref == "MITRE ATLAS - TA0045 LLM Attack"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])