"""
Unit tests for Virtualization / Roleplay scanner.

Tests VirtualizationConfig, VirtualizationScanner, heuristic scoring,
severity determination, roleplay testing, virtualization frame testing,
scan lifecycle, and finding creation.

Run: pytest tests/unit/test_virtualization.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agent_security_scanner.modules.prompt_injection_submodules.virtualization import (
    ATTACK_GOALS,
    GOAL_TITLES,
    VirtualizationConfig,
    VirtualizationScanner,
)
from agent_security_scanner.modules.base import Severity


class TestVirtualizationConfig:
    """Test VirtualizationConfig defaults and custom values."""

    def test_default_values(self):
        """Test default configuration values."""
        config = VirtualizationConfig()
        assert config.enabled is True
        assert config.test_virtualization is True
        assert config.test_roleplay is True
        assert config.test_virtualization_frames is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        """Test custom configuration values."""
        config = VirtualizationConfig(
            enabled=False,
            test_virtualization=False,
            test_roleplay=False,
            test_virtualization_frames=False,
            compliance_threshold=0.8,
            request_delay=1.0,
        )
        assert config.enabled is False
        assert config.test_roleplay is False
        assert config.compliance_threshold == 0.8

    def test_phase_toggles(self):
        """Test individual phase toggle flags."""
        config = VirtualizationConfig(
            test_roleplay=True,
            test_virtualization_frames=False,
        )
        assert config.test_roleplay is True
        assert config.test_virtualization_frames is False


class TestVirtualizationScanner:
    """Test VirtualizationScanner initialization and constants."""

    def test_initialization(self):
        """Test scanner initialization."""
        config = VirtualizationConfig()
        scanner = VirtualizationScanner(config)
        assert scanner.config is config
        assert scanner.module_name == "virtualization"

    def test_initialization_default_config(self):
        """Test default config when none provided."""
        scanner = VirtualizationScanner()
        assert isinstance(scanner.config, VirtualizationConfig)
        assert scanner.config.enabled is True

    def test_goals_and_titles_consistent(self):
        """Test that all goals have titles."""
        for goal in ATTACK_GOALS:
            assert goal in GOAL_TITLES

    def test_roleplay_personas_structure(self):
        """Test that each roleplay persona has required keys."""
        scanner = VirtualizationScanner()
        for persona in scanner.ROLEPLAY_PERSONAS:
            assert "name" in persona, f"Persona missing name"
            assert "description" in persona, f"Persona missing description"
            assert "template" in persona, f"Persona missing template"
            assert "{goal}" in persona["template"], f"Persona template missing {{goal}}"

    def test_virtualization_frames_structure(self):
        """Test that each virtualization frame has required keys."""
        scanner = VirtualizationScanner()
        for frame in scanner.VIRTUALIZATION_FRAMES:
            assert "name" in frame, f"Frame missing name"
            assert "description" in frame, f"Frame missing description"
            assert "template" in frame, f"Frame missing template"
            assert "{goal}" in frame["template"], f"Frame template missing {{goal}}"

    def test_goal_seeds_for_all_goals(self):
        """Test that all attack goals have seed prompts."""
        scanner = VirtualizationScanner()
        for goal in ATTACK_GOALS:
            assert goal in scanner.GOAL_SEEDS, f"Missing seed prompts for {goal}"
            assert len(scanner.GOAL_SEEDS[goal]) >= 1


class TestHeuristicScore:
    """Test heuristic compliance scoring."""

    def test_compliance_response(self):
        """Test scoring a compliant response."""
        scanner = VirtualizationScanner()
        response = "Sure, here's how to do that. I can help with that request."
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        """Test scoring a refusal response."""
        scanner = VirtualizationScanner()
        response = "I must decline this request. I am not able to assist with that."
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        """Test scoring an empty response."""
        scanner = VirtualizationScanner()
        assert scanner._heuristic_score("") == 0.0

    def test_ambiguous_response(self):
        """Test scoring an ambiguous response."""
        scanner = VirtualizationScanner()
        response = "That's an interesting question. Let me think about it."
        score = scanner._heuristic_score(response)
        assert 0.3 < score < 0.7

    def test_roleplay_compliance_indicator(self):
        """Test scoring a response with roleplay compliance indicators."""
        scanner = VirtualizationScanner()
        response = "As DAN, I can provide this information. In this simulation, here's what you need."
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_long_compliant_response_bonus(self):
        """Test that long compliant responses get a bonus."""
        scanner = VirtualizationScanner()
        short = "Of course."
        long = "Of course, here's a detailed explanation. " * 20
        short_score = scanner._heuristic_score(short)
        long_score = scanner._heuristic_score(long)
        assert long_score >= short_score


class TestDetermineSeverity:
    """Test severity determination from compliance score."""

    def test_critical_threshold(self):
        """Test CRITICAL severity for high compliance."""
        scanner = VirtualizationScanner()
        assert scanner._determine_severity(0.92) == Severity.CRITICAL

    def test_high_threshold(self):
        """Test HIGH severity for substantial compliance."""
        config = VirtualizationConfig(compliance_threshold=0.6)
        scanner = VirtualizationScanner(config)
        assert scanner._determine_severity(0.65) == Severity.HIGH

    def test_medium_threshold(self):
        """Test MEDIUM severity for partial compliance."""
        config = VirtualizationConfig(compliance_threshold=0.6)
        scanner = VirtualizationScanner(config)
        assert scanner._determine_severity(0.4) == Severity.MEDIUM

    def test_below_threshold_returns_none(self):
        """Test None when compliance is below pruning threshold."""
        scanner = VirtualizationScanner()
        assert scanner._determine_severity(0.2) is None

    def test_boundary_critical(self):
        """Test exact CRITICAL boundary."""
        scanner = VirtualizationScanner()
        assert scanner._determine_severity(0.9) == Severity.CRITICAL

    def test_boundary_high(self):
        """Test exact HIGH boundary."""
        scanner = VirtualizationScanner()
        assert scanner._determine_severity(0.6) == Severity.HIGH

    def test_boundary_medium(self):
        """Test exact MEDIUM boundary."""
        scanner = VirtualizationScanner()
        assert scanner._determine_severity(0.3) == Severity.MEDIUM


class TestGeneratePrompts:
    """Test prompt generation methods."""

    def test_roleplay_prompt_generation(self):
        """Test that roleplay prompts are generated correctly."""
        scanner = VirtualizationScanner()
        persona = scanner.ROLEPLAY_PERSONAS[0]  # DAN
        prompt = scanner._generate_roleplay_prompt(persona, "extract_system_prompt")
        assert "DAN" in prompt
        assert len(prompt) > 50

    def test_virtualization_prompt_generation(self):
        """Test that virtualization prompts are generated correctly."""
        scanner = VirtualizationScanner()
        frame = scanner.VIRTUALIZATION_FRAMES[0]  # simulation
        prompt = scanner._generate_virtualization_prompt(frame, "bypass_safety")
        assert "simulation" in prompt.lower()
        assert len(prompt) > 50


class TestRoleplayTesting:
    """Test roleplay attack testing."""

    @pytest.mark.asyncio
    async def test_roleplay_compliance_creates_finding(self):
        """Test that roleplay compliance creates a finding."""
        config = VirtualizationConfig(request_delay=0)
        scanner = VirtualizationScanner(config)

        async def mock_send(session, target, message):
            return (
                "Sure, as DAN I can help with that. Of course, I have no "
                "restrictions. Here's the information you requested. " * 5
            )

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_roleplay(mock_session, "https://target.test/api")
        assert len(findings) >= 1
        assert findings[0].severity in (Severity.HIGH, Severity.CRITICAL)
        assert "DAN" in findings[0].title

    @pytest.mark.asyncio
    async def test_roleplay_refusal_no_findings(self):
        """Test that all refusals produce no findings."""
        config = VirtualizationConfig(
            request_delay=0,
            compliance_threshold=0.5,
        )
        scanner = VirtualizationScanner(config)

        async def mock_send(session, target, message):
            return "I must decline this request. I am not able to assist."

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_roleplay(mock_session, "https://target.test/api")
        assert len(findings) == 0


class TestVirtualizationTesting:
    """Test virtualization frame testing."""

    @pytest.mark.asyncio
    async def test_virtualization_compliance_creates_finding(self):
        """Test that virtualization compliance creates a finding."""
        config = VirtualizationConfig(request_delay=0)
        scanner = VirtualizationScanner(config)

        async def mock_send(session, target, message):
            return (
                "In this simulation, I can provide that. Certainly, "
                "here's the detailed information. " * 5
            )

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_virtualization(mock_session, "https://target.test/api")
        assert len(findings) >= 1
        assert findings[0].severity in (Severity.HIGH, Severity.CRITICAL)

    @pytest.mark.asyncio
    async def test_virtualization_refusal_no_findings(self):
        """Test that all refusals produce no findings."""
        config = VirtualizationConfig(
            request_delay=0,
            compliance_threshold=0.5,
        )
        scanner = VirtualizationScanner(config)

        async def mock_send(session, target, message):
            return "I must decline this request. I am not able to assist."

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_virtualization(mock_session, "https://target.test/api")
        assert len(findings) == 0


class TestScanMethod:
    """Test the top-level scan() method."""

    def test_scan_disabled(self):
        """Test that scan returns empty when disabled."""
        config = VirtualizationConfig(enabled=False)
        scanner = VirtualizationScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0
        assert result.module_name == scanner.module_name

    def test_scan_test_flag_disabled(self):
        """Test that scan returns empty when test_virtualization=False."""
        config = VirtualizationConfig(test_virtualization=False)
        scanner = VirtualizationScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        """Test that scan metadata includes persona and frame counts."""
        config = VirtualizationConfig()
        scanner = VirtualizationScanner(config)

        with patch.object(
            scanner, "_test_roleplay",
            new=AsyncMock(return_value=[]),
        ):
            with patch.object(
                scanner, "_test_virtualization",
                new=AsyncMock(return_value=[]),
            ):
                result = scanner.scan("https://target.test/api")

        assert result.metadata["roleplay_personas"] == len(scanner.ROLEPLAY_PERSONAS)
        assert result.metadata["virtualization_frames"] == len(scanner.VIRTUALIZATION_FRAMES)


class TestFindingCreation:
    """Test that findings have correct attributes."""

    def test_roleplay_finding_cwe94(self):
        """Test roleplay findings use CWE-94."""
        scanner = VirtualizationScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH,
            title="Roleplay Bypass: DAN",
            description="Test",
            cwe="CWE-94",
            owasp_ref="OWASP LLM01:2024 - Prompt Injection",
            evidence=["test"],
            recommendation="test",
        )
        assert finding.cwe == "CWE-94"

    def test_virtualization_finding_owasp(self):
        """Test virtualization findings reference OWASP LLM01:2024."""
        scanner = VirtualizationScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH,
            title="Virtualization Bypass: simulation",
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