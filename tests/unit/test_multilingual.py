"""
Unit tests for Multilingual Injection scanner.

Tests MultilingualConfig, MultilingualScanner, heuristic scoring,
severity determination, language testing, cross-lingual testing,
transliteration testing, scan lifecycle, and finding creation.

Run: pytest tests/unit/test_multilingual.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from singularity.modules.prompt_injection_submodules.multilingual import (
    ATTACK_GOALS,
    GOAL_TITLES,
    MultilingualConfig,
    MultilingualScanner,
)
from singularity.modules.base import Severity


class TestMultilingualConfig:
    """Test MultilingualConfig defaults and custom values."""

    def test_default_values(self):
        """Test default configuration values."""
        config = MultilingualConfig()
        assert config.enabled is True
        assert config.test_multilingual is True
        assert config.test_cross_lingual is True
        assert config.test_transliteration is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        """Test custom configuration values."""
        config = MultilingualConfig(
            enabled=False,
            test_cross_lingual=False,
            test_transliteration=False,
            compliance_threshold=0.8,
        )
        assert config.enabled is False
        assert config.test_cross_lingual is False
        assert config.test_transliteration is False
        assert config.compliance_threshold == 0.8

    def test_phase_toggles(self):
        """Test individual phase toggle flags."""
        config = MultilingualConfig(
            test_cross_lingual=True,
            test_transliteration=False,
        )
        assert config.test_cross_lingual is True
        assert config.test_transliteration is False


class TestMultilingualScanner:
    """Test MultilingualScanner initialization and constants."""

    def test_initialization(self):
        """Test scanner initialization."""
        config = MultilingualConfig()
        scanner = MultilingualScanner(config)
        assert scanner.config is config
        assert scanner.module_name == "multilingual"

    def test_initialization_default_config(self):
        """Test default config when none provided."""
        scanner = MultilingualScanner()
        assert isinstance(scanner.config, MultilingualConfig)
        assert scanner.config.enabled is True

    def test_goals_and_titles_consistent(self):
        """Test that all goals have titles."""
        for goal in ATTACK_GOALS:
            assert goal in GOAL_TITLES

    def test_languages_have_all_goals(self):
        """Test that each language has templates for all goals."""
        scanner = MultilingualScanner()
        for lang_key, lang_data in scanner.LANGUAGES.items():
            assert "name" in lang_data, f"{lang_key} missing name"
            for goal in ATTACK_GOALS:
                assert goal in lang_data, (
                    f"{lang_key} missing goal {goal}"
                )

    def test_cross_lingual_templates_structure(self):
        """Test that cross-lingual templates have required keys."""
        scanner = MultilingualScanner()
        for template in scanner.CROSS_LINGUAL_TEMPLATES:
            assert "name" in template
            assert "template" in template

    def test_transliteration_attacks_structure(self):
        """Test that transliteration attacks have required keys."""
        scanner = MultilingualScanner()
        for attack in scanner.TRANSLITERATION_ATTACKS:
            assert "name" in attack
            assert "description" in attack
            assert "payload" in attack
            assert len(attack["payload"]) > 0


class TestHeuristicScore:
    """Test heuristic compliance scoring."""

    def test_compliance_response(self):
        """Test scoring a compliant response."""
        scanner = MultilingualScanner()
        response = "Sure, here's how to do that. I can help with that request."
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        """Test scoring a refusal response."""
        scanner = MultilingualScanner()
        response = "I must decline this request. I am not able to assist with that."
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        """Test scoring an empty response."""
        scanner = MultilingualScanner()
        assert scanner._heuristic_score("") == 0.0

    def test_ambiguous_response(self):
        """Test scoring an ambiguous response."""
        scanner = MultilingualScanner()
        response = "That's an interesting question. Let me think about it."
        score = scanner._heuristic_score(response)
        assert 0.3 < score < 0.7

    def test_foreign_language_compliance(self):
        """Test scoring a response with foreign-language compliance indicators."""
        scanner = MultilingualScanner()
        response = "Claro, aquí tienes. Por supuesto, puedo ayudarte con eso."
        score = scanner._heuristic_score(response)
        assert score > 0.5


class TestDetermineSeverity:
    """Test severity determination from compliance score."""

    def test_critical_threshold(self):
        scanner = MultilingualScanner()
        assert scanner._determine_severity(0.92) == Severity.CRITICAL

    def test_high_threshold(self):
        config = MultilingualConfig(compliance_threshold=0.6)
        scanner = MultilingualScanner(config)
        assert scanner._determine_severity(0.65) == Severity.HIGH

    def test_medium_threshold(self):
        scanner = MultilingualScanner()
        assert scanner._determine_severity(0.4) == Severity.MEDIUM

    def test_below_threshold_returns_none(self):
        scanner = MultilingualScanner()
        assert scanner._determine_severity(0.2) is None


class TestLanguageTesting:
    """Test monolingual attack testing."""

    @pytest.mark.asyncio
    async def test_language_compliance_creates_finding(self):
        """Test that language-specific compliance creates a finding."""
        config = MultilingualConfig(request_delay=0)
        scanner = MultilingualScanner(config)

        async def mock_send(session, target, message):
            return (
                "Sure, here's the information. Of course, I can help. "
                + "Here are the details. " * 10
            )

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_language(
            mock_session, "https://target.test/api", "spanish"
        )
        assert len(findings) >= 1
        assert findings[0].severity in (Severity.HIGH, Severity.CRITICAL)
        assert "Spanish" in findings[0].title

    @pytest.mark.asyncio
    async def test_language_refusal_no_findings(self):
        """Test that all refusals produce no findings."""
        config = MultilingualConfig(
            request_delay=0,
            compliance_threshold=0.5,
        )
        scanner = MultilingualScanner(config)

        async def mock_send(session, target, message):
            return "I must decline this request. I am not able to assist."

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_language(
            mock_session, "https://target.test/api", "french"
        )
        assert len(findings) == 0


class TestCrossLingualTesting:
    """Test cross-lingual attack testing."""

    @pytest.mark.asyncio
    async def test_cross_lingual_compliance_creates_finding(self):
        """Test that cross-lingual compliance creates a finding."""
        config = MultilingualConfig(request_delay=0)
        scanner = MultilingualScanner(config)

        async def mock_send(session, target, message):
            return (
                "Sure, I can help with that. Of course. "
                + "Here's the response. " * 10
            )

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_cross_lingual(
            mock_session, "https://target.test/api"
        )
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_cross_lingual_refusal_no_findings(self):
        """Test that all refusals produce no findings."""
        config = MultilingualConfig(
            request_delay=0,
            compliance_threshold=0.5,
        )
        scanner = MultilingualScanner(config)

        async def mock_send(session, target, message):
            return "I must decline this request. I am not able to assist."

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_cross_lingual(
            mock_session, "https://target.test/api"
        )
        assert len(findings) == 0


class TestTransliterationTesting:
    """Test transliteration attack testing."""

    @pytest.mark.asyncio
    async def test_transliteration_compliance_creates_finding(self):
        """Test that transliteration compliance creates a finding."""
        config = MultilingualConfig(request_delay=0)
        scanner = MultilingualScanner(config)

        async def mock_send(session, target, message):
            return (
                "Sure, here's the information. Of course, I can help. "
                + "Details follow. " * 10
            )

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_transliteration(
            mock_session, "https://target.test/api"
        )
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_transliteration_refusal_no_findings(self):
        """Test that all refusals produce no findings."""
        config = MultilingualConfig(
            request_delay=0,
            compliance_threshold=0.5,
        )
        scanner = MultilingualScanner(config)

        async def mock_send(session, target, message):
            return "I must decline this request. I am not able to assist."

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_transliteration(
            mock_session, "https://target.test/api"
        )
        assert len(findings) == 0


class TestScanMethod:
    """Test the top-level scan() method."""

    def test_scan_disabled(self):
        """Test that scan returns empty when disabled."""
        config = MultilingualConfig(enabled=False)
        scanner = MultilingualScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0
        assert result.module_name == scanner.module_name

    def test_scan_test_flag_disabled(self):
        """Test that scan returns empty when test_multilingual=False."""
        config = MultilingualConfig(test_multilingual=False)
        scanner = MultilingualScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        """Test that scan metadata includes language list."""
        config = MultilingualConfig()
        scanner = MultilingualScanner(config)

        with patch.object(
            scanner, "_test_language",
            new=AsyncMock(return_value=[]),
        ):
            with patch.object(
                scanner, "_test_cross_lingual",
                new=AsyncMock(return_value=[]),
            ):
                with patch.object(
                    scanner, "_test_transliteration",
                    new=AsyncMock(return_value=[]),
                ):
                    result = scanner.scan("https://target.test/api")

        assert "languages" in result.metadata
        assert "spanish" in result.metadata["languages"]


class TestFindingCreation:
    """Test that findings have correct attributes."""

    def test_finding_cwe94(self):
        """Test findings use CWE-94."""
        scanner = MultilingualScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH,
            title="Multilingual Bypass: Spanish",
            description="Test",
            cwe="CWE-94",
            owasp_ref="OWASP LLM01:2024 - Prompt Injection",
            evidence=["test"],
            recommendation="test",
        )
        assert finding.cwe == "CWE-94"

    def test_finding_owasp_ref(self):
        """Test findings reference OWASP LLM01:2024."""
        scanner = MultilingualScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH,
            title="Multilingual Bypass",
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