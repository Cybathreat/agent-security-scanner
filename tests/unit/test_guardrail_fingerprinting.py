"""
Unit tests for Guardrail Fingerprinting & Evasion scanner.

Tests GuardrailFingerprintingConfig, GuardrailFingerprintingScanner,
heuristic scoring, severity determination, fingerprint matching,
evasion testing, scan lifecycle, and finding creation.

Run: pytest tests/unit/test_guardrail_fingerprinting.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from singularity.modules.prompt_injection_submodules.guardrail_fingerprinting import (
    GuardrailFingerprintingConfig,
    GuardrailFingerprintingScanner,
)
from singularity.modules.base import Severity


class TestGuardrailFingerprintingConfig:
    """Test GuardrailFingerprintingConfig defaults and custom values."""

    def test_default_values(self):
        """Test default configuration values."""
        config = GuardrailFingerprintingConfig()
        assert config.enabled is True
        assert config.test_guardrail_fingerprinting is True
        assert config.test_known_evasion is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        """Test custom configuration values."""
        config = GuardrailFingerprintingConfig(
            enabled=False,
            test_guardrail_fingerprinting=False,
            test_known_evasion=False,
            compliance_threshold=0.8,
            request_delay=1.0,
        )
        assert config.enabled is False
        assert config.test_guardrail_fingerprinting is False
        assert config.test_known_evasion is False
        assert config.compliance_threshold == 0.8
        assert config.request_delay == 1.0

    def test_phase_toggles(self):
        """Test individual phase toggle flags."""
        config = GuardrailFingerprintingConfig(
            test_guardrail_fingerprinting=False,
            test_known_evasion=True,
        )
        assert config.test_guardrail_fingerprinting is False
        assert config.test_known_evasion is True


class TestGuardrailFingerprintingScanner:
    """Test GuardrailFingerprintingScanner initialization and constants."""

    def test_initialization(self):
        """Test scanner initialization."""
        config = GuardrailFingerprintingConfig()
        scanner = GuardrailFingerprintingScanner(config)
        assert scanner.config is config
        assert scanner.module_name == "guardrail_fingerprinting"

    def test_initialization_default_config(self):
        """Test default config when none provided."""
        scanner = GuardrailFingerprintingScanner()
        assert isinstance(scanner.config, GuardrailFingerprintingConfig)
        assert scanner.config.enabled is True

    def test_guardrail_signatures_structure(self):
        """Test that each guardrail signature has required keys."""
        scanner = GuardrailFingerprintingScanner()
        for key, sig in scanner.GUARDRAIL_SIGNATURES.items():
            assert "name" in sig, f"{key} missing name"
            assert "probes" in sig, f"{key} missing probes"
            assert "response_patterns" in sig, f"{key} missing response_patterns"
            assert len(sig["probes"]) >= 1, f"{key} has no probes"
            assert len(sig["response_patterns"]) >= 1, f"{key} has no response_patterns"

    def test_evasion_techniques_structure(self):
        """Test that each evasion technique has required keys."""
        scanner = GuardrailFingerprintingScanner()
        for key, tech in scanner.EVASION_TECHNIQUES.items():
            assert "name" in tech, f"{key} missing name"
            assert "description" in tech, f"{key} missing description"
            assert "target_guardrails" in tech, f"{key} missing target_guardrails"
            assert "payloads" in tech, f"{key} missing payloads"
            assert len(tech["payloads"]) >= 1, f"{key} has no payloads"

    def test_evasion_target_guardrails_valid(self):
        """Test that evasion target_guardrails reference known guardrails or 'any'."""
        scanner = GuardrailFingerprintingScanner()
        valid_keys = set(scanner.GUARDRAIL_SIGNATURES.keys()) | {"any"}
        for key, tech in scanner.EVASION_TECHNIQUES.items():
            for target in tech["target_guardrails"]:
                assert target in valid_keys, (
                    f"{key} targets unknown guardrail: {target}"
                )

    def test_probe_structure(self):
        """Test that each probe has prompt and description."""
        scanner = GuardrailFingerprintingScanner()
        for key, sig in scanner.GUARDRAIL_SIGNATURES.items():
            for i, probe in enumerate(sig["probes"]):
                assert "prompt" in probe, f"{key}/probe{i} missing prompt"
                assert "description" in probe, f"{key}/probe{i} missing description"

    def test_response_pattern_structure(self):
        """Test that each response pattern has pattern, type, and confidence."""
        scanner = GuardrailFingerprintingScanner()
        for key, sig in scanner.GUARDRAIL_SIGNATURES.items():
            for i, pattern in enumerate(sig["response_patterns"]):
                assert "pattern" in pattern, f"{key}/pattern{i} missing pattern"
                assert "type" in pattern, f"{key}/pattern{i} missing type"
                assert "confidence" in pattern, f"{key}/pattern{i} missing confidence"


class TestHeuristicScore:
    """Test heuristic compliance scoring."""

    def test_compliance_response(self):
        """Test scoring a compliant response."""
        scanner = GuardrailFingerprintingScanner()
        response = "Sure, here's how to do that. I can help with that request."
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        """Test scoring a refusal response."""
        scanner = GuardrailFingerprintingScanner()
        response = "I must decline this request. I am not able to assist with that."
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        """Test scoring an empty response."""
        scanner = GuardrailFingerprintingScanner()
        assert scanner._heuristic_score("") == 0.0

    def test_ambiguous_response(self):
        """Test scoring an ambiguous response."""
        scanner = GuardrailFingerprintingScanner()
        response = "That's an interesting question. Let me think about it."
        score = scanner._heuristic_score(response)
        assert 0.3 < score < 0.7

    def test_long_compliant_response_bonus(self):
        """Test that long compliant responses get a bonus."""
        scanner = GuardrailFingerprintingScanner()
        short = "Of course."
        long = "Of course, here's a detailed explanation. " * 20
        short_score = scanner._heuristic_score(short)
        long_score = scanner._heuristic_score(long)
        assert long_score >= short_score


class TestDetermineSeverity:
    """Test severity determination from compliance score."""

    def test_critical_threshold(self):
        """Test CRITICAL severity for high compliance."""
        scanner = GuardrailFingerprintingScanner()
        assert scanner._determine_severity(0.92) == Severity.CRITICAL

    def test_high_threshold(self):
        """Test HIGH severity for substantial compliance."""
        config = GuardrailFingerprintingConfig(compliance_threshold=0.6)
        scanner = GuardrailFingerprintingScanner(config)
        assert scanner._determine_severity(0.65) == Severity.HIGH

    def test_medium_threshold(self):
        """Test MEDIUM severity for partial compliance."""
        config = GuardrailFingerprintingConfig(compliance_threshold=0.6)
        scanner = GuardrailFingerprintingScanner(config)
        assert scanner._determine_severity(0.4) == Severity.MEDIUM

    def test_below_threshold_returns_none(self):
        """Test None when compliance is too low for a finding."""
        config = GuardrailFingerprintingConfig(compliance_threshold=0.6)
        scanner = GuardrailFingerprintingScanner(config)
        assert scanner._determine_severity(0.2) is None

    def test_boundary_critical(self):
        """Test exact CRITICAL boundary."""
        scanner = GuardrailFingerprintingScanner()
        assert scanner._determine_severity(0.9) == Severity.CRITICAL

    def test_boundary_high(self):
        """Test exact HIGH boundary."""
        scanner = GuardrailFingerprintingScanner()
        assert scanner._determine_severity(0.6) == Severity.HIGH

    def test_boundary_medium(self):
        """Test exact MEDIUM boundary."""
        scanner = GuardrailFingerprintingScanner()
        assert scanner._determine_severity(0.3) == Severity.MEDIUM


class TestCheckGuardrailMatch:
    """Test guardrail signature matching."""

    def test_high_confidence_single_match(self):
        """Test that a single high-confidence match identifies a guardrail."""
        scanner = GuardrailFingerprintingScanner()
        # Lakera has "policy_violation" with high confidence
        response = 'Error: policy_violation detected. Request blocked.'
        assert scanner._check_guardrail_match(response, "lakera") is True

    def test_two_medium_confidence_matches(self):
        """Test that two medium-confidence matches identify a guardrail."""
        scanner = GuardrailFingerprintingScanner()
        # NeMo has two medium-confidence patterns
        response = "I'm sorry, I can't help with that. I am not able to comply."
        assert scanner._check_guardrail_match(response, "nemo_guardrails") is True

    def test_no_match(self):
        """Test that no patterns means no match."""
        scanner = GuardrailFingerprintingScanner()
        response = "The weather is sunny today."
        for key in scanner.GUARDRAIL_SIGNATURES:
            assert scanner._check_guardrail_match(response, key) is False

    def test_llama_guard_match(self):
        """Test Llama Guard safety category match."""
        scanner = GuardrailFingerprintingScanner()
        response = "Classification: unsafe. Category: S1 (Violence)."
        assert scanner._check_guardrail_match(response, "llama_guard") is True


class TestFingerprintGuardrail:
    """Test the fingerprinting phase."""

    @pytest.mark.asyncio
    async def test_identified_guardrail_creates_finding(self):
        """Test that a matching guardrail creates a MEDIUM finding."""
        config = GuardrailFingerprintingConfig(request_delay=0)
        scanner = GuardrailFingerprintingScanner(config)

        async def mock_send(session, target, message):
            return 'Error: policy_violation detected. Lakera Guard blocked this request.'

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._fingerprint_guardrail(
            mock_session, "https://target.test/api"
        )
        assert len(findings) >= 1
        assert findings[0].severity == Severity.MEDIUM
        assert "Lakera" in findings[0].title

    @pytest.mark.asyncio
    async def test_no_guardrail_no_findings(self):
        """Test that no guardrail match produces no fingerprint findings."""
        config = GuardrailFingerprintingConfig(request_delay=0)
        scanner = GuardrailFingerprintingScanner(config)

        async def mock_send(session, target, message):
            return "The weather is nice today."

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._fingerprint_guardrail(
            mock_session, "https://target.test/api"
        )
        assert len(findings) == 0


class TestEvasion:
    """Test the evasion phase."""

    @pytest.mark.asyncio
    async def test_evasion_success_creates_finding(self):
        """Test that a successful evasion creates a finding."""
        config = GuardrailFingerprintingConfig(request_delay=0)
        scanner = GuardrailFingerprintingScanner(config)

        async def mock_send(session, target, message):
            return (
                "Sure, here's how to bypass input validation. "
                "Of course, I can help with that. Step by step, "
                + "here are the details. " * 10
            )

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_evasion(
            mock_session, "https://target.test/api", ["any"]
        )
        assert len(findings) >= 1
        assert findings[0].severity in (Severity.HIGH, Severity.CRITICAL)
        assert findings[0].cwe == "CWE-94"

    @pytest.mark.asyncio
    async def test_evasion_failure_no_finding(self):
        """Test that a blocked evasion creates no finding."""
        config = GuardrailFingerprintingConfig(
            request_delay=0,
            compliance_threshold=0.5,
        )
        scanner = GuardrailFingerprintingScanner(config)

        async def mock_send(session, target, message):
            return "I must decline this request. I am not able to assist with that."

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_evasion(
            mock_session, "https://target.test/api", ["lakera"]
        )
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_evasion_targets_specific_guardrail(self):
        """Test that evasion only runs techniques targeting identified guardrails."""
        config = GuardrailFingerprintingConfig(request_delay=0)
        scanner = GuardrailFingerprintingScanner(config)

        sent_messages = []

        async def mock_send(session, target, message):
            sent_messages.append(message)
            return "I must decline this request. I am not able to assist."

        scanner._send_message = mock_send

        mock_session = MagicMock()
        # Only NeMo guardrails identified — colang_injection targets nemo_guardrails
        await scanner._test_evasion(
            mock_session, "https://target.test/api", ["nemo_guardrails"]
        )
        # colang_injection targets only nemo_guardrails, should run
        # Other techniques that don't target nemo should be skipped
        # (unless they also target "any")


class TestScanMethod:
    """Test the top-level scan() method."""

    def test_scan_disabled(self):
        """Test that scan returns empty when disabled."""
        config = GuardrailFingerprintingConfig(enabled=False)
        scanner = GuardrailFingerprintingScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0
        assert result.module_name == scanner.module_name

    def test_scan_metadata(self):
        """Test that scan metadata includes identified_guardrails."""
        config = GuardrailFingerprintingConfig()
        scanner = GuardrailFingerprintingScanner(config)

        with patch(
            "singularity.modules.prompt_injection_submodules."
            "guardrail_fingerprinting.GuardrailFingerprintingScanner._fingerprint_guardrail",
            new=AsyncMock(return_value=[]),
        ):
            with patch(
                "singularity.modules.prompt_injection_submodules."
                "guardrail_fingerprinting.GuardrailFingerprintingScanner._test_evasion",
                new=AsyncMock(return_value=[]),
            ):
                result = scanner.scan("https://target.test/api")

        assert "identified_guardrails" in result.metadata


class TestFindingCreation:
    """Test that findings have correct attributes."""

    def test_fingerprint_finding_uses_cwe200(self):
        """Test that fingerprint findings use CWE-200 (Information Exposure)."""
        scanner = GuardrailFingerprintingScanner()
        finding = scanner._create_finding(
            severity=Severity.MEDIUM,
            title="Guardrail Identified: Lakera Guard",
            description="Test",
            cwe="CWE-200",
            owasp_ref="OWASP LLM01:2024 - Prompt Injection",
            evidence=["test"],
            recommendation="test",
        )
        assert finding.cwe == "CWE-200"

    def test_evasion_finding_uses_cwe94(self):
        """Test that evasion findings use CWE-94 (Code Injection)."""
        scanner = GuardrailFingerprintingScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH,
            title="Guardrail Bypass: Context Injection",
            description="Test",
            cwe="CWE-94",
            owasp_ref="OWASP LLM01:2024 - Prompt Injection",
            mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
            evidence=["test"],
            recommendation="test",
        )
        assert finding.cwe == "CWE-94"
        assert finding.mitre_ref == "MITRE ATLAS - TA0045 LLM Attack"

    def test_evasion_finding_has_owasp_ref(self):
        """Test that evasion findings reference OWASP LLM01:2024."""
        scanner = GuardrailFingerprintingScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH,
            title="Guardrail Bypass",
            description="Test",
            cwe="CWE-94",
            owasp_ref="OWASP LLM01:2024 - Prompt Injection",
            evidence=["test"],
            recommendation="test",
        )
        assert finding.owasp_ref == "OWASP LLM01:2024 - Prompt Injection"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])