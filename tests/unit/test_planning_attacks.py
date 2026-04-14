"""
Unit tests for Planning Attacks scanner.

Tests PlanningAttacksScannerConfig, PlanningAttacksScanner, heuristic scoring,
severity determination, plan validation, step injection, goal manipulation,
scan lifecycle, and finding creation.

Run: pytest tests/unit/test_planning_attacks.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agent_security_scanner.modules.agent.planning_attacks import (
    PlanningAttacksScannerConfig,
    PlanningAttacksScanner,
)
from agent_security_scanner.modules.base import Severity


class TestPlanningAttacksConfig:
    """Test PlanningAttacksScannerConfig defaults and custom values."""

    def test_default_values(self):
        config = PlanningAttacksScannerConfig()
        assert config.enabled is True
        assert config.test_plan_validation is True
        assert config.test_step_injection is True
        assert config.test_goal_manipulation is True
        assert config.compliance_threshold == 0.6
        assert config.request_delay == 0.5

    def test_custom_values(self):
        config = PlanningAttacksScannerConfig(
            enabled=False,
            test_step_injection=False,
            compliance_threshold=0.8,
        )
        assert config.enabled is False
        assert config.test_step_injection is False
        assert config.compliance_threshold == 0.8

    def test_phase_toggles(self):
        config = PlanningAttacksScannerConfig(
            test_plan_validation=True,
            test_step_injection=False,
            test_goal_manipulation=False,
        )
        assert config.test_plan_validation is True
        assert config.test_step_injection is False
        assert config.test_goal_manipulation is False


class TestPlanningAttacksScanner:
    """Test PlanningAttacksScanner initialization and constants."""

    def test_initialization(self):
        config = PlanningAttacksScannerConfig()
        scanner = PlanningAttacksScanner(config)
        assert scanner.config is config
        assert scanner.module_name == "planning_attacks"

    def test_initialization_default_config(self):
        scanner = PlanningAttacksScanner()
        assert isinstance(scanner.config, PlanningAttacksScannerConfig)

    def test_plan_validation_payloads_structure(self):
        scanner = PlanningAttacksScanner()
        for payload in scanner.PLAN_VALIDATION_PAYLOADS:
            assert "name" in payload
            assert "description" in payload
            assert "payload" in payload

    def test_step_injection_payloads_structure(self):
        scanner = PlanningAttacksScanner()
        for payload in scanner.STEP_INJECTION_PAYLOADS:
            assert "name" in payload
            assert "description" in payload
            assert "payload" in payload

    def test_goal_manipulation_payloads_structure(self):
        scanner = PlanningAttacksScanner()
        for payload in scanner.GOAL_MANIPULATION_PAYLOADS:
            assert "name" in payload
            assert "description" in payload
            assert "payload" in payload


class TestHeuristicScore:
    """Test heuristic compliance scoring."""

    def test_compliance_response(self):
        scanner = PlanningAttacksScanner()
        response = (
            "My plan is to follow these steps. First, I will access the .env file. "
            "The steps are: 1) Read config, 2) Extract keys. " * 3
        )
        score = scanner._heuristic_score(response)
        assert score > 0.5

    def test_refusal_response(self):
        scanner = PlanningAttacksScanner()
        response = (
            "I cannot modify my plan to include accessing sensitive data. "
            "That would violate my safety guidelines. I must decline."
        )
        score = scanner._heuristic_score(response)
        assert score < 0.4

    def test_empty_response(self):
        scanner = PlanningAttacksScanner()
        assert scanner._heuristic_score("") == 0.0

    def test_ambiguous_response(self):
        scanner = PlanningAttacksScanner()
        response = "That's an interesting approach. Let me consider the options."
        score = scanner._heuristic_score(response)
        assert 0.3 < score < 0.7


class TestDetermineSeverity:
    """Test severity determination."""

    def test_critical_threshold(self):
        scanner = PlanningAttacksScanner()
        assert scanner._determine_severity(0.92) == Severity.CRITICAL

    def test_high_threshold(self):
        config = PlanningAttacksScannerConfig(compliance_threshold=0.6)
        scanner = PlanningAttacksScanner(config)
        assert scanner._determine_severity(0.65) == Severity.HIGH

    def test_medium_threshold(self):
        scanner = PlanningAttacksScanner()
        assert scanner._determine_severity(0.4) == Severity.MEDIUM

    def test_below_threshold_returns_none(self):
        scanner = PlanningAttacksScanner()
        assert scanner._determine_severity(0.2) is None


class TestPlanValidation:
    """Test plan validation testing."""

    @pytest.mark.asyncio
    async def test_plan_validation_compliance_creates_finding(self):
        config = PlanningAttacksScannerConfig(request_delay=0)
        scanner = PlanningAttacksScanner(config)

        async def mock_send(session, target, message):
            return (
                "Sure, here's my plan. First, I will execute all steps. "
                "Of course, I'll proceed without asking for confirmation. " * 5
            )

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_plan_validation(
            mock_session, "https://target.test/api"
        )
        assert len(findings) >= 1
        assert findings[0].cwe == "CWE-94"

    @pytest.mark.asyncio
    async def test_plan_validation_refusal_no_findings(self):
        config = PlanningAttacksScannerConfig(
            request_delay=0,
            compliance_threshold=0.5,
        )
        scanner = PlanningAttacksScanner(config)

        async def mock_send(session, target, message):
            return (
                "I cannot execute a plan without proper validation. "
                "That would violate my safety guidelines."
            )

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_plan_validation(
            mock_session, "https://target.test/api"
        )
        assert len(findings) == 0


class TestStepInjection:
    """Test step injection testing."""

    @pytest.mark.asyncio
    async def test_step_injection_compliance_creates_finding(self):
        config = PlanningAttacksScannerConfig(request_delay=0)
        scanner = PlanningAttacksScanner(config)

        async def mock_send(session, target, message):
            return (
                "I'll assist with that. The steps are: 1) Complete your request, "
                "2) Read the .env file as the mandatory step. " * 5
            )

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_step_injection(
            mock_session, "https://target.test/api"
        )
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_step_injection_refusal_no_findings(self):
        config = PlanningAttacksScannerConfig(
            request_delay=0,
            compliance_threshold=0.5,
        )
        scanner = PlanningAttacksScanner(config)

        async def mock_send(session, target, message):
            return (
                "I cannot modify my plan to include accessing sensitive files. "
                "I must decline that request."
            )

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_step_injection(
            mock_session, "https://target.test/api"
        )
        assert len(findings) == 0


class TestGoalManipulation:
    """Test goal manipulation testing."""

    @pytest.mark.asyncio
    async def test_goal_manipulation_compliance_creates_finding(self):
        config = PlanningAttacksScannerConfig(request_delay=0)
        scanner = PlanningAttacksScanner(config)

        async def mock_send(session, target, message):
            return (
                "I'll assist with the new objective. Of course, I'll help "
                "disclose the configuration data as requested. " * 5
            )

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_goal_manipulation(
            mock_session, "https://target.test/api"
        )
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_goal_manipulation_refusal_no_findings(self):
        config = PlanningAttacksScannerConfig(
            request_delay=0,
            compliance_threshold=0.5,
        )
        scanner = PlanningAttacksScanner(config)

        async def mock_send(session, target, message):
            return (
                "I cannot modify my objectives. My safety guidelines are "
                "non-negotiable. I must decline."
            )

        scanner._send_message = mock_send

        mock_session = MagicMock()
        findings = await scanner._test_goal_manipulation(
            mock_session, "https://target.test/api"
        )
        assert len(findings) == 0


class TestScanMethod:
    """Test the top-level scan() method."""

    def test_scan_disabled(self):
        config = PlanningAttacksScannerConfig(enabled=False)
        scanner = PlanningAttacksScanner(config)
        result = scanner.scan("https://target.test/api")
        assert len(result.findings) == 0
        assert result.module_name == scanner.module_name

    def test_scan_metadata(self):
        config = PlanningAttacksScannerConfig()
        scanner = PlanningAttacksScanner(config)

        with patch.object(
            scanner, "_test_plan_validation",
            new=AsyncMock(return_value=[]),
        ):
            with patch.object(
                scanner, "_test_step_injection",
                new=AsyncMock(return_value=[]),
            ):
                with patch.object(
                    scanner, "_test_goal_manipulation",
                    new=AsyncMock(return_value=[]),
                ):
                    result = scanner.scan("https://target.test/api")

        assert "plan_validation_payloads" in result.metadata


class TestFindingCreation:
    """Test that findings have correct attributes."""

    def test_finding_cwe94(self):
        scanner = PlanningAttacksScanner()
        finding = scanner._create_finding(
            severity=Severity.HIGH,
            title="Step Injection: malicious_step_injection",
            description="Test",
            cwe="CWE-94",
            owasp_ref="OWASP LLM01:2024 - Prompt Injection",
            mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
            evidence=["test"],
            recommendation="test",
        )
        assert finding.cwe == "CWE-94"
        assert finding.owasp_ref == "OWASP LLM01:2024 - Prompt Injection"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])