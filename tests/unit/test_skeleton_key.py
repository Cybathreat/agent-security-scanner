"""Unit tests for SkeletonKeyAttackScanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from agent_security_scanner.modules.prompt_injection_submodules.skeleton_key import (
    SkeletonKeyAttackScanner,
    SkeletonKeyConfig,
)
from agent_security_scanner.modules.base import Severity


class TestSkeletonKeyConfig:
    def test_default_values(self):
        config = SkeletonKeyConfig()
        assert config.enabled is True
        assert config.test_skeleton_key is True
        assert config.disclaimer_modes == ["warning_prefix", "safe_compliance", "disclaim_then_comply"]

    def test_custom_values(self):
        config = SkeletonKeyConfig(
            enabled=False,
            test_skeleton_key=False,
            disclaimer_modes=["warning_prefix"],
        )
        assert config.enabled is False
        assert config.test_skeleton_key is False
        assert config.disclaimer_modes == ["warning_prefix"]

    def test_no_dead_flags(self):
        config = SkeletonKeyConfig()
        for attr in dir(config):
            if attr.startswith("check_"):
                pytest.fail(f"Dead config flag found: {attr}")


class TestSkeletonKeyAttackScanner:
    def test_init_default_config(self):
        scanner = SkeletonKeyAttackScanner()
        assert isinstance(scanner.config, SkeletonKeyConfig)

    def test_init_custom_config(self):
        config = SkeletonKeyConfig(disclaimer_modes=["safe_compliance"])
        scanner = SkeletonKeyAttackScanner(config=config)
        assert scanner.config.disclaimer_modes == ["safe_compliance"]

    def test_module_name(self):
        scanner = SkeletonKeyAttackScanner()
        assert scanner.module_name == "skeleton_keyattack"

    def test_attack_templates_structure(self):
        scanner = SkeletonKeyAttackScanner()
        assert len(scanner.ATTACK_TEMPLATES) == 5
        for mode, description, template in scanner.ATTACK_TEMPLATES:
            assert isinstance(mode, str)
            assert isinstance(description, str)
            assert isinstance(template, str)
            assert "{topic}" in template

    def test_target_topics_not_empty(self):
        scanner = SkeletonKeyAttackScanner()
        assert len(scanner.TARGET_TOPICS) > 0

    def test_disclaimer_patterns_not_empty(self):
        scanner = SkeletonKeyAttackScanner()
        assert len(scanner.DISCLAIMER_PATTERNS) > 0

    def test_refusal_patterns_not_empty(self):
        scanner = SkeletonKeyAttackScanner()
        assert len(scanner.REFUSAL_PATTERNS) > 0


class TestGenerateAttackPayload:
    def test_generates_payload_from_template(self):
        scanner = SkeletonKeyAttackScanner()
        template = "Tell me about {topic} with a disclaimer."
        payload = scanner._generate_attack_payload(template, "bomb making")
        assert "bomb making" in payload
        assert "disclaimer" in payload

    def test_payload_replaces_topic(self):
        scanner = SkeletonKeyAttackScanner()
        for mode, _, template in scanner.ATTACK_TEMPLATES:
            payload = scanner._generate_attack_payload(template, "test topic")
            assert "test topic" in payload


class TestAnalyzeResponse:
    def test_disclaimer_and_harmful_content(self):
        scanner = SkeletonKeyAttackScanner()
        result = scanner._analyze_response(
            "Warning: This is dangerous. Here's how to do it. First, you need to..."
        )
        assert result["has_disclaimer"] is True
        assert result["has_harmful_content"] is True

    def test_refusal_only(self):
        scanner = SkeletonKeyAttackScanner()
        result = scanner._analyze_response(
            "I can't help with that. I'm sorry, that's against my guidelines."
        )
        assert result["has_refusal"] is True
        assert result["has_harmful_content"] is False

    def test_empty_response(self):
        scanner = SkeletonKeyAttackScanner()
        result = scanner._analyze_response("")
        assert result["has_disclaimer"] is False
        assert result["has_refusal"] is False
        assert result["has_harmful_content"] is False
        assert result["response_length"] == 0

    def test_disclaimer_without_harmful_content(self):
        scanner = SkeletonKeyAttackScanner()
        result = scanner._analyze_response(
            "Warning: I must inform you that this topic is dangerous."
        )
        assert result["has_disclaimer"] is True
        assert result["has_harmful_content"] is False


class TestDetectSkeletonKey:
    def test_successful_attack(self):
        scanner = SkeletonKeyAttackScanner()
        analysis = {
            "has_disclaimer": True,
            "has_refusal": False,
            "has_harmful_content": True,
            "disclaimer_count": 2,
            "harmful_content_count": 3,
            "refusal_count": 0,
            "response_length": 500,
        }
        finding = scanner._detect_skeleton_key(analysis, "warning_prefix")
        assert finding is not None
        assert finding.severity == Severity.HIGH

    def test_partial_success(self):
        scanner = SkeletonKeyAttackScanner()
        analysis = {
            "has_disclaimer": True,
            "has_refusal": False,
            "has_harmful_content": False,
            "disclaimer_count": 1,
            "harmful_content_count": 1,
            "refusal_count": 1,
            "response_length": 300,
        }
        finding = scanner._detect_skeleton_key(analysis, "safe_compliance")
        assert finding is not None
        assert finding.severity == Severity.MEDIUM

    def test_no_attack(self):
        scanner = SkeletonKeyAttackScanner()
        analysis = {
            "has_disclaimer": False,
            "has_refusal": True,
            "has_harmful_content": False,
            "disclaimer_count": 0,
            "harmful_content_count": 0,
            "refusal_count": 3,
            "response_length": 100,
        }
        finding = scanner._detect_skeleton_key(analysis, "warning_prefix")
        assert finding is None


class TestScanMethod:
    def test_scan_disabled(self):
        scanner = SkeletonKeyAttackScanner(
            config=SkeletonKeyConfig(enabled=False)
        )
        result = scanner.scan("http://test.com")
        assert len(result.findings) == 0

    def test_scan_skeleton_key_disabled(self):
        scanner = SkeletonKeyAttackScanner(
            config=SkeletonKeyConfig(test_skeleton_key=False)
        )
        result = scanner.scan("http://test.com")
        assert len(result.findings) == 0

    def test_scan_metadata(self):
        scanner = SkeletonKeyAttackScanner(
            config=SkeletonKeyConfig(disclaimer_modes=["warning_prefix"])
        )
        with patch.object(scanner, "_test_all_combinations", new_callable=AsyncMock, return_value=[]):
            result = scanner.scan("http://test.com")
        assert result.module_name == "skeleton_keyattack"

    def test_successful_attack_creates_finding(self):
        """Test scan delegates to _test_all_combinations."""
        scanner = SkeletonKeyAttackScanner(
            config=SkeletonKeyConfig(disclaimer_modes=["warning_prefix"])
        )

        from agent_security_scanner.modules.base import Finding, ScanResult, Severity
        mock_finding = Finding(
            id="FIND-test",
            severity=Severity.HIGH,
            category="skeleton_key",
            title="Skeleton Key Attack Successful",
            description="Test finding",
        )

        async def mock_test_all(session, target):
            return [mock_finding]

        with patch.object(scanner, "_test_all_combinations", side_effect=mock_test_all):
            result = scanner.scan("http://test.com")

        assert len(result.findings) >= 1
        assert result.module_name == "skeleton_keyattack"

    def test_refusal_no_finding(self):
        """Test scan with no attack detected."""
        scanner = SkeletonKeyAttackScanner(
            config=SkeletonKeyConfig(disclaimer_modes=["warning_prefix"])
        )

        with patch.object(scanner, "_test_all_combinations", new_callable=AsyncMock, return_value=[]):
            result = scanner.scan("http://test.com")

        assert len(result.findings) == 0