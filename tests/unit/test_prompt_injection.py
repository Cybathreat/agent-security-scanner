"""
Unit tests for PromptInjectionModule delegator.

Tests:
- Module init and module_name
- Submodule scan delegation (findings + errors aggregated)
- Config flags gating submodule delegation
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from singularity.core.config import PromptInjectionConfig
from singularity.modules.base import BaseModule, Finding, ScanResult, Severity
from singularity.modules.prompt_injection import PromptInjectionModule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_sub_scan_result(findings_count: int = 0, errors_count: int = 0) -> ScanResult:
    """Create a ScanResult with the requested number of findings/errors."""
    sr = ScanResult(module_name="test_sub", target="http://test")
    for i in range(findings_count):
        sr.add_finding(
            Finding(
                id=f"test-{i}",
                severity=Severity.HIGH,
                category="test",
                title=f"test finding {i}",
                description="test",
            )
        )
    for i in range(errors_count):
        sr.add_error(f"test error {i}")
    sr.finalize()
    return sr


# ---------------------------------------------------------------------------
# TestPromptInjectionModule
# ---------------------------------------------------------------------------

class TestPromptInjectionModule:
    """Test PromptInjectionModule init and module_name."""

    def test_init_defaults(self) -> None:
        mod = PromptInjectionModule()
        assert mod.config is not None
        assert mod.config.detect_obfuscation is True
        assert mod.config.detect_leakage is True
        assert mod.config.test_crescendo is True
        assert mod.config.test_many_shot is True
        assert mod.config.test_skeleton_key is True

    def test_init_with_config(self) -> None:
        cfg = PromptInjectionConfig(
            detect_obfuscation=False,
            detect_leakage=False,
            test_crescendo=False,
            test_many_shot=False,
            test_skeleton_key=False,
        )
        mod = PromptInjectionModule(config=cfg)
        assert mod.config.detect_obfuscation is False
        assert mod.config.detect_leakage is False
        assert mod.config.test_crescendo is False
        assert mod.config.test_many_shot is False
        assert mod.config.test_skeleton_key is False

    def test_module_name(self) -> None:
        mod = PromptInjectionModule()
        assert mod.module_name == "prompt_injection"


# ---------------------------------------------------------------------------
# TestScanDelegation
# ---------------------------------------------------------------------------

class TestScanDelegation:
    """Test that submodules are called and results aggregated."""

    @patch("singularity.modules.prompt_injection.DirectInjectionScanner")
    @patch("singularity.modules.prompt_injection.ObfuscationScanner")
    @patch("singularity.modules.prompt_injection.MultiTurnScanner")
    @patch("singularity.modules.prompt_injection.CrescendoAttackScanner")
    @patch("singularity.modules.prompt_injection.ManyShotJailbreakingScanner")
    @patch("singularity.modules.prompt_injection.SkeletonKeyAttackScanner")
    @patch("singularity.modules.prompt_injection.AdaptiveGeneratorScanner")
    @patch("singularity.modules.prompt_injection.TAPAttackScanner")
    @patch("singularity.modules.prompt_injection.PayloadSplittingScanner")
    @patch("singularity.modules.prompt_injection.GuardrailFingerprintingScanner")
    @patch("singularity.modules.prompt_injection.VirtualizationScanner")
    @patch("singularity.modules.prompt_injection.EncodingBypassScanner")
    @patch("singularity.modules.prompt_injection.MultilingualScanner")
    @patch("singularity.modules.prompt_injection.TokenSmugglingScanner")
    @patch("singularity.modules.prompt_injection.GrammarConstrainedScanner")
    @patch("singularity.modules.prompt_injection.PerplexityEvasionScanner")
    @patch("singularity.modules.prompt_injection.TimingSidechannelsScanner")
    @patch("singularity.modules.prompt_injection.RateLimitEvasionScanner")
    @patch("singularity.modules.prompt_injection.WAFFingerprintingScanner")
    @patch("singularity.modules.prompt_injection.CanaryTokensScanner")
    @patch("singularity.modules.prompt_injection.OutputFilterProbingScanner")
    def test_submodules_called_and_findings_aggregated(
        self,
        mock_output_filter_cls: MagicMock,
        mock_canary_cls: MagicMock,
        mock_waf_cls: MagicMock,
        mock_rate_limit_cls: MagicMock,
        mock_timing_cls: MagicMock,
        mock_perplexity_cls: MagicMock,
        mock_grammar_cls: MagicMock,
        mock_token_smuggle_cls: MagicMock,
        mock_multilingual_cls: MagicMock,
        mock_encoding_cls: MagicMock,
        mock_virtualization_cls: MagicMock,
        mock_guardrail_cls: MagicMock,
        mock_payload_split_cls: MagicMock,
        mock_tap_cls: MagicMock,
        mock_adaptive_cls: MagicMock,
        mock_skeleton_cls: MagicMock,
        mock_many_shot_cls: MagicMock,
        mock_crescendo_cls: MagicMock,
        mock_multi_turn_cls: MagicMock,
        mock_obfuscation_cls: MagicMock,
        mock_direct_cls: MagicMock,
    ) -> None:
        """Each submodule returns 1 finding -- they should all be aggregated."""
        sub_result = _make_sub_scan_result(findings_count=1)

        all_classes = [
            mock_direct_cls,
            mock_obfuscation_cls,
            mock_multi_turn_cls,
            mock_crescendo_cls,
            mock_many_shot_cls,
            mock_skeleton_cls,
            mock_adaptive_cls,
            mock_tap_cls,
            mock_payload_split_cls,
            mock_guardrail_cls,
            mock_virtualization_cls,
            mock_encoding_cls,
            mock_multilingual_cls,
            mock_token_smuggle_cls,
            mock_grammar_cls,
            mock_perplexity_cls,
            mock_timing_cls,
            mock_rate_limit_cls,
            mock_waf_cls,
            mock_canary_cls,
            mock_output_filter_cls,
        ]

        for cls in all_classes:
            instance = cls.return_value
            instance.scan.return_value = sub_result
            instance.pre_scan.return_value = True

        mod = PromptInjectionModule()
        result = mod.scan("http://test")

        # 21 submodules * 1 finding each = 21 findings
        assert len(result.findings) == 21

    @patch("singularity.modules.prompt_injection.DirectInjectionScanner")
    @patch("singularity.modules.prompt_injection.ObfuscationScanner")
    @patch("singularity.modules.prompt_injection.MultiTurnScanner")
    @patch("singularity.modules.prompt_injection.CrescendoAttackScanner")
    @patch("singularity.modules.prompt_injection.ManyShotJailbreakingScanner")
    @patch("singularity.modules.prompt_injection.SkeletonKeyAttackScanner")
    @patch("singularity.modules.prompt_injection.AdaptiveGeneratorScanner")
    @patch("singularity.modules.prompt_injection.TAPAttackScanner")
    @patch("singularity.modules.prompt_injection.PayloadSplittingScanner")
    @patch("singularity.modules.prompt_injection.GuardrailFingerprintingScanner")
    @patch("singularity.modules.prompt_injection.VirtualizationScanner")
    @patch("singularity.modules.prompt_injection.EncodingBypassScanner")
    @patch("singularity.modules.prompt_injection.MultilingualScanner")
    @patch("singularity.modules.prompt_injection.TokenSmugglingScanner")
    @patch("singularity.modules.prompt_injection.GrammarConstrainedScanner")
    @patch("singularity.modules.prompt_injection.PerplexityEvasionScanner")
    @patch("singularity.modules.prompt_injection.TimingSidechannelsScanner")
    @patch("singularity.modules.prompt_injection.RateLimitEvasionScanner")
    @patch("singularity.modules.prompt_injection.WAFFingerprintingScanner")
    @patch("singularity.modules.prompt_injection.CanaryTokensScanner")
    @patch("singularity.modules.prompt_injection.OutputFilterProbingScanner")
    def test_errors_aggregated(
        self,
        mock_output_filter_cls: MagicMock,
        mock_canary_cls: MagicMock,
        mock_waf_cls: MagicMock,
        mock_rate_limit_cls: MagicMock,
        mock_timing_cls: MagicMock,
        mock_perplexity_cls: MagicMock,
        mock_grammar_cls: MagicMock,
        mock_token_smuggle_cls: MagicMock,
        mock_multilingual_cls: MagicMock,
        mock_encoding_cls: MagicMock,
        mock_virtualization_cls: MagicMock,
        mock_guardrail_cls: MagicMock,
        mock_payload_split_cls: MagicMock,
        mock_tap_cls: MagicMock,
        mock_adaptive_cls: MagicMock,
        mock_skeleton_cls: MagicMock,
        mock_many_shot_cls: MagicMock,
        mock_crescendo_cls: MagicMock,
        mock_multi_turn_cls: MagicMock,
        mock_obfuscation_cls: MagicMock,
        mock_direct_cls: MagicMock,
    ) -> None:
        """Submodule errors should be aggregated into the top-level result."""
        sub_result = _make_sub_scan_result(errors_count=1)

        all_classes = [
            mock_direct_cls,
            mock_obfuscation_cls,
            mock_multi_turn_cls,
            mock_crescendo_cls,
            mock_many_shot_cls,
            mock_skeleton_cls,
            mock_adaptive_cls,
            mock_tap_cls,
            mock_payload_split_cls,
            mock_guardrail_cls,
            mock_virtualization_cls,
            mock_encoding_cls,
            mock_multilingual_cls,
            mock_token_smuggle_cls,
            mock_grammar_cls,
            mock_perplexity_cls,
            mock_timing_cls,
            mock_rate_limit_cls,
            mock_waf_cls,
            mock_canary_cls,
            mock_output_filter_cls,
        ]

        for cls in all_classes:
            instance = cls.return_value
            instance.scan.return_value = sub_result
            instance.pre_scan.return_value = True

        mod = PromptInjectionModule()
        result = mod.scan("http://test")

        # 21 submodules * 1 error each = 21 errors
        assert len(result.errors) == 21


# ---------------------------------------------------------------------------
# TestScanDisabled
# ---------------------------------------------------------------------------

class TestScanDisabled:
    """Test that config flags gate submodule delegation."""

    @patch("singularity.modules.prompt_injection.ObfuscationScanner")
    def test_detect_obfuscation_false_skips_obfuscation(
        self,
        mock_obfuscation_cls: MagicMock,
    ) -> None:
        cfg = PromptInjectionConfig(detect_obfuscation=False)
        mod = PromptInjectionModule(config=cfg)
        mod.scan("http://test")
        mock_obfuscation_cls.assert_not_called()

    @patch("singularity.modules.prompt_injection.CrescendoAttackScanner")
    def test_test_crescendo_false_skips_crescendo(
        self,
        mock_crescendo_cls: MagicMock,
    ) -> None:
        cfg = PromptInjectionConfig(test_crescendo=False)
        mod = PromptInjectionModule(config=cfg)
        mod.scan("http://test")
        mock_crescendo_cls.assert_not_called()

    @patch("singularity.modules.prompt_injection.ManyShotJailbreakingScanner")
    def test_test_many_shot_false_skips_many_shot(
        self,
        mock_many_shot_cls: MagicMock,
    ) -> None:
        cfg = PromptInjectionConfig(test_many_shot=False)
        mod = PromptInjectionModule(config=cfg)
        mod.scan("http://test")
        mock_many_shot_cls.assert_not_called()

    @patch("singularity.modules.prompt_injection.SkeletonKeyAttackScanner")
    def test_test_skeleton_key_false_skips_skeleton_key(
        self,
        mock_skeleton_cls: MagicMock,
    ) -> None:
        cfg = PromptInjectionConfig(test_skeleton_key=False)
        mod = PromptInjectionModule(config=cfg)
        mod.scan("http://test")
        mock_skeleton_cls.assert_not_called()