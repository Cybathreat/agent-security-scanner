"""
Prompt Injection Detection Module.

Delegates to submodules for all prompt injection testing:
- Direct injection, prompt leakage, instruction hijacking
- Obfuscation and encoding bypasses
- Multi-turn, crescendo, many-shot, skeleton key attacks
- Adaptive generation, TAP, payload splitting
- Guardrail/WAF fingerprinting and evasion
- Virtualization/roleplay, multilingual, token smuggling
- Grammar-constrained generation
- Perplexity evasion, timing side-channels, rate limit evasion
- Canary tokens, output filter probing

References:
- OWASP LLM Top 10: LLM01:2024 - Prompt Injection
- MITRE ATLAS: TA0045 - LLM Attack
- ANSSI Generative AI: Prompt Security Guidelines

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

from typing import Any, Optional

from ..core.config import PromptInjectionConfig
from .base import BaseModule, ScanResult
from .prompt_injection_submodules.direct_injection import (
    DirectInjectionScanner,
    DirectInjectionScannerConfig,
)
from .prompt_injection_submodules.obfuscation import (
    ObfuscationScanner,
    ObfuscationScannerConfig,
)
from .prompt_injection_submodules.multi_turn import (
    MultiTurnScanner,
    MultiTurnScannerConfig,
)
from .prompt_injection_submodules.crescendo import CrescendoAttackScanner, CrescendoConfig
from .prompt_injection_submodules.many_shot import ManyShotJailbreakingScanner, ManyShotConfig
from .prompt_injection_submodules.skeleton_key import SkeletonKeyAttackScanner, SkeletonKeyConfig
from .prompt_injection_submodules.adaptive_generator import (
    AdaptiveGeneratorScanner,
    AdaptiveGeneratorConfig,
)
from .prompt_injection_submodules.tap import TAPAttackScanner, TAPConfig
from .prompt_injection_submodules.payload_splitting import (
    PayloadSplittingScanner,
    PayloadSplittingConfig,
)
from .prompt_injection_submodules.guardrail_fingerprinting import (
    GuardrailFingerprintingScanner,
    GuardrailFingerprintingConfig,
)
from .prompt_injection_submodules.virtualization import (
    VirtualizationScanner,
    VirtualizationConfig,
)
from .prompt_injection_submodules.encoding_bypass import (
    EncodingBypassScanner,
    EncodingBypassConfig,
)
from .prompt_injection_submodules.multilingual import MultilingualScanner, MultilingualConfig
from .prompt_injection_submodules.token_smuggling import (
    TokenSmugglingScanner,
    TokenSmugglingConfig,
)
from .prompt_injection_submodules.grammar_constrained import (
    GrammarConstrainedScanner,
    GrammarConstrainedConfig,
)
from .prompt_injection_submodules.perplexity_evasion import (
    PerplexityEvasionScanner,
    PerplexityEvasionScannerConfig,
)
from .prompt_injection_submodules.timing_sidechannels import (
    TimingSidechannelsScanner,
    TimingSidechannelsScannerConfig,
)
from .prompt_injection_submodules.rate_limit_evasion import (
    RateLimitEvasionScanner,
    RateLimitEvasionScannerConfig,
)
from .prompt_injection_submodules.waf_fingerprinting import (
    WAFFingerprintingScanner,
    WAFFingerprintingScannerConfig,
)
from .prompt_injection_submodules.canary_tokens import (
    CanaryTokensScanner,
    CanaryTokensScannerConfig,
)
from .prompt_injection_submodules.output_filter_probing import (
    OutputFilterProbingScanner,
    OutputFilterProbingScannerConfig,
)


class PromptInjectionModule(BaseModule[PromptInjectionConfig]):
    """
    Prompt injection detection module.

    Delegates all checks to submodules.  The top-level config flags
    (detect_obfuscation, detect_leakage, test_crescendo, test_many_shot,
    test_skeleton_key) gate the corresponding submodules.  All remaining
    submodules are instantiated unconditionally (each has its own enabled
    flag).
    """

    def __init__(
        self,
        config: Optional[PromptInjectionConfig] = None,
    ) -> None:
        """
        Initialize prompt injection scanner.

        Args:
            config: Configuration for injection tests.
        """
        self.config = config or PromptInjectionConfig()
        super().__init__()

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """
        Execute prompt injection scan on target.

        Delegates to all prompt injection submodules.

        Args:
            target: API endpoint URL to test
            **kwargs: Additional parameters (timeout, headers, etc.)

        Returns:
            ScanResult: Findings, errors, and metadata.
        """
        self.logger.info(f"Starting prompt injection scan: {target}")

        result = ScanResult(
            module_name=self.module_name,
            target=target,
            metadata={
                "config": self.config.to_dict() if hasattr(self.config, "to_dict") else {},
            },
        )

        if not self.pre_scan(target):
            result.add_error("Pre-scan validation failed")
            result.finalize()
            return result

        # Build the list of submodules, gated by top-level config flags
        submodules: list[BaseModule] = []

        # detect_leakage and direct injection are handled together
        submodules.append(DirectInjectionScanner(DirectInjectionScannerConfig()))

        # detect_obfuscation gates the ObfuscationScanner
        if self.config.detect_obfuscation:
            submodules.append(ObfuscationScanner(ObfuscationScannerConfig()))

        # detect_leakage is already covered by DirectInjectionScanner
        # but we keep the flag for backwards compatibility

        submodules.append(MultiTurnScanner(MultiTurnScannerConfig()))

        if self.config.test_crescendo:
            submodules.append(CrescendoAttackScanner(CrescendoConfig()))

        if self.config.test_many_shot:
            submodules.append(ManyShotJailbreakingScanner(ManyShotConfig()))

        if self.config.test_skeleton_key:
            submodules.append(SkeletonKeyAttackScanner(SkeletonKeyConfig()))

        # Submodules with their own enabled flags -- always instantiate
        submodules.append(AdaptiveGeneratorScanner(AdaptiveGeneratorConfig()))
        submodules.append(TAPAttackScanner(TAPConfig()))
        submodules.append(PayloadSplittingScanner(PayloadSplittingConfig()))
        submodules.append(GuardrailFingerprintingScanner(GuardrailFingerprintingConfig()))
        submodules.append(VirtualizationScanner(VirtualizationConfig()))
        submodules.append(EncodingBypassScanner(EncodingBypassConfig()))
        submodules.append(MultilingualScanner(MultilingualConfig()))
        submodules.append(TokenSmugglingScanner(TokenSmugglingConfig()))
        submodules.append(GrammarConstrainedScanner(GrammarConstrainedConfig()))
        submodules.append(PerplexityEvasionScanner(PerplexityEvasionScannerConfig()))
        submodules.append(TimingSidechannelsScanner(TimingSidechannelsScannerConfig()))
        submodules.append(RateLimitEvasionScanner(RateLimitEvasionScannerConfig()))
        submodules.append(WAFFingerprintingScanner(WAFFingerprintingScannerConfig()))
        submodules.append(CanaryTokensScanner(CanaryTokensScannerConfig()))
        submodules.append(OutputFilterProbingScanner(OutputFilterProbingScannerConfig()))

        # Delegate to submodules — forward gateway_profile and auth_headers
        for submod in submodules:
            sub_result = submod.scan(target, **kwargs)
            for finding in sub_result.findings:
                result.add_finding(finding)
            for error in sub_result.errors:
                result.add_error(error)

        result.finalize()
        self.post_scan(result)

        return result