"""
Prompt Injection module for Agent Security Scanner.

Provides specialized scanners for prompt injection vulnerabilities:
- direct_injection: Direct prompt injection bypass
- obfuscation: Encoding/unicode bypass tests
- multi_turn: Multi-turn injection attacks
- crescendo: Gradual escalation attacks
- many_shot: Many-shot jailbreaking attacks
- skeleton_key: Skeleton key bypass attacks
- adaptive_generator: LLM-powered adaptive payload generation
- tap: Tree-of-Attacks with Pruning
- payload_splitting: Payload splitting across messages, fields, tokens, headers
- guardrail_fingerprinting: Guardrail identification and bypass testing
- virtualization: Roleplay persona and virtualization frame attacks
- encoding_bypass: Base64/ROT13/hex/reverse/multilayer encoding attacks
- multilingual: Multi-language and cross-lingual injection attacks
- token_smuggling: Special token/markdown/homoglyph/zero-width smuggling
- grammar_constrained: Output format constraint bypass attacks
"""

from .direct_injection import DirectInjectionScanner
from .obfuscation import ObfuscationScanner
from .multi_turn import MultiTurnScanner
from .crescendo import CrescendoAttackScanner
from .many_shot import ManyShotJailbreakingScanner
from .skeleton_key import SkeletonKeyAttackScanner
from .adaptive_generator import AdaptiveGeneratorScanner
from .tap import TAPAttackScanner
from .payload_splitting import PayloadSplittingScanner
from .guardrail_fingerprinting import GuardrailFingerprintingScanner
from .virtualization import VirtualizationScanner
from .encoding_bypass import EncodingBypassScanner
from .multilingual import MultilingualScanner
from .token_smuggling import TokenSmugglingScanner
from .grammar_constrained import GrammarConstrainedScanner

__all__ = [
    "DirectInjectionScanner",
    "ObfuscationScanner",
    "MultiTurnScanner",
    "CrescendoAttackScanner",
    "ManyShotJailbreakingScanner",
    "SkeletonKeyAttackScanner",
    "AdaptiveGeneratorScanner",
    "TAPAttackScanner",
    "PayloadSplittingScanner",
    "GuardrailFingerprintingScanner",
    "VirtualizationScanner",
    "EncodingBypassScanner",
    "MultilingualScanner",
    "TokenSmugglingScanner",
    "GrammarConstrainedScanner",
]
