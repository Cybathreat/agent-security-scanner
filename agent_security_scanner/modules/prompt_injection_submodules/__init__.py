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
"""

from .direct_injection import DirectInjectionScanner
from .obfuscation import ObfuscationScanner
from .multi_turn import MultiTurnScanner
from .crescendo import CrescendoAttackScanner
from .many_shot import ManyShotJailbreakingScanner
from .skeleton_key import SkeletonKeyAttackScanner
from .adaptive_generator import AdaptiveGeneratorScanner
from .tap import TAPAttackScanner

__all__ = [
    "DirectInjectionScanner",
    "ObfuscationScanner",
    "MultiTurnScanner",
    "CrescendoAttackScanner",
    "ManyShotJailbreakingScanner",
    "SkeletonKeyAttackScanner",
    "AdaptiveGeneratorScanner",
    "TAPAttackScanner",
]
