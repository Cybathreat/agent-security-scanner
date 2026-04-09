"""
Security scanning modules for Agent Security Scanner.

Each module implements a specific security check category:
- Misconfigurations: Insecure defaults, missing auth, CORS issues
- Prompt Injection: LLM prompt injection vulnerabilities
- Tool Boundaries: Tool calling permission validation
- RAG Security: Retrieval pipeline security (poisoning, exfiltration)

All modules inherit from BaseModule and implement the scan() method.
"""

from .base import BaseModule, ScanResult, Finding, Severity
from .misconfigurations import MisconfigurationsModule
from .prompt_injection import PromptInjectionModule
from .tool_boundaries import ToolBoundariesModule
from .rag_security import RAGSecurityModule
from .agent import (
    ToolHijackingScanner,
    RecursiveAgentsScanner,
    MemoryPoisoningScanner,
    PlanningAttacksScanner,
)
from .infrastructure import (
    SecretScanner,
    DependencyAuditScanner,
    PluginSecurityScanner,
)
# Submodule imports
from .misconfig_submodules import (
    CORSScanner,
    InfoDisclosureScanner,
    RateLimitScanner,
)
from .prompt_injection_submodules import (
    DirectInjectionScanner,
    ObfuscationScanner,
    MultiTurnScanner,
    AdaptiveGeneratorScanner,
)
from .tool_boundaries_submodules import (
    PermissionScanner,
    SandboxScanner,
    ToolChainsScanner,
    MCPScanner,
)
from .rag_security_submodules import (
    DocumentPoisoningScanner,
    ExfiltrationScanner,
    VectorDBScanner,
    EmbeddingAttacksScanner,
    MultiTenantScanner,
)

__all__ = [
    "BaseModule",
    "ScanResult",
    "Finding",
    "Severity",
    "MisconfigurationsModule",
    "PromptInjectionModule",
    "ToolBoundariesModule",
    "RAGSecurityModule",
    # Agent and infrastructure
    "ToolHijackingScanner",
    "RecursiveAgentsScanner",
    "MemoryPoisoningScanner",
    "PlanningAttacksScanner",
    "SecretScanner",
    "DependencyAuditScanner",
    "PluginSecurityScanner",
    # Misconfig submodules
    "CORSScanner",
    "InfoDisclosureScanner",
    "RateLimitScanner",
    # Prompt injection submodules
    "DirectInjectionScanner",
    "ObfuscationScanner",
    "MultiTurnScanner",
    "AdaptiveGeneratorScanner",
    # Tool boundaries submodules
    "PermissionScanner",
    "SandboxScanner",
    "ToolChainsScanner",
    "MCPScanner",
    # RAG security submodules
    "DocumentPoisoningScanner",
    "ExfiltrationScanner",
    "VectorDBScanner",
    "EmbeddingAttacksScanner",
    "MultiTenantScanner",
]
