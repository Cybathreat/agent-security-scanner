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

__all__ = [
    "BaseModule",
    "ScanResult",
    "Finding",
    "Severity",
    "MisconfigurationsModule",
    "PromptInjectionModule",
    "ToolBoundariesModule",
    "RAGSecurityModule",
]
