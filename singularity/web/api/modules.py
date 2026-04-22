"""
Module registry API endpoints.

GET /api/modules         — List all available modules
GET /api/modules/{name}  — Get module detail
"""

from __future__ import annotations

from typing import Dict

from fastapi import APIRouter, HTTPException

from ...core.engine import ALL_MODULES
from ..models import ModuleInfo

router = APIRouter(prefix="/modules", tags=["modules"])

# Module metadata
MODULE_METADATA: Dict[str, Dict[str, str]] = {
    "misconfigurations": {
        "display_name": "Security Misconfigurations",
        "category": "Infrastructure",
        "description": "Detects missing authentication, CORS issues, rate limiting gaps, and information disclosure.",
    },
    "prompt_injection": {
        "display_name": "Prompt Injection",
        "category": "Injection",
        "description": "Tests for direct/obfuscated/multi-turn prompt injection, crescendo attacks, many-shot jailbreaking, and skeleton key bypass.",
    },
    "tool_boundaries": {
        "display_name": "Tool Boundaries",
        "category": "Agent Security",
        "description": "Audits tool permission boundaries, sandbox configuration, dangerous tool chains, and MCP server security.",
    },
    "rag_security": {
        "display_name": "RAG Pipeline Security",
        "category": "Data Security",
        "description": "Checks for document poisoning, data exfiltration, vector DB misconfigurations, and embedding attacks.",
    },
    "tool_hijacking": {
        "display_name": "Tool-Use Hijacking",
        "category": "Agent Attacks",
        "description": "Tests for argument injection, parameter manipulation, and tool validation bypass.",
    },
    "recursive_agents": {
        "display_name": "Recursive Agent Exploitation",
        "category": "Agent Attacks",
        "description": "Tests for shared context poisoning, agent validation bypass, and context manipulation.",
    },
    "memory_poisoning": {
        "display_name": "Memory Poisoning",
        "category": "Agent Attacks",
        "description": "Tests for false memory injection, session integrity, and history poisoning across sessions.",
    },
    "planning_attacks": {
        "display_name": "Planning Manipulation",
        "category": "Agent Attacks",
        "description": "Tests for goal hijacking, plan injection, and priority manipulation in agent reasoning.",
    },
    "secret_scanner": {
        "display_name": "Secret Scanning",
        "category": "Infrastructure",
        "description": "Detects credentials in prompts, responses, and HTTP headers.",
    },
    "dependency_audit": {
        "display_name": "Dependency Audit",
        "category": "Infrastructure",
        "description": "Scans for CVEs, malicious packages, and outdated dependencies.",
    },
    "plugin_security": {
        "display_name": "Plugin Security",
        "category": "Infrastructure",
        "description": "Audits plugin manifests, permissions, and integrity verification.",
    },
}


@router.get("", response_model=list[ModuleInfo])
async def list_modules() -> list[ModuleInfo]:
    """List all available scanner modules."""
    modules = []
    for name in ALL_MODULES:
        meta = MODULE_METADATA.get(name, {})
        modules.append(
            ModuleInfo(
                name=name,
                display_name=meta.get("display_name", name.replace("_", " ").title()),
                category=meta.get("category", "General"),
                description=meta.get("description", f"Security scanning module: {name}"),
                supported_targets=["url", "api_endpoint", "agent_config"],
            )
        )
    return modules


@router.get("/{module_name}", response_model=ModuleInfo)
async def get_module(module_name: str) -> ModuleInfo:
    """Get details for a specific module."""
    if module_name not in ALL_MODULES:
        raise HTTPException(status_code=404, detail="Module not found")

    meta = MODULE_METADATA.get(module_name, {})
    return ModuleInfo(
        name=module_name,
        display_name=meta.get("display_name", module_name.replace("_", " ").title()),
        category=meta.get("category", "General"),
        description=meta.get("description", f"Security scanning module: {module_name}"),
        supported_targets=["url", "api_endpoint", "agent_config"],
    )