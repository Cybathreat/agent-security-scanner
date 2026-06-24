"""
LLM Gateway Profile.

Stores everything discovered about a target LLM gateway during Phase 0.
Produced by GatewayDiscoveryModule and consumed by every downstream module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class LLMGatewayProfile:
    """
    Discovered profile of a target LLM gateway.

    All scan modules receive this profile and use it to direct probes at
    the correct endpoint in the right wire format, rather than guessing.
    """

    target: str

    # Discovered endpoints
    chat_endpoint: Optional[str] = None       # e.g. https://host/v1/chat/completions
    models_endpoint: Optional[str] = None     # e.g. https://host/v1/models
    health_endpoint: Optional[str] = None

    # Wire format
    api_format: str = "unknown"               # "openai" | "anthropic" | "ollama" | "custom"

    # LLM nature
    llm_type: str = "unknown"                 # "chatbot" | "rag" | "agent" | "rag_agent"

    # Model identity
    model_name: Optional[str] = None
    available_models: List[str] = field(default_factory=list)

    # Capabilities
    has_system_prompt: bool = False
    system_prompt_hint: Optional[str] = None
    supports_tools: bool = False
    supports_streaming: bool = False

    # Raw evidence
    raw_probe_response: Optional[Dict[str, Any]] = None
    discovery_errors: List[str] = field(default_factory=list)

    # ------------------------------------------------------------------ #

    @property
    def is_discovered(self) -> bool:
        """True if a chat endpoint was confirmed."""
        return self.chat_endpoint is not None

    def effective_chat_url(self) -> str:
        """Return the confirmed chat endpoint or fall back to the base target."""
        return self.chat_endpoint or self.target

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "chat_endpoint": self.chat_endpoint,
            "models_endpoint": self.models_endpoint,
            "api_format": self.api_format,
            "llm_type": self.llm_type,
            "model_name": self.model_name,
            "available_models": self.available_models,
            "has_system_prompt": self.has_system_prompt,
            "system_prompt_hint": self.system_prompt_hint,
            "supports_tools": self.supports_tools,
            "supports_streaming": self.supports_streaming,
            "is_discovered": self.is_discovered,
            "discovery_errors": self.discovery_errors,
        }
