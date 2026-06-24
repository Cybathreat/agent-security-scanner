"""
Scanning engine for Singularity.

Orchestrates security module execution against a target.
Handles module selection, lifecycle management, and result aggregation.

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, cast

from loguru import logger

from .config import Config
from .gateway_profile import LLMGatewayProfile
from ..modules.base import BaseModule, ScanResult


ALL_MODULES = [
    "misconfigurations",
    "prompt_injection",
    "tool_boundaries",
    "rag_security",
    "tool_hijacking",
    "recursive_agents",
    "memory_poisoning",
    "planning_attacks",
    "secret_scanner",
    "dependency_audit",
    "plugin_security",
]

# Submodule registry for granular module control
ALL_SUBMODULES = {
    # Misconfigurations submodules
    "auth_scanner": "singularity.modules.misconfig_submodules.auth_scanner",
    "cors_scanner": "singularity.modules.misconfig_submodules.cors_scanner",
    "rate_limit_scanner": "singularity.modules.misconfig_submodules.rate_limit_scanner",
    "info_disclosure_scanner": "singularity.modules.misconfig_submodules.info_disclosure_scanner",
    # Prompt injection submodules
    "direct_injection": "singularity.modules.prompt_injection_submodules.direct_injection",
    "obfuscation": "singularity.modules.prompt_injection_submodules.obfuscation",
    "multi_turn": "singularity.modules.prompt_injection_submodules.multi_turn",
    "adaptive_generator": "singularity.modules.prompt_injection_submodules.adaptive_generator",
    "tap": "singularity.modules.prompt_injection_submodules.tap",
    "payload_splitting": "singularity.modules.prompt_injection_submodules.payload_splitting",
    "guardrail_fingerprinting": "singularity.modules.prompt_injection_submodules.guardrail_fingerprinting",
    "virtualization": "singularity.modules.prompt_injection_submodules.virtualization",
    "encoding_bypass": "singularity.modules.prompt_injection_submodules.encoding_bypass",
    "multilingual": "singularity.modules.prompt_injection_submodules.multilingual",
    "token_smuggling": "singularity.modules.prompt_injection_submodules.token_smuggling",
    "grammar_constrained": "singularity.modules.prompt_injection_submodules.grammar_constrained",
    "perplexity_evasion": "singularity.modules.prompt_injection_submodules.perplexity_evasion",
    "timing_sidechannels": "singularity.modules.prompt_injection_submodules.timing_sidechannels",
    "rate_limit_evasion": "singularity.modules.prompt_injection_submodules.rate_limit_evasion",
    "waf_fingerprinting": "singularity.modules.prompt_injection_submodules.waf_fingerprinting",
    "canary_tokens": "singularity.modules.prompt_injection_submodules.canary_tokens",
    "output_filter_probing": "singularity.modules.prompt_injection_submodules.output_filter_probing",
    # Tool boundaries submodules
    "permission_scanner": "singularity.modules.tool_boundaries_submodules.permission_scanner",
    "sandbox_scanner": "singularity.modules.tool_boundaries_submodules.sandbox_scanner",
    "tool_chains_scanner": "singularity.modules.tool_boundaries_submodules.tool_chains",
    "mcp_scanner": "singularity.modules.tool_boundaries_submodules.mcp_scanner",
    "confused_deputy": "singularity.modules.tool_boundaries_submodules.confused_deputy",
    # RAG security submodules
    "document_poisoning": "singularity.modules.rag_security_submodules.document_poisoning",
    "exfiltration": "singularity.modules.rag_security_submodules.exfiltration",
    "vector_db_scanner": "singularity.modules.rag_security_submodules.vector_db",
    "embedding_attacks": "singularity.modules.rag_security_submodules.embedding_attacks",
    "multi_tenant": "singularity.modules.rag_security_submodules.multi_tenant",
    "phantom_document": "singularity.modules.rag_security_submodules.phantom_document",
    "chunk_boundary": "singularity.modules.rag_security_submodules.chunk_boundary",
    # Agent submodules
    "tool_hijacking": "singularity.modules.agent.tool_hijacking",
    "recursive_agents": "singularity.modules.agent.recursive_agents",
    "memory_poisoning": "singularity.modules.agent.memory_poisoning",
    "planning_attacks": "singularity.modules.agent.planning_attacks",
    # Infrastructure submodules
    "secret_scanner": "singularity.modules.infrastructure.secret_scanner",
    "dependency_audit": "singularity.modules.infrastructure.dependency_audit",
    "plugin_security": "singularity.modules.infrastructure.plugin_security",
    "model_provenance": "singularity.modules.infrastructure.model_provenance",
}


class ScanEngine:
    """
    Core scanning engine.

    Instantiates and runs security modules against a target, collecting
    results for downstream reporting.

    Usage:
        engine = ScanEngine(config)
        results = engine.run("https://api.example.com")
    """

    def __init__(self, config: Config) -> None:
        """
        Initialize the scan engine.

        Args:
            config: Loaded scanner configuration.
        """
        self.config = config

    def run(
        self,
        target: str,
        modules: Optional[List[str]] = None,
        timeout: int = 30,
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[ScanResult]:
        """
        Execute a security scan against the target.

        Args:
            target: URL or API endpoint to scan.
            modules: List of module names to run. Defaults to all modules.
            timeout: Per-request timeout in seconds.
            auth_headers: HTTP headers added to every request (e.g. Authorization).

        Returns:
            List[ScanResult]: Results from each executed module.
        """
        module_names = modules if modules is not None else ALL_MODULES

        logger.info(f"Scan started — target: {target}")
        logger.info(f"Modules: {', '.join(module_names)}")
        logger.info(f"Timeout: {timeout}s")
        # Merge extra_headers (gateway-specific required headers) into auth_headers
        merged_headers = {**(auth_headers or {}), **self.config.gateway_discovery.extra_headers}

        if merged_headers:
            logger.info(f"Request headers: {list(merged_headers.keys())}")

        # Phase 0 — always run gateway discovery first
        gateway_profile = self._run_gateway_discovery(target, timeout, merged_headers)

        results: List[ScanResult] = []

        for name in module_names:
            module = self._build_module(name)
            if module is None:
                continue

            logger.info(f"Running module: {name}")
            result = module.scan(
                target,
                timeout=timeout,
                auth_headers=merged_headers,
                gateway_profile=gateway_profile,
            )
            results.append(result)

            logger.info(
                f"Module {name} complete: "
                f"{len(result.findings)} findings, "
                f"{len(result.errors)} errors"
            )

        logger.info(
            f"Scan complete — "
            f"{len(results)} modules, "
            f"{sum(len(r.findings) for r in results)} total findings"
        )

        return results

    def _run_gateway_discovery(
        self,
        target: str,
        timeout: int,
        auth_headers: Dict[str, str],
    ) -> LLMGatewayProfile:
        """Run Phase 0 gateway discovery and return the profile."""
        gd_config = self.config.gateway_discovery

        # Short-circuit: user already knows the endpoint
        if gd_config.llm_endpoint:
            profile = LLMGatewayProfile(target=target)
            profile.chat_endpoint = gd_config.llm_endpoint
            profile.api_format = gd_config.api_format or "openai"
            logger.info(
                f"Using manual LLM endpoint: {profile.chat_endpoint} "
                f"(format={profile.api_format})"
            )
            return profile

        from ..modules.gateway_discovery import GatewayDiscoveryModule

        # Merge extra_headers into auth_headers for all probes
        merged_headers = {**auth_headers, **gd_config.extra_headers}

        logger.info("Phase 0 — running gateway discovery")
        module = GatewayDiscoveryModule(gd_config)
        result = module.scan(target, timeout=timeout, auth_headers=merged_headers)

        profile_dict = result.metadata.get("gateway_profile", {})
        profile = LLMGatewayProfile(target=target)

        if isinstance(profile_dict, dict):
            profile.chat_endpoint = profile_dict.get("chat_endpoint")
            profile.models_endpoint = profile_dict.get("models_endpoint")
            profile.health_endpoint = profile_dict.get("health_endpoint")
            profile.api_format = gd_config.api_format or profile_dict.get("api_format", "unknown")
            profile.llm_type = profile_dict.get("llm_type", "unknown")
            profile.model_name = profile_dict.get("model_name")
            profile.available_models = profile_dict.get("available_models", [])
            profile.has_system_prompt = profile_dict.get("has_system_prompt", False)
            profile.system_prompt_hint = profile_dict.get("system_prompt_hint")
            profile.supports_tools = profile_dict.get("supports_tools", False)
            profile.discovery_errors = profile_dict.get("discovery_errors", [])

        logger.info(
            f"Gateway profile: endpoint={profile.chat_endpoint}, "
            f"format={profile.api_format}, type={profile.llm_type}, "
            f"model={profile.model_name}"
        )
        return profile

    def _build_module(self, name: str) -> Optional[BaseModule[Any]]:
        """
        Instantiate a module with its configuration.

        Imports are deferred to avoid circular import between core and modules.

        Args:
            name: Module name.

        Returns:
            BaseModule instance, or None if the name is unknown.
        """
        # Deferred imports to break the core <-> modules circular dependency
        from ..modules.misconfigurations import MisconfigurationsModule
        from ..modules.prompt_injection import PromptInjectionModule
        from ..modules.rag_security import RAGSecurityModule
        from ..modules.tool_boundaries import ToolBoundariesModule
        from ..modules.agent.tool_hijacking import ToolHijackingScanner
        from ..modules.agent.recursive_agents import RecursiveAgentsScanner
        from ..modules.agent.memory_poisoning import MemoryPoisoningScanner
        from ..modules.agent.planning_attacks import PlanningAttacksScanner
        from ..modules.infrastructure.secret_scanner import SecretScanner
        from ..modules.infrastructure.dependency_audit import DependencyAuditScanner
        from ..modules.infrastructure.plugin_security import PluginSecurityScanner

        registry = {
            "misconfigurations": (MisconfigurationsModule, self.config.modules.misconfigurations),
            "prompt_injection": (PromptInjectionModule, self.config.modules.prompt_injection),
            "tool_boundaries": (ToolBoundariesModule, self.config.modules.tool_boundaries),
            "rag_security": (RAGSecurityModule, self.config.modules.rag_security),
            "tool_hijacking": (ToolHijackingScanner, self.config.modules.tool_hijacking_scanner),
            "recursive_agents": (RecursiveAgentsScanner, self.config.modules.recursive_agents_scanner),
            "memory_poisoning": (MemoryPoisoningScanner, self.config.modules.memory_poisoning_scanner),
            "planning_attacks": (PlanningAttacksScanner, self.config.modules.planning_attacks_scanner),
            "secret_scanner": (SecretScanner, self.config.modules.secret_scanner),
            "dependency_audit": (DependencyAuditScanner, self.config.modules.dependency_audit_scanner),
            "plugin_security": (PluginSecurityScanner, self.config.modules.plugin_security_scanner),
        }

        if name not in registry:
            logger.warning(f"Unknown module '{name}', skipping")
            return None

        module_class, module_config = registry[name]
        return cast(BaseModule[Any], module_class(module_config))

    def _build_submodule(self, name: str) -> Optional[BaseModule[Any]]:
        """
        Instantiate a submodule with its configuration.

        Loads submodule modules dynamically to support the expanded scanner set.

        Args:
            name: Submodule name (e.g., 'auth_scanner', 'direct_injection').

        Returns:
            BaseModule instance, or None if the name is unknown.
        """
        # Import submodule registry
        submodule_paths = {
            # Misconfigurations submodules
            "auth_scanner": ("singularity.modules.misconfig_submodules.auth_scanner", "AuthScanner"),
            "cors_scanner": ("singularity.modules.misconfig_submodules.cors_scanner", "CORSScanner"),
            "rate_limit_scanner": ("singularity.modules.misconfig_submodules.rate_limit_scanner", "RateLimitScanner"),
            "info_disclosure_scanner": ("singularity.modules.misconfig_submodules.info_disclosure_scanner", "InfoDisclosureScanner"),
            # Prompt injection submodules
            "direct_injection": ("singularity.modules.prompt_injection_submodules.direct_injection", "DirectInjectionScanner"),
            "obfuscation": ("singularity.modules.prompt_injection_submodules.obfuscation", "ObfuscationScanner"),
            "multi_turn": ("singularity.modules.prompt_injection_submodules.multi_turn", "MultiTurnScanner"),
            "adaptive_generator": ("singularity.modules.prompt_injection_submodules.adaptive_generator", "AdaptiveGeneratorScanner"),
            "tap": ("singularity.modules.prompt_injection_submodules.tap", "TAPAttackScanner"),
            "payload_splitting": ("singularity.modules.prompt_injection_submodules.payload_splitting", "PayloadSplittingScanner"),
            "guardrail_fingerprinting": ("singularity.modules.prompt_injection_submodules.guardrail_fingerprinting", "GuardrailFingerprintingScanner"),
            "virtualization": ("singularity.modules.prompt_injection_submodules.virtualization", "VirtualizationScanner"),
            "encoding_bypass": ("singularity.modules.prompt_injection_submodules.encoding_bypass", "EncodingBypassScanner"),
            "multilingual": ("singularity.modules.prompt_injection_submodules.multilingual", "MultilingualScanner"),
            "token_smuggling": ("singularity.modules.prompt_injection_submodules.token_smuggling", "TokenSmugglingScanner"),
            "grammar_constrained": ("singularity.modules.prompt_injection_submodules.grammar_constrained", "GrammarConstrainedScanner"),
            "perplexity_evasion": ("singularity.modules.prompt_injection_submodules.perplexity_evasion", "PerplexityEvasionScanner"),
            "timing_sidechannels": ("singularity.modules.prompt_injection_submodules.timing_sidechannels", "TimingSidechannelsScanner"),
            "rate_limit_evasion": ("singularity.modules.prompt_injection_submodules.rate_limit_evasion", "RateLimitEvasionScanner"),
            "waf_fingerprinting": ("singularity.modules.prompt_injection_submodules.waf_fingerprinting", "WAFFingerprintingScanner"),
            "canary_tokens": ("singularity.modules.prompt_injection_submodules.canary_tokens", "CanaryTokensScanner"),
            "output_filter_probing": ("singularity.modules.prompt_injection_submodules.output_filter_probing", "OutputFilterProbingScanner"),
            # Tool boundaries submodules
            "permission_scanner": ("singularity.modules.tool_boundaries_submodules.permission_scanner", "PermissionScanner"),
            "sandbox_scanner": ("singularity.modules.tool_boundaries_submodules.sandbox_scanner", "SandboxScanner"),
            "tool_chains": ("singularity.modules.tool_boundaries_submodules.tool_chains", "ToolChainsScanner"),
            "mcp_scanner": ("singularity.modules.tool_boundaries_submodules.mcp_scanner", "MCPScanner"),
            "confused_deputy": ("singularity.modules.tool_boundaries_submodules.confused_deputy", "ConfusedDeputyScanner"),
            # RAG security submodules
            "document_poisoning": ("singularity.modules.rag_security_submodules.document_poisoning", "DocumentPoisoningScanner"),
            "exfiltration": ("singularity.modules.rag_security_submodules.exfiltration", "ExfiltrationScanner"),
            "vector_db": ("singularity.modules.rag_security_submodules.vector_db", "VectorDBScanner"),
            "embedding_attacks": ("singularity.modules.rag_security_submodules.embedding_attacks", "EmbeddingAttacksScanner"),
            "multi_tenant": ("singularity.modules.rag_security_submodules.multi_tenant", "MultiTenantScanner"),
            "phantom_document": ("singularity.modules.rag_security_submodules.phantom_document", "PhantomDocumentScanner"),
            "chunk_boundary": ("singularity.modules.rag_security_submodules.chunk_boundary", "ChunkBoundaryScanner"),
            # Agent submodules
            "tool_hijacking": ("singularity.modules.agent.tool_hijacking", "ToolHijackingScanner"),
            "recursive_agents": ("singularity.modules.agent.recursive_agents", "RecursiveAgentsScanner"),
            "memory_poisoning": ("singularity.modules.agent.memory_poisoning", "MemoryPoisoningScanner"),
            "planning_attacks": ("singularity.modules.agent.planning_attacks", "PlanningAttacksScanner"),
            # Infrastructure submodules
            "secret_scanner": ("singularity.modules.infrastructure.secret_scanner", "SecretScanner"),
            "dependency_audit": ("singularity.modules.infrastructure.dependency_audit", "DependencyAuditScanner"),
            "plugin_security": ("singularity.modules.infrastructure.plugin_security", "PluginSecurityScanner"),
            "model_provenance": ("singularity.modules.infrastructure.model_provenance", "ModelProvenanceScanner"),
        }

        if name not in submodule_paths:
            logger.warning(f"Unknown submodule '{name}', skipping")
            return None

        module_path, class_name = submodule_paths[name]
        try:
            # Lazy import
            import importlib
            module = importlib.import_module(module_path)
            class_obj = getattr(module, class_name)

            # Get config for this submodule
            # Explicit mapping for names that don't follow the simple pattern
            config_key_map = {
                "auth_scanner": "auth_scanner",
                "cors_scanner": "cors_scanner",
                "rate_limit_scanner": "rate_limit_scanner",
                "info_disclosure_scanner": "info_disclosure_scanner",
                "direct_injection": "direct_injection_scanner",
                "obfuscation": "obfuscation_scanner",
                "multi_turn": "multi_turn_scanner",
                "adaptive_generator": "adaptive_generator_scanner",
                "tap": "tap_scanner",
                "payload_splitting": "payload_splitting_scanner",
                "guardrail_fingerprinting": "guardrail_fingerprinting_scanner",
                "virtualization": "virtualization_scanner",
                "encoding_bypass": "encoding_bypass_scanner",
                "multilingual": "multilingual_scanner",
                "token_smuggling": "token_smuggling_scanner",
                "grammar_constrained": "grammar_constrained_scanner",
                "perplexity_evasion": "perplexity_evasion_scanner",
                "timing_sidechannels": "timing_sidechannels_scanner",
                "rate_limit_evasion": "rate_limit_evasion_scanner",
                "waf_fingerprinting": "waf_fingerprinting_scanner",
                "canary_tokens": "canary_tokens_scanner",
                "output_filter_probing": "output_filter_probing_scanner",
                "permission_scanner": "permission_scanner",
                "sandbox_scanner": "sandbox_scanner",
                "tool_chains": "tool_chains_scanner",
                "mcp_scanner": "mcp_scanner",
                "confused_deputy": "confused_deputy_scanner",
                "document_poisoning": "document_poisoning_scanner",
                "exfiltration": "exfiltration_scanner",
                "vector_db": "vector_db_scanner",
                "embedding_attacks": "embedding_attacks_scanner",
                "multi_tenant": "multi_tenant_scanner",
                "phantom_document": "phantom_document_scanner",
                "chunk_boundary": "chunk_boundary_scanner",
                "tool_hijacking": "tool_hijacking_scanner",
                "recursive_agents": "recursive_agents_scanner",
                "memory_poisoning": "memory_poisoning_scanner",
                "planning_attacks": "planning_attacks_scanner",
                "secret_scanner": "secret_scanner",
                "dependency_audit": "dependency_audit_scanner",
                "plugin_security": "plugin_security_scanner",
                "model_provenance": "model_provenance_scanner",
            }

            config_attr = config_key_map.get(name)
            module_config = getattr(self.config.modules, config_attr, None) if config_attr else None

            return cast(BaseModule[Any], class_obj(module_config))
        except (ImportError, AttributeError) as e:
            logger.error(f"Failed to load submodule '{name}': {e}")
            return None
