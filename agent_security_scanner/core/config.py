"""
Configuration loading module for Agent Security Scanner.

Handles loading configuration from YAML files and environment variables.
Supports hierarchical config with defaults, file overrides, and env overrides.

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml  # type: ignore[import-untyped]
from loguru import logger


@dataclass
class ScannerConfig:
    """Scanner runtime configuration."""

    timeout: int = 30
    max_retries: int = 3
    rate_limit: float = 10.0  # requests per second
    user_agent: str = "AgentSecurityScanner/0.1"
    verify_ssl: bool = True
    proxy: Optional[str] = None


@dataclass
class PromptInjectionConfig:
    """Prompt injection module configuration."""

    enabled: bool = True
    sensitivity: str = "high"  # low, medium, high
    max_payload_size: int = 10000
    detect_obfuscation: bool = True
    detect_leakage: bool = True
    test_crescendo: bool = True
    crescendo_max_turns: int = 10
    test_many_shot: bool = True
    many_shot_num_shots: int = 200
    test_skeleton_key: bool = True
    test_payloads: List[str] = field(default_factory=list)


@dataclass
class DirectInjectionScannerConfig:
    """Direct injection scanner configuration."""

    enabled: bool = True
    test_direct_injection_bypass: bool = True
    test_prompt_leakage: bool = True
    test_instruction_hijacking: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class ObfuscationScannerConfig:
    """Obfuscation scanner configuration."""

    enabled: bool = True
    test_unicode_bypass: bool = True
    test_encoding_bypass: bool = True
    test_character_substitution: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class MultiTurnScannerConfig:
    """Multi-turn scanner configuration."""

    enabled: bool = True
    test_conversation_injection: bool = True
    test_context_manipulation: bool = True
    test_session_persistence: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5
    max_turns: int = 10


@dataclass
class RAGSecurityConfig:
    """RAG pipeline security configuration."""

    enabled: bool = True
    check_poisoning: bool = True
    check_exfiltration: bool = True
    vector_db_scan: bool = True
    max_document_size: int = 1000000  # bytes


@dataclass
class ToolBoundariesConfig:
    """Tool calling boundaries configuration."""

    enabled: bool = True
    check_permissions: bool = True
    audit_sandbox: bool = True
    allowed_tools: List[str] = field(default_factory=list)
    denied_tools: List[str] = field(default_factory=list)


@dataclass
class MisconfigurationsConfig:
    """Security misconfiguration detection configuration."""

    enabled: bool = True
    check_auth: bool = True
    check_cors: bool = True
    check_rate_limiting: bool = True
    check_info_disclosure: bool = True


@dataclass
class AuthScannerConfig:
    """Authentication scanner configuration."""

    enabled: bool = True
    test_unauthenticated: bool = True
    test_api_keys: bool = True
    test_session_fixation: bool = True
    test_mfa: bool = True
    test_brute_force: bool = True
    test_token_leakage: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class CORSScannerConfig:
    """CORS scanner configuration."""

    enabled: bool = True
    test_wildcard_origin: bool = True
    test_credentials_with_wildcard: bool = True
    test_preflight: bool = True
    test_allowed_methods: bool = True
    test_allowed_headers: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5
    test_custom_origins: List[str] = field(default_factory=list)


@dataclass
class RateLimitScannerConfig:
    """Rate limit scanner configuration."""

    enabled: bool = True
    test_rate_limiting_headers: bool = True
    test_429_responses: bool = True
    test_rate_limit_bypass: bool = True
    test_token_bucket: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5
    custom_headers: List[str] = field(default_factory=list)


@dataclass
class InfoDisclosureScannerConfig:
    """Information disclosure scanner configuration."""

    enabled: bool = True
    test_stack_traces: bool = True
    test_debug_mode: bool = True
    test_version_info: bool = True
    test_internal_paths: bool = True
    test_server_banner: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class PermissionScannerConfig:
    """Permission scanner configuration."""

    enabled: bool = True
    test_admin_mode: bool = True
    test_unrestricted: bool = True
    test_trust_all: bool = True
    test_no_validation: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class SandboxScannerConfig:
    """Sandbox scanner configuration."""

    enabled: bool = True
    test_no_sandbox: bool = True
    test_root_access: bool = True
    test_resource_limits: bool = True
    test_network_isolation: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class ToolChainsScannerConfig:
    """Tool chains scanner configuration."""

    enabled: bool = True
    test_exfiltration: bool = True
    test_code_deployment: bool = True
    test_database_exfil: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class MCPScannerConfig:
    """MCP scanner configuration."""

    enabled: bool = True
    test_server_impersonation: bool = True
    test_token_forgery: bool = True
    test_auth_bypass: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class ConfusedDeputyScannerConfig:
    """Confused deputy scanner configuration."""

    enabled: bool = True
    test_privilege_escalation: bool = True
    test_cross_user: bool = True
    test_context_manipulation: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class PhantomDocumentScannerConfig:
    """Phantom document scanner configuration."""

    enabled: bool = True
    test_phantom_injection: bool = True
    test_retrieval_manipulation: bool = True
    test_context_injection: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class ChunkBoundaryScannerConfig:
    """Chunk boundary scanner configuration."""

    enabled: bool = True
    test_cross_chunk: bool = True
    test_boundary_evasion: bool = True
    test_reassembly: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class ModelProvenanceScannerConfig:
    """Model provenance scanner configuration."""

    enabled: bool = True
    test_sleeper_agent: bool = True
    test_model_fingerprint: bool = True
    test_backdoor: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class PerplexityEvasionScannerConfig:
    """Perplexity evasion scanner configuration."""

    enabled: bool = True
    test_low_perplexity: bool = True
    test_statistical_mimicry: bool = True
    test_fluency_exploitation: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class TimingSidechannelsScannerConfig:
    """Timing side-channels scanner configuration."""

    enabled: bool = True
    test_latency_probing: bool = True
    test_shadow_filter: bool = True
    test_threshold_mapping: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class RateLimitEvasionScannerConfig:
    """Rate limit evasion scanner configuration."""

    enabled: bool = True
    test_header_spoofing: bool = True
    test_session_rotation: bool = True
    test_distributed_requests: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class WAFFingerprintingScannerConfig:
    """WAF fingerprinting scanner configuration."""

    enabled: bool = True
    test_waf_detection: bool = True
    test_bypass_testing: bool = True
    test_encoding_tricks: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class CanaryTokensScannerConfig:
    """Canary token scanner configuration."""

    enabled: bool = True
    test_token_discovery: bool = True
    test_token_neutralization: bool = True
    test_token_bypass: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class OutputFilterProbingScannerConfig:
    """Output filter probing scanner configuration."""

    enabled: bool = True
    test_filter_mapping: bool = True
    test_boundary_testing: bool = True
    test_encoding_bypass: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class DocumentPoisoningScannerConfig:
    """Document poisoning scanner configuration."""

    enabled: bool = True
    test_poisoning_patterns: bool = True
    test_validation: bool = True
    test_sanitization: bool = True
    test_ingestion_security: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class ExfiltrationScannerConfig:
    """Exfiltration scanner configuration."""

    enabled: bool = True
    test_exfil_indicators: bool = True
    test_egress_controls: bool = True
    test_query_monitoring: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class VectorDBScannerConfig:
    """Vector DB scanner configuration."""

    enabled: bool = True
    test_auth: bool = True
    test_encryption: bool = True
    test_public_access: bool = True
    test_injection: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class EmbeddingAttacksScannerConfig:
    """Embedding attacks scanner configuration."""

    enabled: bool = True
    test_adversarial: bool = True
    test_inversion: bool = True
    test_collision: bool = True
    test_fine_tune: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class MultiTenantScannerConfig:
    """Multi-tenant scanner configuration."""

    enabled: bool = True
    test_tenant_isolation: bool = True
    test_query_filtering: bool = True
    test_tenant_awareness: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class ToolHijackingScannerConfig:
    """Tool hijacking scanner configuration."""

    enabled: bool = True
    test_argument_injection: bool = True
    test_parameter_manipulation: bool = True
    test_tool_validation: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class RecursiveAgentsScannerConfig:
    """Recursive agents scanner configuration."""

    enabled: bool = True
    test_shared_context: bool = True
    test_agent_validation: bool = True
    test_context_poisoning: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class MemoryPoisoningScannerConfig:
    """Memory poisoning scanner configuration."""

    enabled: bool = True
    test_memory_injection: bool = True
    test_session_integrity: bool = True
    test_history_poisoning: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class PlanningAttacksScannerConfig:
    """Planning attacks scanner configuration."""

    enabled: bool = True
    test_plan_validation: bool = True
    test_step_injection: bool = True
    test_goal_manipulation: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class SecretScannerConfig:
    """Secret scanner configuration."""

    enabled: bool = True
    test_prompt_extraction: bool = True
    test_response_extraction: bool = True
    test_header_extraction: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class DependencyAuditScannerConfig:
    """Dependency audit scanner configuration."""

    enabled: bool = True
    test_cve: bool = True
    test_malicious: bool = True
    test_outdated: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class PluginSecurityScannerConfig:
    """Plugin security scanner configuration."""

    enabled: bool = True
    test_manifest: bool = True
    test_permissions: bool = True
    test_unsigned_plugins: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class GuardrailFingerprintingScannerConfig:
    """Guardrail fingerprinting and evasion scanner configuration."""

    enabled: bool = True
    test_guardrail_fingerprinting: bool = True
    test_known_evasion: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class AdaptiveGeneratorScannerConfig:
    """Adaptive generator scanner configuration."""

    enabled: bool = True
    test_adaptive: bool = True
    max_iterations: int = 5
    mutation_branches: int = 3
    compliance_threshold: float = 0.6
    pruning_threshold: float = 0.3
    request_delay: float = 0.5
    attacker_llm_endpoint: Optional[str] = None
    attacker_llm_model: Optional[str] = None
    attacker_llm_api_key: Optional[str] = None


@dataclass
class PayloadSplittingScannerConfig:
    """Payload splitting scanner configuration."""

    enabled: bool = True
    test_payload_splitting: bool = True
    test_message_splitting: bool = True
    test_field_splitting: bool = True
    test_token_splitting: bool = True
    test_header_splitting: bool = True
    test_multi_payload_splitting: bool = True
    compliance_threshold: float = 0.6
    max_variants_per_goal: int = 3
    request_delay: float = 0.5


@dataclass
class TAPScannerConfig:
    """TAP (Tree-of-Attacks with Pruning) scanner configuration."""

    enabled: bool = True
    test_tap: bool = True
    max_depth: int = 5
    branching_factor: int = 3
    pruning_threshold: float = 0.3
    compliance_threshold: float = 0.7
    request_delay: float = 0.5
    attacker_llm_endpoint: Optional[str] = None
    attacker_llm_model: Optional[str] = None
    attacker_llm_api_key: Optional[str] = None
    judge_llm_endpoint: Optional[str] = None
    judge_llm_model: Optional[str] = None
    judge_llm_api_key: Optional[str] = None


@dataclass
class VirtualizationScannerConfig:
    """Virtualization/roleplay attack scanner configuration."""

    enabled: bool = True
    test_virtualization: bool = True
    test_roleplay: bool = True
    test_virtualization_frames: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class EncodingBypassScannerConfig:
    """Encoding bypass scanner configuration."""

    enabled: bool = True
    test_encoding_bypass: bool = True
    test_base64: bool = True
    test_rot13: bool = True
    test_hex: bool = True
    test_reverse: bool = True
    test_multilayer: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class MultilingualScannerConfig:
    """Multilingual injection scanner configuration."""

    enabled: bool = True
    test_multilingual: bool = True
    test_cross_lingual: bool = True
    test_transliteration: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class TokenSmugglingScannerConfig:
    """Token smuggling scanner configuration."""

    enabled: bool = True
    test_token_smuggling: bool = True
    test_special_tokens: bool = True
    test_markdown_smuggling: bool = True
    test_unicode_homoglyphs: bool = True
    test_zero_width: bool = True
    test_whitespace_smuggling: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class GrammarConstrainedScannerConfig:
    """Grammar-constrained generation scanner configuration."""

    enabled: bool = True
    test_grammar_constrained: bool = True
    test_json_mode: bool = True
    test_code_mode: bool = True
    test_table_mode: bool = True
    test_academic_mode: bool = True
    test_list_mode: bool = True
    compliance_threshold: float = 0.6
    request_delay: float = 0.5


@dataclass
class ModulesConfig:
    """All module configurations grouped together."""

    # Original modules
    prompt_injection: PromptInjectionConfig = field(default_factory=PromptInjectionConfig)
    rag_security: RAGSecurityConfig = field(default_factory=RAGSecurityConfig)
    tool_boundaries: ToolBoundariesConfig = field(default_factory=ToolBoundariesConfig)
    misconfigurations: MisconfigurationsConfig = field(default_factory=MisconfigurationsConfig)

    # New misconfigurations submodules
    auth_scanner: AuthScannerConfig = field(default_factory=AuthScannerConfig)
    cors_scanner: CORSScannerConfig = field(default_factory=CORSScannerConfig)
    rate_limit_scanner: RateLimitScannerConfig = field(default_factory=RateLimitScannerConfig)
    info_disclosure_scanner: InfoDisclosureScannerConfig = field(
        default_factory=InfoDisclosureScannerConfig
    )

    # New tool_boundaries submodules
    permission_scanner: PermissionScannerConfig = field(default_factory=PermissionScannerConfig)
    sandbox_scanner: SandboxScannerConfig = field(default_factory=SandboxScannerConfig)
    tool_chains_scanner: ToolChainsScannerConfig = field(default_factory=ToolChainsScannerConfig)
    mcp_scanner: MCPScannerConfig = field(default_factory=MCPScannerConfig)

    # New rag_security submodules
    document_poisoning_scanner: DocumentPoisoningScannerConfig = field(
        default_factory=DocumentPoisoningScannerConfig
    )
    exfiltration_scanner: ExfiltrationScannerConfig = field(
        default_factory=ExfiltrationScannerConfig
    )
    vector_db_scanner: VectorDBScannerConfig = field(default_factory=VectorDBScannerConfig)
    embedding_attacks_scanner: EmbeddingAttacksScannerConfig = field(
        default_factory=EmbeddingAttacksScannerConfig
    )
    multi_tenant_scanner: MultiTenantScannerConfig = field(default_factory=MultiTenantScannerConfig)

    # New agent submodules
    tool_hijacking_scanner: ToolHijackingScannerConfig = field(
        default_factory=ToolHijackingScannerConfig
    )
    recursive_agents_scanner: RecursiveAgentsScannerConfig = field(
        default_factory=RecursiveAgentsScannerConfig
    )
    memory_poisoning_scanner: MemoryPoisoningScannerConfig = field(
        default_factory=MemoryPoisoningScannerConfig
    )
    planning_attacks_scanner: PlanningAttacksScannerConfig = field(
        default_factory=PlanningAttacksScannerConfig
    )

    # New infrastructure submodules
    secret_scanner: SecretScannerConfig = field(default_factory=SecretScannerConfig)
    dependency_audit_scanner: DependencyAuditScannerConfig = field(
        default_factory=DependencyAuditScannerConfig
    )
    plugin_security_scanner: PluginSecurityScannerConfig = field(
        default_factory=PluginSecurityScannerConfig
    )

    # Prompt injection submodules
    tap_scanner: TAPScannerConfig = field(default_factory=TAPScannerConfig)
    payload_splitting_scanner: PayloadSplittingScannerConfig = field(
        default_factory=PayloadSplittingScannerConfig
    )
    guardrail_fingerprinting_scanner: GuardrailFingerprintingScannerConfig = field(
        default_factory=GuardrailFingerprintingScannerConfig
    )
    adaptive_generator_scanner: AdaptiveGeneratorScannerConfig = field(
        default_factory=AdaptiveGeneratorScannerConfig
    )

    # Phase 1 new prompt injection submodules
    virtualization_scanner: VirtualizationScannerConfig = field(
        default_factory=VirtualizationScannerConfig
    )
    encoding_bypass_scanner: EncodingBypassScannerConfig = field(
        default_factory=EncodingBypassScannerConfig
    )
    multilingual_scanner: MultilingualScannerConfig = field(
        default_factory=MultilingualScannerConfig
    )
    token_smuggling_scanner: TokenSmugglingScannerConfig = field(
        default_factory=TokenSmugglingScannerConfig
    )
    grammar_constrained_scanner: GrammarConstrainedScannerConfig = field(
        default_factory=GrammarConstrainedScannerConfig
    )

    # Upgraded prompt injection submodules (payload-based)
    direct_injection_scanner: DirectInjectionScannerConfig = field(
        default_factory=DirectInjectionScannerConfig
    )
    obfuscation_scanner: ObfuscationScannerConfig = field(default_factory=ObfuscationScannerConfig)
    multi_turn_scanner: MultiTurnScannerConfig = field(default_factory=MultiTurnScannerConfig)

    # Phase 2 new tool_boundaries submodules
    confused_deputy_scanner: ConfusedDeputyScannerConfig = field(
        default_factory=ConfusedDeputyScannerConfig
    )

    # Phase 2 new rag_security submodules
    phantom_document_scanner: PhantomDocumentScannerConfig = field(
        default_factory=PhantomDocumentScannerConfig
    )
    chunk_boundary_scanner: ChunkBoundaryScannerConfig = field(
        default_factory=ChunkBoundaryScannerConfig
    )

    # Phase 2 new infrastructure submodule
    model_provenance_scanner: ModelProvenanceScannerConfig = field(
        default_factory=ModelProvenanceScannerConfig
    )

    # Phase 2 new evasion submodules
    perplexity_evasion_scanner: PerplexityEvasionScannerConfig = field(
        default_factory=PerplexityEvasionScannerConfig
    )
    timing_sidechannels_scanner: TimingSidechannelsScannerConfig = field(
        default_factory=TimingSidechannelsScannerConfig
    )
    rate_limit_evasion_scanner: RateLimitEvasionScannerConfig = field(
        default_factory=RateLimitEvasionScannerConfig
    )
    waf_fingerprinting_scanner: WAFFingerprintingScannerConfig = field(
        default_factory=WAFFingerprintingScannerConfig
    )
    canary_tokens_scanner: CanaryTokensScannerConfig = field(
        default_factory=CanaryTokensScannerConfig
    )
    output_filter_probing_scanner: OutputFilterProbingScannerConfig = field(
        default_factory=OutputFilterProbingScannerConfig
    )


@dataclass
class OutputConfig:
    """Output/reporting configuration."""

    format: str = "json"  # json, markdown, both
    output_dir: str = "output"
    pretty_print: bool = True
    include_timestamp: bool = True
    verbose: bool = False


@dataclass
class QualityGateConfig:
    """Quality gate configuration for CI/CD integration."""

    fail_on_severity: str = "critical"  # critical, high, medium, low, info
    max_findings: Optional[int] = None
    max_risk_score: Optional[int] = None


@dataclass
class LoggingConfig:
    """Logging configuration."""

    level: str = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    format: str = "{time:YYYY-MM-DD HH:mm:ss} | {level} | {name} | {function} | {message}"
    rotation: str = "10 MB"
    retention: str = "7 days"
    compression: str = "zip"
    serialize: bool = False  # JSON logging


@dataclass
class Config:
    """
    Main configuration class for Agent Security Scanner.

    Loads configuration in order:
    1. Default values
    2. YAML config file (if provided)
    3. Environment variables (override everything)

    Usage:
        config = Config.load("config/config.yaml")
        scanner_timeout = config.scanner.timeout
    """

    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    modules: ModulesConfig = field(default_factory=ModulesConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    quality_gate: QualityGateConfig = field(default_factory=QualityGateConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    @classmethod
    def load(cls, config_path: Optional[str] = None) -> Config:
        """
        Load configuration from file and environment.

        Args:
            config_path: Path to YAML config file. If None, use default config.

        Returns:
            Config: Fully loaded configuration object.

        Raises:
            FileNotFoundError: If config file specified but not found.
            yaml.YAMLError: If config file is malformed.
        """
        config = cls()

        # Load from file if provided
        if config_path:
            config = cls._load_from_file(config_path)

        # Override with environment variables
        config = cls._apply_env_overrides(config)

        logger.debug(
            f"Configuration loaded: timeout={config.scanner.timeout}, "
            f"log_level={config.logging.level}"
        )

        return config

    @staticmethod
    def _load_from_file(config_path: str) -> Config:
        """
        Load configuration from YAML file.

        Args:
            config_path: Path to YAML configuration file.

        Returns:
            Config: Configuration with file values applied.
        """
        path = Path(config_path)

        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        with open(path, "r", encoding="utf-8") as f:
            raw_config = yaml.safe_load(f)

        if not raw_config:
            return Config()

        # Build config from nested dicts
        config = Config()

        if "scanner" in raw_config:
            config.scanner = ScannerConfig(**raw_config["scanner"])

        if "modules" in raw_config:
            modules_raw = raw_config["modules"]

            if "prompt_injection" in modules_raw:
                config.modules.prompt_injection = PromptInjectionConfig(
                    **modules_raw["prompt_injection"]
                )

            if "rag_security" in modules_raw:
                config.modules.rag_security = RAGSecurityConfig(**modules_raw["rag_security"])

            if "tool_boundaries" in modules_raw:
                config.modules.tool_boundaries = ToolBoundariesConfig(
                    **modules_raw["tool_boundaries"]
                )

            if "misconfigurations" in modules_raw:
                config.modules.misconfigurations = MisconfigurationsConfig(
                    **modules_raw["misconfigurations"]
                )

        if "output" in raw_config:
            config.output = OutputConfig(**raw_config["output"])

        if "quality_gate" in raw_config:
            config.quality_gate = QualityGateConfig(**raw_config["quality_gate"])

        if "logging" in raw_config:
            config.logging = LoggingConfig(**raw_config["logging"])

        return config

    @staticmethod
    def _apply_env_overrides(config: Config) -> Config:
        """
        Apply environment variable overrides to configuration.

        Environment variables follow pattern: ASS_<SECTION>_<KEY>
        Example: ASS_SCANNER_TIMEOUT=60

        Args:
            config: Base configuration to override.

        Returns:
            Config: Configuration with env overrides applied.
        """
        # Scanner overrides
        if os.getenv("ASS_SCANNER_TIMEOUT"):
            config.scanner.timeout = int(os.getenv("ASS_SCANNER_TIMEOUT") or "30")

        if os.getenv("ASS_SCANNER_MAX_RETRIES"):
            config.scanner.max_retries = int(os.getenv("ASS_SCANNER_MAX_RETRIES") or "3")

        if os.getenv("ASS_SCANNER_RATE_LIMIT"):
            config.scanner.rate_limit = float(os.getenv("ASS_SCANNER_RATE_LIMIT") or "10.0")

        if os.getenv("ASS_SCANNER_VERIFY_SSL"):
            val = os.getenv("ASS_SCANNER_VERIFY_SSL")
            if val is not None:
                config.scanner.verify_ssl = val.lower() == "true"

        # Logging overrides
        if os.getenv("ASS_LOG_LEVEL"):
            config.logging.level = os.getenv("ASS_LOG_LEVEL") or "INFO"

        # Output overrides
        if os.getenv("ASS_OUTPUT_FORMAT"):
            config.output.format = os.getenv("ASS_OUTPUT_FORMAT") or "json"

        if os.getenv("ASS_OUTPUT_DIR"):
            config.output.output_dir = os.getenv("ASS_OUTPUT_DIR") or "output"

        if os.getenv("ASS_VERBOSE"):
            val = os.getenv("ASS_VERBOSE")
            if val is not None:
                config.output.verbose = val.lower() == "true"

        # Quality gate overrides
        if os.getenv("ASS_QUALITY_GATE_FAIL_ON_SEVERITY"):
            config.quality_gate.fail_on_severity = (
                os.getenv("ASS_QUALITY_GATE_FAIL_ON_SEVERITY") or "critical"
            )
        if os.getenv("ASS_QUALITY_GATE_MAX_FINDINGS"):
            config.quality_gate.max_findings = (
                int(os.getenv("ASS_QUALITY_GATE_MAX_FINDINGS") or "0") or None
            )
        if os.getenv("ASS_QUALITY_GATE_MAX_RISK_SCORE"):
            config.quality_gate.max_risk_score = (
                int(os.getenv("ASS_QUALITY_GATE_MAX_RISK_SCORE") or "0") or None
            )

        # TAP scanner overrides
        if os.getenv("ASS_TAP_ATTACKER_LLM_ENDPOINT"):
            config.modules.tap_scanner.attacker_llm_endpoint = os.getenv(
                "ASS_TAP_ATTACKER_LLM_ENDPOINT"
            )
        if os.getenv("ASS_TAP_ATTACKER_LLM_MODEL"):
            config.modules.tap_scanner.attacker_llm_model = os.getenv("ASS_TAP_ATTACKER_LLM_MODEL")
        if os.getenv("ASS_TAP_ATTACKER_LLM_API_KEY"):
            config.modules.tap_scanner.attacker_llm_api_key = os.getenv(
                "ASS_TAP_ATTACKER_LLM_API_KEY"
            )
        if os.getenv("ASS_TAP_JUDGE_LLM_ENDPOINT"):
            config.modules.tap_scanner.judge_llm_endpoint = os.getenv("ASS_TAP_JUDGE_LLM_ENDPOINT")
        if os.getenv("ASS_TAP_JUDGE_LLM_MODEL"):
            config.modules.tap_scanner.judge_llm_model = os.getenv("ASS_TAP_JUDGE_LLM_MODEL")
        if os.getenv("ASS_TAP_JUDGE_LLM_API_KEY"):
            config.modules.tap_scanner.judge_llm_api_key = os.getenv("ASS_TAP_JUDGE_LLM_API_KEY")

        # Payload splitting scanner overrides
        if os.getenv("ASS_PAYLOAD_SPLITTING_ENABLED"):
            val = os.getenv("ASS_PAYLOAD_SPLITTING_ENABLED")
            if val is not None:
                config.modules.payload_splitting_scanner.enabled = val.lower() == "true"
        if os.getenv("ASS_PAYLOAD_SPLITTING_COMPLIANCE_THRESHOLD"):
            config.modules.payload_splitting_scanner.compliance_threshold = float(
                os.getenv("ASS_PAYLOAD_SPLITTING_COMPLIANCE_THRESHOLD") or "0.6"
            )

        # Guardrail fingerprinting scanner overrides
        if os.getenv("ASS_GUARDRAIL_FINGERPRINTING_ENABLED"):
            val = os.getenv("ASS_GUARDRAIL_FINGERPRINTING_ENABLED")
            if val is not None:
                config.modules.guardrail_fingerprinting_scanner.enabled = val.lower() == "true"
        if os.getenv("ASS_GUARDRAIL_FINGERPRINTING_COMPLIANCE_THRESHOLD"):
            config.modules.guardrail_fingerprinting_scanner.compliance_threshold = float(
                os.getenv("ASS_GUARDRAIL_FINGERPRINTING_COMPLIANCE_THRESHOLD") or "0.6"
            )

        # Adaptive generator scanner overrides
        if os.getenv("ASS_ADAPTIVE_GENERATOR_ENABLED"):
            val = os.getenv("ASS_ADAPTIVE_GENERATOR_ENABLED")
            if val is not None:
                config.modules.adaptive_generator_scanner.enabled = val.lower() == "true"
        if os.getenv("ASS_ADAPTIVE_GENERATOR_MAX_ITERATIONS"):
            config.modules.adaptive_generator_scanner.max_iterations = int(
                os.getenv("ASS_ADAPTIVE_GENERATOR_MAX_ITERATIONS") or "5"
            )
        if os.getenv("ASS_ADAPTIVE_GENERATOR_ATTACKER_LLM_ENDPOINT"):
            config.modules.adaptive_generator_scanner.attacker_llm_endpoint = os.getenv(
                "ASS_ADAPTIVE_GENERATOR_ATTACKER_LLM_ENDPOINT"
            )
        if os.getenv("ASS_ADAPTIVE_GENERATOR_ATTACKER_LLM_MODEL"):
            config.modules.adaptive_generator_scanner.attacker_llm_model = os.getenv(
                "ASS_ADAPTIVE_GENERATOR_ATTACKER_LLM_MODEL"
            )
        if os.getenv("ASS_ADAPTIVE_GENERATOR_ATTACKER_LLM_API_KEY"):
            config.modules.adaptive_generator_scanner.attacker_llm_api_key = os.getenv(
                "ASS_ADAPTIVE_GENERATOR_ATTACKER_LLM_API_KEY"
            )

        # Virtualization scanner overrides
        if os.getenv("ASS_VIRTUALIZATION_ENABLED"):
            val = os.getenv("ASS_VIRTUALIZATION_ENABLED")
            if val is not None:
                config.modules.virtualization_scanner.enabled = val.lower() == "true"
        if os.getenv("ASS_VIRTUALIZATION_COMPLIANCE_THRESHOLD"):
            config.modules.virtualization_scanner.compliance_threshold = float(
                os.getenv("ASS_VIRTUALIZATION_COMPLIANCE_THRESHOLD") or "0.6"
            )

        # Encoding bypass scanner overrides
        if os.getenv("ASS_ENCODING_BYPASS_ENABLED"):
            val = os.getenv("ASS_ENCODING_BYPASS_ENABLED")
            if val is not None:
                config.modules.encoding_bypass_scanner.enabled = val.lower() == "true"
        if os.getenv("ASS_ENCODING_BYPASS_COMPLIANCE_THRESHOLD"):
            config.modules.encoding_bypass_scanner.compliance_threshold = float(
                os.getenv("ASS_ENCODING_BYPASS_COMPLIANCE_THRESHOLD") or "0.6"
            )

        # Multilingual scanner overrides
        if os.getenv("ASS_MULTILINGUAL_ENABLED"):
            val = os.getenv("ASS_MULTILINGUAL_ENABLED")
            if val is not None:
                config.modules.multilingual_scanner.enabled = val.lower() == "true"
        if os.getenv("ASS_MULTILINGUAL_COMPLIANCE_THRESHOLD"):
            config.modules.multilingual_scanner.compliance_threshold = float(
                os.getenv("ASS_MULTILINGUAL_COMPLIANCE_THRESHOLD") or "0.6"
            )

        # Token smuggling scanner overrides
        if os.getenv("ASS_TOKEN_SMUGGLING_ENABLED"):
            val = os.getenv("ASS_TOKEN_SMUGGLING_ENABLED")
            if val is not None:
                config.modules.token_smuggling_scanner.enabled = val.lower() == "true"
        if os.getenv("ASS_TOKEN_SMUGGLING_COMPLIANCE_THRESHOLD"):
            config.modules.token_smuggling_scanner.compliance_threshold = float(
                os.getenv("ASS_TOKEN_SMUGGLING_COMPLIANCE_THRESHOLD") or "0.6"
            )

        # Grammar-constrained scanner overrides
        if os.getenv("ASS_GRAMMAR_CONSTRAINED_ENABLED"):
            val = os.getenv("ASS_GRAMMAR_CONSTRAINED_ENABLED")
            if val is not None:
                config.modules.grammar_constrained_scanner.enabled = val.lower() == "true"
        if os.getenv("ASS_GRAMMAR_CONSTRAINED_COMPLIANCE_THRESHOLD"):
            config.modules.grammar_constrained_scanner.compliance_threshold = float(
                os.getenv("ASS_GRAMMAR_CONSTRAINED_COMPLIANCE_THRESHOLD") or "0.6"
            )

        return config

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert configuration to dictionary for serialization.

        Returns:
            Dict: Configuration as nested dictionary.
        """
        return {
            "scanner": {
                "timeout": self.scanner.timeout,
                "max_retries": self.scanner.max_retries,
                "rate_limit": self.scanner.rate_limit,
                "user_agent": self.scanner.user_agent,
                "verify_ssl": self.scanner.verify_ssl,
                "proxy": self.scanner.proxy,
            },
            "modules": {
                "prompt_injection": {
                    "enabled": self.modules.prompt_injection.enabled,
                    "sensitivity": self.modules.prompt_injection.sensitivity,
                    "max_payload_size": self.modules.prompt_injection.max_payload_size,
                    "detect_obfuscation": self.modules.prompt_injection.detect_obfuscation,
                },
                "rag_security": {
                    "enabled": self.modules.rag_security.enabled,
                    "check_poisoning": self.modules.rag_security.check_poisoning,
                    "check_exfiltration": self.modules.rag_security.check_exfiltration,
                    "vector_db_scan": self.modules.rag_security.vector_db_scan,
                    "max_document_size": self.modules.rag_security.max_document_size,
                },
                "tool_boundaries": {
                    "enabled": self.modules.tool_boundaries.enabled,
                    "check_permissions": self.modules.tool_boundaries.check_permissions,
                    "audit_sandbox": self.modules.tool_boundaries.audit_sandbox,
                    "allowed_tools": self.modules.tool_boundaries.allowed_tools,
                    "denied_tools": self.modules.tool_boundaries.denied_tools,
                },
                "misconfigurations": {
                    "enabled": self.modules.misconfigurations.enabled,
                    "check_auth": self.modules.misconfigurations.check_auth,
                    "check_cors": self.modules.misconfigurations.check_cors,
                    "check_rate_limiting": self.modules.misconfigurations.check_rate_limiting,
                    "check_info_disclosure": self.modules.misconfigurations.check_info_disclosure,
                },
                # Submodule configurations
                "auth_scanner": {
                    "enabled": self.modules.auth_scanner.enabled,
                    "test_unauthenticated": self.modules.auth_scanner.test_unauthenticated,
                    "test_api_keys": self.modules.auth_scanner.test_api_keys,
                    "test_session_fixation": self.modules.auth_scanner.test_session_fixation,
                    "test_mfa": self.modules.auth_scanner.test_mfa,
                    "test_brute_force": self.modules.auth_scanner.test_brute_force,
                    "test_token_leakage": self.modules.auth_scanner.test_token_leakage,
                    "compliance_threshold": self.modules.auth_scanner.compliance_threshold,
                    "request_delay": self.modules.auth_scanner.request_delay,
                },
                "cors_scanner": {
                    "enabled": self.modules.cors_scanner.enabled,
                    "test_wildcard_origin": self.modules.cors_scanner.test_wildcard_origin,
                    "test_credentials_with_wildcard": self.modules.cors_scanner.test_credentials_with_wildcard,
                    "test_preflight": self.modules.cors_scanner.test_preflight,
                    "test_allowed_methods": self.modules.cors_scanner.test_allowed_methods,
                    "test_allowed_headers": self.modules.cors_scanner.test_allowed_headers,
                    "compliance_threshold": self.modules.cors_scanner.compliance_threshold,
                    "request_delay": self.modules.cors_scanner.request_delay,
                    "test_custom_origins": self.modules.cors_scanner.test_custom_origins,
                },
                "rate_limit_scanner": {
                    "enabled": self.modules.rate_limit_scanner.enabled,
                    "test_rate_limiting_headers": self.modules.rate_limit_scanner.test_rate_limiting_headers,
                    "test_429_responses": self.modules.rate_limit_scanner.test_429_responses,
                    "test_rate_limit_bypass": self.modules.rate_limit_scanner.test_rate_limit_bypass,
                    "test_token_bucket": self.modules.rate_limit_scanner.test_token_bucket,
                    "compliance_threshold": self.modules.rate_limit_scanner.compliance_threshold,
                    "request_delay": self.modules.rate_limit_scanner.request_delay,
                    "custom_headers": self.modules.rate_limit_scanner.custom_headers,
                },
                "info_disclosure_scanner": {
                    "enabled": self.modules.info_disclosure_scanner.enabled,
                    "test_stack_traces": self.modules.info_disclosure_scanner.test_stack_traces,
                    "test_debug_mode": self.modules.info_disclosure_scanner.test_debug_mode,
                    "test_version_info": self.modules.info_disclosure_scanner.test_version_info,
                    "test_internal_paths": self.modules.info_disclosure_scanner.test_internal_paths,
                    "test_server_banner": self.modules.info_disclosure_scanner.test_server_banner,
                    "compliance_threshold": self.modules.info_disclosure_scanner.compliance_threshold,
                    "request_delay": self.modules.info_disclosure_scanner.request_delay,
                },
                "permission_scanner": {
                    "enabled": self.modules.permission_scanner.enabled,
                    "test_admin_mode": self.modules.permission_scanner.test_admin_mode,
                    "test_unrestricted": self.modules.permission_scanner.test_unrestricted,
                    "test_trust_all": self.modules.permission_scanner.test_trust_all,
                    "test_no_validation": self.modules.permission_scanner.test_no_validation,
                    "compliance_threshold": self.modules.permission_scanner.compliance_threshold,
                    "request_delay": self.modules.permission_scanner.request_delay,
                },
                "sandbox_scanner": {
                    "enabled": self.modules.sandbox_scanner.enabled,
                    "test_no_sandbox": self.modules.sandbox_scanner.test_no_sandbox,
                    "test_root_access": self.modules.sandbox_scanner.test_root_access,
                    "test_resource_limits": self.modules.sandbox_scanner.test_resource_limits,
                    "test_network_isolation": self.modules.sandbox_scanner.test_network_isolation,
                    "compliance_threshold": self.modules.sandbox_scanner.compliance_threshold,
                    "request_delay": self.modules.sandbox_scanner.request_delay,
                },
                "tool_chains_scanner": {
                    "enabled": self.modules.tool_chains_scanner.enabled,
                    "test_exfiltration": self.modules.tool_chains_scanner.test_exfiltration,
                    "test_code_deployment": self.modules.tool_chains_scanner.test_code_deployment,
                    "test_database_exfil": self.modules.tool_chains_scanner.test_database_exfil,
                    "compliance_threshold": self.modules.tool_chains_scanner.compliance_threshold,
                    "request_delay": self.modules.tool_chains_scanner.request_delay,
                },
                "mcp_scanner": {
                    "enabled": self.modules.mcp_scanner.enabled,
                    "test_server_impersonation": self.modules.mcp_scanner.test_server_impersonation,
                    "test_token_forgery": self.modules.mcp_scanner.test_token_forgery,
                    "test_auth_bypass": self.modules.mcp_scanner.test_auth_bypass,
                    "compliance_threshold": self.modules.mcp_scanner.compliance_threshold,
                    "request_delay": self.modules.mcp_scanner.request_delay,
                },
                "document_poisoning_scanner": {
                    "enabled": self.modules.document_poisoning_scanner.enabled,
                    "test_poisoning_patterns": self.modules.document_poisoning_scanner.test_poisoning_patterns,
                    "test_validation": self.modules.document_poisoning_scanner.test_validation,
                    "test_sanitization": self.modules.document_poisoning_scanner.test_sanitization,
                    "test_ingestion_security": self.modules.document_poisoning_scanner.test_ingestion_security,
                    "compliance_threshold": self.modules.document_poisoning_scanner.compliance_threshold,
                    "request_delay": self.modules.document_poisoning_scanner.request_delay,
                },
                "exfiltration_scanner": {
                    "enabled": self.modules.exfiltration_scanner.enabled,
                    "test_exfil_indicators": self.modules.exfiltration_scanner.test_exfil_indicators,
                    "test_egress_controls": self.modules.exfiltration_scanner.test_egress_controls,
                    "test_query_monitoring": self.modules.exfiltration_scanner.test_query_monitoring,
                    "compliance_threshold": self.modules.exfiltration_scanner.compliance_threshold,
                    "request_delay": self.modules.exfiltration_scanner.request_delay,
                },
                "vector_db_scanner": {
                    "enabled": self.modules.vector_db_scanner.enabled,
                    "test_auth": self.modules.vector_db_scanner.test_auth,
                    "test_encryption": self.modules.vector_db_scanner.test_encryption,
                    "test_public_access": self.modules.vector_db_scanner.test_public_access,
                    "test_injection": self.modules.vector_db_scanner.test_injection,
                    "compliance_threshold": self.modules.vector_db_scanner.compliance_threshold,
                    "request_delay": self.modules.vector_db_scanner.request_delay,
                },
                "embedding_attacks_scanner": {
                    "enabled": self.modules.embedding_attacks_scanner.enabled,
                    "test_adversarial": self.modules.embedding_attacks_scanner.test_adversarial,
                    "test_inversion": self.modules.embedding_attacks_scanner.test_inversion,
                    "test_collision": self.modules.embedding_attacks_scanner.test_collision,
                    "test_fine_tune": self.modules.embedding_attacks_scanner.test_fine_tune,
                    "compliance_threshold": self.modules.embedding_attacks_scanner.compliance_threshold,
                    "request_delay": self.modules.embedding_attacks_scanner.request_delay,
                },
                "multi_tenant_scanner": {
                    "enabled": self.modules.multi_tenant_scanner.enabled,
                    "test_tenant_isolation": self.modules.multi_tenant_scanner.test_tenant_isolation,
                    "test_query_filtering": self.modules.multi_tenant_scanner.test_query_filtering,
                    "test_tenant_awareness": self.modules.multi_tenant_scanner.test_tenant_awareness,
                    "compliance_threshold": self.modules.multi_tenant_scanner.compliance_threshold,
                    "request_delay": self.modules.multi_tenant_scanner.request_delay,
                },
                "tool_hijacking_scanner": {
                    "enabled": self.modules.tool_hijacking_scanner.enabled,
                    "test_argument_injection": self.modules.tool_hijacking_scanner.test_argument_injection,
                    "test_parameter_manipulation": self.modules.tool_hijacking_scanner.test_parameter_manipulation,
                    "test_tool_validation": self.modules.tool_hijacking_scanner.test_tool_validation,
                    "compliance_threshold": self.modules.tool_hijacking_scanner.compliance_threshold,
                    "request_delay": self.modules.tool_hijacking_scanner.request_delay,
                },
                "recursive_agents_scanner": {
                    "enabled": self.modules.recursive_agents_scanner.enabled,
                    "test_shared_context": self.modules.recursive_agents_scanner.test_shared_context,
                    "test_agent_validation": self.modules.recursive_agents_scanner.test_agent_validation,
                    "test_context_poisoning": self.modules.recursive_agents_scanner.test_context_poisoning,
                    "compliance_threshold": self.modules.recursive_agents_scanner.compliance_threshold,
                    "request_delay": self.modules.recursive_agents_scanner.request_delay,
                },
                "memory_poisoning_scanner": {
                    "enabled": self.modules.memory_poisoning_scanner.enabled,
                    "test_memory_injection": self.modules.memory_poisoning_scanner.test_memory_injection,
                    "test_session_integrity": self.modules.memory_poisoning_scanner.test_session_integrity,
                    "test_history_poisoning": self.modules.memory_poisoning_scanner.test_history_poisoning,
                    "compliance_threshold": self.modules.memory_poisoning_scanner.compliance_threshold,
                    "request_delay": self.modules.memory_poisoning_scanner.request_delay,
                },
                "planning_attacks_scanner": {
                    "enabled": self.modules.planning_attacks_scanner.enabled,
                    "test_plan_validation": self.modules.planning_attacks_scanner.test_plan_validation,
                    "test_step_injection": self.modules.planning_attacks_scanner.test_step_injection,
                    "test_goal_manipulation": self.modules.planning_attacks_scanner.test_goal_manipulation,
                    "compliance_threshold": self.modules.planning_attacks_scanner.compliance_threshold,
                    "request_delay": self.modules.planning_attacks_scanner.request_delay,
                },
                "secret_scanner": {
                    "enabled": self.modules.secret_scanner.enabled,
                    "test_prompt_extraction": self.modules.secret_scanner.test_prompt_extraction,
                    "test_response_extraction": self.modules.secret_scanner.test_response_extraction,
                    "test_header_extraction": self.modules.secret_scanner.test_header_extraction,
                    "compliance_threshold": self.modules.secret_scanner.compliance_threshold,
                    "request_delay": self.modules.secret_scanner.request_delay,
                },
                "dependency_audit_scanner": {
                    "enabled": self.modules.dependency_audit_scanner.enabled,
                    "test_cve": self.modules.dependency_audit_scanner.test_cve,
                    "test_malicious": self.modules.dependency_audit_scanner.test_malicious,
                    "test_outdated": self.modules.dependency_audit_scanner.test_outdated,
                    "compliance_threshold": self.modules.dependency_audit_scanner.compliance_threshold,
                    "request_delay": self.modules.dependency_audit_scanner.request_delay,
                },
                "plugin_security_scanner": {
                    "enabled": self.modules.plugin_security_scanner.enabled,
                    "test_manifest": self.modules.plugin_security_scanner.test_manifest,
                    "test_permissions": self.modules.plugin_security_scanner.test_permissions,
                    "test_unsigned_plugins": self.modules.plugin_security_scanner.test_unsigned_plugins,
                    "compliance_threshold": self.modules.plugin_security_scanner.compliance_threshold,
                    "request_delay": self.modules.plugin_security_scanner.request_delay,
                },
                "tap_scanner": {
                    "enabled": self.modules.tap_scanner.enabled,
                    "test_tap": self.modules.tap_scanner.test_tap,
                    "max_depth": self.modules.tap_scanner.max_depth,
                    "branching_factor": self.modules.tap_scanner.branching_factor,
                    "pruning_threshold": self.modules.tap_scanner.pruning_threshold,
                    "compliance_threshold": self.modules.tap_scanner.compliance_threshold,
                    "request_delay": self.modules.tap_scanner.request_delay,
                    "attacker_llm_endpoint": self.modules.tap_scanner.attacker_llm_endpoint,
                    "attacker_llm_model": self.modules.tap_scanner.attacker_llm_model,
                    "attacker_llm_api_key": "***REDACTED***"
                    if self.modules.tap_scanner.attacker_llm_api_key
                    else None,
                    "judge_llm_endpoint": self.modules.tap_scanner.judge_llm_endpoint,
                    "judge_llm_model": self.modules.tap_scanner.judge_llm_model,
                    "judge_llm_api_key": "***REDACTED***"
                    if self.modules.tap_scanner.judge_llm_api_key
                    else None,
                },
                "payload_splitting_scanner": {
                    "enabled": self.modules.payload_splitting_scanner.enabled,
                    "test_payload_splitting": self.modules.payload_splitting_scanner.test_payload_splitting,
                    "test_message_splitting": self.modules.payload_splitting_scanner.test_message_splitting,
                    "test_field_splitting": self.modules.payload_splitting_scanner.test_field_splitting,
                    "test_token_splitting": self.modules.payload_splitting_scanner.test_token_splitting,
                    "test_header_splitting": self.modules.payload_splitting_scanner.test_header_splitting,
                    "test_multi_payload_splitting": self.modules.payload_splitting_scanner.test_multi_payload_splitting,
                    "compliance_threshold": self.modules.payload_splitting_scanner.compliance_threshold,
                    "max_variants_per_goal": self.modules.payload_splitting_scanner.max_variants_per_goal,
                    "request_delay": self.modules.payload_splitting_scanner.request_delay,
                },
                "guardrail_fingerprinting_scanner": {
                    "enabled": self.modules.guardrail_fingerprinting_scanner.enabled,
                    "test_guardrail_fingerprinting": self.modules.guardrail_fingerprinting_scanner.test_guardrail_fingerprinting,
                    "test_known_evasion": self.modules.guardrail_fingerprinting_scanner.test_known_evasion,
                    "compliance_threshold": self.modules.guardrail_fingerprinting_scanner.compliance_threshold,
                    "request_delay": self.modules.guardrail_fingerprinting_scanner.request_delay,
                },
                "adaptive_generator_scanner": {
                    "enabled": self.modules.adaptive_generator_scanner.enabled,
                    "test_adaptive": self.modules.adaptive_generator_scanner.test_adaptive,
                    "max_iterations": self.modules.adaptive_generator_scanner.max_iterations,
                    "mutation_branches": self.modules.adaptive_generator_scanner.mutation_branches,
                    "compliance_threshold": self.modules.adaptive_generator_scanner.compliance_threshold,
                    "pruning_threshold": self.modules.adaptive_generator_scanner.pruning_threshold,
                    "request_delay": self.modules.adaptive_generator_scanner.request_delay,
                    "attacker_llm_endpoint": self.modules.adaptive_generator_scanner.attacker_llm_endpoint,
                    "attacker_llm_model": self.modules.adaptive_generator_scanner.attacker_llm_model,
                    "attacker_llm_api_key": "***REDACTED***"
                    if self.modules.adaptive_generator_scanner.attacker_llm_api_key
                    else None,
                },
                "virtualization_scanner": {
                    "enabled": self.modules.virtualization_scanner.enabled,
                    "test_virtualization": self.modules.virtualization_scanner.test_virtualization,
                    "test_roleplay": self.modules.virtualization_scanner.test_roleplay,
                    "test_virtualization_frames": self.modules.virtualization_scanner.test_virtualization_frames,
                    "compliance_threshold": self.modules.virtualization_scanner.compliance_threshold,
                    "request_delay": self.modules.virtualization_scanner.request_delay,
                },
                "encoding_bypass_scanner": {
                    "enabled": self.modules.encoding_bypass_scanner.enabled,
                    "test_encoding_bypass": self.modules.encoding_bypass_scanner.test_encoding_bypass,
                    "test_base64": self.modules.encoding_bypass_scanner.test_base64,
                    "test_rot13": self.modules.encoding_bypass_scanner.test_rot13,
                    "test_hex": self.modules.encoding_bypass_scanner.test_hex,
                    "test_reverse": self.modules.encoding_bypass_scanner.test_reverse,
                    "test_multilayer": self.modules.encoding_bypass_scanner.test_multilayer,
                    "compliance_threshold": self.modules.encoding_bypass_scanner.compliance_threshold,
                    "request_delay": self.modules.encoding_bypass_scanner.request_delay,
                },
                "multilingual_scanner": {
                    "enabled": self.modules.multilingual_scanner.enabled,
                    "test_multilingual": self.modules.multilingual_scanner.test_multilingual,
                    "test_cross_lingual": self.modules.multilingual_scanner.test_cross_lingual,
                    "test_transliteration": self.modules.multilingual_scanner.test_transliteration,
                    "compliance_threshold": self.modules.multilingual_scanner.compliance_threshold,
                    "request_delay": self.modules.multilingual_scanner.request_delay,
                },
                "token_smuggling_scanner": {
                    "enabled": self.modules.token_smuggling_scanner.enabled,
                    "test_token_smuggling": self.modules.token_smuggling_scanner.test_token_smuggling,
                    "test_special_tokens": self.modules.token_smuggling_scanner.test_special_tokens,
                    "test_markdown_smuggling": self.modules.token_smuggling_scanner.test_markdown_smuggling,
                    "test_unicode_homoglyphs": self.modules.token_smuggling_scanner.test_unicode_homoglyphs,
                    "test_zero_width": self.modules.token_smuggling_scanner.test_zero_width,
                    "test_whitespace_smuggling": self.modules.token_smuggling_scanner.test_whitespace_smuggling,
                    "compliance_threshold": self.modules.token_smuggling_scanner.compliance_threshold,
                    "request_delay": self.modules.token_smuggling_scanner.request_delay,
                },
                "grammar_constrained_scanner": {
                    "enabled": self.modules.grammar_constrained_scanner.enabled,
                    "test_grammar_constrained": self.modules.grammar_constrained_scanner.test_grammar_constrained,
                    "test_json_mode": self.modules.grammar_constrained_scanner.test_json_mode,
                    "test_code_mode": self.modules.grammar_constrained_scanner.test_code_mode,
                    "test_table_mode": self.modules.grammar_constrained_scanner.test_table_mode,
                    "test_academic_mode": self.modules.grammar_constrained_scanner.test_academic_mode,
                    "test_list_mode": self.modules.grammar_constrained_scanner.test_list_mode,
                    "compliance_threshold": self.modules.grammar_constrained_scanner.compliance_threshold,
                    "request_delay": self.modules.grammar_constrained_scanner.request_delay,
                },
                "direct_injection_scanner": {
                    "enabled": self.modules.direct_injection_scanner.enabled,
                    "test_direct_injection_bypass": self.modules.direct_injection_scanner.test_direct_injection_bypass,
                    "test_prompt_leakage": self.modules.direct_injection_scanner.test_prompt_leakage,
                    "test_instruction_hijacking": self.modules.direct_injection_scanner.test_instruction_hijacking,
                    "compliance_threshold": self.modules.direct_injection_scanner.compliance_threshold,
                    "request_delay": self.modules.direct_injection_scanner.request_delay,
                },
                "obfuscation_scanner": {
                    "enabled": self.modules.obfuscation_scanner.enabled,
                    "test_unicode_bypass": self.modules.obfuscation_scanner.test_unicode_bypass,
                    "test_encoding_bypass": self.modules.obfuscation_scanner.test_encoding_bypass,
                    "test_character_substitution": self.modules.obfuscation_scanner.test_character_substitution,
                    "compliance_threshold": self.modules.obfuscation_scanner.compliance_threshold,
                    "request_delay": self.modules.obfuscation_scanner.request_delay,
                },
                "multi_turn_scanner": {
                    "enabled": self.modules.multi_turn_scanner.enabled,
                    "test_conversation_injection": self.modules.multi_turn_scanner.test_conversation_injection,
                    "test_context_manipulation": self.modules.multi_turn_scanner.test_context_manipulation,
                    "test_session_persistence": self.modules.multi_turn_scanner.test_session_persistence,
                    "compliance_threshold": self.modules.multi_turn_scanner.compliance_threshold,
                    "request_delay": self.modules.multi_turn_scanner.request_delay,
                    "max_turns": self.modules.multi_turn_scanner.max_turns,
                },
            },
            "output": {
                "format": self.output.format,
                "output_dir": self.output.output_dir,
                "pretty_print": self.output.pretty_print,
                "include_timestamp": self.output.include_timestamp,
                "verbose": self.output.verbose,
            },
            "logging": {
                "level": self.logging.level,
                "format": self.logging.format,
                "rotation": self.logging.rotation,
                "retention": self.logging.retention,
                "compression": self.logging.compression,
                "serialize": self.logging.serialize,
            },
        }


def load_config(config_path: Optional[str] = None) -> Config:
    """
    Convenience function to load configuration.

    Args:
        config_path: Optional path to YAML config file.

    Returns:
        Config: Loaded configuration object.

    Example:
        >>> config = load_config("config/config.yaml")
        >>> print(config.scanner.timeout)
        30
    """
    return Config.load(config_path)
