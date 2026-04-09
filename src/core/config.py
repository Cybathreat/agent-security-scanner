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

import yaml
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
    test_payloads: List[str] = field(default_factory=list)


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
    check_basic_auth: bool = True
    check_api_keys: bool = True
    check_session_fixation: bool = True
    check_mfa: bool = True
    check_token_leakage: bool = True
    test_unauthenticated: bool = True


@dataclass
class CORSScannerConfig:
    """CORS scanner configuration."""

    enabled: bool = True
    check_wildcard_origin: bool = True
    check_credentials_with_wildcard: bool = True
    check_preflight: bool = True
    check_allowed_methods: bool = True
    check_allowed_headers: bool = True
    test_custom_origins: List[str] = field(default_factory=list)


@dataclass
class RateLimitScannerConfig:
    """Rate limit scanner configuration."""

    enabled: bool = True
    check_rate_limiting_headers: bool = True
    check_429_responses: bool = True
    test_rate_limit_bypass: bool = True
    custom_headers: List[str] = field(default_factory=list)


@dataclass
class InfoDisclosureScannerConfig:
    """Information disclosure scanner configuration."""

    enabled: bool = True
    check_stack_traces: bool = True
    check_debug_mode: bool = True
    check_version_info: bool = True
    check_internal_paths: bool = True
    check_server_banner: bool = True
    check_error_messages: bool = True


@dataclass
class PermissionScannerConfig:
    """Permission scanner configuration."""

    enabled: bool = True
    check_admin_mode: bool = True
    check_unrestricted: bool = True
    check_trust_all: bool = True
    check_no_validation: bool = True


@dataclass
class SandboxScannerConfig:
    """Sandbox scanner configuration."""

    enabled: bool = True
    check_no_sandbox: bool = True
    check_root_access: bool = True
    check_resource_limits: bool = True
    check_network_isolation: bool = True


@dataclass
class ToolChainsScannerConfig:
    """Tool chains scanner configuration."""

    enabled: bool = True
    check_exfiltration: bool = True
    check_code_deployment: bool = True
    check_database_exfil: bool = True
    check_privilege_escalation: bool = True


@dataclass
class MCPScannerConfig:
    """MCP scanner configuration."""

    enabled: bool = True
    check_server_identity: bool = True
    check_token_verification: bool = True
    check_auth_headers: bool = True


@dataclass
class DocumentPoisoningScannerConfig:
    """Document poisoning scanner configuration."""

    enabled: bool = True
    check_poisoning_patterns: bool = True
    check_validation: bool = True
    check_sanitization: bool = True
    check_ingestion_security: bool = True


@dataclass
class ExfiltrationScannerConfig:
    """Exfiltration scanner configuration."""

    enabled: bool = True
    check_exfil_indicators: bool = True
    check_egress_controls: bool = True
    check_response_filtering: bool = True
    check_query_monitoring: bool = True


@dataclass
class VectorDBScannerConfig:
    """Vector DB scanner configuration."""

    enabled: bool = True
    check_no_auth: bool = True
    check_plaintext: bool = True
    check_public_access: bool = True
    check_injection: bool = True


@dataclass
class EmbeddingAttacksScannerConfig:
    """Embedding attacks scanner configuration."""

    enabled: bool = True
    check_adversarial: bool = True
    check_inversion: bool = True
    check_collision: bool = True
    check_fine_tune: bool = True


@dataclass
class MultiTenantScannerConfig:
    """Multi-tenant scanner configuration."""

    enabled: bool = True
    check_tenant_isolation: bool = True
    check_query_filtering: bool = True
    check_tenant_awareness: bool = True


@dataclass
class ToolHijackingScannerConfig:
    """Tool hijacking scanner configuration."""

    enabled: bool = True
    check_argument_injection: bool = True
    check_parameter_manipulation: bool = True
    check_tool_validation: bool = True


@dataclass
class RecursiveAgentsScannerConfig:
    """Recursive agents scanner configuration."""

    enabled: bool = True
    check_shared_context: bool = True
    check_agent_validation: bool = True
    check_context_poisoning: bool = True


@dataclass
class MemoryPoisoningScannerConfig:
    """Memory poisoning scanner configuration."""

    enabled: bool = True
    check_memory_validation: bool = True
    check_session_integrity: bool = True
    check_history_poisoning: bool = True


@dataclass
class PlanningAttacksScannerConfig:
    """Planning attacks scanner configuration."""

    enabled: bool = True
    check_plan_validation: bool = True
    check_step_injection: bool = True
    check_goal_manipulation: bool = True


@dataclass
class SecretScannerConfig:
    """Secret scanner configuration."""

    enabled: bool = True
    check_prompts: bool = True
    check_responses: bool = True
    check_headers: bool = True


@dataclass
class DependencyAuditScannerConfig:
    """Dependency audit scanner configuration."""

    enabled: bool = True
    check_cve: bool = True
    check_malicious: bool = True
    check_outdated: bool = True


@dataclass
class PluginSecurityScannerConfig:
    """Plugin security scanner configuration."""

    enabled: bool = True
    check_manifest: bool = True
    check_permissions: bool = True
    check_unsigned_plugins: bool = True


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
    info_disclosure_scanner: InfoDisclosureScannerConfig = field(default_factory=InfoDisclosureScannerConfig)

    # New tool_boundaries submodules
    permission_scanner: PermissionScannerConfig = field(default_factory=PermissionScannerConfig)
    sandbox_scanner: SandboxScannerConfig = field(default_factory=SandboxScannerConfig)
    tool_chains_scanner: ToolChainsScannerConfig = field(default_factory=ToolChainsScannerConfig)
    mcp_scanner: MCPScannerConfig = field(default_factory=MCPScannerConfig)

    # New rag_security submodules
    document_poisoning_scanner: DocumentPoisoningScannerConfig = field(default_factory=DocumentPoisoningScannerConfig)
    exfiltration_scanner: ExfiltrationScannerConfig = field(default_factory=ExfiltrationScannerConfig)
    vector_db_scanner: VectorDBScannerConfig = field(default_factory=VectorDBScannerConfig)
    embedding_attacks_scanner: EmbeddingAttacksScannerConfig = field(default_factory=EmbeddingAttacksScannerConfig)
    multi_tenant_scanner: MultiTenantScannerConfig = field(default_factory=MultiTenantScannerConfig)

    # New agent submodules
    tool_hijacking_scanner: ToolHijackingScannerConfig = field(default_factory=ToolHijackingScannerConfig)
    recursive_agents_scanner: RecursiveAgentsScannerConfig = field(default_factory=RecursiveAgentsScannerConfig)
    memory_poisoning_scanner: MemoryPoisoningScannerConfig = field(default_factory=MemoryPoisoningScannerConfig)
    planning_attacks_scanner: PlanningAttacksScannerConfig = field(default_factory=PlanningAttacksScannerConfig)

    # New infrastructure submodules
    secret_scanner: SecretScannerConfig = field(default_factory=SecretScannerConfig)
    dependency_audit_scanner: DependencyAuditScannerConfig = field(default_factory=DependencyAuditScannerConfig)
    plugin_security_scanner: PluginSecurityScannerConfig = field(default_factory=PluginSecurityScannerConfig)


@dataclass
class OutputConfig:
    """Output/reporting configuration."""

    format: str = "json"  # json, markdown, both
    output_dir: str = "output"
    pretty_print: bool = True
    include_timestamp: bool = True
    verbose: bool = False


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

        logger.debug(f"Configuration loaded: timeout={config.scanner.timeout}, "
                    f"log_level={config.logging.level}")

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
                config.modules.rag_security = RAGSecurityConfig(
                    **modules_raw["rag_security"]
                )

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
            config.scanner.timeout = int(os.getenv("ASS_SCANNER_TIMEOUT"))

        if os.getenv("ASS_SCANNER_MAX_RETRIES"):
            config.scanner.max_retries = int(os.getenv("ASS_SCANNER_MAX_RETRIES"))

        if os.getenv("ASS_SCANNER_RATE_LIMIT"):
            config.scanner.rate_limit = float(os.getenv("ASS_SCANNER_RATE_LIMIT"))

        if os.getenv("ASS_SCANNER_VERIFY_SSL"):
            config.scanner.verify_ssl = os.getenv("ASS_SCANNER_VERIFY_SSL").lower() == "true"

        # Logging overrides
        if os.getenv("ASS_LOG_LEVEL"):
            config.logging.level = os.getenv("ASS_LOG_LEVEL")

        # Output overrides
        if os.getenv("ASS_OUTPUT_FORMAT"):
            config.output.format = os.getenv("ASS_OUTPUT_FORMAT")

        if os.getenv("ASS_OUTPUT_DIR"):
            config.output.output_dir = os.getenv("ASS_OUTPUT_DIR")

        if os.getenv("ASS_VERBOSE"):
            config.output.verbose = os.getenv("ASS_VERBOSE").lower() == "true"

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
