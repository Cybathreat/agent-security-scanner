"""
Unit tests for configuration module.

Tests Config loading, environment overrides, and serialization.

Run: pytest tests/unit/test_config.py -v
"""

import os
import pytest
import tempfile
from pathlib import Path

import yaml

from agent_security_scanner.core.config import (
    Config,
    ScannerConfig,
    PromptInjectionConfig,
    RAGSecurityConfig,
    ToolBoundariesConfig,
    MisconfigurationsConfig,
    OutputConfig,
    LoggingConfig,
    load_config,
)


class TestScannerConfig:
    """Test ScannerConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = ScannerConfig()
        assert config.timeout == 30
        assert config.max_retries == 3
        assert config.rate_limit == 10.0
        assert config.verify_ssl is True
        assert config.proxy is None

    def test_custom_values(self):
        """Test custom configuration values."""
        config = ScannerConfig(timeout=60, max_retries=5, rate_limit=20.0)
        assert config.timeout == 60
        assert config.max_retries == 5
        assert config.rate_limit == 20.0


class TestPromptInjectionConfig:
    """Test PromptInjectionConfig dataclass."""

    def test_default_values(self):
        """Test default values."""
        config = PromptInjectionConfig()
        assert config.enabled is True
        assert config.sensitivity == "high"
        assert config.detect_obfuscation is True

    def test_custom_values(self):
        """Test custom values."""
        config = PromptInjectionConfig(enabled=False, sensitivity="low")
        assert config.enabled is False
        assert config.sensitivity == "low"


class TestRAGSecurityConfig:
    """Test RAGSecurityConfig dataclass."""

    def test_default_values(self):
        """Test default values."""
        config = RAGSecurityConfig()
        assert config.enabled is True
        assert config.check_poisoning is True
        assert config.check_exfiltration is True
        assert config.vector_db_scan is True


class TestConfigLoad:
    """Test Config.load() method."""

    def test_load_default_config(self):
        """Test loading with no config file (defaults)."""
        config = Config.load()
        assert config.scanner.timeout == 30
        assert config.modules.prompt_injection.enabled is True
        assert config.output.format == "json"

    def test_load_from_yaml_file(self):
        """Test loading from YAML file."""
        yaml_content = """
scanner:
  timeout: 60
  max_retries: 5

modules:
  prompt_injection:
    enabled: false
    sensitivity: low

output:
  format: markdown
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            temp_path = f.name

        try:
            config = Config.load(temp_path)
            assert config.scanner.timeout == 60
            assert config.scanner.max_retries == 5
            assert config.modules.prompt_injection.enabled is False
            assert config.modules.prompt_injection.sensitivity == "low"
            assert config.output.format == "markdown"
        finally:
            os.unlink(temp_path)

    def test_load_nonexistent_file(self):
        """Test loading nonexistent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            Config.load("/nonexistent/path/config.yaml")

    def test_load_empty_file(self):
        """Test loading empty YAML file returns defaults."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("")
            temp_path = f.name

        try:
            config = Config.load(temp_path)
            assert config.scanner.timeout == 30  # Default
        finally:
            os.unlink(temp_path)


class TestEnvironmentOverrides:
    """Test environment variable overrides."""

    def test_scanner_timeout_override(self):
        """Test ASS_SCANNER_TIMEOUT override."""
        os.environ["ASS_SCANNER_TIMEOUT"] = "90"
        config = Config.load()
        assert config.scanner.timeout == 90
        del os.environ["ASS_SCANNER_TIMEOUT"]

    def test_log_level_override(self):
        """Test ASS_LOG_LEVEL override."""
        os.environ["ASS_LOG_LEVEL"] = "DEBUG"
        config = Config.load()
        assert config.logging.level == "DEBUG"
        del os.environ["ASS_LOG_LEVEL"]

    def test_output_format_override(self):
        """Test ASS_OUTPUT_FORMAT override."""
        os.environ["ASS_OUTPUT_FORMAT"] = "markdown"
        config = Config.load()
        assert config.output.format == "markdown"
        del os.environ["ASS_OUTPUT_FORMAT"]

    def test_verify_ssl_override(self):
        """Test ASS_SCANNER_VERIFY_SSL override."""
        os.environ["ASS_SCANNER_VERIFY_SSL"] = "false"
        config = Config.load()
        assert config.scanner.verify_ssl is False
        del os.environ["ASS_SCANNER_VERIFY_SSL"]


class TestConfigToDict:
    """Test Config.to_dict() serialization."""

    def test_to_dict_structure(self):
        """Test dictionary structure."""
        config = Config()
        result = config.to_dict()

        assert "scanner" in result
        assert "modules" in result
        assert "output" in result
        assert "logging" in result

        assert "timeout" in result["scanner"]
        assert "prompt_injection" in result["modules"]
        assert "format" in result["output"]
        assert "level" in result["logging"]

    def test_to_dict_values(self):
        """Test dictionary values match config."""
        config = Config()
        result = config.to_dict()

        assert result["scanner"]["timeout"] == 30
        assert result["modules"]["prompt_injection"]["enabled"] is True
        assert result["output"]["format"] == "json"


class TestLoadConfigFunction:
    """Test load_config() convenience function."""

    def test_load_config_default(self):
        """Test load_config with no arguments."""
        config = load_config()
        assert isinstance(config, Config)
        assert config.scanner.timeout == 30

    def test_load_config_with_path(self):
        """Test load_config with YAML path."""
        yaml_content = "scanner:\n  timeout: 45\n"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            temp_path = f.name

        try:
            config = load_config(temp_path)
            assert config.scanner.timeout == 45
        finally:
            os.unlink(temp_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
