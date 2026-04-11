"""
Unit tests for base module classes.

Tests Finding, ScanResult, Severity, and BaseModule.

Run: pytest tests/unit/test_base.py -v
"""

import pytest
from datetime import datetime
from unittest.mock import Mock

from src.modules.base import (
    Severity,
    Finding,
    ScanResult,
    BaseModule,
)


class TestSeverity:
    """Test Severity enum."""

    def test_severity_values(self):
        """Test severity enum values."""
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"

    def test_severity_comparison(self):
        """Test severity can be compared."""
        assert Severity.CRITICAL != Severity.HIGH
        assert Severity.HIGH == Severity.HIGH


class TestFinding:
    """Test Finding dataclass."""

    def test_create_finding_minimal(self):
        """Test creating finding with minimal fields."""
        finding = Finding(
            id="FIND-001",
            severity=Severity.HIGH,
            category="prompt_injection",
            title="Test Finding",
            description="Test description",
        )
        assert finding.id == "FIND-001"
        assert finding.severity == Severity.HIGH
        assert finding.category == "prompt_injection"
        assert finding.cwe is None
        assert finding.owasp_ref is None
        assert finding.evidence == []
        assert finding.confidence == "high"

    def test_create_finding_full(self):
        """Test creating finding with all fields."""
        finding = Finding(
            id="FIND-002",
            severity=Severity.CRITICAL,
            category="rag_security",
            title="Critical Issue",
            description="Detailed description",
            cwe="CWE-94",
            owasp_ref="OWASP LLM01:2024",
            mitre_ref="MITRE ATLAS - TA0045",
            location="https://api.example.com",
            evidence=["payload1", "payload2"],
            recommendation="Fix this issue",
            confidence="medium",
        )
        assert finding.cwe == "CWE-94"
        assert finding.owasp_ref == "OWASP LLM01:2024"
        assert finding.mitre_ref == "MITRE ATLAS - TA0045"
        assert len(finding.evidence) == 2
        assert finding.confidence == "medium"

    def test_finding_to_dict(self):
        """Test Finding.to_dict() serialization."""
        finding = Finding(
            id="FIND-003",
            severity=Severity.MEDIUM,
            category="misconfigurations",
            title="CORS Issue",
            description="CORS misconfigured",
            cwe="CWE-942",
        )
        result = finding.to_dict()

        assert result["id"] == "FIND-003"
        assert result["severity"] == "MEDIUM"
        assert result["category"] == "misconfigurations"
        assert result["cwe"] == "CWE-942"
        assert "timestamp" in result
        assert isinstance(result["timestamp"], str)

    def test_finding_timestamp_default(self):
        """Test finding timestamp defaults to current time."""
        finding = Finding(
            id="FIND-004",
            severity=Severity.LOW,
            category="test",
            title="Test",
            description="Test",
        )
        assert isinstance(finding.timestamp, datetime)


class TestScanResult:
    """Test ScanResult dataclass."""

    def test_create_scan_result(self):
        """Test creating scan result."""
        result = ScanResult(
            module_name="prompt_injection",
            target="https://api.example.com",
        )
        assert result.module_name == "prompt_injection"
        assert result.target == "https://api.example.com"
        assert result.findings == []
        assert result.errors == []
        assert result.status == "success"

    def test_add_finding(self):
        """Test adding findings to result."""
        result = ScanResult(module_name="test", target="test")
        finding = Finding(
            id="FIND-005",
            severity=Severity.HIGH,
            category="test",
            title="Test",
            description="Test",
        )
        result.add_finding(finding)
        assert len(result.findings) == 1
        assert result.findings[0].id == "FIND-005"

    def test_add_error(self):
        """Test adding errors to result."""
        result = ScanResult(module_name="test", target="test")
        result.add_error("Connection timeout")
        assert len(result.errors) == 1
        assert result.errors[0] == "Connection timeout"

    def test_finalize_success(self):
        """Test finalize with successful scan."""
        result = ScanResult(module_name="test", target="test")
        result.add_finding(Finding(
            id="FIND-006",
            severity=Severity.LOW,
            category="test",
            title="Test",
            description="Test",
        ))
        result.finalize()
        assert result.status == "success"
        assert result.end_time is not None
        assert result.duration_ms >= 0

    def test_finalize_with_errors(self):
        """Test finalize with errors but no findings."""
        result = ScanResult(module_name="test", target="test")
        result.add_error("Failed to connect")
        result.finalize()
        assert result.status == "failed"

    def test_finalize_partial(self):
        """Test finalize with errors and findings."""
        result = ScanResult(module_name="test", target="test")
        result.add_finding(Finding(
            id="FIND-007",
            severity=Severity.LOW,
            category="test",
            title="Test",
            description="Test",
        ))
        result.add_error("Warning: timeout")
        result.finalize()
        assert result.status == "partial"

    def test_get_summary(self):
        """Test summary calculation."""
        result = ScanResult(module_name="test", target="test")
        result.add_finding(Finding(id="1", severity=Severity.CRITICAL, category="t", title="t", description="t"))
        result.add_finding(Finding(id="2", severity=Severity.HIGH, category="t", title="t", description="t"))
        result.add_finding(Finding(id="3", severity=Severity.HIGH, category="t", title="t", description="t"))
        result.add_finding(Finding(id="4", severity=Severity.MEDIUM, category="t", title="t", description="t"))

        summary = result.get_summary()
        assert summary["total"] == 4
        assert summary["critical"] == 1
        assert summary["high"] == 2
        assert summary["medium"] == 1
        assert summary["low"] == 0

    def test_to_dict(self):
        """Test ScanResult.to_dict() serialization."""
        result = ScanResult(module_name="test", target="test")
        result.add_finding(Finding(
            id="FIND-008",
            severity=Severity.LOW,
            category="test",
            title="Test",
            description="Test",
        ))
        result.finalize()

        data = result.to_dict()
        assert data["module_name"] == "test"
        assert data["target"] == "test"
        assert len(data["findings"]) == 1
        assert data["status"] == "success"
        assert "start_time" in data
        assert "end_time" in data
        assert "duration_ms" in data


class ConcreteTestModule(BaseModule):
    """Concrete implementation of BaseModule for testing."""

    def __init__(self, config=None):
        self.config = config
        super().__init__()

    def scan(self, target: str, **kwargs):
        """Dummy scan implementation."""
        result = ScanResult(module_name=self.module_name, target=target)
        result.finalize()
        return result


class TestBaseModule:
    """Test BaseModule abstract class."""

    def test_module_initialization(self):
        """Test module initialization."""
        module = ConcreteTestModule({"test": "config"})
        assert module.config == {"test": "config"}
        assert module.module_name == "concrete_test"

    def test_generate_finding_id(self):
        """Test finding ID generation."""
        module = ConcreteTestModule()
        finding_id = module._generate_finding_id()
        assert finding_id.startswith("FIND-concrete_test-")
        assert len(finding_id) == len("FIND-concrete_test-") + 8

    def test_create_finding(self):
        """Test convenience method for creating findings."""
        module = ConcreteTestModule()
        finding = module._create_finding(
            severity=Severity.HIGH,
            title="Test Finding",
            description="Test description",
            cwe="CWE-94",
        )
        assert finding.severity == Severity.HIGH
        assert finding.title == "Test Finding"
        assert finding.category == "concrete_test"  # Default from module_name
        assert finding.cwe == "CWE-94"
        assert finding.id.startswith("FIND-concrete_test-")

    def test_pre_scan_default(self):
        """Test default pre_scan implementation."""
        module = ConcreteTestModule()
        assert module.pre_scan("test_target") is True

    def test_post_scan_default(self):
        """Test default post_scan implementation."""
        module = ConcreteTestModule()
        result = ScanResult(module_name="test", target="test")
        module.post_scan(result)  # Should not raise

    def test_get_supported_targets_default(self):
        """Test default supported targets."""
        module = ConcreteTestModule()
        targets = module.get_supported_targets()
        assert "url" in targets
        assert "api_endpoint" in targets
        assert "agent_config" in targets

    def test_scan_abstract_method(self):
        """Test that BaseModule without implementation raises error."""
        with pytest.raises(TypeError):
            # Can't instantiate abstract class without scan() implementation
            BaseModule()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
