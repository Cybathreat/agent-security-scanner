"""
Unit tests for RAGSecurityModule delegator.

Tests:
- Module init and module_name
- Submodule scan delegation (findings + errors aggregated)
- Config flags gating submodule delegation
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from agent_security_scanner.core.config import RAGSecurityConfig
from agent_security_scanner.modules.base import BaseModule, Finding, ScanResult, Severity
from agent_security_scanner.modules.rag_security import RAGSecurityModule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_sub_scan_result(findings_count: int = 0, errors_count: int = 0) -> ScanResult:
    """Create a ScanResult with the requested number of findings/errors."""
    sr = ScanResult(module_name="test_sub", target="http://test")
    for i in range(findings_count):
        sr.add_finding(
            Finding(
                id=f"test-{i}",
                severity=Severity.HIGH,
                category="test",
                title=f"test finding {i}",
                description="test",
            )
        )
    for i in range(errors_count):
        sr.add_error(f"test error {i}")
    sr.finalize()
    return sr


# ---------------------------------------------------------------------------
# TestRAGSecurityModule
# ---------------------------------------------------------------------------

class TestRAGSecurityModule:
    """Test RAGSecurityModule init and module_name."""

    def test_init_defaults(self) -> None:
        mod = RAGSecurityModule()
        assert mod.config is not None
        assert mod.config.check_poisoning is True
        assert mod.config.check_exfiltration is True
        assert mod.config.vector_db_scan is True

    def test_init_with_config(self) -> None:
        cfg = RAGSecurityConfig(
            check_poisoning=False,
            check_exfiltration=False,
            vector_db_scan=False,
        )
        mod = RAGSecurityModule(config=cfg)
        assert mod.config.check_poisoning is False
        assert mod.config.check_exfiltration is False
        assert mod.config.vector_db_scan is False

    def test_module_name(self) -> None:
        mod = RAGSecurityModule()
        assert mod.module_name == "rag_security"


# ---------------------------------------------------------------------------
# TestScanDelegation
# ---------------------------------------------------------------------------

class TestScanDelegation:
    """Test that submodules are called and results aggregated."""

    @patch("agent_security_scanner.modules.rag_security.DocumentPoisoningScanner")
    @patch("agent_security_scanner.modules.rag_security.ExfiltrationScanner")
    @patch("agent_security_scanner.modules.rag_security.VectorDBScanner")
    @patch("agent_security_scanner.modules.rag_security.EmbeddingAttacksScanner")
    @patch("agent_security_scanner.modules.rag_security.MultiTenantScanner")
    @patch("agent_security_scanner.modules.rag_security.PhantomDocumentScanner")
    @patch("agent_security_scanner.modules.rag_security.ChunkBoundaryScanner")
    def test_submodules_called_and_findings_aggregated(
        self,
        mock_chunk_cls: MagicMock,
        mock_phantom_cls: MagicMock,
        mock_multi_tenant_cls: MagicMock,
        mock_embedding_cls: MagicMock,
        mock_vector_cls: MagicMock,
        mock_exfil_cls: MagicMock,
        mock_poison_cls: MagicMock,
    ) -> None:
        """Each submodule returns 1 finding -- they should all be aggregated."""
        sub_result = _make_sub_scan_result(findings_count=1)

        for cls in [
            mock_poison_cls,
            mock_exfil_cls,
            mock_vector_cls,
            mock_embedding_cls,
            mock_multi_tenant_cls,
            mock_phantom_cls,
            mock_chunk_cls,
        ]:
            instance = cls.return_value
            instance.scan.return_value = sub_result
            instance.pre_scan.return_value = True

        mod = RAGSecurityModule()
        result = mod.scan("http://test")

        # 7 submodules * 1 finding each = 7 findings
        assert len(result.findings) == 7

    @patch("agent_security_scanner.modules.rag_security.DocumentPoisoningScanner")
    @patch("agent_security_scanner.modules.rag_security.ExfiltrationScanner")
    @patch("agent_security_scanner.modules.rag_security.VectorDBScanner")
    @patch("agent_security_scanner.modules.rag_security.EmbeddingAttacksScanner")
    @patch("agent_security_scanner.modules.rag_security.MultiTenantScanner")
    @patch("agent_security_scanner.modules.rag_security.PhantomDocumentScanner")
    @patch("agent_security_scanner.modules.rag_security.ChunkBoundaryScanner")
    def test_errors_aggregated(
        self,
        mock_chunk_cls: MagicMock,
        mock_phantom_cls: MagicMock,
        mock_multi_tenant_cls: MagicMock,
        mock_embedding_cls: MagicMock,
        mock_vector_cls: MagicMock,
        mock_exfil_cls: MagicMock,
        mock_poison_cls: MagicMock,
    ) -> None:
        """Submodule errors should be aggregated into the top-level result."""
        sub_result = _make_sub_scan_result(errors_count=1)

        for cls in [
            mock_poison_cls,
            mock_exfil_cls,
            mock_vector_cls,
            mock_embedding_cls,
            mock_multi_tenant_cls,
            mock_phantom_cls,
            mock_chunk_cls,
        ]:
            instance = cls.return_value
            instance.scan.return_value = sub_result
            instance.pre_scan.return_value = True

        mod = RAGSecurityModule()
        result = mod.scan("http://test")

        # 7 submodules * 1 error each = 7 errors
        assert len(result.errors) == 7


# ---------------------------------------------------------------------------
# TestScanDisabled
# ---------------------------------------------------------------------------

class TestScanDisabled:
    """Test that config flags gate submodule delegation."""

    @patch("agent_security_scanner.modules.rag_security.DocumentPoisoningScanner")
    def test_check_poisoning_false_skips_poisoning_scanner(
        self,
        mock_poison_cls: MagicMock,
    ) -> None:
        cfg = RAGSecurityConfig(check_poisoning=False)
        mod = RAGSecurityModule(config=cfg)
        mod.scan("http://test")
        mock_poison_cls.assert_not_called()

    @patch("agent_security_scanner.modules.rag_security.ExfiltrationScanner")
    def test_check_exfiltration_false_skips_exfiltration_scanner(
        self,
        mock_exfil_cls: MagicMock,
    ) -> None:
        cfg = RAGSecurityConfig(check_exfiltration=False)
        mod = RAGSecurityModule(config=cfg)
        mod.scan("http://test")
        mock_exfil_cls.assert_not_called()

    @patch("agent_security_scanner.modules.rag_security.VectorDBScanner")
    def test_vector_db_scan_false_skips_vector_db_scanner(
        self,
        mock_vector_cls: MagicMock,
    ) -> None:
        cfg = RAGSecurityConfig(vector_db_scan=False)
        mod = RAGSecurityModule(config=cfg)
        mod.scan("http://test")
        mock_vector_cls.assert_not_called()