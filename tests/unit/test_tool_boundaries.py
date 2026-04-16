"""
Unit tests for ToolBoundariesModule delegator.

Tests:
- Module init and module_name
- Submodule scan delegation (findings + errors aggregated)
- Config flags gating submodule delegation
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent_security_scanner.core.config import ToolBoundariesConfig
from agent_security_scanner.modules.base import BaseModule, Finding, ScanResult, Severity
from agent_security_scanner.modules.tool_boundaries import ToolBoundariesModule


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
# TestToolBoundariesModule
# ---------------------------------------------------------------------------

class TestToolBoundariesModule:
    """Test ToolBoundariesModule init and module_name."""

    def test_init_defaults(self) -> None:
        mod = ToolBoundariesModule()
        assert mod.config is not None
        assert mod.config.check_permissions is True
        assert mod.config.audit_sandbox is True

    def test_init_with_config(self) -> None:
        cfg = ToolBoundariesConfig(check_permissions=False, audit_sandbox=False)
        mod = ToolBoundariesModule(config=cfg)
        assert mod.config.check_permissions is False
        assert mod.config.audit_sandbox is False

    def test_module_name(self) -> None:
        mod = ToolBoundariesModule()
        assert mod.module_name == "tool_boundaries"


# ---------------------------------------------------------------------------
# TestScanDelegation
# ---------------------------------------------------------------------------

class TestScanDelegation:
    """Test that submodules are called and results aggregated."""

    @patch("agent_security_scanner.modules.tool_boundaries.PermissionScanner")
    @patch("agent_security_scanner.modules.tool_boundaries.SandboxScanner")
    @patch("agent_security_scanner.modules.tool_boundaries.ToolChainsScanner")
    @patch("agent_security_scanner.modules.tool_boundaries.MCPScanner")
    @patch("agent_security_scanner.modules.tool_boundaries.ConfusedDeputyScanner")
    def test_submodules_called_and_findings_aggregated(
        self,
        mock_confused_deputy_cls: MagicMock,
        mock_mcp_cls: MagicMock,
        mock_tool_chains_cls: MagicMock,
        mock_sandbox_cls: MagicMock,
        mock_permission_cls: MagicMock,
    ) -> None:
        """Each submodule returns 1 finding -- they should all be aggregated."""
        sub_result = _make_sub_scan_result(findings_count=1)

        for cls in [
            mock_permission_cls,
            mock_sandbox_cls,
            mock_tool_chains_cls,
            mock_mcp_cls,
            mock_confused_deputy_cls,
        ]:
            instance = cls.return_value
            instance.scan.return_value = sub_result
            instance.pre_scan.return_value = True

        # Patch the local async check to be a no-op coroutine
        with patch.object(
            ToolBoundariesModule,
            "_check_allowed_denied_lists",
            new=AsyncMock(),
        ):
            mod = ToolBoundariesModule()
            result = mod.scan("http://test")

        # 5 submodules * 1 finding each = 5 findings
        assert len(result.findings) == 5

    @patch("agent_security_scanner.modules.tool_boundaries.PermissionScanner")
    @patch("agent_security_scanner.modules.tool_boundaries.SandboxScanner")
    @patch("agent_security_scanner.modules.tool_boundaries.ToolChainsScanner")
    @patch("agent_security_scanner.modules.tool_boundaries.MCPScanner")
    @patch("agent_security_scanner.modules.tool_boundaries.ConfusedDeputyScanner")
    def test_errors_aggregated(
        self,
        mock_confused_deputy_cls: MagicMock,
        mock_mcp_cls: MagicMock,
        mock_tool_chains_cls: MagicMock,
        mock_sandbox_cls: MagicMock,
        mock_permission_cls: MagicMock,
    ) -> None:
        """Submodule errors should be aggregated into the top-level result."""
        sub_result = _make_sub_scan_result(errors_count=1)

        for cls in [
            mock_permission_cls,
            mock_sandbox_cls,
            mock_tool_chains_cls,
            mock_mcp_cls,
            mock_confused_deputy_cls,
        ]:
            instance = cls.return_value
            instance.scan.return_value = sub_result
            instance.pre_scan.return_value = True

        with patch.object(
            ToolBoundariesModule,
            "_check_allowed_denied_lists",
            new=AsyncMock(),
        ):
            mod = ToolBoundariesModule()
            result = mod.scan("http://test")

        # 5 submodules * 1 error each = 5 errors
        assert len(result.errors) == 5


# ---------------------------------------------------------------------------
# TestScanDisabled
# ---------------------------------------------------------------------------

class TestScanDisabled:
    """Test that config flags gate submodule delegation."""

    @patch("agent_security_scanner.modules.tool_boundaries.PermissionScanner")
    @patch("agent_security_scanner.modules.tool_boundaries.SandboxScanner")
    def test_check_permissions_false_skips_permission_scanner(
        self,
        mock_sandbox_cls: MagicMock,
        mock_permission_cls: MagicMock,
    ) -> None:
        cfg = ToolBoundariesConfig(check_permissions=False, audit_sandbox=True)
        mod = ToolBoundariesModule(config=cfg)

        with patch.object(
            ToolBoundariesModule,
            "_check_allowed_denied_lists",
            new=AsyncMock(),
        ):
            mod.scan("http://test")

        mock_permission_cls.assert_not_called()

    @patch("agent_security_scanner.modules.tool_boundaries.PermissionScanner")
    @patch("agent_security_scanner.modules.tool_boundaries.SandboxScanner")
    def test_audit_sandbox_false_skips_sandbox_scanner(
        self,
        mock_sandbox_cls: MagicMock,
        mock_permission_cls: MagicMock,
    ) -> None:
        cfg = ToolBoundariesConfig(check_permissions=True, audit_sandbox=False)
        mod = ToolBoundariesModule(config=cfg)

        with patch.object(
            ToolBoundariesModule,
            "_check_allowed_denied_lists",
            new=AsyncMock(),
        ):
            mod.scan("http://test")

        mock_sandbox_cls.assert_not_called()