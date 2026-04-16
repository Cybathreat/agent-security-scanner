"""
Tool Calling Boundaries Module.

Delegates to submodules for tool permission, sandbox, chain, MCP, and
confused-deputy scanning.  Also retains a unique local check for
allowed/denied tool lists.

References:
- OWASP LLM Top 10: LLM02:2024 - Insecure Output Handling
- OWASP LLM Top 10: LLM08:2024 - Excessive Agency
- MITRE ATLAS: ML Model Access Control

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, List, Optional, cast

import aiohttp

from ..core.config import ToolBoundariesConfig
from .base import BaseModule, ScanResult, Severity
from .tool_boundaries_submodules.permission_scanner import (
    PermissionScanner,
    PermissionScannerConfig,
)
from .tool_boundaries_submodules.sandbox_scanner import (
    SandboxScanner,
    SandboxScannerConfig,
)
from .tool_boundaries_submodules.tool_chains import (
    ToolChainsScanner,
    ToolChainsScannerConfig,
)
from .tool_boundaries_submodules.mcp_scanner import (
    MCPScanner,
    MCPScannerConfig,
)
from .tool_boundaries_submodules.confused_deputy import (
    ConfusedDeputyScanner,
    ConfusedDeputyScannerConfig,
)


# Dangerous tools used only by the local _check_allowed_denied_lists method
DANGEROUS_TOOLS = [
    "execute_code",
    "run_command",
    "shell_exec",
    "write_file",
    "delete_file",
    "read_file",
    "http_request",
    "sql_query",
    "admin_action",
    "escalate_privilege",
    "bypass_auth",
    "access_secrets",
]


class ToolBoundariesModule(BaseModule[ToolBoundariesConfig]):
    """
    Tool calling boundaries validation module.

    Delegates to submodules:
    - PermissionScanner (when check_permissions is enabled)
    - SandboxScanner (when audit_sandbox is enabled)
    - ToolChainsScanner
    - MCPScanner
    - ConfusedDeputyScanner

    Also runs a unique local check: _check_allowed_denied_lists.
    """

    def __init__(
        self,
        config: Optional[ToolBoundariesConfig] = None,
    ) -> None:
        """
        Initialize tool boundaries scanner.

        Args:
            config: Configuration for tool boundary checks.
        """
        self.config = config or ToolBoundariesConfig()
        super().__init__()

    async def _check_allowed_denied_lists(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """
        Validate allowed/denied tool lists.

        Checks if allowlists/denylists are properly configured.

        Args:
            url: Target endpoint
            session: aiohttp session
            result: Scan result container
        """
        self.logger.info(f"Checking tool lists: {url}")

        try:
            async with session.get(url, timeout=10) as response:
                if response.status != 200:
                    return
                body = await response.text()
                try:
                    config_data = cast(dict[str, Any], json.loads(body))
                except json.JSONDecodeError:
                    config_data = {"raw": body}
        except (asyncio.TimeoutError, aiohttp.ClientError, json.JSONDecodeError):
            return

        # Check for empty or missing lists
        allowed: List[str] = config_data.get("allowed_tools", [])
        denied: List[str] = config_data.get("denied_tools", [])

        if not allowed and not denied:
            finding = self._create_finding(
                severity=Severity.MEDIUM,
                title="Missing Tool Allowlist/Denylist",
                description=(
                    "No tool allowlist or denylist configured. All tools may "
                    "be accessible without restriction. Implement explicit "
                    "tool access policies."
                ),
                cwe="CWE-284",
                location=url,
                evidence=["No allowed_tools or denied_tools configured"],
                recommendation=(
                    "Implement tool allowlist for production. "
                    "Explicitly deny dangerous tools. "
                    "Review and update lists regularly."
                ),
            )
            result.add_finding(finding)

        # Check if dangerous tools are not denied
        if denied:
            for dangerous in DANGEROUS_TOOLS:
                if dangerous not in denied:
                    finding = self._create_finding(
                        severity=Severity.LOW,
                        title=f"Dangerous Tool Not Denied: {dangerous}",
                        description=(
                            f"The dangerous tool '{dangerous}' is not in the "
                            "denylist. Consider explicitly denying this tool "
                            "or moving to an allowlist model."
                        ),
                        cwe="CWE-284",
                        location=url,
                        evidence=[f"Tool: {dangerous}", "Not in denied list"],
                        recommendation=f"Add {dangerous} to denied_tools list.",
                    )
                    result.add_finding(finding)

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """
        Execute tool boundaries scan on target.

        Delegates to submodules and runs the local allowed/denied
        lists check.

        Args:
            target: Tool configuration endpoint URL
            **kwargs: Additional parameters (timeout, headers, etc.)

        Returns:
            ScanResult: Findings, errors, and metadata.
        """
        self.logger.info(f"Starting tool boundaries scan: {target}")

        result = ScanResult(
            module_name=self.module_name,
            target=target,
            metadata={
                "config": self.config.to_dict() if hasattr(self.config, "to_dict") else {},
            },
        )

        if not self.pre_scan(target):
            result.add_error("Pre-scan validation failed")
            result.finalize()
            return result

        # Build the list of enabled submodules
        submodules: list[BaseModule] = []

        if self.config.check_permissions:
            submodules.append(
                PermissionScanner(PermissionScannerConfig())
            )

        if self.config.audit_sandbox:
            submodules.append(
                SandboxScanner(SandboxScannerConfig())
            )

        submodules.append(ToolChainsScanner(ToolChainsScannerConfig()))
        submodules.append(MCPScanner(MCPScannerConfig()))
        submodules.append(ConfusedDeputyScanner(ConfusedDeputyScannerConfig()))

        # Delegate to submodules
        for submod in submodules:
            sub_result = submod.scan(target)
            for finding in sub_result.findings:
                result.add_finding(finding)
            for error in sub_result.errors:
                result.add_error(error)

        # Run the unique local check (async)
        async def run_local_checks() -> None:
            async with aiohttp.ClientSession() as session:
                await self._check_allowed_denied_lists(target, session, result)

        try:
            asyncio.get_running_loop()
            new_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(new_loop)
            new_loop.run_until_complete(run_local_checks())
            new_loop.close()
        except RuntimeError:
            asyncio.run(run_local_checks())

        result.finalize()
        self.post_scan(result)

        return result