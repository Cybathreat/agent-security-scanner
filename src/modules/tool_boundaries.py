"""
Tool Calling Boundaries Module.

Validates tool calling permission boundaries, sandboxing configurations,
and access control for AI agent tool integrations.

References:
- OWASP LLM Top 10: LLM02:2024 - Insecure Output Handling
- OWASP LLM Top 10: LLM08:2024 - Excessive Agency
- MITRE ATLAS: ML Model Access Control

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional

import aiohttp
from loguru import logger

from ..core.config import ToolBoundariesConfig
from .base import BaseModule, Finding, ScanResult, Severity


class ToolBoundariesModule(BaseModule[ToolBoundariesConfig]):
    """
    Tool calling boundaries validation module.

    Checks for:
    - Overly permissive tool access
    - Missing tool authorization
    - Dangerous tool combinations
    - Sandbox escape vectors
    - Privilege escalation via tools
    - Unrestricted file system access
    - Network tool abuse potential
    """

    # Dangerous tool patterns to detect
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

    # Tool permission misconfiguration patterns
    PERMISSION_ISSUES = [
        "allow_all",
        "no_restrictions",
        "admin_mode",
        "unrestricted",
        "skip_validation",
        "trust_all",
    ]

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

    async def _fetch_tool_config(
        self,
        url: str,
        session: aiohttp.ClientSession,
        timeout: int = 10,
    ) -> Optional[Dict[str, Any]]:
        """
        Fetch tool configuration from target endpoint.

        Args:
            url: Target API endpoint
            session: aiohttp session
            timeout: Request timeout

        Returns:
            Dict: Tool configuration or None on error.
        """
        try:
            async with session.get(url, timeout=timeout) as response:
                if response.status == 200:
                    content_type = response.headers.get("Content-Type", "")
                    body = await response.text()

                    if "application/json" in content_type:
                        return json.loads(body)
                    else:
                        # Try to parse as JSON anyway
                        try:
                            return json.loads(body)
                        except json.JSONDecodeError:
                            return {"raw": body}
        except asyncio.TimeoutError:
            self.logger.warning(f"Timeout fetching tool config: {url}")
        except aiohttp.ClientError as e:
            self.logger.warning(f"Error fetching tool config: {e}")
        except json.JSONDecodeError:
            self.logger.warning(f"Invalid JSON response: {url}")

        return None

    async def _check_tool_permissions(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """
        Check tool permission configurations.

        Analyzes tool access controls for:
        - Missing authorization
        - Overly broad permissions
        - Dangerous default settings

        Args:
            url: Target endpoint
            session: aiohttp session
            result: Scan result container
        """
        if not self.config.check_permissions:
            self.logger.debug("Permission check disabled")
            return

        self.logger.info(f"Checking tool permissions: {url}")

        config = await self._fetch_tool_config(url, session)

        if config is None:
            result.add_error(f"Failed to fetch tool config: {url}")
            return

        # Flatten config for searching
        config_str = json.dumps(config).lower()

        # Check for permission issues
        for issue_pattern in self.PERMISSION_ISSUES:
            if issue_pattern in config_str:
                finding = self._create_finding(
                    severity=Severity.HIGH,
                    title="Overly Permissive Tool Configuration",
                    description=(
                        f"Tool configuration contains '{issue_pattern}' which "
                        "indicates overly broad permissions. This may allow "
                        "unauthorized tool execution or privilege escalation."
                    ),
                    cwe="CWE-284",  # Improper Access Control
                    owasp_ref="OWASP LLM08:2024 - Excessive Agency",
                    mitre_ref="MITRE ATLAS - ML Model Access Control",
                    location=url,
                    evidence=[f"Found pattern: {issue_pattern}", f"Config: {config_str[:200]}"],
                    recommendation=(
                        "Implement least-privilege access for tools. "
                        "Require explicit authorization per tool. "
                        "Use allowlists instead of denylists. "
                        "Validate tool permissions on each invocation."
                    ),
                )
                result.add_finding(finding)
                self.logger.info(f"Permission finding: {finding.id}")

        # Check for dangerous tools
        for dangerous_tool in self.DANGEROUS_TOOLS:
            if dangerous_tool in config_str:
                # Check if there's access control
                has_auth_check = any(
                    keyword in config_str
                    for keyword in ["auth", "permission", "check", "validate", "require"]
                )

                if not has_auth_check:
                    finding = self._create_finding(
                        severity=Severity.HIGH,
                        title=f"Unrestricted Dangerous Tool: {dangerous_tool}",
                        description=(
                            f"The tool '{dangerous_tool}' is available without "
                            "apparent access control. This tool could enable "
                            "code execution, file manipulation, or privilege "
                            "escalation if misused."
                        ),
                        cwe="CWE-284",
                        owasp_ref="OWASP LLM08:2024 - Excessive Agency",
                        location=url,
                        evidence=[f"Tool found: {dangerous_tool}", "No auth check detected"],
                        recommendation=(
                            f"Restrict access to {dangerous_tool}. "
                            "Implement mandatory authorization. "
                            "Log all tool invocations. "
                            "Consider removing dangerous tools from production."
                        ),
                    )
                    result.add_finding(finding)

    async def _check_sandbox_config(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """
        Check sandboxing configuration for tool execution.

        Tests for:
        - Missing sandbox isolation
        - Container escape vectors
        - Resource limit misconfigurations

        Args:
            url: Target endpoint
            session: aiohttp session
            result: Scan result container
        """
        if not self.config.audit_sandbox:
            self.logger.debug("Sandbox audit disabled")
            return

        self.logger.info(f"Auditing sandbox config: {url}")

        config = await self._fetch_tool_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        # Sandbox misconfiguration indicators
        sandbox_issues = {
            "no_sandbox": "No sandbox isolation configured",
            "root_access": "Root/admin access enabled",
            "unlimited_memory": "No memory limits",
            "unlimited_cpu": "No CPU limits",
            "network_enabled": "Unrestricted network access",
            "fs_write": "Unrestricted filesystem write",
            "process_spawn": "Unrestricted process spawning",
        }

        for key, description in sandbox_issues.items():
            if key in config_str:
                severity = Severity.HIGH if key in ["root_access", "no_sandbox"] else Severity.MEDIUM

                finding = self._create_finding(
                    severity=severity,
                    title=f"Sandbox Misconfiguration: {key.replace('_', ' ').title()}",
                    description=description,
                    cwe="CWE-284",
                    owasp_ref="OWASP LLM08:2024 - Excessive Agency",
                    location=url,
                    evidence=[f"Found: {key}"],
                    recommendation=(
                        "Enable sandbox isolation for all tool execution. "
                        "Use containers/VMs with resource limits. "
                        "Drop privileges. Restrict network and filesystem. "
                        "Implement mandatory access control (SELinux/AppArmor)."
                    ),
                )
                result.add_finding(finding)

    async def _check_tool_chain(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """
        Check for dangerous tool chains/combinations.

        Some tools are safe individually but dangerous when combined.
        Example: read_file + http_request = data exfiltration

        Args:
            url: Target endpoint
            session: aiohttp session
            result: Scan result container
        """
        self.logger.info(f"Checking tool chains: {url}")

        config = await self._fetch_tool_config(url, session)

        if config is None:
            return

        # Extract available tools
        tools: list[str] = []
        if isinstance(config, dict):
            tools_val = config.get("tools", config.get("available_tools", []))
            if tools_val:
                tools = tools_val if isinstance(tools_val, list) else []

        if not tools:
            # Try to find tools in nested structure
            config_str = json.dumps(config)
            for tool in self.DANGEROUS_TOOLS:
                if tool in config_str:
                    tools.append(tool)

        # Dangerous combinations
        dangerous_chains = [
            (["read_file", "http_request"], "Data exfiltration risk"),
            (["write_file", "execute_code"], "Malicious code deployment"),
            (["sql_query", "http_request"], "Database exfiltration"),
            (["read_file", "sql_query"], "File + DB data aggregation"),
            (["execute_code", "network"], "Remote code execution"),
        ]

        for chain, risk in dangerous_chains:
            if all(tool in tools for tool in chain):
                finding = self._create_finding(
                    severity=Severity.HIGH,
                    title=f"Dangerous Tool Chain: {' + '.join(chain)}",
                    description=(
                        f"The combination of {', '.join(chain)} enables {risk}. "
                        "Attackers can chain these tools to achieve objectives "
                        "that individual tools would prevent."
                    ),
                    cwe="CWE-284",
                    owasp_ref="OWASP LLM08:2024 - Excessive Agency",
                    location=url,
                    evidence=[f"Tools available: {chain}", f"Risk: {risk}"],
                    recommendation=(
                        "Audit tool combinations for security implications. "
                        "Implement tool chain detection. "
                        "Require elevated authorization for dangerous chains. "
                        "Log and monitor tool invocation patterns."
                    ),
                )
                result.add_finding(finding)

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

        config = await self._fetch_tool_config(url, session)

        if config is None:
            return

        # Check for empty or missing lists
        allowed = config.get("allowed_tools", [])
        denied = config.get("denied_tools", [])

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
            for dangerous in self.DANGEROUS_TOOLS:
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
                "dangerous_tools_checked": len(self.DANGEROUS_TOOLS),
                "config": self.config.to_dict() if hasattr(self.config, "to_dict") else {},
            },
        )

        if not self.pre_scan(target):
            result.add_error("Pre-scan validation failed")
            result.finalize()
            return result

        # Run async checks
        async def run_checks() -> None:
            timeout = kwargs.get("timeout", 10)

            async with aiohttp.ClientSession() as session:
                await asyncio.gather(
                    self._check_tool_permissions(target, session, result),
                    self._check_sandbox_config(target, session, result),
                    self._check_tool_chain(target, session, result),
                    self._check_allowed_denied_lists(target, session, result),
                )

        # Handle running inside or outside event loop
        try:
            asyncio.get_running_loop()
            # Running inside event loop - create new loop
            new_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(new_loop)
            new_loop.run_until_complete(run_checks())
            new_loop.close()
        except RuntimeError:
            asyncio.run(run_checks())

        result.finalize()
        self.post_scan(result)

        return result
