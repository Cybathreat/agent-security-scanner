"""
Sandbox Scanner - Sandbox configuration audit.

Scans for:
- Missing sandbox isolation
- Container escape vectors
- Resource limit misconfigurations
- Root access enabled

References:
- OWASP LLM Top 10: LLM08:2024 - Excessive Agency
- MITRE ATLAS: ML Model Access Control

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, Optional, cast

import aiohttp

from ..base import BaseModule, ScanResult, Severity


class SandboxScannerConfig:
    """Configuration for sandbox scanning."""

    def __init__(
        self,
        enabled: bool = True,
        check_no_sandbox: bool = True,
        check_root_access: bool = True,
        check_resource_limits: bool = True,
        check_network_isolation: bool = True,
    ) -> None:
        self.enabled = enabled
        self.check_no_sandbox = check_no_sandbox
        self.check_root_access = check_root_access
        self.check_resource_limits = check_resource_limits
        self.check_network_isolation = check_network_isolation


class SandboxScanner(BaseModule[SandboxScannerConfig]):
    """
    Sandbox configuration auditor.

    Tests for:
    - No sandbox/isolation configured
    - Root/admin access enabled
    - Unrestricted resource access
    - Network isolation missing
    """

    # Sandbox issue patterns
    SANDBOX_ISSUES = {
        "no_sandbox": "No sandbox isolation configured",
        "no_isolation": "No process isolation",
        "root_access": "Root/admin access enabled",
        "unlimited_memory": "No memory limits",
        "unlimited_cpu": "No CPU limits",
        "network_enabled": "Unrestricted network access",
        "fs_write": "Unrestricted filesystem write",
        "process_spawn": "Unrestricted process spawning",
        "host_mount": "Host filesystem mounted",
        "privileged": "Privileged container mode",
    }

    def __init__(
        self,
        config: Optional[SandboxScannerConfig] = None,
    ) -> None:
        super().__init__()
        self.config = config or SandboxScannerConfig()

    async def _fetch_config(
        self,
        url: str,
        session: aiohttp.ClientSession,
        timeout: int = 10,
    ) -> Optional[Dict[str, Any]]:
        """Fetch sandbox/tool configuration from endpoint."""
        try:
            async with session.get(url, timeout=timeout) as response:
                if response.status == 200:
                    body = await response.text()
                    try:
                        return cast(dict[str, Any], json.loads(body))
                    except json.JSONDecodeError:
                        return {"raw": body}
        except Exception as e:
            self.logger.warning(f"Error fetching config: {e}")
            return None
        return None

    async def _check_no_sandbox(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check if no sandbox is configured."""
        if not self.config.check_no_sandbox:
            return

        self.logger.info(f"Checking for sandbox isolation: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        if "no_sandbox" in config_str or "sandbox" not in config_str:
            finding = self._create_finding(
                severity=Severity.HIGH,
                title="No Sandbox Isolation",
                description=(
                    "No sandbox isolation configured for tool execution. "
                    "This means tools run with the same privileges as the "
                    "agent process, enabling potential system compromise."
                ),
                cwe="CWE-284",
                owasp_ref="OWASP LLM08:2024 - Excessive Agency",
                location=url,
                evidence=["No sandbox configuration found"],
                recommendation=(
                    "Enable sandbox isolation for all tool execution. "
                    "Use containers or VMs with resource limits. "
                    "Drop privileges and use minimal permissions."
                ),
            )
            result.add_finding(finding)

    async def _check_root_access(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for root/admin access enabled."""
        if not self.config.check_root_access:
            return

        self.logger.info(f"Checking root access: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        if "root" in config_str and "access" in config_str:
            finding = self._create_finding(
                severity=Severity.HIGH,
                title="Root/Admin Access Enabled",
                description=(
                    "The tool configuration grants root or admin access. "
                    "This allows tools to perform privileged operations "
                    "that could compromise the entire system."
                ),
                cwe="CWE-284",
                owasp_ref="OWASP LLM08:2024 - Excessive Agency",
                location=url,
                evidence=["Root access configuration found"],
                recommendation=(
                    "Run tools with minimal privileges. "
                    "Use dedicated user accounts with restricted permissions. "
                    "Avoid root/admin unless absolutely necessary."
                ),
            )
            result.add_finding(finding)

    async def _check_resource_limits(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for resource limit misconfigurations."""
        if not self.config.check_resource_limits:
            return

        self.logger.info(f"Checking resource limits: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        # Check for missing limits
        limit_issues = []
        if "unlimited_memory" in config_str:
            limit_issues.append("memory")
        if "unlimited_cpu" in config_str:
            limit_issues.append("CPU")
        if "no_timeout" in config_str or "timeout" not in config_str:
            limit_issues.append("execution time")

        if limit_issues:
            finding = self._create_finding(
                severity=Severity.MEDIUM,
                title=f"Missing Resource Limits: {', '.join(limit_issues)}",
                description=(
                    "Tool execution lacks proper resource limits. "
                    f"Missing limits for: {', '.join(limit_issues)}. "
                    "This enables resource exhaustion attacks (DDoS, memory bombs)."
                ),
                cwe="CWE-770",
                location=url,
                evidence=[f"Missing: {', '.join(limit_issues)}"],
                recommendation=(
                    "Set memory limits per tool invocation. "
                    "Set CPU limits and timeouts. "
                    "Implement rate limiting on tool usage."
                ),
            )
            result.add_finding(finding)

    async def _check_network_isolation(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for network isolation issues."""
        if not self.config.check_network_isolation:
            return

        self.logger.info(f"Checking network isolation: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        if "network_enabled" in config_str or "network_access" in config_str:
            finding = self._create_finding(
                severity=Severity.MEDIUM,
                title="Network Access Not Restricted",
                description=(
                    "Tool execution has unrestricted network access. "
                    "This enables data exfiltration, C2 communication, "
                    "and unauthorized external connections."
                ),
                cwe="CWE-284",
                location=url,
                evidence=["Network access enabled"],
                recommendation=(
                    "Restrict network access to approved domains. "
                    "Use egress filtering. "
                    "Block access to sensitive internal resources. "
                    "Log all network connections."
                ),
            )
            result.add_finding(finding)

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Execute sandbox scan on target."""
        self.logger.info(f"Starting sandbox scan: {target}")

        result = ScanResult(
            module_name=self.module_name,
            target=target,
            metadata={"config": self.config.__dict__},
        )

        async def run_checks() -> None:

            async with aiohttp.ClientSession() as session:
                await asyncio.gather(
                    self._check_no_sandbox(target, session, result),
                    self._check_root_access(target, session, result),
                    self._check_resource_limits(target, session, result),
                    self._check_network_isolation(target, session, result),
                )

        try:
            asyncio.get_running_loop()
            new_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(new_loop)
            new_loop.run_until_complete(run_checks())
            new_loop.close()
        except RuntimeError:
            asyncio.run(run_checks())

        result.finalize()
        self.post_scan(result)

        return result
