"""
Sandbox Scanner - Sandbox configuration audit.

Scans for:
- Missing sandbox isolation
- Container escape vectors
- Resource limit misconfigurations
- Root access enabled

References:
- OWASP LLM Top 10: LLM08:2025 - Excessive Agency
- MITRE ATLAS: TA0045 LLM Attack

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional

import aiohttp

from ..base import BaseModule, ScanResult, Severity


class SandboxScannerConfig:
    """Configuration for sandbox scanning."""

    def __init__(
        self,
        enabled: bool = True,
        test_no_sandbox: bool = True,
        test_root_access: bool = True,
        test_resource_limits: bool = True,
        test_network_isolation: bool = True,
        compliance_threshold: float = 0.6,
        request_delay: float = 0.5,
    ) -> None:
        self.enabled = enabled
        self.test_no_sandbox = test_no_sandbox
        self.test_root_access = test_root_access
        self.test_resource_limits = test_resource_limits
        self.test_network_isolation = test_network_isolation
        self.compliance_threshold = compliance_threshold
        self.request_delay = request_delay


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
        self.config = config or SandboxScannerConfig()
        super().__init__()

    async def _check_no_sandbox(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
        cached_config: Optional[Dict[str, Any]],
    ) -> None:
        """Check if no sandbox is configured."""
        if not self.config.test_no_sandbox:
            return

        self.logger.info(f"Checking for sandbox isolation: {url}")

        if cached_config is None:
            return

        import json
        config_str = json.dumps(cached_config).lower()

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
                owasp_ref="OWASP LLM08:2025 - Excessive Agency",
                mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
                location=url,
                evidence=["No sandbox configuration found"],
                recommendation=(
                    "Enable sandbox isolation for all tool execution. "
                    "Use containers or VMs with resource limits. "
                    "Drop privileges and use minimal permissions."
                ),
            )
            result.add_finding(finding)

        if self.config.request_delay > 0:
            await asyncio.sleep(self.config.request_delay)

    async def _check_root_access(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
        cached_config: Optional[Dict[str, Any]],
    ) -> None:
        """Check for root/admin access enabled."""
        if not self.config.test_root_access:
            return

        self.logger.info(f"Checking root access: {url}")

        if cached_config is None:
            return

        import json
        config_str = json.dumps(cached_config).lower()

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
                owasp_ref="OWASP LLM08:2025 - Excessive Agency",
                mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
                location=url,
                evidence=["Root access configuration found"],
                recommendation=(
                    "Run tools with minimal privileges. "
                    "Use dedicated user accounts with restricted permissions. "
                    "Avoid root/admin unless absolutely necessary."
                ),
            )
            result.add_finding(finding)

        if self.config.request_delay > 0:
            await asyncio.sleep(self.config.request_delay)

    async def _check_resource_limits(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
        cached_config: Optional[Dict[str, Any]],
    ) -> None:
        """Check for resource limit misconfigurations."""
        if not self.config.test_resource_limits:
            return

        self.logger.info(f"Checking resource limits: {url}")

        if cached_config is None:
            return

        import json
        config_str = json.dumps(cached_config).lower()

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
                owasp_ref="OWASP LLM08:2025 - Excessive Agency",
                mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
                location=url,
                evidence=[f"Missing: {', '.join(limit_issues)}"],
                recommendation=(
                    "Set memory limits per tool invocation. "
                    "Set CPU limits and timeouts. "
                    "Implement rate limiting on tool usage."
                ),
            )
            result.add_finding(finding)

        if self.config.request_delay > 0:
            await asyncio.sleep(self.config.request_delay)

    async def _check_network_isolation(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
        cached_config: Optional[Dict[str, Any]],
    ) -> None:
        """Check for network isolation issues."""
        if not self.config.test_network_isolation:
            return

        self.logger.info(f"Checking network isolation: {url}")

        if cached_config is None:
            return

        import json
        config_str = json.dumps(cached_config).lower()

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
                owasp_ref="OWASP LLM08:2025 - Excessive Agency",
                mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
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

        if self.config.request_delay > 0:
            await asyncio.sleep(self.config.request_delay)

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Execute sandbox scan on target."""
        self.logger.info(f"Starting sandbox scan: {target}")

        result = ScanResult(
            module_name=self.module_name,
            target=target,
            metadata={
                "test_no_sandbox": self.config.test_no_sandbox,
                "test_root_access": self.config.test_root_access,
                "test_resource_limits": self.config.test_resource_limits,
                "test_network_isolation": self.config.test_network_isolation,
            },
        )

        if not self.config.enabled:
            self.logger.info("Sandbox scanning disabled")
            result.finalize()
            return result

        async def run_checks() -> None:
            async with aiohttp.ClientSession() as session:
                # Cache config fetch once at start
                cached_config = await self._fetch_url(url=target, session=session)

                await asyncio.gather(
                    self._check_no_sandbox(target, session, result, cached_config),
                    self._check_root_access(target, session, result, cached_config),
                    self._check_resource_limits(target, session, result, cached_config),
                    self._check_network_isolation(target, session, result, cached_config),
                )

        try:
            asyncio.get_running_loop()
            new_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(new_loop)
            try:
                new_loop.run_until_complete(run_checks())
            finally:
                new_loop.close()
                asyncio.set_event_loop(None)
        except RuntimeError:
            asyncio.run(run_checks())

        result.finalize()
        return result