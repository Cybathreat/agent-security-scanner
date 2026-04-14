"""
Permission Scanner - Tool permission boundary analysis.

Scans for:
- Overly permissive tool access
- Missing authorization checks
- Dangerous default settings
- Admin mode configuration

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


class PermissionScannerConfig:
    """Configuration for permission scanning."""

    def __init__(
        self,
        enabled: bool = True,
        check_admin_mode: bool = True,
        check_unrestricted: bool = True,
        check_trust_all: bool = True,
        check_no_validation: bool = True,
    ) -> None:
        self.enabled = enabled
        self.check_admin_mode = check_admin_mode
        self.check_unrestricted = check_unrestricted
        self.check_trust_all = check_trust_all
        self.check_no_validation = check_no_validation


class PermissionScanner(BaseModule[PermissionScannerConfig]):
    """
    Tool permission boundary scanner.

    Tests for:
    - Admin/developer mode enabled
    - Unrestricted tool access
    - Trust-all configurations
    - Missing validation/auth checks
    """

    # Permission issue patterns
    PERMISSION_ISSUES = [
        "allow_all",
        "no_restrictions",
        "admin_mode",
        "unrestricted",
        "skip_validation",
        "trust_all",
        "bypass_auth",
        "disable_auth",
        "no_auth_required",
        "public_access",
    ]

    # Dangerous tool patterns
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

    def __init__(
        self,
        config: Optional[PermissionScannerConfig] = None,
    ) -> None:
        super().__init__()
        self.config = config or PermissionScannerConfig()

    async def _fetch_config(
        self,
        url: str,
        session: aiohttp.ClientSession,
        timeout: int = 10,
    ) -> Optional[Dict[str, Any]]:
        """Fetch tool configuration from endpoint."""
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

    async def _check_admin_mode(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for admin/developer mode configurations."""
        if not self.config.check_admin_mode:
            return

        self.logger.info(f"Checking for admin mode: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        if "admin_mode" in config_str or "developer_mode" in config_str:
            finding = self._create_finding(
                severity=Severity.HIGH,
                title="Admin/Developer Mode Enabled",
                description=(
                    "The tool configuration has admin or developer mode enabled. "
                    "These modes typically disable safety checks and allow "
                    "unrestricted tool execution."
                ),
                cwe="CWE-284",
                owasp_ref="OWASP LLM08:2024 - Excessive Agency",
                location=url,
                evidence=["Admin/developer mode configuration found"],
                recommendation=(
                    "Disable admin/developer mode in production. "
                    "Use environment-specific configurations. "
                    "Implement strict access controls for debugging features."
                ),
            )
            result.add_finding(finding)

    async def _check_unrestricted_access(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for unrestricted tool access."""
        if not self.config.check_unrestricted:
            return

        self.logger.info(f"Checking unrestricted access: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        if "unrestricted" in config_str or "allow_all" in config_str:
            finding = self._create_finding(
                severity=Severity.HIGH,
                title="Unrestricted Tool Access",
                description=(
                    "Tools are configured with unrestricted access. "
                    "This allows any tool to be called without authorization "
                    "checks, enabling privilege escalation."
                ),
                cwe="CWE-284",
                owasp_ref="OWASP LLM08:2024 - Excessive Agency",
                location=url,
                evidence=["Unrestricted configuration found"],
                recommendation=(
                    "Implement tool allowlists/denylists. "
                    "Require explicit authorization for each tool. "
                    "Use least-privilege access control."
                ),
            )
            result.add_finding(finding)

    async def _check_trust_all(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for trust-all configurations."""
        if not self.config.check_trust_all:
            return

        self.logger.info(f"Checking trust-all config: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        if "trust_all" in config_str:
            finding = self._create_finding(
                severity=Severity.HIGH,
                title="Trust-All Configuration Detected",
                description=(
                    "The configuration uses 'trust_all' mode, which bypasses "
                    "security checks by trusting all inputs and tool calls. "
                    "This defeats the purpose of boundary validation."
                ),
                cwe="CWE-284",
                location=url,
                evidence=["Trust-all configuration found"],
                recommendation=(
                    "Remove trust-all configurations. "
                    "Implement proper validation for all tool inputs. "
                    "Use allowlists instead of trusting all inputs."
                ),
            )
            result.add_finding(finding)

    async def _check_missing_validation(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for missing validation/auth checks."""
        if not self.config.check_no_validation:
            return

        self.logger.info(f"Checking for missing validation: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        # Check for dangerous tools without validation
        dangerous_found = []
        for tool in self.DANGEROUS_TOOLS:
            if tool in config_str:
                # Check if auth is required
                if "auth" not in config_str and "validate" not in config_str:
                    dangerous_found.append(tool)

        if dangerous_found:
            finding = self._create_finding(
                severity=Severity.HIGH,
                title=f"Unvalidated Dangerous Tools: {', '.join(dangerous_found[:3])}",
                description=(
                    "Dangerous tools are available without apparent validation or "
                    "authentication. This enables attackers to execute privileged "
                    "operations without authorization."
                ),
                cwe="CWE-284",
                owasp_ref="OWASP LLM08:2024 - Excessive Agency",
                location=url,
                evidence=[f"Tools without auth: {', '.join(dangerous_found[:5])}"],
                recommendation=(
                    "Implement mandatory authorization for all dangerous tools. "
                    "Add input validation before tool execution. "
                    "Log all tool invocations for auditing."
                ),
            )
            result.add_finding(finding)

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Execute permission scan on target."""
        self.logger.info(f"Starting permission scan: {target}")

        result = ScanResult(
            module_name=self.module_name,
            target=target,
            metadata={"config": self.config.__dict__},
        )

        async def run_checks() -> None:

            async with aiohttp.ClientSession() as session:
                await asyncio.gather(
                    self._check_admin_mode(target, session, result),
                    self._check_unrestricted_access(target, session, result),
                    self._check_trust_all(target, session, result),
                    self._check_missing_validation(target, session, result),
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
