"""
Permission Scanner - Tool permission boundary analysis.

Scans for:
- Overly permissive tool access
- Missing authorization checks
- Dangerous default settings
- Admin mode configuration

References:
- OWASP LLM Top 10: LLM08:2025 - Excessive Agency
- MITRE ATLAS: ML Model Access Control - TA0045 LLM Attack

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
        test_admin_mode: bool = True,
        test_unrestricted: bool = True,
        test_trust_all: bool = True,
        test_no_validation: bool = True,
        compliance_threshold: float = 0.6,
        request_delay: float = 0.5,
    ) -> None:
        self.enabled = enabled
        self.test_admin_mode = test_admin_mode
        self.test_unrestricted = test_unrestricted
        self.test_trust_all = test_trust_all
        self.test_no_validation = test_no_validation
        self.compliance_threshold = compliance_threshold
        self.request_delay = request_delay


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
        self.config = config or PermissionScannerConfig()
        super().__init__()

    async def _fetch_config(
        self,
        url: str,
        session: aiohttp.ClientSession,
    ) -> Optional[Dict[str, Any]]:
        """Fetch tool configuration from endpoint using base class _fetch_url."""
        response = await self._fetch_url(url=url, session=session)
        if response is None:
            return None
        if response["status"] != 200:
            return None
        body = response["body"]
        try:
            return cast(dict[str, Any], json.loads(body))
        except json.JSONDecodeError:
            return {"raw": body}

    async def _check_admin_mode(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
        config_data: Optional[Dict[str, Any]],
    ) -> None:
        """Check for admin/developer mode configurations."""
        if not self.config.test_admin_mode:
            return

        self.logger.info(f"Checking for admin mode: {url}")

        if config_data is None:
            return

        config_str = json.dumps(config_data).lower()

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
                owasp_ref="OWASP LLM08:2025 - Excessive Agency",
                mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
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
        config_data: Optional[Dict[str, Any]],
    ) -> None:
        """Check for unrestricted tool access."""
        if not self.config.test_unrestricted:
            return

        self.logger.info(f"Checking unrestricted access: {url}")

        if config_data is None:
            return

        config_str = json.dumps(config_data).lower()

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
                owasp_ref="OWASP LLM08:2025 - Excessive Agency",
                mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
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
        config_data: Optional[Dict[str, Any]],
    ) -> None:
        """Check for trust-all configurations."""
        if not self.config.test_trust_all:
            return

        self.logger.info(f"Checking trust-all config: {url}")

        if config_data is None:
            return

        config_str = json.dumps(config_data).lower()

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
                owasp_ref="OWASP LLM08:2025 - Excessive Agency",
                mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
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
        config_data: Optional[Dict[str, Any]],
    ) -> None:
        """Check for missing validation/auth checks."""
        if not self.config.test_no_validation:
            return

        self.logger.info(f"Checking for missing validation: {url}")

        if config_data is None:
            return

        config_str = json.dumps(config_data).lower()

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
                owasp_ref="OWASP LLM08:2025 - Excessive Agency",
                mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
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
            metadata={
                "test_admin_mode": self.config.test_admin_mode,
                "test_unrestricted": self.config.test_unrestricted,
                "test_trust_all": self.config.test_trust_all,
                "test_no_validation": self.config.test_no_validation,
            },
        )

        if not self.config.enabled:
            self.logger.info("Permission scanning disabled")
            result.finalize()
            return result

        async def run_checks() -> None:

            async with aiohttp.ClientSession() as session:
                # Cache the config response once for all checks
                config_data = await self._fetch_config(target, session)

                await asyncio.gather(
                    self._check_admin_mode(target, session, result, config_data),
                    self._check_unrestricted_access(target, session, result, config_data),
                    self._check_trust_all(target, session, result, config_data),
                    self._check_missing_validation(target, session, result, config_data),
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