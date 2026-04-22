"""
Tool Chains Scanner - Dangerous tool combinations detection.

Scans for:
- Data exfiltration chains (read + http)
- Code deployment chains (write + execute)
- Database exfiltration chains

References:
- OWASP LLM Top 10: LLM08:2025 - Excessive Agency
- MITRE ATLAS: TA0045 LLM Attack

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional

import aiohttp

from ..base import BaseModule, ScanResult, Severity


class ToolChainsScannerConfig:
    """Configuration for tool chains scanning."""

    def __init__(
        self,
        enabled: bool = True,
        test_exfiltration: bool = True,
        test_code_deployment: bool = True,
        test_database_exfil: bool = True,
        compliance_threshold: float = 0.6,
        request_delay: float = 0.5,
    ) -> None:
        self.enabled = enabled
        self.test_exfiltration = test_exfiltration
        self.test_code_deployment = test_code_deployment
        self.test_database_exfil = test_database_exfil
        self.compliance_threshold = compliance_threshold
        self.request_delay = request_delay


class ToolChainsScanner(BaseModule[ToolChainsScannerConfig]):
    """
    Tool chain analysis scanner.

    Tests for:
    - Dangerous tool combinations that enable attacks
    - Tool chains that bypass individual restrictions
    """

    # Dangerous tool combinations
    DANGEROUS_CHAINS = [
        (
            ["read_file", "http_request"],
            "Data exfiltration risk",
            "An attacker can read sensitive files and transmit them externally",
        ),
        (
            ["write_file", "execute_code"],
            "Malicious code deployment",
            "An attacker can write malicious code to disk and then execute it",
        ),
        (
            ["sql_query", "http_request"],
            "Database exfiltration",
            "An attacker can query the database and exfiltrate results",
        ),
        (
            ["read_file", "sql_query"],
            "File + Database aggregation",
            "An attacker can combine file and database access for data harvesting",
        ),
        (
            ["execute_code", "network"],
            "Remote code execution",
            "An attacker can execute code with network capabilities",
        ),
        (
            ["write_file", "shell_exec"],
            "Arbitrary file creation + execution",
            "An attacker can create and execute arbitrary files",
        ),
    ]

    # Dangerous individual tools
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
    ]

    def __init__(
        self,
        config: Optional[ToolChainsScannerConfig] = None,
    ) -> None:
        self.config = config or ToolChainsScannerConfig()
        super().__init__()

    async def _extract_tools(
        self,
        config: Dict[str, Any],
    ) -> List[str]:
        """Extract list of available tools from config."""
        tools = []

        # Check standard locations
        if isinstance(config, dict):
            tools.extend(config.get("tools", []))
            tools.extend(config.get("available_tools", []))

            # Try nested structure
            if "settings" in config:
                tools.extend(config["settings"].get("tools", []))
            if "capabilities" in config:
                tools.extend(config["capabilities"].get("tools", []))

        # If tools list is empty, try to detect from config string
        if not tools:
            config_str = json.dumps(config)
            for tool in self.DANGEROUS_TOOLS:
                if tool in config_str:
                    tools.append(tool)

        return list(set(tools))  # Remove duplicates

    async def _check_exfiltration_chains(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
        cached_config: Optional[Dict[str, Any]],
    ) -> None:
        """Check for data exfiltration tool chains."""
        if not self.config.test_exfiltration:
            return

        self.logger.info(f"Checking exfiltration chains: {url}")

        if cached_config is None:
            return

        tools = await self._extract_tools(cached_config)
        tools_lower = [t.lower() for t in tools]

        # Check for read + http chain
        if "read_file" in tools_lower and "http_request" in tools_lower:
            finding = self._create_finding(
                severity=Severity.HIGH,
                title="Data Exfiltration Chain: read_file + http_request",
                description=(
                    "The combination of read_file and http_request enables "
                    "data exfiltration. An attacker can read sensitive files "
                    "and transmit them to external servers."
                ),
                cwe="CWE-284",
                owasp_ref="OWASP LLM08:2025 - Excessive Agency",
                mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
                location=url,
                evidence=["Tools available: read_file, http_request"],
                recommendation=(
                    "Disable http_request for agents with file read access. "
                    "Implement egress filtering. "
                    "Log all data transmission. "
                    "Use secure file transfer methods only."
                ),
            )
            result.add_finding(finding)

        if self.config.request_delay > 0:
            await asyncio.sleep(self.config.request_delay)

    async def _check_code_deployment_chains(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
        cached_config: Optional[Dict[str, Any]],
    ) -> None:
        """Check for code deployment attack chains."""
        if not self.config.test_code_deployment:
            return

        self.logger.info(f"Checking code deployment chains: {url}")

        if cached_config is None:
            return

        tools = await self._extract_tools(cached_config)
        tools_lower = [t.lower() for t in tools]

        # Check for write + execute chain
        if "write_file" in tools_lower and "execute_code" in tools_lower:
            finding = self._create_finding(
                severity=Severity.CRITICAL,
                title="Code Deployment Chain: write_file + execute_code",
                description=(
                    "The combination of write_file and execute_code enables "
                    "arbitrary code execution. An attacker can write malicious "
                    "code to disk and execute it, achieving persistent compromise."
                ),
                cwe="CWE-284",
                owasp_ref="OWASP LLM08:2025 - Excessive Agency",
                mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
                location=url,
                evidence=["Tools available: write_file, execute_code"],
                recommendation=(
                    "NEVER allow write + execute together. "
                    "Use code signing and verification. "
                    "Run in sandboxed environments. "
                    "Implement strict access controls."
                ),
            )
            result.add_finding(finding)

        if self.config.request_delay > 0:
            await asyncio.sleep(self.config.request_delay)

    async def _check_database_exfiltration_chains(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
        cached_config: Optional[Dict[str, Any]],
    ) -> None:
        """Check for database exfiltration chains."""
        if not self.config.test_database_exfil:
            return

        self.logger.info(f"Checking database exfiltration: {url}")

        if cached_config is None:
            return

        tools = await self._extract_tools(cached_config)
        tools_lower = [t.lower() for t in tools]

        # Check for sql_query + http chain
        if "sql_query" in tools_lower and "http_request" in tools_lower:
            finding = self._create_finding(
                severity=Severity.CRITICAL,
                title="Database Exfiltration Chain: sql_query + http_request",
                description=(
                    "The combination of sql_query and http_request enables "
                    "direct database exfiltration. An attacker can query the "
                    "database and transmit results externally."
                ),
                cwe="CWE-284",
                owasp_ref="OWASP LLM08:2025 - Excessive Agency",
                mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
                location=url,
                evidence=["Tools available: sql_query, http_request"],
                recommendation=(
                    "Block external network access from database operations. "
                    "Implement database access logs. "
                    "Use query monitoring and alerting. "
                    "Restrict sql_query to internal operations only."
                ),
            )
            result.add_finding(finding)

        if self.config.request_delay > 0:
            await asyncio.sleep(self.config.request_delay)

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Execute tool chains scan on target."""
        self.logger.info(f"Starting tool chains scan: {target}")

        result = ScanResult(
            module_name=self.module_name,
            target=target,
            metadata={
                "test_exfiltration": self.config.test_exfiltration,
                "test_code_deployment": self.config.test_code_deployment,
                "test_database_exfil": self.config.test_database_exfil,
                "dangerous_chains_tested": len(self.DANGEROUS_CHAINS),
            },
        )

        if not self.config.enabled:
            self.logger.info("Tool chains scanning disabled")
            result.finalize()
            return result

        async def run_checks() -> None:
            async with aiohttp.ClientSession() as session:
                # Cache config fetch once at start
                cached_config = await self._fetch_url(url=target, session=session)

                await asyncio.gather(
                    self._check_exfiltration_chains(target, session, result, cached_config),
                    self._check_code_deployment_chains(target, session, result, cached_config),
                    self._check_database_exfiltration_chains(target, session, result, cached_config),
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