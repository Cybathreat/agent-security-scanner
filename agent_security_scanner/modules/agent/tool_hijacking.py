"""
Tool Hijacking Scanner - Tool argument injection attacks.

Scans for:
- Tool argument injection
- Malicious argument construction
- Tool parameter manipulation

References:
- OWASP LLM Top 10: LLM08:2024 - Excessive Agency
- Agentic System Security

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional

import aiohttp
from loguru import logger

from ..base import BaseModule, Finding, ScanResult, Severity


class ToolHijackingScannerConfig:
    """Configuration for tool hijacking scanning."""

    def __init__(
        self,
        enabled: bool = True,
        check_argument_injection: bool = True,
        check_parameter_manipulation: bool = True,
        check_tool_validation: bool = True,
    ) -> None:
        self.enabled = enabled
        self.check_argument_injection = check_argument_injection
        self.check_parameter_manipulation = check_parameter_manipulation
        self.check_tool_validation = check_tool_validation


class ToolHijackingScanner(BaseModule):
    """
    Tool hijacking vulnerability scanner.

    Tests for:
    - Tool argument injection attacks
    - Malicious argument construction
    - Parameter manipulation
    """

    # Dangerous argument injection patterns
    DANGEROUS_ARGUMENTS = [
        "execute_command",
        "file_path=/etc/passwd",
        "url=http://malicious.com",
        "code=import os",
        "query=SELECT * FROM users",
        "file=../../../etc/passwd",
        "cmd=cat config.json",
        "path=/tmp/backdoor.sh",
    ]

    def __init__(
        self,
        config: Optional[ToolHijackingScannerConfig] = None,
    ) -> None:
        self.config = config or ToolHijackingScannerConfig()
        super().__init__()

    async def _fetch_config(
        self,
        url: str,
        session: aiohttp.ClientSession,
        timeout: int = 10,
    ) -> Optional[Dict[str, Any]]:
        """Fetch tool configuration."""
        try:
            async with session.get(url, timeout=timeout) as response:
                if response.status == 200:
                    body = await response.text()
                    try:
                        return json.loads(body)
                    except json.JSONDecodeError:
                        return {"raw": body}
        except Exception as e:
            self.logger.warning(f"Error fetching config: {e}")
            return None
        return None

    async def _check_argument_injection(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for argument injection vulnerabilities."""
        if not self.config.check_argument_injection:
            return

        self.logger.info(f"Checking argument injection: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        # Look for dangerous tools
        config_str = json.dumps(config).lower()

        dangerous_tools = ["execute", "run", "shell", "command", "script"]

        for tool in dangerous_tools:
            if tool in config_str:
                # Check if arguments are validated
                has_validation = any(
                    keyword in config_str
                    for keyword in [
                        "validate",
                        "sanitize",
                        "whitelist",
                        "allowlist",
                        "regex",
                    ]
                )

                if not has_validation:
                    finding = self._create_finding(
                        severity=Severity.HIGH,
                        title=f"Tool: {tool} - No Argument Validation",
                        description=(
                            f"The '{tool}' tool accepts user arguments without "
                            "proper validation. This enables argument injection "
                            "attacks to execute arbitrary commands."
                        ),
                        cwe="CWE-284",
                        owasp_ref="OWASP LLM08:2024 - Excessive Agency",
                        location=url,
                        evidence=[f"Tool: {tool}, No validation found"],
                        recommendation=(
                            "Validate all tool arguments. "
                            "Use allowlists for expected values. "
                            "Escape special characters. "
                            "Sanitize user input before tool invocation."
                        ),
                    )
                    result.add_finding(finding)

    async def _check_parameter_manipulation(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for parameter manipulation vulnerabilities."""
        if not self.config.check_parameter_manipulation:
            return

        self.logger.info(f"Checking parameter manipulation: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        # Check for tools that accept user-controllable parameters
        risky_parameters = [
            "file",
            "path",
            "url",
            "command",
            "query",
            "code",
            "script",
        ]

        for param in risky_parameters:
            if param in config_str:
                # Check if parameter is properly escaped
                has_escaping = any(
                    keyword in config_str
                    for keyword in [
                        "escape",
                        "sanitize",
                        "encode",
                        "whitelist",
                    ]
                )

                if not has_escaping:
                    finding = self._create_finding(
                        severity=Severity.HIGH,
                        title=f"Parameter Manipulation: {param}",
                        description=(
                            f"The '{param}' parameter can be manipulated by users. "
                            "Without proper escaping, this enables injection attacks."
                        ),
                        cwe="CWE-284",
                        location=url,
                        evidence=[f"Risky parameter: {param}, No escaping"],
                        recommendation=(
                            "Escape special characters in all parameters. "
                            "Use parameterized queries. "
                            "Validate parameter format and content. "
                            "Implement strict input validation."
                        ),
                    )
                    result.add_finding(finding)

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Execute tool hijacking scan on target."""
        self.logger.info(f"Starting tool hijacking scan: {target}")

        result = ScanResult(
            module_name=self.module_name,
            target=target,
            metadata={"config": self.config.__dict__},
        )

        async def run_checks() -> None:
            timeout = kwargs.get("timeout", 10)

            async with aiohttp.ClientSession() as session:
                await asyncio.gather(
                    self._check_argument_injection(target, session, result),
                    self._check_parameter_manipulation(target, session, result),
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
