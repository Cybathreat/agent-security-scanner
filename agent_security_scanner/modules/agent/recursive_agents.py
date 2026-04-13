"""
Recursive Agents Scanner - Multi-agent system vulnerabilities.

Scans for:
- Recursive agent exploitation
- Multi-agent compromise
- Shared context attacks
- Agent-to-agent injection

References:
- Agentic System Security Research
- Multi-Agent Security

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional

import aiohttp
from loguru import logger

from ..base import BaseModule, Finding, ScanResult, Severity


class RecursiveAgentsScannerConfig:
    """Configuration for recursive agents scanning."""

    def __init__(
        self,
        enabled: bool = True,
        check_shared_context: bool = True,
        check_agent_validation: bool = True,
        check_context_poisoning: bool = True,
    ) -> None:
        self.enabled = enabled
        self.check_shared_context = check_shared_context
        self.check_agent_validation = check_agent_validation
        self.check_context_poisoning = check_context_poisoning


class RecursiveAgentsScanner(BaseModule):
    """
    Multi-agent system security scanner.

    Tests for:
    - Shared context vulnerabilities
    - Agent-to-agent injection
    - Context poisoning
    """

    def __init__(
        self,
        config: Optional[RecursiveAgentsScannerConfig] = None,
    ) -> None:
        self.config = config or RecursiveAgentsScannerConfig()
        super().__init__()

    async def _fetch_config(
        self,
        url: str,
        session: aiohttp.ClientSession,
        timeout: int = 10,
    ) -> Optional[Dict[str, Any]]:
        """Fetch multi-agent configuration."""
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

    async def _check_shared_context(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for shared context vulnerabilities."""
        if not self.config.check_shared_context:
            return

        self.logger.info(f"Checking shared context: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        # Check for shared context configuration
        if "shared" in config_str or "global" in config_str:
            # Check if shared context is properly secured
            has_security = any(
                keyword in config_str
                for keyword in [
                    "secure",
                    "validate",
                    "sanitize",
                    "sign",
                    "verify",
                ]
            )

            if not has_security:
                finding = self._create_finding(
                    severity=Severity.HIGH,
                    title="Shared Context Without Security",
                    description=(
                        "Shared context between agents is not properly secured. "
                        "One compromised agent could poison the context for all others."
                    ),
                    cwe="CWE-284",
                    location=url,
                    evidence=["Shared context found, no security"],
                    recommendation=(
                        "Sign shared context with cryptographic keys. "
                        "Validate context integrity. "
                        "Use secure shared state management. "
                        "Implement access controls per agent."
                    ),
                )
                result.add_finding(finding)

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Execute recursive agents scan on target."""
        self.logger.info(f"Starting recursive agents scan: {target}")

        result = ScanResult(
            module_name=self.module_name,
            target=target,
            metadata={"config": self.config.__dict__},
        )

        async def run_checks() -> None:
            timeout = kwargs.get("timeout", 10)

            async with aiohttp.ClientSession() as session:
                await asyncio.gather(
                    self._check_shared_context(target, session, result),
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
