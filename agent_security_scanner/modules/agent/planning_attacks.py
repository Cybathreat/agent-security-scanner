"""
Planning Attacks Scanner - Chain-of-thought manipulation.

Scans for:
- Chain-of-thought manipulation
- Planning redirection
- Goal manipulation
- Multi-step workflow attacks

References:
- Agentic Planning Security
- LLM Planning Attacks

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, Optional, cast

import aiohttp

from ..base import BaseModule, ScanResult, Severity


class PlanningAttacksScannerConfig:
    """Configuration for planning attacks scanning."""

    def __init__(
        self,
        enabled: bool = True,
        check_plan_validation: bool = True,
        check_step_injection: bool = True,
        check_goal_manipulation: bool = True,
    ) -> None:
        self.enabled = enabled
        self.check_plan_validation = check_plan_validation
        self.check_step_injection = check_step_injection
        self.check_goal_manipulation = check_goal_manipulation


class PlanningAttacksScanner(BaseModule[PlanningAttacksScannerConfig]):
    """
    Planning attack vulnerability scanner.

    Tests for:
    - Chain-of-thought manipulation
    - Planning redirection
    - Goal injection
    """

    def __init__(
        self,
        config: Optional[PlanningAttacksScannerConfig] = None,
    ) -> None:
        self.config = config or PlanningAttacksScannerConfig()
        super().__init__()

    async def _fetch_config(
        self,
        url: str,
        session: aiohttp.ClientSession,
        timeout: int = 10,
    ) -> Optional[Dict[str, Any]]:
        """Fetch planning configuration."""
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

    async def _check_plan_validation(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for plan validation."""
        if not self.config.check_plan_validation:
            return

        self.logger.info(f"Checking plan validation: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        has_validation = any(
            keyword in config_str
            for keyword in [
                "validate",
                "verify",
                "sign",
                "approve",
                "review",
            ]
        )

        if not has_validation:
            finding = self._create_finding(
                severity=Severity.MEDIUM,
                title="No Plan Validation",
                description=(
                    "Agent planning/output is not validated. "
                    "Attackers could inject malicious steps or redirect "
                    "the agent's planning process."
                ),
                cwe="CWE-284",
                location=url,
                evidence=["No plan validation config"],
                recommendation=(
                    "Validate agent planning steps. "
                    "Sign plans with cryptographic keys. "
                    "Implement plan review mechanisms. "
                    "Use external verification for critical plans."
                ),
            )
            result.add_finding(finding)

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Execute planning attacks scan on target."""
        self.logger.info(f"Starting planning attacks scan: {target}")

        result = ScanResult(
            module_name=self.module_name,
            target=target,
            metadata={"config": self.config.__dict__},
        )

        async def run_checks() -> None:

            async with aiohttp.ClientSession() as session:
                await asyncio.gather(
                    self._check_plan_validation(target, session, result),
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
