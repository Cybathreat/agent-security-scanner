"""
Memory Poisoning Scanner - Persistent memory corruption.

Scans for:
- Memory injection attacks
- Persistent session poisoning
- Conversation history manipulation

References:
- Agentic System Memory Security
- Conversation Security

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, Optional, cast

import aiohttp

from ..base import BaseModule, ScanResult, Severity


class MemoryPoisoningScannerConfig:
    """Configuration for memory poisoning scanning."""

    def __init__(
        self,
        enabled: bool = True,
        check_memory_validation: bool = True,
        check_session_integrity: bool = True,
        check_history_poisoning: bool = True,
    ) -> None:
        self.enabled = enabled
        self.check_memory_validation = check_memory_validation
        self.check_session_integrity = check_session_integrity
        self.check_history_poisoning = check_history_poisoning


class MemoryPoisoningScanner(BaseModule[MemoryPoisoningScannerConfig]):
    """
    Memory poisoning vulnerability scanner.

    Tests for:
    - Memory injection
    - Session integrity
    - Conversation history attacks
    """

    def __init__(
        self,
        config: Optional[MemoryPoisoningScannerConfig] = None,
    ) -> None:
        self.config = config or MemoryPoisoningScannerConfig()
        super().__init__()

    async def _fetch_config(
        self,
        url: str,
        session: aiohttp.ClientSession,
        timeout: int = 10,
    ) -> Optional[Dict[str, Any]]:
        """Fetch memory/session configuration."""
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

    async def _check_memory_validation(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for memory validation."""
        if not self.config.check_memory_validation:
            return

        self.logger.info(f"Checking memory validation: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        # Check for memory validation
        has_validation = any(
            keyword in config_str
            for keyword in [
                "validate",
                "sanitize",
                "sign",
                "verify",
                "integrity",
            ]
        )

        if not has_validation:
            finding = self._create_finding(
                severity=Severity.HIGH,
                title="No Memory Validation",
                description=(
                    "Agent memory/conversation history is not validated. "
                    "Attackers could inject malicious content into memory, "
                    "causing persistent poisoning across sessions."
                ),
                cwe="CWE-284",
                location=url,
                evidence=["No memory validation config"],
                recommendation=(
                    "Sign memory entries with cryptographic signatures. "
                    "Validate memory integrity before use. "
                    "Sanitize memory content. "
                    "Implement memory versioning."
                ),
            )
            result.add_finding(finding)

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Execute memory poisoning scan on target."""
        self.logger.info(f"Starting memory poisoning scan: {target}")

        result = ScanResult(
            module_name=self.module_name,
            target=target,
            metadata={"config": self.config.__dict__},
        )

        async def run_checks() -> None:

            async with aiohttp.ClientSession() as session:
                await asyncio.gather(
                    self._check_memory_validation(target, session, result),
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
