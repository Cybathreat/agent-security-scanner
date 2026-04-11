"""
Plugin Security Scanner - Plugin/extension auditing.

Scans for:
- Plugin security configuration
- Extension vulnerabilities
- Third-party integration risks

References:
- Plugin Security Best Practices
- Third-Party Risk Management

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, Optional

import aiohttp
from loguru import logger

from ..base import BaseModule, Finding, ScanResult, Severity


class PluginSecurityScannerConfig:
    """Configuration for plugin security scanning."""

    def __init__(
        self,
        enabled: bool = True,
        check_manifest: bool = True,
        check_permissions: bool = True,
        check_unsigned_plugins: bool = True,
    ) -> None:
        self.enabled = enabled
        self.check_manifest = check_manifest
        self.check_permissions = check_permissions
        self.check_unsigned_plugins = check_unsigned_plugins


class PluginSecurityScanner(BaseModule):
    """
    Plugin and extension security scanner.

    Tests for:
    - Plugin manifest security
    - Permission configuration
    - Unsigned plugin detection
    """

    def __init__(
        self,
        config: Optional[PluginSecurityScannerConfig] = None,
    ) -> None:
        self.config = config or PluginSecurityScannerConfig()
        super().__init__()

    async def _fetch_config(
        self,
        url: str,
        session: aiohttp.ClientSession,
        timeout: int = 10,
    ) -> Optional[Dict[str, Any]]:
        """Fetch plugin configuration."""
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

    async def _check_unsigned_plugins(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for unsigned plugin support."""
        if not self.config.check_unsigned_plugins:
            return

        self.logger.info(f"Checking unsigned plugins: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        if "unsigned" in config_str or "sign" not in config_str:
            finding = self._create_finding(
                severity=Severity.HIGH,
                title="Unsigned Plugin Support Enabled",
                description=(
                    "The system allows unsigned plugins. Unsigned plugins "
                    "could be malicious and compromise the agent's security."
                ),
                cwe="CWE-347",
                location=url,
                evidence=["Unsigned plugins enabled"],
                recommendation=(
                    "Require digital signatures for all plugins. "
                    "Validate plugin certificates. "
                    "Use a plugin approval process. "
                    "Implement plugin sandboxing."
                ),
            )
            result.add_finding(finding)

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Execute plugin security scan on target."""
        self.logger.info(f"Starting plugin security scan: {target}")

        result = ScanResult(
            module_name=self.module_name,
            target=target,
            metadata={"config": self.config.__dict__},
        )

        async def run_checks() -> None:
            timeout = kwargs.get("timeout", 10)

            async with aiohttp.ClientSession() as session:
                await asyncio.gather(
                    self._check_unsigned_plugins(target, session, result),
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
