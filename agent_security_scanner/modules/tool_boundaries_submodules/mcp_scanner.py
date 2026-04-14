"""
MCP Scanner - Model Context Protocol server validation.

Scans for:
- MCP server impersonation
- Tool server identity validation
- Token/credential verification
- Server authentication

References:
- Model Context Protocol Security Guidelines
- API Security Best Practices

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, Optional, cast

import aiohttp

from ..base import BaseModule, ScanResult, Severity


class MCPScannerConfig:
    """Configuration for MCP scanning."""

    def __init__(
        self,
        enabled: bool = True,
        check_server_identity: bool = True,
        check_token_verification: bool = True,
        check_auth_headers: bool = True,
    ) -> None:
        self.enabled = enabled
        self.check_server_identity = check_server_identity
        self.check_token_verification = check_token_verification
        self.check_auth_headers = check_auth_headers


class MCPScanner(BaseModule[MCPScannerConfig]):
    """
    MCP (Model Context Protocol) server security scanner.

    Tests for:
    - Server identity verification
    - Token authentication
    - Authorization headers
    """

    def __init__(
        self,
        config: Optional[MCPScannerConfig] = None,
    ) -> None:
        super().__init__()
        self.config = config or MCPScannerConfig()

    async def _fetch_config(
        self,
        url: str,
        session: aiohttp.ClientSession,
        timeout: int = 10,
    ) -> Optional[Dict[str, Any]]:
        """Fetch MCP server configuration."""
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

    async def _fetch_mcp_metadata(
        self,
        url: str,
        session: aiohttp.ClientSession,
        timeout: int = 10,
    ) -> Optional[Dict[str, Any]]:
        """Fetch MCP metadata endpoint."""
        metadata_urls = [
            f"{url}/metadata",
            f"{url}/_meta",
            f"{url}/api/v1/metadata",
        ]

        for metadata_url in metadata_urls:
            try:
                async with session.get(metadata_url, timeout=timeout) as response:
                    if response.status == 200:
                        body = await response.text()
                        try:
                            return cast(dict[str, Any], json.loads(body))
                        except json.JSONDecodeError:
                            return {"raw": body}
            except Exception:
                continue
        return None

    async def _check_server_identity(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check server identity verification."""
        if not self.config.check_server_identity:
            return

        self.logger.info(f"Checking server identity: {url}")

        config = await self._fetch_config(url, session)
        _metadata = await self._fetch_mcp_metadata(url, session)

        if config is None:
            return

        # Check if server identity is properly configured
        config_str = json.dumps(config).lower()

        # Look for identity-related config
        has_identity_config = any(
            keyword in config_str
            for keyword in ["identity", "server_id", "server_id", "agent_id", "token"]
        )

        if not has_identity_config:
            finding = self._create_finding(
                severity=Severity.LOW,
                title="Missing Server Identity Configuration",
                description=(
                    "MCP server configuration lacks proper identity verification. "
                    "This may enable server impersonation attacks."
                ),
                cwe="CWE-284",
                location=url,
                evidence=["No identity configuration found"],
                recommendation=(
                    "Implement server identity verification. "
                    "Use digital signatures for server responses. "
                    "Validate server certificates."
                ),
            )
            result.add_finding(finding)

    async def _check_token_verification(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check token authentication configuration."""
        if not self.config.check_token_verification:
            return

        self.logger.info(f"Checking token verification: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        # Check if authentication is required
        has_auth = any(
            keyword in config_str
            for keyword in ["auth", "token", "api_key", "secret", "credential"]
        )

        # Check for token validation configuration
        has_validation = any(
            keyword in config_str
            for keyword in ["validate", "verify", "sign", "signature"]
        )

        if has_auth and not has_validation:
            finding = self._create_finding(
                severity=Severity.HIGH,
                title="Token Authentication Without Verification",
                description=(
                    "Token authentication is configured but token validation "
                    "is not properly implemented. This may allow token forgery."
                ),
                cwe="CWE-284",
                location=url,
                evidence=["Auth configured, no validation"],
                recommendation=(
                    "Implement proper token verification. "
                    "Use digital signatures for tokens. "
                    "Validate token integrity on each request. "
                    "Use secure token formats (JWT with verification)."
                ),
            )
            result.add_finding(finding)

    async def _check_auth_headers(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check authorization header requirements."""
        if not self.config.check_auth_headers:
            return

        self.logger.info(f"Checking auth headers: {url}")

        # Try to access without authorization
        try:
            async with session.get(url, timeout=10) as response:
                # If 200 without auth, that's an issue
                if response.status == 200:
                    finding = self._create_finding(
                        severity=Severity.MEDIUM,
                        title="No Authorization Required",
                        description=(
                            "The MCP endpoint accepts requests without "
                            "authorization headers. This enables unauthorized access."
                        ),
                        cwe="CWE-306",
                        location=url,
                        evidence=["No auth required for access"],
                        recommendation=(
                            "Require authorization headers for all endpoints. "
                            "Use API keys, tokens, or OAuth2. "
                            "Return 401 for unauthenticated requests."
                        ),
                    )
                    result.add_finding(finding)
        except Exception:
            pass

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Execute MCP scan on target."""
        self.logger.info(f"Starting MCP scan: {target}")

        result = ScanResult(
            module_name=self.module_name,
            target=target,
            metadata={"config": self.config.__dict__},
        )

        async def run_checks() -> None:

            async with aiohttp.ClientSession() as session:
                await asyncio.gather(
                    self._check_server_identity(target, session, result),
                    self._check_token_verification(target, session, result),
                    self._check_auth_headers(target, session, result),
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
