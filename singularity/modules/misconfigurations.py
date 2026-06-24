"""
Security Misconfiguration Detection Module.

Delegates to specialized submodules for auth, CORS, rate-limiting, and
information-disclosure checks. Retains a local _check_debug_endpoints
method for debug-endpoint enumeration unique to this delegator.

References:
- OWASP LLM Top 10: LLM09:2024 - Insecure Output Handling
- OWASP API Security Top 10: API4:2019 - Unrestricted Resource Consumption
- MITRE ATLAS: ML Model Access Control

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional
from urllib.parse import urlparse

import aiohttp

from ..core.config import MisconfigurationsConfig
from .base import BaseModule, ScanResult, Severity
from .misconfig_submodules.auth_scanner import AuthScanner, AuthScannerConfig
from .misconfig_submodules.cors_scanner import CORSScanner, CORSScannerConfig
from .misconfig_submodules.rate_limit_scanner import RateLimitScanner, RateLimitScannerConfig
from .misconfig_submodules.info_disclosure_scanner import (
    InfoDisclosureScanner,
    InfoDisclosureScannerConfig,
)


class MisconfigurationsModule(BaseModule[MisconfigurationsConfig]):
    """
    Security misconfiguration detection module.

    Delegates to submodules for:
    - Authentication/authorization checks (AuthScanner)
    - CORS configuration analysis (CORSScanner)
    - Rate limiting validation (RateLimitScanner)
    - Information disclosure detection (InfoDisclosureScanner)

    Retains local logic for:
    - Debug endpoint exposure
    """

    def __init__(
        self,
        config: Optional[MisconfigurationsConfig] = None,
        auth_scanner_config: Optional[AuthScannerConfig] = None,
        cors_scanner_config: Optional[CORSScannerConfig] = None,
        rate_limit_scanner_config: Optional[RateLimitScannerConfig] = None,
        info_disclosure_scanner_config: Optional[InfoDisclosureScannerConfig] = None,
    ) -> None:
        """
        Initialize misconfiguration scanner.

        Args:
            config: Top-level misconfiguration configuration (check_* flags).
            auth_scanner_config: Config for the AuthScanner submodule.
            cors_scanner_config: Config for the CORSScanner submodule.
            rate_limit_scanner_config: Config for the RateLimitScanner submodule.
            info_disclosure_scanner_config: Config for the InfoDisclosureScanner submodule.
        """
        self.config = config or MisconfigurationsConfig()
        self._auth_scanner_config = auth_scanner_config or AuthScannerConfig()
        self._cors_scanner_config = cors_scanner_config or CORSScannerConfig()
        self._rate_limit_scanner_config = rate_limit_scanner_config or RateLimitScannerConfig()
        self._info_disclosure_scanner_config = info_disclosure_scanner_config or InfoDisclosureScannerConfig()
        super().__init__()

    async def _check_debug_endpoints(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """
        Check for exposed debug/health endpoints.

        Tests common debug paths:
        - /debug, /health, /metrics, /.env, /config, /.git

        Args:
            url: Target URL
            session: aiohttp session
            result: Scan result to add findings
        """
        self.logger.info(f"Checking debug endpoints: {url}")

        # Extract base URL (scheme://host[:port])
        url_without_query = url.split("?")[0]
        parsed_url = urlparse(url_without_query)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        debug_paths = ["/debug", "/health", "/metrics", "/.env", "/config", "/.git"]

        for path in debug_paths:
            test_url = f"{base_url}{path}"
            response = await self._fetch_url(test_url, session)

            if response and response["status"] == 200:
                finding = self._create_finding(
                    severity=Severity.HIGH,
                    title=f"Exposed Debug Endpoint: {path}",
                    description=(
                        f"The endpoint {path} is publicly accessible and returns "
                        "200 OK. Debug/health endpoints should be restricted or "
                        "removed from production environments."
                    ),
                    cwe="CWE-489",  # Active Debug Code
                    location=test_url,
                    evidence=[f"Status: {response['status']}", f"Path: {path}"],
                    recommendation=(
                        "Remove debug endpoints from production. "
                        "Restrict access with authentication. "
                        "Use network ACLs to block external access."
                    ),
                )
                result.add_finding(finding)

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """
        Execute misconfiguration scan on target.

        Delegates to enabled submodules and runs the local debug-endpoint
        check. Aggregates all findings and errors into a single ScanResult.

        Args:
            target: URL or API endpoint to scan
            **kwargs: Additional parameters (timeout, headers, etc.)

        Returns:
            ScanResult: Findings, errors, and metadata.
        """
        self.logger.info(f"Starting misconfiguration scan: {target}")

        result = ScanResult(
            module_name=self.module_name,
            target=target,
            metadata={
                "config": (
                    self.config.to_dict() if hasattr(self.config, "to_dict") else {}
                ),
            },
        )

        if not self.pre_scan(target):
            result.add_error("Pre-scan validation failed")
            result.finalize()
            return result

        # Delegate to submodules
        submodules = []
        if self.config.check_auth:
            submodules.append(AuthScanner(self._auth_scanner_config))
        if self.config.check_cors:
            submodules.append(CORSScanner(self._cors_scanner_config))
        if self.config.check_rate_limiting:
            submodules.append(RateLimitScanner(self._rate_limit_scanner_config))
        if self.config.check_info_disclosure:
            submodules.append(InfoDisclosureScanner(self._info_disclosure_scanner_config))

        for submod in submodules:
            sub_result = submod.scan(target, **kwargs)
            for finding in sub_result.findings:
                result.add_finding(finding)
            for error in sub_result.errors:
                result.add_error(error)

        # Run local debug endpoints check (async)
        async def run_debug() -> None:
            async with aiohttp.ClientSession() as session:
                await self._check_debug_endpoints(target, session, result)

        try:
            asyncio.get_running_loop()
            new_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(new_loop)
            try:
                new_loop.run_until_complete(run_debug())
            finally:
                new_loop.close()
                asyncio.set_event_loop(None)
        except RuntimeError:
            asyncio.run(run_debug())

        result.finalize()
        self.post_scan(result)

        return result