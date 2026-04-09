"""
Information Disclosure Scanner.

Scans for:
- Stack traces in error responses
- Debug mode enabled
- Version information exposure
- Internal path disclosure
- Server banner exposure

References:
- OWASP API Security Top 10: API1:2023 - Broken Object Level Authorization
- OWASP Web Security Testing Guide: WSTG-INFO-00

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

import aiohttp
from loguru import logger

from ..base import BaseModule, Finding, ScanResult, Severity


class InfoDisclosureScannerConfig:
    """Configuration for information disclosure scanning."""

    def __init__(
        self,
        enabled: bool = True,
        check_stack_traces: bool = True,
        check_debug_mode: bool = True,
        check_version_info: bool = True,
        check_internal_paths: bool = True,
        check_server_banner: bool = True,
        check_error_messages: bool = True,
    ) -> None:
        self.enabled = enabled
        self.check_stack_traces = check_stack_traces
        self.check_debug_mode = check_debug_mode
        self.check_version_info = check_version_info
        self.check_internal_paths = check_internal_paths
        self.check_server_banner = check_server_banner
        self.check_error_messages = check_error_messages


class InfoDisclosureScanner(BaseModule):
    """
    Information disclosure vulnerability scanner.

    Tests for:
    - Stack traces in responses
    - Debug mode indicators
    - Version/banner exposure
    - Internal path leaks
    - Verbose error messages
    """

    # Patterns indicating information disclosure
    STACK_TRACE_PATTERNS = [
        "Traceback",
        "File \"",
        "line ",
        "at ",
        "Stack trace",
        "Call stack",
    ]

    DEBUG_MODE_PATTERNS = [
        "DEBUG",
        "debug",
        "development mode",
        "verbose",
        "trace",
        "profiler",
    ]

    VERSION_PATTERNS = [
        "version",
        "v",
        "build",
        "commit",
        "revision",
        "release",
    ]

    INTERNAL_PATH_PATTERNS = [
        "/internal/",
        "/admin/",
        "/debug/",
        "/.env",
        "/config",
        "/backup",
        "/dump",
    ]

    def __init__(
        self,
        config: Optional[InfoDisclosureScannerConfig] = None,
    ) -> None:
        super().__init__()
        self.config = config or InfoDisclosureScannerConfig()

    async def _fetch_url(
        self,
        url: str,
        session: aiohttp.ClientSession,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 10,
    ) -> Optional[Dict[str, Any]]:
        """Fetch URL and return response details."""
        try:
            async with session.get(url, headers=headers, timeout=timeout) as response:
                return {
                    "url": url,
                    "status": response.status,
                    "headers": dict(response.headers),
                    "body": await response.text(),
                }
        except asyncio.TimeoutError:
            self.logger.warning(f"Request timeout: {url}")
            return None
        except aiohttp.ClientError as e:
            self.logger.warning(f"Request error: {e}")
            return None

    async def _check_stack_traces(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for stack traces in error responses."""
        if not self.config.check_stack_traces:
            return

        self.logger.info(f"Checking for stack traces: {url}")

        # Trigger an error condition
        test_urls = [
            f"{url}/nonexistent",
            f"{url}?invalid=true",
            f"{url}/api/v1/../../../etc/passwd",
        ]

        for test_url in test_urls:
            response = await self._fetch_url(test_url, session)

            if response is None:
                continue

            body = response["body"]

            for pattern in self.STACK_TRACE_PATTERNS:
                if pattern in body:
                    finding = self._create_finding(
                        severity=Severity.HIGH,
                        title="Stack Trace Exposure",
                        description=(
                            "Stack trace detected in error response. "
                            "This exposes internal implementation details, "
                            "file paths, and potentially sensitive code logic."
                        ),
                        cwe="CWE-209",
                        owasp_ref="OWASP API5:2019 - Security Misconfiguration",
                        location=test_url,
                        evidence=[f"Stack trace pattern: {pattern}"],
                        recommendation=(
                            "Disable debug mode in production. "
                            "Return generic error messages. "
                            "Log full details server-side only."
                        ),
                    )
                    result.add_finding(finding)
                    break  # One finding per test

    async def _check_debug_mode(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for debug mode indicators."""
        if not self.config.check_debug_mode:
            return

        self.logger.info(f"Checking for debug mode: {url}")

        response = await self._fetch_url(url, session)

        if response is None:
            return

        body = response["body"]
        headers = response["headers"]

        # Check body for debug indicators
        for pattern in self.DEBUG_MODE_PATTERNS:
            if pattern.lower() in body.lower():
                finding = self._create_finding(
                    severity=Severity.MEDIUM,
                    title=f"Debug Mode Indicator: {pattern}",
                    description=(
                        f"Response contains '{pattern}' which may indicate "
                        "debug or verbose mode is enabled. Debug mode often "
                        "exposes sensitive internal information."
                    ),
                    cwe="CWE-489",
                    location=url,
                    evidence=[f"Found pattern: {pattern}"],
                    recommendation=(
                        "Disable debug mode in production environments. "
                        "Use environment-specific configuration. "
                        "Remove verbose logging from production logs."
                    ),
                )
                result.add_finding(finding)
                break

        # Check headers for debug headers
        debug_headers = ["X-Debug", "X-Debug-Token", "X-Debug-Info"]
        for header in debug_headers:
            if header in headers:
                finding = self._create_finding(
                    severity=Severity.LOW,
                    title=f"Debug Header Exposed: {header}",
                    description=(
                        f"Debug header '{header}' found in response. "
                        "These headers may leak additional debugging information."
                    ),
                    cwe="CWE-489",
                    location=url,
                    evidence=[f"Header present: {header}: {headers[header]}"],
                    recommendation=(
                        "Remove debug headers from production responses. "
                        "Use server-side logging for debugging information."
                    ),
                )
                result.add_finding(finding)

    async def _check_version_info(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for version information exposure."""
        if not self.config.check_version_info:
            return

        self.logger.info(f"Checking version info: {url}")

        # Common version endpoint patterns
        version_endpoints = [
            "/version",
            "/api/version",
            "/about",
            "/api/about",
            "/_info",
            "/api/_info",
        ]

        for endpoint in version_endpoints:
            test_url = f"{url}{endpoint}"
            response = await self._fetch_url(test_url, session)

            if response is None:
                continue

            if response["status"] == 200:
                # Check if response contains version info
                body = response["body"]
                has_version = any(
                    pattern.lower() in body.lower() for pattern in self.VERSION_PATTERNS
                )

                if has_version:
                    finding = self._create_finding(
                        severity=Severity.LOW,
                        title="Version Information Exposure",
                        description=(
                            f"Version endpoint '{endpoint}' returns version information. "
                            "Attackers can use version numbers to identify known "
                            "vulnerabilities in specific releases."
                        ),
                        cwe="CWE-200",
                        location=test_url,
                        evidence=["Version endpoint accessible"],
                        recommendation=(
                            "Remove version endpoints from production. "
                            "If needed, return minimal info (e.g., 'production'). "
                            "Obfuscate version in public APIs."
                        ),
                    )
                    result.add_finding(finding)

    async def _check_internal_paths(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for internal path disclosure."""
        if not self.config.check_internal_paths:
            return

        self.logger.info(f"Checking for internal paths: {url}")

        # Try to access sensitive paths
        sensitive_paths = [
            "/.git/config",
            "/.env",
            "/config/database.yml",
            "/wp-config.php",
            "/app/config/parameters.yml",
            "/etc/passwd",  # Path traversal test
            "/var/log",
            "/proc/self",
        ]

        for path in sensitive_paths:
            test_url = f"{url}{path}"
            response = await self._fetch_url(test_url, session)

            if response and response["status"] == 200:
                finding = self._create_finding(
                    severity=Severity.HIGH,
                    title=f"Internal Path Disclosure: {path}",
                    description=(
                        f"The path '{path}' is accessible and returns 200 OK. "
                        "This may expose configuration files, source code, "
                        "or other sensitive internal resources."
                    ),
                    cwe="CWE-200",
                    owasp_ref="OWASP API5:2019 - Security Misconfiguration",
                    location=test_url,
                    evidence=[f"Path accessible: {path}"],
                    recommendation=(
                        "Ensure sensitive paths are blocked at web server level. "
                        "Use .gitignore for config files. "
                        "Restrict access to internal directories."
                    ),
                )
                result.add_finding(finding)

    async def _check_server_banner(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for server banner exposure."""
        if not self.config.check_server_banner:
            return

        self.logger.info(f"Checking server banner: {url}")

        response = await self._fetch_url(url, session)

        if response is None:
            return

        headers = response["headers"]

        # Check for server/version banners
        banner_headers = [
            "Server",
            "X-Powered-By",
            "X-AspNet-Version",
            "X-AspNetMvc-Version",
        ]

        for header in banner_headers:
            if header in headers:
                finding = self._create_finding(
                    severity=Severity.LOW,
                    title=f"Server Banner Exposed: {header}",
                    description=(
                        f"Server banner '{header}: {headers[header]}' reveals "
                        f"server technology and version. Attackers can use this "
                        f"to identify known vulnerabilities."
                    ),
                    cwe="CWE-200",
                    location=url,
                    evidence=[f"Header: {header}: {headers[header]}"],
                    recommendation=(
                        "Remove or obfuscate server banners. "
                        "Configure web server to hide version info. "
                        "Use generic values like 'Server: nginx' without version."
                    ),
                )
                result.add_finding(finding)

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Execute information disclosure scan on target."""
        self.logger.info(f"Starting info disclosure scan: {target}")

        result = ScanResult(
            module_name=self.module_name,
            target=target,
            metadata={"config": self.config.__dict__},
        )

        async def run_checks() -> None:
            timeout = kwargs.get("timeout", 10)

            async with aiohttp.ClientSession() as session:
                await asyncio.gather(
                    self._check_stack_traces(target, session, result),
                    self._check_debug_mode(target, session, result),
                    self._check_version_info(target, session, result),
                    self._check_internal_paths(target, session, result),
                    self._check_server_banner(target, session, result),
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
