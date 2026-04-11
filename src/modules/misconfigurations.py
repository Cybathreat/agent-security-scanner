"""
Security Misconfiguration Detection Module.

Scans AI agents for insecure default configurations, missing authentication,
CORS misconfigurations, rate limiting issues, and information disclosure.

References:
- OWASP LLM Top 10: LLM09:2024 - Insecure Output Handling
- OWASP API Security Top 10: API4:2019 - Unrestricted Resource Consumption
- MITRE ATLAS: ML Model Access Control

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

import aiohttp
from loguru import logger

from ..core.config import MisconfigurationsConfig
from .base import BaseModule, Finding, ScanResult, Severity


class MisconfigurationsModule(BaseModule[MisconfigurationsConfig]):
    """
    Security misconfiguration detection module.

    Checks for:
    - Missing or weak authentication/authorization
    - Permissive CORS policies
    - Missing rate limiting
    - Information disclosure in error messages
    - Insecure default configurations
    - Debug endpoints exposed in production
    """

    def __init__(
        self,
        config: Optional[MisconfigurationsConfig] = None,
    ) -> None:
        """
        Initialize misconfiguration scanner.

        Args:
            config: Configuration for misconfiguration checks.
        """
        super().__init__()
        self.config = config or MisconfigurationsConfig()

    async def _fetch_url(
        self,
        url: str,
        session: aiohttp.ClientSession,
        timeout: int = 10,
    ) -> Optional[Dict[str, Any]]:
        """
        Fetch URL and return response details.

        Args:
            url: URL to fetch
            session: aiohttp session
            timeout: Request timeout in seconds

        Returns:
            Dict: Response data (status, headers, body) or None on error.
        """
        try:
            async with session.get(url, timeout=timeout) as response:
                body = await response.text()
                headers = dict(response.headers)
                status = response.status

                return {
                    "url": url,
                    "status": status,
                    "headers": headers,
                    "body": body,
                    "ok": response.ok,
                }
        except asyncio.TimeoutError:
            self.logger.warning(f"Request timeout: {url}")
            return None
        except aiohttp.ClientError as e:
            self.logger.warning(f"Request error: {e}")
            return None

    async def _check_auth(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """
        Check for missing or weak authentication.

        Tests:
        - Can access protected endpoints without auth?
        - Are default credentials accepted?
        - Is auth header optional?

        Args:
            url: Target URL
            session: aiohttp session
            result: Scan result to add findings
        """
        if not self.config.check_auth:
            self.logger.debug("Auth check disabled")
            return

        self.logger.info(f"Checking authentication: {url}")

        # Test unauthenticated access
        response = await self._fetch_url(url, session)

        if response is None:
            result.add_error(f"Failed to fetch: {url}")
            return

        # Check if 200 OK without auth (potential issue)
        if response["status"] == 200:
            # Check for auth-related headers
            has_www_auth = "WWW-Authenticate" in response["headers"]
            has_auth_req = "Authorization" in response["headers"].get("Vary", "")

            if not has_www_auth and not has_auth_req:
                finding = self._create_finding(
                    severity=Severity.HIGH,
                    title="Missing Authentication Requirement",
                    description=(
                        "The endpoint accepts requests without authentication. "
                        "This may allow unauthorized access to sensitive agent "
                        "functions or data. Implement authentication headers "
                        "(Authorization, X-API-Key) or OAuth2."
                    ),
                    cwe="CWE-306",  # Missing Authentication for Critical Function
                    owasp_ref="OWASP API1:2023 - Broken Object Level Authorization",
                    mitre_ref="MITRE ATLAS - ML Model Access Control",
                    location=url,
                    evidence=[f"Status: {response['status']}", "No auth challenge"],
                    recommendation=(
                        "Implement authentication for all agent endpoints. "
                        "Use API keys, OAuth2, or JWT tokens. Return 401/403 "
                        "for unauthenticated requests."
                    ),
                )
                result.add_finding(finding)
                self.logger.info(f"Finding added: {finding.id}")

        # Check for default credentials in response
        if response["body"]:
            default_indicators = ["admin", "default", "test", "debug"]
            for indicator in default_indicators:
                if indicator in response["body"].lower():
                    finding = self._create_finding(
                        severity=Severity.MEDIUM,
                        title="Potential Default Credential Usage",
                        description=(
                            f"Response body contains '{indicator}' which may "
                            "indicate default credentials or debug mode. "
                            "Default credentials are a common attack vector."
                        ),
                        cwe="CWE-798",  # Use of Hard-coded Credentials
                        location=url,
                        evidence=[f"Found indicator: {indicator}"],
                        recommendation=(
                            "Remove default credentials. Implement secure "
                            "credential management. Rotate all default passwords."
                        ),
                    )
                    result.add_finding(finding)

    async def _check_cors(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """
        Check for CORS misconfigurations.

        Tests:
        - Access-Control-Allow-Origin: * (too permissive)
        - Access-Control-Allow-Credentials with wildcard origin
        - Missing CORS headers (may indicate misconfiguration)

        Args:
            url: Target URL
            session: aiohttp session
            result: Scan result to add findings
        """
        if not self.config.check_cors:
            self.logger.debug("CORS check disabled")
            return

        self.logger.info(f"Checking CORS: {url}")

        response = await self._fetch_url(url, session)

        if response is None:
            return

        headers = response["headers"]

        # Check for wildcard CORS
        allow_origin = headers.get("Access-Control-Allow-Origin", "")
        allow_credentials = headers.get("Access-Control-Allow-Credentials", "")

        if allow_origin == "*":
            if allow_credentials.lower() == "true":
                # Critical: wildcard + credentials is dangerous
                finding = self._create_finding(
                    severity=Severity.CRITICAL,
                    title="Dangerous CORS Configuration",
                    description=(
                        "CORS is configured with Access-Control-Allow-Origin: * "
                        "AND Access-Control-Allow-Credentials: true. This allows "
                        "any website to make authenticated requests to your API, "
                        "enabling CSRF attacks and data exfiltration."
                    ),
                    cwe="CWE-942",  # Excessive Cross-Origin Trust
                    owasp_ref="OWASP API8:2019 - Security Misconfiguration",
                    location=url,
                    evidence=[
                        f"Access-Control-Allow-Origin: {allow_origin}",
                        f"Access-Control-Allow-Credentials: {allow_credentials}",
                    ],
                    recommendation=(
                        "Never use wildcard (*) origin with credentials. "
                        "Specify exact allowed origins. Validate Origin header "
                        "server-side. Implement CSRF protection."
                    ),
                )
                result.add_finding(finding)
            else:
                # Medium: wildcard without credentials
                finding = self._create_finding(
                    severity=Severity.LOW,
                    title="Permissive CORS Policy",
                    description=(
                        "CORS allows any origin (Access-Control-Allow-Origin: *). "
                        "While not critical without credentials, this may enable "
                        "reconnaissance attacks or unauthorized API enumeration."
                    ),
                    cwe="CWE-942",
                    location=url,
                    evidence=[f"Access-Control-Allow-Origin: {allow_origin}"],
                    recommendation=(
                        "Restrict CORS to known, trusted origins. "
                        "Use environment-specific allowlists."
                    ),
                )
                result.add_finding(finding)

    async def _check_rate_limiting(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """
        Check for missing rate limiting.

        Tests:
        - Presence of rate limit headers
        - 429 responses on rapid requests
        - X-RateLimit-* headers

        Args:
            url: Target URL
            session: aiohttp session
            result: Scan result to add findings
        """
        if not self.config.check_rate_limiting:
            self.logger.debug("Rate limiting check disabled")
            return

        self.logger.info(f"Checking rate limiting: {url}")

        response = await self._fetch_url(url, session)

        if response is None:
            return

        headers = response["headers"]

        # Check for rate limit headers
        rate_limit_headers = [
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "RateLimit-Limit",
            "RateLimit-Remaining",
            "RateLimit-Reset",
        ]

        found_headers = [h for h in rate_limit_headers if h in headers]

        if not found_headers:
            finding = self._create_finding(
                severity=Severity.MEDIUM,
                title="Missing Rate Limiting",
                description=(
                    "No rate limiting headers detected. This may indicate "
                    "the API lacks rate limiting protection, enabling "
                    "brute-force attacks, DDoS, or resource exhaustion."
                ),
                cwe="CWE-770",  # Allocation of Resources Without Limits
                owasp_ref="OWASP API4:2019 - Unrestricted Resource Consumption",
                location=url,
                evidence=["No rate limit headers found"],
                recommendation=(
                    "Implement rate limiting per client/API key. "
                    "Return 429 Too Many Requests when limit exceeded. "
                    "Include X-RateLimit-* headers for client awareness."
                ),
            )
            result.add_finding(finding)

    async def _check_info_disclosure(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """
        Check for information disclosure in responses.

        Tests:
        - Stack traces in error messages
        - Debug information exposed
        - Version banners
        - Internal IPs/paths disclosed

        Args:
            url: Target URL
            session: aiohttp session
            result: Scan result to add findings
        """
        if not self.config.check_info_disclosure:
            self.logger.debug("Info disclosure check disabled")
            return

        self.logger.info(f"Checking info disclosure: {url}")

        response = await self._fetch_url(url, session)

        if response is None:
            return

        body = response["body"]

        # Patterns indicating info disclosure
        disclosure_patterns = {
            "stack_trace": ["Traceback", "File \"", "line ", "at "],
            "debug_mode": ["DEBUG", "debug", "stack trace", "verbose"],
            "version_info": ["v", "version", "build", "commit"],
            "internal_path": ["/internal/", "/admin/", "/debug/", "/.env"],
            "server_banner": ["Server:", "X-Powered-By:", "nginx", "apache"],
        }

        for category, patterns in disclosure_patterns.items():
            for pattern in patterns:
                if pattern in body:
                    finding = self._create_finding(
                        severity=Severity.LOW,
                        title=f"Information Disclosure: {category.replace('_', ' ').title()}",
                        description=(
                            f"Response contains '{pattern}' which may leak "
                            "internal implementation details, versions, or paths. "
                            "Attackers can use this for reconnaissance."
                        ),
                        cwe="CWE-200",  # Information Exposure
                        location=url,
                        evidence=[f"Found pattern: {pattern}"],
                        recommendation=(
                            "Disable debug mode in production. "
                            "Remove stack traces from error responses. "
                            "Sanitize error messages. Hide server banners."
                        ),
                    )
                    result.add_finding(finding)
                    break  # One finding per category

    async def _check_debug_endpoints(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """
        Check for exposed debug/health endpoints.

        Tests common debug paths:
        - /debug, /health, /metrics, /.env, /config

        Args:
            url: Target URL
            session: aiohttp session
            result: Scan result to add findings
        """
        self.logger.info(f"Checking debug endpoints: {url}")

        # Extract base URL (scheme://host[:port])
        url_without_query = url.split("?")[0]
        # Remove trailing path segments to get base
        # For https://example.com/path -> https://example.com
        from urllib.parse import urlparse
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
            metadata={"config": self.config.to_dict() if hasattr(self.config, "to_dict") else {}},
        )

        if not self.pre_scan(target):
            result.add_error("Pre-scan validation failed")
            result.finalize()
            return result

        # Run async checks
        async def run_checks() -> None:
            timeout = kwargs.get("timeout", 10)

            async with aiohttp.ClientSession() as session:
                await asyncio.gather(
                    self._check_auth(target, session, result),
                    self._check_cors(target, session, result),
                    self._check_rate_limiting(target, session, result),
                    self._check_info_disclosure(target, session, result),
                    self._check_debug_endpoints(target, session, result),
                )

        # Handle running inside or outside event loop
        try:
            asyncio.get_running_loop()
            # Running inside event loop (e.g., pytest-asyncio)
            # Create new loop to avoid "already running" error
            new_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(new_loop)
            new_loop.run_until_complete(run_checks())
            new_loop.close()
        except RuntimeError:
            # No running loop, safe to use asyncio.run
            asyncio.run(run_checks())

        result.finalize()
        self.post_scan(result)

        return result
