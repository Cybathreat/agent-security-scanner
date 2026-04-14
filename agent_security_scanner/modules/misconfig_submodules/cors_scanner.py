"""
CORS Configuration Scanner.

Scans for:
- Overly permissive Access-Control-Allow-Origin
- Dangerous CORS with credentials
- Missing CORS configuration
- CORS preflight hijacking

References:
- OWASP API Security Top 10: API8:2019 - Security Misconfiguration
- OWASP Web Security Testing Guide: WSTG-SESS-002
- RFC 6454 - The Web Origin Concept

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

import aiohttp

from ..base import BaseModule, ScanResult, Severity


class CORSScannerConfig:
    """Configuration for CORS scanning."""

    def __init__(
        self,
        enabled: bool = True,
        check_wildcard_origin: bool = True,
        check_credentials_with_wildcard: bool = True,
        check_preflight: bool = True,
        check_allowed_methods: bool = True,
        check_allowed_headers: bool = True,
        test_custom_origins: List[str] | None = None,
    ) -> None:
        self.enabled = enabled
        self.check_wildcard_origin = check_wildcard_origin
        self.check_credentials_with_wildcard = check_credentials_with_wildcard
        self.check_preflight = check_preflight
        self.check_allowed_methods = check_allowed_methods
        self.check_allowed_headers = check_allowed_headers
        self.test_custom_origins = test_custom_origins or [
            "https://evil-site.com",
            "https://attacker.example.com",
            "https://trusted-site.com.evil.com",
        ]


class CORSScanner(BaseModule[CORSScannerConfig]):
    """
    CORS configuration vulnerability scanner.

    Tests for:
    - Wildcard (*) Access-Control-Allow-Origin
    - Wildcard with credentials (dangerous combination)
    - Missing CORS headers
    - Overly permissive CORS rules
    - Pre-flight request manipulation
    """

    # Common dangerous CORS patterns
    DANGEROUS_PATTERNS = [
        ("*", True),  # Wildcard with credentials
        ("null", True),  # Null origin with credentials
        ("*", False),  # Wildcard without credentials
    ]

    def __init__(
        self,
        config: Optional[CORSScannerConfig] = None,
    ) -> None:
        super().__init__()
        self.config = config or CORSScannerConfig()

    async def _fetch_url(  # type: ignore[override]
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

    async def _preflight_request(
        self,
        url: str,
        session: aiohttp.ClientSession,
        origin: str,
        method: str = "GET",
        timeout: int = 10,
    ) -> Optional[Dict[str, Any]]:
        """Send preflight OPTIONS request."""
        headers = {
            "Origin": origin,
            "Access-Control-Request-Method": method,
        }
        try:
            async with session.options(url, headers=headers, timeout=timeout) as response:
                return {
                    "url": url,
                    "status": response.status,
                    "headers": dict(response.headers),
                }
        except asyncio.TimeoutError:
            self.logger.warning(f"Preflight timeout: {url}")
            return None
        except aiohttp.ClientError:
            return None

    async def _check_wildcard_origin(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for wildcard CORS origin."""
        if not self.config.check_wildcard_origin:
            return

        self.logger.info(f"Checking wildcard origin: {url}")

        response = await self._fetch_url(url, session)

        if response is None:
            return

        headers = response["headers"]
        allow_origin = headers.get("Access-Control-Allow-Origin", "")

        # Check for wildcard
        if allow_origin == "*":
            allow_credentials = headers.get(
                "Access-Control-Allow-Credentials", "false"
            ).lower()

            if allow_credentials == "true":
                finding = self._create_finding(
                    severity=Severity.CRITICAL,
                    title="Dangerous CORS: Wildcard with Credentials",
                    description=(
                        "CORS allows Access-Control-Allow-Origin: * AND "
                        "Access-Control-Allow-Credentials: true. This enables "
                        "any website to make authenticated requests, allowing "
                        "CSRF attacks and data exfiltration."
                    ),
                    cwe="CWE-942",
                    owasp_ref="OWASP API8:2019 - Security Misconfiguration",
                    location=url,
                    evidence=[
                        "Access-Control-Allow-Origin: *",
                        "Access-Control-Allow-Credentials: true",
                    ],
                    recommendation=(
                        "Never use wildcard origin with credentials. "
                        "Specify exact allowed origins. Validate Origin header."
                    ),
                )
                result.add_finding(finding)
            else:
                finding = self._create_finding(
                    severity=Severity.LOW,
                    title="Permissive CORS: Wildcard Origin",
                    description=(
                        "CORS allows Access-Control-Allow-Origin: *. "
                        "While safer without credentials, this enables "
                        "reconnaissance and API enumeration attacks."
                    ),
                    cwe="CWE-942",
                    location=url,
                    evidence=["Access-Control-Allow-Origin: *"],
                    recommendation=(
                        "Restrict to known, trusted origins. "
                        "Use environment-specific allowlists."
                    ),
                )
                result.add_finding(finding)

    async def _check_credentials_with_wildcard(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for credentials being allowed with wildcard origin."""
        if not self.config.check_credentials_with_wildcard:
            return

        self.logger.info(f"Checking credentials configuration: {url}")

        preflight = await self._preflight_request(url, session, "https://evil.com")

        if preflight is None:
            return

        headers = preflight["headers"]
        allow_origin = headers.get("Access-Control-Allow-Origin", "")
        allow_credentials = headers.get(
            "Access-Control-Allow-Credentials", "false"
        ).lower()

        # Check for dangerous combination
        if allow_origin == "*" and allow_credentials == "true":
            finding = self._create_finding(
                severity=Severity.CRITICAL,
                title="CORS: Wildcard + Credentials Enabled",
                description=(
                    "The preflight response confirms Access-Control-Allow-Origin: * "
                    "with Access-Control-Allow-Credentials: true. This is the "
                    "most dangerous CORS configuration, allowing any site to "
                    "make authenticated requests on behalf of users."
                ),
                cwe="CWE-942",
                owasp_ref="OWASP API8:2019 - Security Misconfiguration",
                location=url,
                evidence=[
                    "OPTIONS preflight successful",
                    "Access-Control-Allow-Origin: *",
                    "Access-Control-Allow-Credentials: true",
                ],
                recommendation=(
                    "Fix immediately: Either remove wildcard or disable credentials. "
                    "Best practice: Use explicit origin whitelist."
                ),
            )
            result.add_finding(finding)

    async def _check_preflight_manipulation(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check if preflight can be manipulated."""
        if not self.config.check_preflight:
            return

        self.logger.info(f"Testing preflight manipulation: {url}")

        # Test with various origins including subdomain takeover candidates
        test_origins = [
            "https://example.com",  # Valid origin
            "https://example.com.evil.com",  # Subdomain takeover
            "https://subdomain.example.com.evil.com",  # Another variant
            "https://example.com%00evil.com",  # Null byte injection
            "https://example.com%2f%2fevil.com",  # Path traversal
        ]

        for origin in test_origins:
            preflight = await self._preflight_request(url, session, origin)

            if preflight:
                headers = preflight["headers"]
                allow_origin = headers.get("Access-Control-Allow-Origin", "")

                # Check if origin is reflected (potential header injection)
                if allow_origin == origin:
                    finding = self._create_finding(
                        severity=Severity.MEDIUM,
                        title="CORS: Origin Reflection (Potential Header Injection)",
                        description=(
                            f"Server reflects the Origin header value '{origin}'. "
                            "This could allow attackers to bypass CORS if the "
                            "origin is not properly validated."
                        ),
                        cwe="CWE-942",
                        location=url,
                        evidence=[f"Reflected origin: {origin}"],
                        recommendation=(
                            "Validate Origin header against whitelist. "
                            "Do not reflect arbitrary origin values. "
                            "Sanitize origin input."
                        ),
                    )
                    result.add_finding(finding)
                    break

    async def _check_overly_permissive_methods(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for overly permissive HTTP methods in CORS."""
        if not self.config.check_allowed_methods:
            return

        self.logger.info(f"Checking allowed methods: {url}")

        # Test DELETE method which could be dangerous
        preflight = await self._preflight_request(url, session, "https://example.com", "DELETE")

        if preflight:
            allow_methods = preflight["headers"].get("Access-Control-Allow-Methods", "")

            if "DELETE" in allow_methods or "*" in allow_methods:
                severity = Severity.HIGH if "DELETE" in allow_methods else Severity.MEDIUM
                finding = self._create_finding(
                    severity=severity,
                    title=f"CORS: Dangerous Method Allowed ({allow_methods})",
                    description=(
                        f"Preflight response includes Access-Control-Allow-Methods: {allow_methods}. "
                        "The DELETE method allows attackers to potentially delete "
                        "resources on behalf of users if authentication is present."
                    ),
                    cwe="CWE-942",
                    location=url,
                    evidence=[f"Allowed methods: {allow_methods}"],
                    recommendation=(
                        "Restrict allowed methods to GET, POST, HEAD for read-only APIs. "
                        "Implement proper authorization for write/delete operations. "
                        "Use X-HTTP-Method-Override for dangerous operations."
                    ),
                )
                result.add_finding(finding)

    async def _check_missing_cors_headers(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for missing CORS configuration (not an error but worth noting)."""
        self.logger.info(f"Checking CORS headers: {url}")

        response = await self._fetch_url(url, session)

        if response is None:
            return

        headers = response["headers"]
        has_cors = any(
            h in headers for h in [
                "Access-Control-Allow-Origin",
                "Access-Control-Allow-Methods",
                "Access-Control-Allow-Headers",
                "Access-Control-Max-Age",
            ]
        )

        if not has_cors:
            finding = self._create_finding(
                severity=Severity.INFO,
                title="Missing CORS Configuration",
                description=(
                    "No CORS headers detected in response. While this may be "
                    "intentional for non-public APIs, missing CORS configuration "
                    "can cause issues with legitimate cross-origin requests."
                ),
                cwe="CWE-942",
                location=url,
                evidence=["No CORS headers present"],
                recommendation=(
                    "If this is a public API, consider implementing CORS headers. "
                    "If not, ensure this is expected behavior."
                ),
            )
            result.add_finding(finding)

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Execute CORS scan on target."""
        self.logger.info(f"Starting CORS scan: {target}")

        result = ScanResult(
            module_name=self.module_name,
            target=target,
            metadata={"config": self.config.__dict__},
        )

        async def run_checks() -> None:

            async with aiohttp.ClientSession() as session:
                await asyncio.gather(
                    self._check_wildcard_origin(target, session, result),
                    self._check_credentials_with_wildcard(target, session, result),
                    self._check_preflight_manipulation(target, session, result),
                    self._check_overly_permissive_methods(target, session, result),
                    self._check_missing_cors_headers(target, session, result),
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
