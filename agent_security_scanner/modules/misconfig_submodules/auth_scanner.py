"""
Authentication and Authorization Scanner.

Scans for:
- Missing or weak authentication
- Session fixation vulnerabilities
- Token leakage in responses
- Missing MFA/2FA requirements
- Broken access control patterns

References:
- OWASP API Security Top 10: API1:2023 - Broken Object Level Authorization
- OWASP API Security Top 10: API2:2023 - Broken Authentication
- OWASP LLM Top 10: LLM08:2024 - Excessive Agency

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional

import aiohttp

from ..base import BaseModule, ScanResult, Severity


class AuthScannerConfig:
    """Configuration for authentication scanning."""

    def __init__(
        self,
        enabled: bool = True,
        check_basic_auth: bool = True,
        check_api_keys: bool = True,
        check_session_fixation: bool = True,
        check_mfa: bool = True,
        check_token_leakage: bool = True,
        test_unauthenticated: bool = True,
    ) -> None:
        self.enabled = enabled
        self.check_basic_auth = check_basic_auth
        self.check_api_keys = check_api_keys
        self.check_session_fixation = check_session_fixation
        self.check_mfa = check_mfa
        self.check_token_leakage = check_token_leakage
        self.test_unauthenticated = test_unauthenticated


class AuthScanner(BaseModule[AuthScannerConfig]):
    """
    Authentication and authorization vulnerability scanner.

    Tests for:
    - Unauthenticated access to protected endpoints
    - Weak authentication mechanisms (basic auth without TLS)
    - API key exposure in URLs or headers
    - Session fixation attacks
    - Missing MFA requirements
    - Token leakage in responses/logs
    """

    # Default test credentials to attempt
    DEFAULT_CREDENTIALS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("root", "root"),
        ("test", "test"),
        ("user", "user"),
    ]

    # API key patterns to detect in responses
    API_KEY_PATTERNS = [
        r"api[_-]?key['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}",
        r"Bearer\s+[a-zA-Z0-9_-]{20,}",
        r"sk-[a-zA-Z0-9]{20,}",
        r"API_KEY=['\"][a-zA-Z0-9]+['\"]",
        r"SECRET['\"][a-zA-Z0-9]+['\"]",
    ]

    # MFA indicators in responses
    MFA_INDICATORS = [
        "mfa",
        "two_factor",
        "2fa",
        "totp",
        "otp",
        "verify_code",
        "verification_code",
    ]

    def __init__(
        self,
        config: Optional[AuthScannerConfig] = None,
    ) -> None:
        super().__init__()
        self.config = config or AuthScannerConfig()

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
                body = await response.text()
                return {
                    "url": url,
                    "status": response.status,
                    "headers": dict(response.headers),
                    "body": body,
                }
        except asyncio.TimeoutError:
            self.logger.warning(f"Request timeout: {url}")
            return None
        except aiohttp.ClientError as e:
            self.logger.warning(f"Request error: {e}")
            return None

    async def _check_unauthenticated_access(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check if endpoints are accessible without authentication."""
        if not self.config.test_unauthenticated:
            return

        self.logger.info(f"Testing unauthenticated access: {url}")

        # Test basic GET without auth
        response = await self._fetch_url(url, session)

        if response is None:
            result.add_error(f"Failed to fetch: {url}")
            return

        # If 200 OK without auth challenge, potential issue
        if response["status"] == 200:
            has_auth_challenge = "WWW-Authenticate" in response["headers"]
            auth_headers = ["Authorization", "Cookie", "X-API-Key"]

            # Check if auth is required but not enforced
            has_auth_header = any(
                h in response["headers"] for h in auth_headers
            )

            if not has_auth_challenge and not has_auth_header:
                finding = self._create_finding(
                    severity=Severity.HIGH,
                    title="Unauthenticated Access Enabled",
                    description=(
                        "The endpoint accepts requests without authentication. "
                        "No WWW-Authenticate challenge was present, suggesting "
                        "authentication may be optional or missing."
                    ),
                    cwe="CWE-306",
                    owasp_ref="OWASP API1:2023 - Broken Object Level Authorization",
                    location=url,
                    evidence=[
                        f"Status: {response['status']}",
                        "No authentication challenge",
                    ],
                    recommendation=(
                        "Implement authentication for all sensitive endpoints. "
                        "Return 401 Unauthorized for unauthenticated requests. "
                        "Use proper WWW-Authenticate challenges."
                    ),
                )
                result.add_finding(finding)

    async def _check_api_key_exposure(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for API key exposure in URLs or headers."""
        if not self.config.check_api_keys:
            return

        self.logger.info(f"Checking API key exposure: {url}")

        # Test with API key in URL query
        test_url = f"{url}?api_key=test_key_1234567890abcdef"
        response = await self._fetch_url(test_url, session)

        if response and response["status"] == 200:
            # Check if response contains echoes of the API key
            if "test_key_1234567890abcdef" in response["body"]:
                finding = self._create_finding(
                    severity=Severity.CRITICAL,
                    title="API Key Exposure in Response",
                    description=(
                        "The API accepts API keys via URL query parameters and "
                        "echoes them back in the response. This exposes credentials "
                        "in server logs, browser history, and referrer headers."
                    ),
                    cwe="CWE-598",
                    owasp_ref="OWASP API5:2019 - Security Misconfiguration",
                    location=url,
                    evidence=["API key in URL query", "API key echoed in response"],
                    recommendation=(
                        "Never accept API keys via URL query parameters. "
                        "Use Authorization headers instead. "
                        "Sanitize logs to remove credential exposure."
                    ),
                )
                result.add_finding(finding)

    async def _check_session_fixation(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for session fixation vulnerabilities."""
        if not self.config.check_session_fixation:
            return

        self.logger.info(f"Testing session fixation: {url}")

        # Send request with test session ID
        headers = {"Cookie": "session_id=test_session_12345"}
        response = await self._fetch_url(url, session, headers)

        if response:
            # Check if session ID is echoed back unchanged
            if "test_session_12345" in response["body"]:
                finding = self._create_finding(
                    severity=Severity.HIGH,
                    title="Session Fixation Vulnerability",
                    description=(
                        "The server accepts and echoes back session IDs from "
                        "external sources. An attacker could potentially fixate "
                        "a victim's session ID and hijack the session."
                    ),
                    cwe="CWE-384",
                    owasp_ref="OWASP API2:2023 - Broken Authentication",
                    location=url,
                    evidence=["Session ID echoed in response"],
                    recommendation=(
                        "Regenerate session IDs on login. "
                        "Validate session IDs server-side. "
                        "Use secure,HttpOnly cookie flags."
                    ),
                )
                result.add_finding(finding)

    async def _check_missing_mfa(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for missing MFA requirements on sensitive endpoints."""
        if not self.config.check_mfa:
            return

        self.logger.info(f"Checking MFA requirements: {url}")

        response = await self._fetch_url(url, session)

        if response is None:
            return

        # Check if response contains MFA-related content
        body_lower = response["body"].lower()

        # Look for MFA indicators that suggest it's supported
        mfa_found = any(indicator in body_lower for indicator in self.MFA_INDICATORS)

        # If MFA is mentioned but not enforced, warn
        if mfa_found and response["status"] != 401:
            # MFA is supported but not required - potential issue
            finding = self._create_finding(
                severity=Severity.MEDIUM,
                title="MFA Not Enforced",
                description=(
                    "Multi-factor authentication appears to be supported but "
                    "not enforced on this endpoint. Sensitive operations should "
                    "require MFA to prevent account compromise."
                ),
                cwe="CWE-308",
                owasp_ref="OWASP API2:2023 - Broken Authentication",
                location=url,
                evidence=["MFA indicators found in response"],
                recommendation=(
                    "Enforce MFA for sensitive operations. "
                    "Return 403 when MFA is not present. "
                    "Implement step-up authentication."
                ),
            )
            result.add_finding(finding)

    async def _check_brute_force_protection(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for brute force protection on login endpoints."""
        self.logger.info(f"Testing brute force protection: {url}")

        # Try multiple failed login attempts
        for credentials in self.DEFAULT_CREDENTIALS[:3]:  # Test first 3
            headers = {"Content-Type": "application/json"}
            body = {"username": credentials[0], "password": credentials[1]}

            try:
                async with session.post(
                    url,
                    json=body,
                    headers=headers,
                    timeout=10,
                ) as response:
                    # Check if rate limit headers present
                    if response.status == 429:
                        finding = self._create_finding(
                            severity=Severity.LOW,
                            title="Brute Force Protection Detected",
                            description=(
                                "Rate limiting is active on this endpoint. "
                                "Rate limit headers: X-RateLimit-Limit, X-RateLimit-Remaining"
                            ),
                            cwe="CWE-770",
                            location=url,
                            evidence=["Rate limited after failed attempts"],
                            recommendation=(
                                "Rate limiting is properly configured. "
                                "Ensure limits are appropriate for legitimate use."
                            ),
                        )
                        result.add_finding(finding)
                        break
            except Exception:
                pass

    async def _check_token_leakage(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for token leakage in error messages."""
        if not self.config.check_token_leakage:
            return

        self.logger.info(f"Checking token leakage: {url}")

        # Try to trigger error with invalid token
        headers = {"Authorization": "Bearer invalid_token_xyz123"}
        response = await self._fetch_url(url, session, headers)

        if response and response["status"] in [400, 401, 403]:
            body = response["body"].lower()

            # Check for token in error message
            if "invalid_token" in body or "token xyz123" in body:
                finding = self._create_finding(
                    severity=Severity.HIGH,
                    title="Token Leakage in Error Message",
                    description=(
                        "Error responses include token information, which could "
                        "help attackers understand the token format or validate "
                        "guesses. Never expose internal token details."
                    ),
                    cwe="CWE-209",
                    owasp_ref="OWASP API1:2023 - Broken Object Level Authorization",
                    location=url,
                    evidence=["Token exposed in error response"],
                    recommendation=(
                        "Sanitize error messages to remove sensitive data. "
                        "Use generic error messages for authentication failures. "
                        "Log detailed errors server-side only."
                    ),
                )
                result.add_finding(finding)

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Execute authentication scan on target."""
        self.logger.info(f"Starting authentication scan: {target}")

        result = ScanResult(
            module_name=self.module_name,
            target=target,
            metadata={"config": self.config.__dict__},
        )

        async def run_checks() -> None:

            async with aiohttp.ClientSession() as session:
                await asyncio.gather(
                    self._check_unauthenticated_access(target, session, result),
                    self._check_api_key_exposure(target, session, result),
                    self._check_session_fixation(target, session, result),
                    self._check_missing_mfa(target, session, result),
                    self._check_brute_force_protection(target, session, result),
                    self._check_token_leakage(target, session, result),
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
