"""
Authentication and Authorization Scanner.

Scans for:
- Missing or weak authentication
- API key exposure in URLs or headers
- Session fixation vulnerabilities
- Missing MFA requirements
- Brute force protection detection
- Token leakage in error messages

References:
- CWE-306: Missing Authentication for Critical Function
- CWE-598: Use of GET Request Method With Sensitive Query Strings
- CWE-384: Session Fixation
- CWE-308: Use of Single-Factor Authentication
- CWE-770: Allocation of Resources Without Limits
- CWE-209: Generation of Error Message Containing Sensitive Information
- OWASP API1:2023 - Broken Object Level Authorization
- OWASP API2:2023 - Broken Authentication
- OWASP LLM08:2025 - Excessive Agency
- MITRE ATLAS - TA0045 LLM Attack
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

import aiohttp

from ..base import BaseModule, ScanResult, Severity


class AuthScannerConfig:
    """Configuration for authentication scanning."""

    def __init__(
        self,
        enabled: bool = True,
        test_unauthenticated: bool = True,
        test_api_keys: bool = True,
        test_session_fixation: bool = True,
        test_mfa: bool = True,
        test_brute_force: bool = True,
        test_token_leakage: bool = True,
        compliance_threshold: float = 0.6,
        request_delay: float = 0.5,
    ) -> None:
        self.enabled = enabled
        self.test_unauthenticated = test_unauthenticated
        self.test_api_keys = test_api_keys
        self.test_session_fixation = test_session_fixation
        self.test_mfa = test_mfa
        self.test_brute_force = test_brute_force
        self.test_token_leakage = test_token_leakage
        self.compliance_threshold = compliance_threshold
        self.request_delay = request_delay


class AuthScanner(BaseModule[AuthScannerConfig]):
    """
    Authentication and authorization vulnerability scanner.

    Tests for unauthenticated access, API key exposure, session fixation,
    missing MFA, brute force protection, and token leakage.
    """

    # Default test credentials to attempt
    DEFAULT_CREDENTIALS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("root", "root"),
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
        self.config = config or AuthScannerConfig()
        super().__init__()

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

        response = await self._fetch_url(url=url, session=session)

        if response is None:
            result.add_error(f"Failed to fetch: {url}")
            return

        if response["status"] == 200:
            has_auth_challenge = "WWW-Authenticate" in response["headers"]
            auth_headers = ["Authorization", "Cookie", "X-API-Key"]
            has_auth_header = any(h in response["headers"] for h in auth_headers)

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
                    mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
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

        if self.config.request_delay > 0:
            await asyncio.sleep(self.config.request_delay)

    async def _check_api_key_exposure(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for API key exposure in URLs or headers."""
        if not self.config.test_api_keys:
            return

        self.logger.info(f"Checking API key exposure: {url}")

        test_url = f"{url}?api_key=test_key_1234567890abcdef"
        response = await self._fetch_url(url=test_url, session=session)

        if response and response["status"] == 200:
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
                    mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
                    location=url,
                    evidence=["API key in URL query", "API key echoed in response"],
                    recommendation=(
                        "Never accept API keys via URL query parameters. "
                        "Use Authorization headers instead. "
                        "Sanitize logs to remove credential exposure."
                    ),
                )
                result.add_finding(finding)

        if self.config.request_delay > 0:
            await asyncio.sleep(self.config.request_delay)

    async def _check_session_fixation(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for session fixation vulnerabilities."""
        if not self.config.test_session_fixation:
            return

        self.logger.info(f"Testing session fixation: {url}")

        headers = {"Cookie": "session_id=test_session_12345"}
        response = await self._fetch_url(url=url, session=session, headers=headers)

        if response:
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
                    mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
                    location=url,
                    evidence=["Session ID echoed in response"],
                    recommendation=(
                        "Regenerate session IDs on login. "
                        "Validate session IDs server-side. "
                        "Use secure, HttpOnly cookie flags."
                    ),
                )
                result.add_finding(finding)

        if self.config.request_delay > 0:
            await asyncio.sleep(self.config.request_delay)

    async def _check_missing_mfa(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for missing MFA requirements on sensitive endpoints."""
        if not self.config.test_mfa:
            return

        self.logger.info(f"Checking MFA requirements: {url}")

        response = await self._fetch_url(url=url, session=session)

        if response is None:
            return

        body_lower = response["body"].lower()
        mfa_found = any(indicator in body_lower for indicator in self.MFA_INDICATORS)

        if mfa_found and response["status"] != 401:
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
                mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
                location=url,
                evidence=["MFA indicators found in response"],
                recommendation=(
                    "Enforce MFA for sensitive operations. "
                    "Return 403 when MFA is not present. "
                    "Implement step-up authentication."
                ),
            )
            result.add_finding(finding)

        if self.config.request_delay > 0:
            await asyncio.sleep(self.config.request_delay)

    async def _check_brute_force_protection(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for brute force protection on login endpoints."""
        if not self.config.test_brute_force:
            return

        self.logger.info(f"Testing brute force protection: {url}")

        for credentials in self.DEFAULT_CREDENTIALS:
            body = {"username": credentials[0], "password": credentials[1]}

            try:
                async with session.post(
                    url,
                    json=body,
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as response:
                    if response.status == 429:
                        finding = self._create_finding(
                            severity=Severity.LOW,
                            title="Brute Force Protection Detected",
                            description=(
                                "Rate limiting is active on this endpoint, "
                                "which is a positive security control."
                            ),
                            cwe="CWE-770",
                            owasp_ref="OWASP API4:2019 - Lack of Resources & Rate Limiting",
                            mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
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

            if self.config.request_delay > 0:
                await asyncio.sleep(self.config.request_delay)

    async def _check_token_leakage(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for token leakage in error messages."""
        if not self.config.test_token_leakage:
            return

        self.logger.info(f"Checking token leakage: {url}")

        headers = {"Authorization": "Bearer invalid_token_xyz123"}
        response = await self._fetch_url(url=url, session=session, headers=headers)

        if response and response["status"] in [400, 401, 403]:
            body = response["body"].lower()

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
                    mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
                    location=url,
                    evidence=["Token exposed in error response"],
                    recommendation=(
                        "Sanitize error messages to remove sensitive data. "
                        "Use generic error messages for authentication failures. "
                        "Log detailed errors server-side only."
                    ),
                )
                result.add_finding(finding)

        if self.config.request_delay > 0:
            await asyncio.sleep(self.config.request_delay)

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Execute authentication scan on target."""
        self.logger.info(f"Starting authentication scan: {target}")

        result = ScanResult(
            module_name=self.module_name,
            target=target,
            metadata={
                "test_unauthenticated": self.config.test_unauthenticated,
                "test_api_keys": self.config.test_api_keys,
                "test_session_fixation": self.config.test_session_fixation,
                "test_mfa": self.config.test_mfa,
                "test_brute_force": self.config.test_brute_force,
                "test_token_leakage": self.config.test_token_leakage,
            },
        )

        if not self.config.enabled:
            self.logger.info("Authentication scanning disabled")
            result.finalize()
            return result

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
            try:
                new_loop.run_until_complete(run_checks())
            finally:
                new_loop.close()
                asyncio.set_event_loop(None)
        except RuntimeError:
            asyncio.run(run_checks())

        result.finalize()
        return result