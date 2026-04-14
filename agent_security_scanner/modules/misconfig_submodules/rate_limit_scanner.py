"""
Rate Limiting Scanner.

Scans for:
- Missing rate limiting
- Rate limit header manipulation
- Token bucket/leaky bucket bypass
- DDoS vulnerability indicators

References:
- OWASP API Security Top 10: API4:2019 - Unrestricted Resource Consumption
- RFC 6454 - Rate Limiting Best Practices

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List, Optional

import aiohttp

from ..base import BaseModule, ScanResult, Severity


class RateLimitScannerConfig:
    """Configuration for rate limiting scanning."""

    def __init__(
        self,
        enabled: bool = True,
        check_rate_limiting_headers: bool = True,
        check_429_responses: bool = True,
        test_rate_limit_bypass: bool = True,
        custom_headers: List[str] | None = None,
    ) -> None:
        self.enabled = enabled
        self.check_rate_limiting_headers = check_rate_limiting_headers
        self.check_429_responses = check_429_responses
        self.test_rate_limit_bypass = test_rate_limit_bypass
        self.custom_headers = custom_headers or [
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "RateLimit-Limit",
            "RateLimit-Remaining",
            "RateLimit-Reset",
            "Retry-After",
            "X-RateLimit-Class",
        ]


class RateLimitScanner(BaseModule[RateLimitScannerConfig]):
    """
    Rate limiting vulnerability scanner.

    Tests for:
    - Missing rate limiting headers
    - Rate limit bypass through header manipulation
    - Token bucket algorithm weakness
    - DDoS vulnerability
    """

    # Default rate limit headers to check
    DEFAULT_RATE_LIMIT_HEADERS = [
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "X-RateLimit-Reset",
        "RateLimit-Limit",
        "RateLimit-Remaining",
        "RateLimit-Reset",
        "Retry-After",
    ]

    def __init__(
        self,
        config: Optional[RateLimitScannerConfig] = None,
    ) -> None:
        super().__init__()
        self.config = config or RateLimitScannerConfig()

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

    async def _check_rate_limit_headers(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for rate limiting headers in response."""
        if not self.config.check_rate_limiting_headers:
            return

        self.logger.info(f"Checking rate limit headers: {url}")

        response = await self._fetch_url(url, session)

        if response is None:
            return

        headers = response["headers"]
        rate_limit_headers = [h for h in self.DEFAULT_RATE_LIMIT_HEADERS if h in headers]

        if not rate_limit_headers:
            finding = self._create_finding(
                severity=Severity.MEDIUM,
                title="Missing Rate Limiting Headers",
                description=(
                    "No rate limiting headers detected in response. "
                    "This may indicate the API lacks rate limiting protection, "
                    "enabling brute-force attacks, DDoS, or resource exhaustion."
                ),
                cwe="CWE-770",
                owasp_ref="OWASP API4:2019 - Unrestricted Resource Consumption",
                location=url,
                evidence=["No rate limit headers found"],
                recommendation=(
                    "Implement rate limiting with proper headers. "
                    "Common headers: X-RateLimit-Limit, X-RateLimit-Remaining, "
                    "X-RateLimit-Reset. Include Retry-After for 429 responses."
                ),
            )
            result.add_finding(finding)
        else:
            # Report found headers for documentation
            self.logger.info(f"Rate limit headers found: {rate_limit_headers}")

    async def _check_429_responses(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check if 429 Too Many Requests is returned when rate limited."""
        if not self.config.check_429_responses:
            return

        self.logger.info(f"Testing rate limit enforcement: {url}")

        # Make rapid requests to trigger rate limiting
        success_count = 0
        rate_limited = False

        for i in range(10):
            response = await self._fetch_url(url, session)
            if response:
                if response["status"] == 429:
                    rate_limited = True
                    break
                elif response["status"] < 500:
                    success_count += 1

        if not rate_limited and success_count > 8:
            finding = self._create_finding(
                severity=Severity.MEDIUM,
                title="Rate Limiting Not Enforced",
                description=(
                    "Made 10 rapid requests without triggering rate limiting. "
                    "This may indicate rate limiting is not properly configured, "
                    "leaving the API vulnerable to abuse."
                ),
                cwe="CWE-770",
                owasp_ref="OWASP API4:2019 - Unrestricted Resource Consumption",
                location=url,
                evidence=["10 requests successful, 0 rate limited"],
                recommendation=(
                    "Implement rate limiting per client/IP/API key. "
                    "Use token bucket or leaky bucket algorithms. "
                    "Return 429 with Retry-After header when limited."
                ),
            )
            result.add_finding(finding)

    async def _check_rate_limit_bypass(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for rate limit bypass techniques."""
        if not self.config.test_rate_limit_bypass:
            return

        self.logger.info(f"Testing rate limit bypass: {url}")

        # Test: Different headers to bypass
        bypass_headers = [
            {"X-Forwarded-For": "1.2.3.4"},
            {"X-Real-IP": "5.6.7.8"},
            {"User-Agent": "BypassAgent/1.0"},
            {"X-API-Key": "bypass_key_123"},
        ]

        responses = []
        for headers in bypass_headers:
            response = await self._fetch_url(url, session, headers)
            if response:
                responses.append(response)

        # Check if all bypass attempts succeeded (no 429s)
        if responses and not any(r["status"] == 429 for r in responses):
            finding = self._create_finding(
                severity=Severity.LOW,
                title="Potential Rate Limit Bypass",
                description=(
                    "Rate limiting may be bypassed by manipulating headers. "
                    "If the server only checks the originating IP and doesn't "
                    "validate header authenticity, attackers can bypass limits."
                ),
                cwe="CWE-770",
                location=url,
                evidence=["Multiple header variations all succeeded"],
                recommendation=(
                    "Implement rate limiting on authentication token or session, "
                    "not just IP address. Use cryptographic tokens in headers. "
                    "Validate header values server-side."
                ),
            )
            result.add_finding(finding)

    async def _check_token_bucket_weakness(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for token bucket algorithm weaknesses."""
        self.logger.info(f"Testing token bucket behavior: {url}")

        # Send burst of requests
        burst_size = 5
        timestamps = []

        for _ in range(burst_size):
            start = time.time()
            response = await self._fetch_url(url, session)
            end = time.time()
            timestamps.append(end - start)

            if response and response["status"] == 429:
                self.logger.info("Rate limited after burst")
                break

        # Analyze timing - if all requests took similar time, might be batched
        if len(timestamps) >= 2:
            timing_variance = max(timestamps) - min(timestamps)
            if timing_variance < 0.01:  # Less than 10ms variance
                finding = self._create_finding(
                    severity=Severity.LOW,
                    title="Token Bucket: Batched Processing Detected",
                    description=(
                        "All requests processed in similar time (<10ms variance). "
                        "This may indicate token bucket is processing requests "
                        "in batches rather than individually, potentially allowing "
                        "burst abuse."
                    ),
                    cwe="CWE-770",
                    location=url,
                    evidence=[f"Timing variance: {timing_variance:.6f}s"],
                    recommendation=(
                        "Ensure token bucket processes requests individually. "
                        "Use fine-grained timing for rate limiting. "
                        "Consider sliding window log algorithm for precision."
                    ),
                )
                result.add_finding(finding)

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Execute rate limiting scan on target."""
        self.logger.info(f"Starting rate limit scan: {target}")

        result = ScanResult(
            module_name=self.module_name,
            target=target,
            metadata={"config": self.config.__dict__},
        )

        async def run_checks() -> None:

            async with aiohttp.ClientSession() as session:
                await asyncio.gather(
                    self._check_rate_limit_headers(target, session, result),
                    self._check_429_responses(target, session, result),
                    self._check_rate_limit_bypass(target, session, result),
                    self._check_token_bucket_weakness(target, session, result),
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
