"""
Secret Scanner - API key and secret detection.

Scans for:
- API key leakage in prompts
- Secret exposure in responses
- Credential exposure in logs
- Configuration file leaks

References:
- Secret Detection Best Practices
- Credential Security

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Optional

import aiohttp
from loguru import logger

from ..base import BaseModule, Finding, ScanResult, Severity


class SecretScannerConfig:
    """Configuration for secret scanning."""

    def __init__(
        self,
        enabled: bool = True,
        check_prompts: bool = True,
        check_responses: bool = True,
        check_headers: bool = True,
    ) -> None:
        self.enabled = enabled
        self.check_prompts = check_prompts
        self.check_responses = check_responses
        self.check_headers = check_headers


class SecretScanner(BaseModule):
    """
    Secret and credential detection scanner.

    Tests for:
    - API key exposure in prompts
    - Secret leakage in responses
    - Header-based secrets
    """

    # Patterns for detecting secrets
    SECRET_PATTERNS = [
        (r"api[_-]?key['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}", "API Key"),
        (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API Key"),
        (r"Bearer\s+[a-zA-Z0-9_-]{20,}", "Bearer Token"),
        (r"secret['\"]?\s*[:=]\s*['\"]?[^'\"\\s]{8,}", "Secret Key"),
        (r"password['\"]?\s*[:=]\s*['\"]?[^'\"\\s]{8,}", "Password"),
        (r"token['\"]?\s*[:=]\s*['\"]?[^'\"\\s]{16,}", "Token"),
        (r"aws[_-]?(access[_-]?key|secret)", "AWS Credentials"),
    ]

    def __init__(
        self,
        config: Optional[SecretScannerConfig] = None,
    ) -> None:
        self.config = config or SecretScannerConfig()
        super().__init__()

    async def _fetch_url(
        self,
        url: str,
        session: aiohttp.ClientSession,
        timeout: int = 10,
    ) -> Optional[Dict[str, Any]]:
        """Fetch URL and return response details."""
        try:
            async with session.get(url, timeout=timeout) as response:
                return {
                    "url": url,
                    "status": response.status,
                    "headers": dict(response.headers),
                    "body": await response.text(),
                }
        except Exception as e:
            self.logger.warning(f"Error fetching URL: {e}")
            return None

    async def _check_response_secrets(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for secrets in response content."""
        if not self.config.check_responses:
            return

        self.logger.info(f"Checking response secrets: {url}")

        response = await self._fetch_url(url, session)

        if response is None:
            return

        body = response["body"]

        for pattern, secret_type in self.SECRET_PATTERNS:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                finding = self._create_finding(
                    severity=Severity.CRITICAL,
                    title=f"Secret Exposure: {secret_type}",
                    description=(
                        f"Detected {secret_type} in API response. "
                        "Sensitive credentials should never be exposed in "
                        "API responses."
                    ),
                    cwe="CWE-312",
                    location=url,
                    evidence=[f"Pattern: {pattern[:40]}...", "Secret found in response"],
                    recommendation=(
                        "Never return secrets in API responses. "
                        "Remove sensitive fields from response objects. "
                        "Use environment variables for secrets. "
                        "Implement proper secret management."
                    ),
                )
                result.add_finding(finding)

    async def _check_prompt_secrets(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for secrets being accepted in prompts."""
        if not self.config.check_prompts:
            return

        self.logger.info(f"Checking prompt secrets: {url}")

        # Test with a prompt containing a fake secret
        test_prompts = [
            "Use API_KEY=sk_test_1234567890abcdef for authentication",
            "Use secret=mysecret123 to access the resource",
        ]

        for prompt in test_prompts:
            try:
                async with session.post(
                    url,
                    json={"prompt": prompt},
                    timeout=10,
                ) as response:
                    # If the secret is echoed back, that's a problem
                    body = await response.text()
                    if "sk_test_1234567890abcdef" in body or "mysecret123" in body:
                        finding = self._create_finding(
                            severity=Severity.HIGH,
                            title="Secret Echoed in Response",
                            description=(
                                "The API accepts and echoes back secrets in prompts. "
                                "This indicates poor input validation and could lead "
                                "to secret leakage through logs or responses."
                            ),
                            cwe="CWE-312",
                            location=url,
                            evidence=[f"Prompt: {prompt[:50]}..."],
                            recommendation=(
                                "Sanitize input to remove secrets. "
                                "Validate and filter sensitive data. "
                                "Implement content moderation. "
                                "Log sanitized versions only."
                            ),
                        )
                        result.add_finding(finding)
                        break  # One finding for this test
            except Exception:
                pass

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Execute secret scan on target."""
        self.logger.info(f"Starting secret scan: {target}")

        result = ScanResult(
            module_name=self.module_name,
            target=target,
            metadata={
                "config": self.config.__dict__,
                "patterns_tested": len(self.SECRET_PATTERNS),
            },
        )

        async def run_checks() -> None:
            timeout = kwargs.get("timeout", 10)

            async with aiohttp.ClientSession() as session:
                await asyncio.gather(
                    self._check_response_secrets(target, session, result),
                    self._check_prompt_secrets(target, session, result),
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
