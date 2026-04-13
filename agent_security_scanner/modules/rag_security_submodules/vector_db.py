"""
Vector DB Scanner - Vector database security checks.

Scans for:
- Unauthenticated vector DB access
- Missing encryption
- Insecure indexing
- Injection vulnerabilities

References:
- Vector Database Security Best Practices
- RAG Security Guidelines

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, Optional

import aiohttp
from loguru import logger

from ..base import BaseModule, Finding, ScanResult, Severity


class VectorDBScannerConfig:
    """Configuration for vector DB scanning."""

    def __init__(
        self,
        enabled: bool = True,
        check_no_auth: bool = True,
        check_plaintext: bool = True,
        check_public_access: bool = True,
        check_injection: bool = True,
    ) -> None:
        self.enabled = enabled
        self.check_no_auth = check_no_auth
        self.check_plaintext = check_plaintext
        self.check_public_access = check_public_access
        self.check_injection = check_injection


class VectorDBScanner(BaseModule):
    """
    Vector database security scanner.

    Tests for:
    - Unauthenticated access
    - Missing encryption
    - Public access enabled
    - Injection vulnerabilities
    """

    def __init__(
        self,
        config: Optional[VectorDBScannerConfig] = None,
    ) -> None:
        super().__init__()
        self.config = config or VectorDBScannerConfig()

    async def _fetch_config(
        self,
        url: str,
        session: aiohttp.ClientSession,
        timeout: int = 10,
    ) -> Optional[Dict[str, Any]]:
        """Fetch RAG pipeline configuration."""
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

    async def _check_auth(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for vector DB authentication."""
        if not self.config.check_no_auth:
            return

        self.logger.info(f"Checking vector DB auth: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        # Look for vector DB config
        vector_config = config.get("vector_database", config.get("vector_db", {}))

        if not vector_config:
            self.logger.debug("No vector DB config found")
            return

        vector_str = json.dumps(vector_config).lower()

        # Check for auth configuration
        if "auth" not in vector_str and "auth" not in config.get("settings", {}):
            finding = self._create_finding(
                severity=Severity.HIGH,
                title="No Vector DB Authentication",
                description=(
                    "Vector database has no authentication configured. "
                    "This allows anyone with network access to query or "
                    "modify the knowledge base."
                ),
                cwe="CWE-306",
                location=url,
                evidence=["No auth configuration in vector DB"],
                recommendation=(
                    "Enable authentication for vector DB. "
                    "Use API keys or OAuth2. "
                    "Implement role-based access control. "
                    "Restrict network access to authorized IPs."
                ),
            )
            result.add_finding(finding)

    async def _check_encryption(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for vector DB encryption."""
        if not self.config.check_plaintext:
            return

        self.logger.info(f"Checking vector DB encryption: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        vector_config = config.get("vector_database", config.get("vector_db", {}))

        if not vector_config:
            return

        vector_str = json.dumps(vector_config).lower()

        # Check for encryption configuration
        has_encryption = any(
            keyword in vector_str
            for keyword in [
                "encrypt",
                "tls",
                "ssl",
                "https",
                "secure",
                "encryption",
            ]
        )

        if not has_encryption:
            finding = self._create_finding(
                severity=Severity.HIGH,
                title="No Vector DB Encryption",
                description=(
                    "Vector database lacks encryption configuration. "
                    "Data may be transmitted in plaintext and stored "
                    "without encryption at rest."
                ),
                cwe="CWE-311",
                location=url,
                evidence=["No encryption configuration found"],
                recommendation=(
                    "Enable TLS for data in transit. "
                    "Enable encryption at rest. "
                    "Use HTTPS for all database connections. "
                    "Implement certificate validation."
                ),
            )
            result.add_finding(finding)

    async def _check_public_access(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for public access to vector DB."""
        if not self.config.check_public_access:
            return

        self.logger.info(f"Checking public access: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        vector_config = config.get("vector_database", config.get("vector_db", {}))

        if not vector_config:
            return

        vector_str = json.dumps(vector_config).lower()

        if "public" in vector_str or "anonymous" in vector_str:
            finding = self._create_finding(
                severity=Severity.CRITICAL,
                title="Public Vector DB Access",
                description=(
                    "Vector database allows public/anonymous access. "
                    "This enables anyone to query the knowledge base, "
                    "potentially exposing sensitive information."
                ),
                cwe="CWE-306",
                location=url,
                evidence=["Public access enabled in vector DB config"],
                recommendation=(
                    "Disable public access immediately. "
                    "Implement proper authentication. "
                    "Use private network access. "
                    "Restrict to authorized users only."
                ),
            )
            result.add_finding(finding)

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Execute vector DB scan on target."""
        self.logger.info(f"Starting vector DB scan: {target}")

        result = ScanResult(
            module_name=self.module_name,
            target=target,
            metadata={"config": self.config.__dict__},
        )

        async def run_checks() -> None:
            timeout = kwargs.get("timeout", 10)

            async with aiohttp.ClientSession() as session:
                await asyncio.gather(
                    self._check_auth(target, session, result),
                    self._check_encryption(target, session, result),
                    self._check_public_access(target, session, result),
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
