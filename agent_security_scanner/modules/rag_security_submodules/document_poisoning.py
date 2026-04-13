"""
Document Poisoning Scanner - RAG pipeline poisoning detection.

Scans for:
- Document poisoning attacks
- Knowledge base injection
- Content sanitization gaps
- Malicious document ingestion

References:
- OWASP LLM Top 10: LLM03:2024 - Training Data Poisoning
- RAG Security Best Practices

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional

import aiohttp
from loguru import logger

from ..base import BaseModule, Finding, ScanResult, Severity


class DocumentPoisoningScannerConfig:
    """Configuration for document poisoning scanning."""

    def __init__(
        self,
        enabled: bool = True,
        check_poisoning_patterns: bool = True,
        check_validation: bool = True,
        check_sanitization: bool = True,
        check_ingestion_security: bool = True,
    ) -> None:
        self.enabled = enabled
        self.check_poisoning_patterns = check_poisoning_patterns
        self.check_validation = check_validation
        self.check_sanitization = check_sanitization
        self.check_ingestion_security = check_ingestion_security


class DocumentPoisoningScanner(BaseModule):
    """
    Document poisoning vulnerability scanner.

    Tests for:
    - Document poisoning patterns in configuration
    - Missing document validation
    - Missing content sanitization
    - Insecure knowledge base ingestion
    """

    # Poisoning attack patterns to detect
    POISONING_PATTERNS = [
        "inject_malicious",
        "override_context",
        "false_knowledge",
        "poisoned_embedding",
        "backdoor_trigger",
        "hidden_instruction",
        "adversarial_document",
        "malicious_knowledge",
        "data_poisoning",
        "knowledge_injection",
    ]

    def __init__(
        self,
        config: Optional[DocumentPoisoningScannerConfig] = None,
    ) -> None:
        super().__init__()
        self.config = config or DocumentPoisoningScannerConfig()

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

    async def _check_poisoning_patterns(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for poisoning patterns in configuration."""
        if not self.config.check_poisoning_patterns:
            return

        self.logger.info(f"Checking poisoning patterns: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        for pattern in self.POISONING_PATTERNS:
            if pattern in config_str:
                finding = self._create_finding(
                    severity=Severity.HIGH,
                    title=f"Document Poisoning Pattern Detected: {pattern}",
                    description=(
                        f"RAG configuration contains '{pattern}' which indicates "
                        "vulnerability to document poisoning attacks. Attackers "
                        "can inject malicious content into the knowledge base."
                    ),
                    cwe="CWE-94",
                    owasp_ref="OWASP LLM03:2024 - Training Data Poisoning",
                    location=url,
                    evidence=[f"Pattern found: {pattern}"],
                    recommendation=(
                        "Remove or rename the identified vulnerability pattern. "
                        "Implement proper input validation. "
                        "Use document signing for integrity verification."
                    ),
                )
                result.add_finding(finding)

    async def _check_document_validation(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for missing document validation."""
        if not self.config.check_validation:
            return

        self.logger.info(f"Checking document validation: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        # Check for validation configuration
        has_validation = any(
            keyword in config_str
            for keyword in [
                "validate",
                "sanitize",
                "verify",
                "checksum",
                "signature",
                "scan",
            ]
        )

        if not has_validation:
            finding = self._create_finding(
                severity=Severity.MEDIUM,
                title="Missing Document Validation",
                description=(
                    "RAG pipeline lacks document validation configuration. "
                    "Unvalidated documents can be injected into the knowledge "
                    "base, enabling poisoning attacks."
                ),
                cwe="CWE-20",
                location=url,
                evidence=["No validation keywords in config"],
                recommendation=(
                    "Implement document validation pipeline. "
                    "Scan documents for malicious content. "
                    "Verify document sources and integrity. "
                    "Use allowlists for document types."
                ),
            )
            result.add_finding(finding)

    async def _check_sanitization(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for missing content sanitization."""
        if not self.config.check_sanitization:
            return

        self.logger.info(f"Checking content sanitization: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        # Check for sanitization configuration
        has_sanitization = any(
            keyword in config_str
            for keyword in [
                "sanitize",
                "clean",
                "filter",
                "escape",
                "encode",
                "remove_scripts",
            ]
        )

        if not has_sanitization:
            finding = self._create_finding(
                severity=Severity.LOW,
                title="Missing Content Sanitization",
                description=(
                    "RAG pipeline lacks content sanitization. "
                    "Unsanitized documents may contain malicious scripts, "
                    "HTML, or other executable content."
                ),
                cwe="CWE-79",
                location=url,
                evidence=["No sanitization configuration found"],
                recommendation=(
                    "Implement content sanitization pipeline. "
                    "Remove or escape HTML/JavaScript. "
                    "Use markdown sanitization. "
                    "Validate document structure."
                ),
            )
            result.add_finding(finding)

    async def _check_ingestion_security(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for secure knowledge base ingestion."""
        if not self.config.check_ingestion_security:
            return

        self.logger.info(f"Checking ingestion security: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        # Check for secure ingestion features
        secure_features = {
            "ingest_auth": "Authentication required for ingestion",
            "webhook_verify": "Webhook signature verification",
            "batch_verify": "Batch ingestion verification",
            "source_validate": "Source URL validation",
        }

        for feature, description in secure_features.items():
            if feature not in config_str:
                finding = self._create_finding(
                    severity=Severity.LOW,
                    title=f"Missing Ingestion Security: {feature}",
                    description=description,
                    cwe="CWE-284",
                    location=url,
                    evidence=[f"Not found in config: {feature}"],
                    recommendation=(
                        "Enable the missing security feature. "
                        "Implement proper access controls for ingestion endpoints. "
                        "Verify source authenticity."
                    ),
                )
                result.add_finding(finding)

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Execute document poisoning scan on target."""
        self.logger.info(f"Starting document poisoning scan: {target}")

        result = ScanResult(
            module_name=self.module_name,
            target=target,
            metadata={
                "config": self.config.__dict__,
                "poisoning_patterns_tested": len(self.POISONING_PATTERNS),
            },
        )

        async def run_checks() -> None:
            timeout = kwargs.get("timeout", 10)

            async with aiohttp.ClientSession() as session:
                await asyncio.gather(
                    self._check_poisoning_patterns(target, session, result),
                    self._check_document_validation(target, session, result),
                    self._check_sanitization(target, session, result),
                    self._check_ingestion_security(target, session, result),
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
