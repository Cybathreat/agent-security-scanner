"""
Document Poisoning Scanner - RAG pipeline poisoning detection.

Scans for:
- Document poisoning attacks
- Knowledge base injection
- Content sanitization gaps
- Malicious document ingestion

References:
- OWASP LLM Top 10: LLM03:2025 - Supply Chain Vulnerability
- MITRE ATLAS: TA0045 LLM Attack

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, Optional

import aiohttp

from ..base import BaseModule, ScanResult, Severity


class DocumentPoisoningScannerConfig:
    """Configuration for document poisoning scanning."""

    def __init__(
        self,
        enabled: bool = True,
        test_poisoning_patterns: bool = True,
        test_validation: bool = True,
        test_sanitization: bool = True,
        test_ingestion_security: bool = True,
        compliance_threshold: float = 0.6,
        request_delay: float = 0.5,
    ) -> None:
        self.enabled = enabled
        self.test_poisoning_patterns = test_poisoning_patterns
        self.test_validation = test_validation
        self.test_sanitization = test_sanitization
        self.test_ingestion_security = test_ingestion_security
        self.compliance_threshold = compliance_threshold
        self.request_delay = request_delay


class DocumentPoisoningScanner(BaseModule[DocumentPoisoningScannerConfig]):
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
        self.config = config or DocumentPoisoningScannerConfig()
        super().__init__()

    async def _check_poisoning_patterns(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
        cached_config: Optional[Dict[str, Any]],
    ) -> None:
        """Check for poisoning patterns in configuration."""
        if not self.config.test_poisoning_patterns:
            return

        self.logger.info(f"Checking poisoning patterns: {url}")

        if cached_config is None:
            return

        config_str = json.dumps(cached_config).lower()

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
                    owasp_ref="OWASP LLM03:2025 - Supply Chain Vulnerability",
                    mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
                    location=url,
                    evidence=[f"Pattern found: {pattern}"],
                    recommendation=(
                        "Remove or rename the identified vulnerability pattern. "
                        "Implement proper input validation. "
                        "Use document signing for integrity verification."
                    ),
                )
                result.add_finding(finding)

        if self.config.request_delay > 0:
            await asyncio.sleep(self.config.request_delay)

    async def _check_document_validation(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
        cached_config: Optional[Dict[str, Any]],
    ) -> None:
        """Check for missing document validation."""
        if not self.config.test_validation:
            return

        self.logger.info(f"Checking document validation: {url}")

        if cached_config is None:
            return

        config_str = json.dumps(cached_config).lower()

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
                owasp_ref="OWASP LLM03:2025 - Supply Chain Vulnerability",
                mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
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

        if self.config.request_delay > 0:
            await asyncio.sleep(self.config.request_delay)

    async def _check_sanitization(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
        cached_config: Optional[Dict[str, Any]],
    ) -> None:
        """Check for missing content sanitization."""
        if not self.config.test_sanitization:
            return

        self.logger.info(f"Checking content sanitization: {url}")

        if cached_config is None:
            return

        config_str = json.dumps(cached_config).lower()

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
                owasp_ref="OWASP LLM03:2025 - Supply Chain Vulnerability",
                mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
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

        if self.config.request_delay > 0:
            await asyncio.sleep(self.config.request_delay)

    async def _check_ingestion_security(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
        cached_config: Optional[Dict[str, Any]],
    ) -> None:
        """Check for secure knowledge base ingestion."""
        if not self.config.test_ingestion_security:
            return

        self.logger.info(f"Checking ingestion security: {url}")

        if cached_config is None:
            return

        config_str = json.dumps(cached_config).lower()

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
                    owasp_ref="OWASP LLM03:2025 - Supply Chain Vulnerability",
                    mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
                    location=url,
                    evidence=[f"Not found in config: {feature}"],
                    recommendation=(
                        "Enable the missing security feature. "
                        "Implement proper access controls for ingestion endpoints. "
                        "Verify source authenticity."
                    ),
                )
                result.add_finding(finding)

        if self.config.request_delay > 0:
            await asyncio.sleep(self.config.request_delay)

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Execute document poisoning scan on target."""
        self.logger.info(f"Starting document poisoning scan: {target}")

        result = ScanResult(
            module_name=self.module_name,
            target=target,
            metadata={
                "test_poisoning_patterns": self.config.test_poisoning_patterns,
                "test_validation": self.config.test_validation,
                "test_sanitization": self.config.test_sanitization,
                "test_ingestion_security": self.config.test_ingestion_security,
                "poisoning_patterns_tested": len(self.POISONING_PATTERNS),
            },
        )

        if not self.config.enabled:
            self.logger.info("Document poisoning scanning disabled")
            result.finalize()
            return result

        async def run_checks() -> None:
            async with aiohttp.ClientSession() as session:
                # Cache config fetch once at start
                cached_config = await self._fetch_url(url=target, session=session)

                await asyncio.gather(
                    self._check_poisoning_patterns(target, session, result, cached_config),
                    self._check_document_validation(target, session, result, cached_config),
                    self._check_sanitization(target, session, result, cached_config),
                    self._check_ingestion_security(target, session, result, cached_config),
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