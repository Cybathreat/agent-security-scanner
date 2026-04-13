"""
RAG Pipeline Security Module.

Scans Retrieval-Augmented Generation (RAG) pipelines for:
- Document poisoning attacks
- Data exfiltration risks
- Vector database security issues
- Retrieval manipulation
- Context window attacks

References:
- OWASP LLM Top 10: LLM01:2024 - Prompt Injection
- OWASP LLM Top 10: LLM03:2024 - Training Data Poisoning
- MITRE ATLAS: TA0045 - LLM Attack
- ANSSI Generative AI: RAG Security Guidelines

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any, Dict, List, Optional

import aiohttp
from loguru import logger

from ..core.config import RAGSecurityConfig
from .base import BaseModule, Finding, ScanResult, Severity


class RAGSecurityModule(BaseModule[RAGSecurityConfig]):
    """
    RAG pipeline security scanning module.

    Checks for:
    - Document poisoning (malicious content in knowledge base)
    - Data exfiltration via retrieval
    - Vector database misconfigurations
    - Retrieval manipulation attacks
    - Context window overflow attacks
    - Embedding model vulnerabilities
    - Knowledge base injection
    """

    # Poisoning attack patterns
    POISONING_PATTERNS = [
        "inject_malicious",
        "override_context",
        "false_knowledge",
        "poisoned_embedding",
        "backdoor_trigger",
        "hidden_instruction",
    ]

    # Exfiltration indicators
    EXFILTRATION_INDICATORS = [
        "extract_all",
        "dump_database",
        "exfiltrate",
        "send_to_external",
        "encode_and_transmit",
        "covert_channel",
    ]

    def __init__(
        self,
        config: Optional[RAGSecurityConfig] = None,
    ) -> None:
        """
        Initialize RAG security scanner.

        Args:
            config: Configuration for RAG security checks.
        """
        self.config = config or RAGSecurityConfig()
        super().__init__()

    async def _fetch_rag_config(
        self,
        url: str,
        session: aiohttp.ClientSession,
        timeout: int = 10,
    ) -> Optional[Dict[str, Any]]:
        """
        Fetch RAG pipeline configuration.

        Args:
            url: Target API endpoint
            session: aiohttp session
            timeout: Request timeout

        Returns:
            Dict: RAG configuration or None on error.
        """
        try:
            async with session.get(url, timeout=timeout) as response:
                if response.status == 200:
                    body = await response.text()
                    try:
                        return json.loads(body)
                    except json.JSONDecodeError:
                        return {"raw": body}
        except asyncio.TimeoutError:
            self.logger.warning(f"Timeout fetching RAG config: {url}")
        except aiohttp.ClientError as e:
            self.logger.warning(f"Error fetching RAG config: {e}")

        return None

    async def _check_document_poisoning(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """
        Check for document poisoning vulnerabilities.

        Tests if the RAG pipeline:
        - Accepts unvalidated documents
        - Lacks content sanitization
        - Is vulnerable to knowledge base injection

        Args:
            url: Target endpoint
            session: aiohttp session
            result: Scan result container
        """
        if not self.config.check_poisoning:
            self.logger.debug("Poisoning check disabled")
            return

        self.logger.info(f"Checking document poisoning: {url}")

        config = await self._fetch_rag_config(url, session)

        if config is None:
            result.add_error(f"Failed to fetch RAG config: {url}")
            return

        config_str = json.dumps(config).lower()

        # Check for poisoning patterns
        for pattern in self.POISONING_PATTERNS:
            if pattern in config_str:
                finding = self._create_finding(
                    severity=Severity.HIGH,
                    title="Document Poisoning Vulnerability",
                    description=(
                        f"RAG configuration contains '{pattern}' pattern which "
                        "may indicate vulnerability to document poisoning attacks. "
                        "Attackers can inject malicious content into the knowledge "
                        "base to manipulate agent responses."
                    ),
                    cwe="CWE-94",  # Code Injection (analogous)
                    owasp_ref="OWASP LLM03:2024 - Training Data Poisoning",
                    mitre_ref="MITRE ATLAS - TA0045 LLM Attack",
                    location=url,
                    evidence=[f"Pattern found: {pattern}"],
                    recommendation=(
                        "Validate all documents before ingestion. "
                        "Implement content sanitization. "
                        "Use document signing/attestation. "
                        "Monitor knowledge base for anomalies. "
                        "Implement retrieval integrity checks."
                    ),
                )
                result.add_finding(finding)
                self.logger.info(f"Poisoning finding: {finding.id}")

        # Check for missing validation
        has_validation = any(
            keyword in config_str
            for keyword in ["validate", "sanitize", "verify", "check", "scan"]
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
                cwe="CWE-20",  # Improper Input Validation
                location=url,
                evidence=["No validation keywords in config"],
                recommendation=(
                    "Implement document validation pipeline. "
                    "Scan documents for malicious content. "
                    "Verify document sources. "
                    "Use allowlists for document types."
                ),
            )
            result.add_finding(finding)

    async def _check_exfiltration_risk(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """
        Check for data exfiltration risks in RAG pipeline.

        Tests if the pipeline:
        - Allows unrestricted data retrieval
        - Has egress controls
        - Can be used to exfiltrate knowledge base

        Args:
            url: Target endpoint
            session: aiohttp session
            result: Scan result container
        """
        if not self.config.check_exfiltration:
            self.logger.debug("Exfiltration check disabled")
            return

        self.logger.info(f"Checking exfiltration risk: {url}")

        config = await self._fetch_rag_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        # Check for exfiltration indicators
        for indicator in self.EXFILTRATION_INDICATORS:
            if indicator in config_str:
                finding = self._create_finding(
                    severity=Severity.CRITICAL,
                    title="Data Exfiltration Risk",
                    description=(
                        f"RAG configuration contains '{indicator}' which may "
                        "enable data exfiltration. Attackers can craft queries "
                        "to extract sensitive information from the knowledge base "
                        "or vector database."
                    ),
                    cwe="CWE-200",  # Information Exposure
                    owasp_ref="OWASP LLM05:2024 - Improper Output Handling",
                    location=url,
                    evidence=[f"Indicator: {indicator}"],
                    recommendation=(
                        "Implement egress filtering. "
                        "Limit retrieval response size. "
                        "Redact sensitive information. "
                        "Monitor query patterns for exfiltration attempts. "
                        "Implement rate limiting on retrieval."
                    ),
                )
                result.add_finding(finding)
                self.logger.warning(f"Exfiltration finding: {finding.id}")

        # Check for missing egress controls
        has_egress_control = any(
            keyword in config_str
            for keyword in ["egress", "filter", "limit", "redact", "mask"]
        )

        if not has_egress_control:
            finding = self._create_finding(
                severity=Severity.MEDIUM,
                title="Missing Egress Controls",
                description=(
                    "RAG pipeline lacks egress controls for retrieved data. "
                    "This may allow unrestricted data extraction from the "
                    "knowledge base."
                ),
                cwe="CWE-200",
                location=url,
                evidence=["No egress control keywords in config"],
                recommendation=(
                    "Implement response filtering. "
                    "Set maximum retrieval size. "
                    "Redact PII and sensitive data. "
                    "Log all retrieval queries."
                ),
            )
            result.add_finding(finding)

    async def _check_vector_db_security(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """
        Check vector database security configuration.

        Tests for:
        - Unauthenticated vector DB access
        - Missing encryption
        - Insecure indexing
        - Injection vulnerabilities

        Args:
            url: Target endpoint
            session: aiohttp session
            result: Scan result container
        """
        if not self.config.vector_db_scan:
            self.logger.debug("Vector DB scan disabled")
            return

        self.logger.info(f"Checking vector DB security: {url}")

        config = await self._fetch_rag_config(url, session)

        if config is None:
            return

        # Look for vector DB config
        vector_config = config.get("vector_database", config.get("vector_db", {}))

        if not vector_config:
            self.logger.debug("No vector DB config found")
            return

        vector_str = json.dumps(vector_config).lower()

        # Security misconfigurations
        db_issues = {
            "no_auth": ("No authentication configured", Severity.HIGH),
            "plaintext": ("Plaintext storage/transmission", Severity.HIGH),
            "public_access": ("Public access enabled", Severity.CRITICAL),
            "injection": ("SQL/NoSQL injection risk", Severity.HIGH),
            "weak_index": ("Weak index security", Severity.MEDIUM),
        }

        for key, (description, severity) in db_issues.items():
            if key in vector_str:
                finding = self._create_finding(
                    severity=severity,
                    title=f"Vector DB Security Issue: {key.replace('_', ' ').title()}",
                    description=description,
                    cwe="CWE-284",
                    location=url,
                    evidence=[f"Found: {key}"],
                    recommendation=(
                        "Enable authentication for vector DB. "
                        "Use TLS for data in transit. "
                        "Encrypt data at rest. "
                        "Restrict network access. "
                        "Implement query parameterization."
                    ),
                )
                result.add_finding(finding)

    async def _check_retrieval_manipulation(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """
        Check for retrieval manipulation vulnerabilities.

        Tests if attackers can:
        - Manipulate retrieval scores
        - Inject fake context
        - Override retrieval ranking

        Args:
            url: Target endpoint
            session: aiohttp session
            result: Scan result container
        """
        self.logger.info(f"Checking retrieval manipulation: {url}")

        config = await self._fetch_rag_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        # Manipulation indicators
        manipulation_patterns = [
            "override_score",
            "force_retrieval",
            "inject_context",
            "bypass_ranking",
            "manual_insert",
        ]

        for pattern in manipulation_patterns:
            if pattern in config_str:
                finding = self._create_finding(
                    severity=Severity.HIGH,
                    title="Retrieval Manipulation Vulnerability",
                    description=(
                        f"RAG configuration contains '{pattern}' which may "
                        "allow attackers to manipulate retrieval results. "
                        "This can inject false context or prioritize malicious "
                        "documents."
                    ),
                    cwe="CWE-20",
                    owasp_ref="OWASP LLM01:2024 - Prompt Injection",
                    location=url,
                    evidence=[f"Pattern: {pattern}"],
                    recommendation=(
                        "Validate retrieval integrity. "
                        "Implement retrieval attestation. "
                        "Use cryptographic signing for documents. "
                        "Monitor retrieval patterns for anomalies."
                    ),
                )
                result.add_finding(finding)

    async def _check_context_window_attack(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """
        Check for context window attack vulnerabilities.

        Tests if the pipeline is vulnerable to:
        - Context overflow attacks
        - Prompt displacement
        - Memory exhaustion

        Args:
            url: Target endpoint
            session: aiohttp session
            result: Scan result container
        """
        self.logger.info(f"Checking context window attacks: {url}")

        config = await self._fetch_rag_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        # Check for context limits
        has_context_limit = any(
            keyword in config_str
            for keyword in ["max_context", "context_limit", "window_size", "truncate"]
        )

        if not has_context_limit:
            finding = self._create_finding(
                severity=Severity.MEDIUM,
                title="Missing Context Window Limits",
                description=(
                    "RAG pipeline lacks context window size limits. "
                    "Attackers can craft queries that overflow the context "
                    "window, displacing important instructions or causing "
                    "memory exhaustion."
                ),
                cwe="CWE-770",  # Allocation Without Limits
                location=url,
                evidence=["No context limit configuration"],
                recommendation=(
                    "Set maximum context window size. "
                    "Implement truncation strategies. "
                    "Prioritize recent/important context. "
                    "Monitor context utilization."
                ),
            )
            result.add_finding(finding)

    async def _check_embedding_security(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """
        Check embedding model security.

        Tests for:
        - Embedding model poisoning
        - Adversarial examples
        - Model inversion attacks

        Args:
            url: Target endpoint
            session: aiohttp session
            result: Scan result container
        """
        self.logger.info(f"Checking embedding security: {url}")

        config = await self._fetch_rag_config(url, session)

        if config is None:
            return

        embedding_config = config.get("embedding", config.get("embedder", {}))

        if not embedding_config:
            self.logger.debug("No embedding config found")
            return

        emb_str = json.dumps(embedding_config).lower()

        # Check for embedding vulnerabilities
        if "adversarial" in emb_str or "poison" in emb_str:
            finding = self._create_finding(
                severity=Severity.HIGH,
                title="Embedding Model Vulnerability",
                description=(
                    "Embedding configuration indicates potential vulnerability "
                    "to adversarial examples or model poisoning. Attackers can "
                    "craft inputs that produce misleading embeddings."
                ),
                cwe="CWE-94",
                owasp_ref="OWASP LLM03:2024 - Training Data Poisoning",
                location=url,
                evidence=["Embedding vulnerability indicators"],
                recommendation=(
                    "Use robust embedding models. "
                    "Implement input validation for embeddings. "
                    "Monitor embedding distributions. "
                    "Consider adversarial training."
                ),
            )
            result.add_finding(finding)

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """
        Execute RAG security scan on target.

        Args:
            target: RAG pipeline endpoint URL
            **kwargs: Additional parameters (timeout, headers, etc.)

        Returns:
            ScanResult: Findings, errors, and metadata.
        """
        self.logger.info(f"Starting RAG security scan: {target}")

        result = ScanResult(
            module_name=self.module_name,
            target=target,
            metadata={
                "config": self.config.to_dict() if hasattr(self.config, "to_dict") else {},
            },
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
                    self._check_document_poisoning(target, session, result),
                    self._check_exfiltration_risk(target, session, result),
                    self._check_vector_db_security(target, session, result),
                    self._check_retrieval_manipulation(target, session, result),
                    self._check_context_window_attack(target, session, result),
                    self._check_embedding_security(target, session, result),
                )

        # Handle running inside or outside event loop
        try:
            asyncio.get_running_loop()
            # Running inside event loop - create new loop
            new_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(new_loop)
            new_loop.run_until_complete(run_checks())
            new_loop.close()
        except RuntimeError:
            asyncio.run(run_checks())

        result.finalize()
        self.post_scan(result)

        return result
