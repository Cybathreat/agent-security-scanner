"""
RAG Pipeline Security Module.

Delegates to submodules for document poisoning, exfiltration, vector DB,
embedding attacks, multi-tenant, phantom document, and chunk boundary
scanning.

References:
- OWASP LLM Top 10: LLM01:2024 - Prompt Injection
- OWASP LLM Top 10: LLM03:2024 - Training Data Poisoning
- MITRE ATLAS: TA0045 - LLM Attack
- ANSSI Generative AI: RAG Security Guidelines

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

from typing import Any, Optional

from ..core.config import RAGSecurityConfig
from .base import BaseModule, ScanResult
from .rag_security_submodules.document_poisoning import (
    DocumentPoisoningScanner,
    DocumentPoisoningScannerConfig,
)
from .rag_security_submodules.exfiltration import (
    ExfiltrationScanner,
    ExfiltrationScannerConfig,
)
from .rag_security_submodules.vector_db import (
    VectorDBScanner,
    VectorDBScannerConfig,
)
from .rag_security_submodules.embedding_attacks import (
    EmbeddingAttacksScanner,
    EmbeddingAttacksScannerConfig,
)
from .rag_security_submodules.multi_tenant import (
    MultiTenantScanner,
    MultiTenantScannerConfig,
)
from .rag_security_submodules.phantom_document import (
    PhantomDocumentScanner,
    PhantomDocumentScannerConfig,
)
from .rag_security_submodules.chunk_boundary import (
    ChunkBoundaryScanner,
    ChunkBoundaryScannerConfig,
)


class RAGSecurityModule(BaseModule[RAGSecurityConfig]):
    """
    RAG pipeline security scanning module.

    Delegates all checks to submodules:
    - DocumentPoisoningScanner (when check_poisoning is enabled)
    - ExfiltrationScanner (when check_exfiltration is enabled)
    - VectorDBScanner (when vector_db_scan is enabled)
    - EmbeddingAttacksScanner
    - MultiTenantScanner
    - PhantomDocumentScanner
    - ChunkBoundaryScanner
    """

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

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """
        Execute RAG security scan on target.

        Delegates to submodules for all checks.

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

        # Build the list of enabled submodules
        submodules: list[BaseModule] = []

        if self.config.check_poisoning:
            submodules.append(
                DocumentPoisoningScanner(DocumentPoisoningScannerConfig())
            )

        if self.config.check_exfiltration:
            submodules.append(
                ExfiltrationScanner(ExfiltrationScannerConfig())
            )

        if self.config.vector_db_scan:
            submodules.append(
                VectorDBScanner(VectorDBScannerConfig())
            )

        submodules.append(EmbeddingAttacksScanner(EmbeddingAttacksScannerConfig()))
        submodules.append(MultiTenantScanner(MultiTenantScannerConfig()))
        submodules.append(PhantomDocumentScanner(PhantomDocumentScannerConfig()))
        submodules.append(ChunkBoundaryScanner(ChunkBoundaryScannerConfig()))

        # Delegate to submodules
        for submod in submodules:
            sub_result = submod.scan(target, **kwargs)
            for finding in sub_result.findings:
                result.add_finding(finding)
            for error in sub_result.errors:
                result.add_error(error)

        result.finalize()
        self.post_scan(result)

        return result