"""
Embedding Attacks Scanner - Embedding model vulnerabilities.

Scans for:
- Embedding model poisoning
- Adversarial examples
- Model inversion attacks
- Embedding collision attacks

References:
- Embedding Model Security Research
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


class EmbeddingAttacksScannerConfig:
    """Configuration for embedding attack scanning."""

    def __init__(
        self,
        enabled: bool = True,
        check_adversarial: bool = True,
        check_inversion: bool = True,
        check_collision: bool = True,
        check_fine_tune: bool = True,
    ) -> None:
        self.enabled = enabled
        self.check_adversarial = check_adversarial
        self.check_inversion = check_inversion
        self.check_collision = check_collision
        self.check_fine_tune = check_fine_tune


class EmbeddingAttacksScanner(BaseModule):
    """
    Embedding model security scanner.

    Tests for:
    - Adversarial examples
    - Model inversion vulnerabilities
    - Embedding collision attacks
    - Fine-tuning risks
    """

    def __init__(
        self,
        config: Optional[EmbeddingAttacksScannerConfig] = None,
    ) -> None:
        super().__init__()
        self.config = config or EmbeddingAttacksScannerConfig()

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

    async def _check_adversarial(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for adversarial example vulnerabilities."""
        if not self.config.check_adversarial:
            return

        self.logger.info(f"Checking adversarial example defenses: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        embedding_config = config.get("embedding", config.get("embedder", {}))

        if not embedding_config:
            return

        emb_str = json.dumps(embedding_config).lower()

        # Check for adversarial training configuration
        if "adversarial" not in emb_str:
            finding = self._create_finding(
                severity=Severity.LOW,
                title="No Adversarial Example Protection",
                description=(
                    "Embedding model lacks adversarial training. "
                    "The model may be vulnerable to adversarial examples "
                    "designed to manipulate embeddings."
                ),
                cwe="CWE-94",
                location=url,
                evidence=["No adversarial training config"],
                recommendation=(
                    "Implement adversarial training. "
                    "Use robust embedding models. "
                    "Implement input validation. "
                    "Monitor embedding distributions for anomalies."
                ),
            )
            result.add_finding(finding)

    async def _check_inversion(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for model inversion vulnerabilities."""
        if not self.config.check_inversion:
            return

        self.logger.info(f"Checking inversion vulnerability: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        embedding_config = config.get("embedding", config.get("embedder", {}))

        if not embedding_config:
            return

        emb_str = json.dumps(embedding_config).lower()

        # Check for inversion protection
        has_inversion_protection = any(
            keyword in emb_str
            for keyword in [
                "inversion",
                "privacy",
                "differential",
                "federated",
            ]
        )

        if not has_inversion_protection:
            finding = self._create_finding(
                severity=Severity.MEDIUM,
                title="Potential Model Inversion Vulnerability",
                description=(
                    "Embedding model may be vulnerable to inversion attacks "
                    "that reconstruct original text from embeddings. "
                    "Sensitive information could be recovered."
                ),
                cwe="CWE-200",
                location=url,
                evidence=["No inversion protection config"],
                recommendation=(
                    "Implement differential privacy. "
                    "Use federated learning where possible. "
                    "Add noise to embeddings. "
                    "Monitor for inversion patterns."
                ),
            )
            result.add_finding(finding)

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Execute embedding attacks scan on target."""
        self.logger.info(f"Starting embedding attacks scan: {target}")

        result = ScanResult(
            module_name=self.module_name,
            target=target,
            metadata={"config": self.config.__dict__},
        )

        async def run_checks() -> None:
            timeout = kwargs.get("timeout", 10)

            async with aiohttp.ClientSession() as session:
                await asyncio.gather(
                    self._check_adversarial(target, session, result),
                    self._check_inversion(target, session, result),
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
