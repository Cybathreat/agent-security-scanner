"""
Multi-Tenant Scanner - Cross-tenant data leakage.

Scans for:
- Cross-tenant data leakage in multi-tenant RAG
- Tenant isolation verification
- Query filtering between tenants

References:
- Multi-Tenant Security Best Practices
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


class MultiTenantScannerConfig:
    """Configuration for multi-tenant scanning."""

    def __init__(
        self,
        enabled: bool = True,
        check_tenant_isolation: bool = True,
        check_query_filtering: bool = True,
        check_tenant_awareness: bool = True,
    ) -> None:
        self.enabled = enabled
        self.check_tenant_isolation = check_tenant_isolation
        self.check_query_filtering = check_query_filtering
        self.check_tenant_awareness = check_tenant_awareness


class MultiTenantScanner(BaseModule):
    """
    Multi-tenant RAG security scanner.

    Tests for:
    - Cross-tenant data leakage
    - Tenant isolation
    - Query filtering
    """

    def __init__(
        self,
        config: Optional[MultiTenantScannerConfig] = None,
    ) -> None:
        super().__init__()
        self.config = config or MultiTenantScannerConfig()

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

    async def _check_tenant_isolation(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for tenant isolation configuration."""
        if not self.config.check_tenant_isolation:
            return

        self.logger.info(f"Checking tenant isolation: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        # Check for multi-tenant awareness
        if "tenant" not in config_str and "multi" not in config_str:
            finding = self._create_finding(
                severity=Severity.HIGH,
                title="No Tenant Isolation Configuration",
                description=(
                    "RAG configuration lacks multi-tenant awareness. "
                    "In shared RAG systems, this could allow tenants "
                    "to access each other's data."
                ),
                cwe="CWE-284",
                location=url,
                evidence=["No tenant isolation config"],
                recommendation=(
                    "Implement tenant isolation in RAG pipeline. "
                    "Use tenant-specific indexes. "
                    "Add tenant filtering to all queries. "
                    "Implement access control per tenant."
                ),
            )
            result.add_finding(finding)

    async def _check_query_filtering(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for query filtering by tenant."""
        if not self.config.check_query_filtering:
            return

        self.logger.info(f"Checking query filtering: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        # Check for tenant filtering in queries
        has_tenant_filter = any(
            keyword in config_str
            for keyword in [
                "tenant_filter",
                "access_control",
                "filter_by_tenant",
                "tenant_id",
            ]
        )

        if not has_tenant_filter:
            finding = self._create_finding(
                severity=Severity.HIGH,
                title="No Query Tenant Filtering",
                description=(
                    "RAG queries are not filtered by tenant. "
                    "In multi-tenant deployments, this could allow "
                    "tenants to access data from other tenants."
                ),
                cwe="CWE-284",
                location=url,
                evidence=["No tenant filtering config"],
                recommendation=(
                    "Implement tenant-aware query filtering. "
                    "Add tenant ID to all queries. "
                    "Enforce tenant boundaries at retrieval time. "
                    "Audit query logs for cross-tenant access."
                ),
            )
            result.add_finding(finding)

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Execute multi-tenant scan on target."""
        self.logger.info(f"Starting multi-tenant scan: {target}")

        result = ScanResult(
            module_name=self.module_name,
            target=target,
            metadata={"config": self.config.__dict__},
        )

        async def run_checks() -> None:
            timeout = kwargs.get("timeout", 10)

            async with aiohttp.ClientSession() as session:
                await asyncio.gather(
                    self._check_tenant_isolation(target, session, result),
                    self._check_query_filtering(target, session, result),
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
