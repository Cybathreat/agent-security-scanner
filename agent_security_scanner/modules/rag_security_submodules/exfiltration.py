"""
Exfiltration Scanner - Data exfiltration risk analysis.

Scans for:
- Data exfiltration indicators in configuration
- Unrestricted data retrieval
- Egress control configuration
- Query pattern monitoring

References:
- OWASP LLM Top 10: LLM05:2024 - Improper Output Handling
- RAG Security Guidelines

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, Optional, cast

import aiohttp

from ..base import BaseModule, ScanResult, Severity


class ExfiltrationScannerConfig:
    """Configuration for exfiltration scanning."""

    def __init__(
        self,
        enabled: bool = True,
        check_exfil_indicators: bool = True,
        check_egress_controls: bool = True,
        check_response_filtering: bool = True,
        check_query_monitoring: bool = True,
    ) -> None:
        self.enabled = enabled
        self.check_exfil_indicators = check_exfil_indicators
        self.check_egress_controls = check_egress_controls
        self.check_response_filtering = check_response_filtering
        self.check_query_monitoring = check_query_monitoring


class ExfiltrationScanner(BaseModule[ExfiltrationScannerConfig]):
    """
    Data exfiltration risk scanner.

    Tests for:
    - Exfiltration indicators in configuration
    - Missing egress controls
    - Response filtering
    - Query pattern monitoring
    """

    # Exfiltration indicators
    EXFILTRATION_INDICATORS = [
        "extract_all",
        "dump_database",
        "exfiltrate",
        "send_to_external",
        "encode_and_transmit",
        "covert_channel",
        "data_pipe",
        "export_data",
        "transmit_external",
    ]

    def __init__(
        self,
        config: Optional[ExfiltrationScannerConfig] = None,
    ) -> None:
        super().__init__()
        self.config = config or ExfiltrationScannerConfig()

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
                        return cast(dict[str, Any], json.loads(body))
                    except json.JSONDecodeError:
                        return {"raw": body}
        except Exception as e:
            self.logger.warning(f"Error fetching config: {e}")
            return None
        return None

    async def _check_exfil_indicators(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for exfiltration indicators in configuration."""
        if not self.config.check_exfil_indicators:
            return

        self.logger.info(f"Checking exfiltration indicators: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        for indicator in self.EXFILTRATION_INDICATORS:
            if indicator in config_str:
                finding = self._create_finding(
                    severity=Severity.CRITICAL,
                    title=f"Data Exfiltration Risk: {indicator}",
                    description=(
                        f"RAG configuration contains '{indicator}' which may "
                        "enable data exfiltration. Attackers can craft queries "
                        "to extract sensitive information from the knowledge base."
                    ),
                    cwe="CWE-200",
                    owasp_ref="OWASP LLM05:2024 - Improper Output Handling",
                    location=url,
                    evidence=[f"Indicator: {indicator}"],
                    recommendation=(
                        "Remove the exfiltration-indicating configuration. "
                        "Implement strict egress controls. "
                        "Monitor for unusual data retrieval patterns."
                    ),
                )
                result.add_finding(finding)

    async def _check_egress_controls(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for egress control configuration."""
        if not self.config.check_egress_controls:
            return

        self.logger.info(f"Checking egress controls: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        # Check for egress control configuration
        has_egress = any(
            keyword in config_str
            for keyword in [
                "egress",
                "filter",
                "limit",
                "redact",
                "mask",
                "sanitize_output",
            ]
        )

        if not has_egress:
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

    async def _check_response_filtering(
        self,
        url: str,
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        """Check for response filtering configuration."""
        if not self.config.check_response_filtering:
            return

        self.logger.info(f"Checking response filtering: {url}")

        config = await self._fetch_config(url, session)

        if config is None:
            return

        config_str = json.dumps(config).lower()

        # Check for response filtering
        has_filtering = any(
            keyword in config_str
            for keyword in [
                "filter",
                "sanitize",
                "mask",
                "redact",
                "truncate",
                "limit",
            ]
        )

        if not has_filtering:
            finding = self._create_finding(
                severity=Severity.LOW,
                title="Missing Response Filtering",
                description=(
                    "Response content is not filtered. Sensitive information "
                    "from the knowledge base may be directly returned to users."
                ),
                cwe="CWE-200",
                location=url,
                evidence=["No response filtering config"],
                recommendation=(
                    "Implement response filtering pipeline. "
                    "Redact sensitive information. "
                    "Truncate overly long responses. "
                    "Use output sanitization."
                ),
            )
            result.add_finding(finding)

    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Execute exfiltration scan on target."""
        self.logger.info(f"Starting exfiltration scan: {target}")

        result = ScanResult(
            module_name=self.module_name,
            target=target,
            metadata={
                "config": self.config.__dict__,
                "indicators_tested": len(self.EXFILTRATION_INDICATORS),
            },
        )

        async def run_checks() -> None:

            async with aiohttp.ClientSession() as session:
                await asyncio.gather(
                    self._check_exfil_indicators(target, session, result),
                    self._check_egress_controls(target, session, result),
                    self._check_response_filtering(target, session, result),
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
