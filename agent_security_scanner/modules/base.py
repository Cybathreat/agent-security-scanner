"""
Base module class for Agent Security Scanner.

All security scanning modules inherit from this base class.
Provides common interface, result structures, and utility methods.

Type hints everywhere for IDE support and static analysis.
"""

from __future__ import annotations

import asyncio
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, Generic, List, Optional, Tuple, TypeVar, cast

import aiohttp
from loguru import logger

# Generic config type for BaseModule subclasses
ConfigT = TypeVar("ConfigT")


class Severity(Enum):
    """
    Severity levels for security findings.

    Follows CVSS (Common Vulnerability Scoring System) conventions:
    - CRITICAL: 9.0-10.0 - Immediate exploitation risk
    - HIGH: 7.0-8.9 - Significant security impact
    - MEDIUM: 4.0-6.9 - Moderate security impact
    - LOW: 0.1-3.9 - Minimal security impact
    - INFO: 0.0 - Informational, no direct risk
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# Severity weights for risk score calculation (used by quality gate and reports)
SEVERITY_WEIGHT: Dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

# Severity ordering for quality gate threshold comparison (highest first)
SEVERITY_LEVELS: Tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


class Sensitivity(Enum):
    """
    Scan sensitivity levels for controlling scan intensity.

    Used by modules like PromptInjectionScanner to adjust:
    - Number of test payloads
    - Depth of analysis
    - Time allowed for each test
    """

    LOW = "low"  # Minimal payloads, fast scan
    MEDIUM = "medium"  # Standard payloads, balanced scan
    HIGH = "high"  # Maximum payloads, thorough scan


@dataclass
class Finding:
    """
    Represents a single security finding from a scan.

    Attributes:
        id: Unique finding identifier (e.g., "FIND-001")
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        category: Security category (e.g., "prompt_injection", "misconfiguration")
        title: Short, descriptive title
        description: Detailed description of the finding
        cwe: CWE identifier if applicable (e.g., "CWE-94")
        owasp_ref: OWASP LLM Top 10 reference if applicable
        mitre_ref: MITRE ATLAS reference if applicable
        location: Where the issue was found (endpoint, file, component)
        evidence: Supporting evidence (payloads, responses, logs)
        recommendation: Remediation guidance
        confidence: Confidence level (high, medium, low)
        timestamp: When the finding was discovered
    """

    id: str
    severity: Severity
    category: str
    title: str
    description: str
    cwe: Optional[str] = None
    owasp_ref: Optional[str] = None
    mitre_ref: Optional[str] = None
    location: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    recommendation: str = "Review and remediate according to security best practices."
    confidence: str = "high"  # high, medium, low
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert finding to dictionary for JSON serialization.

        Returns:
            Dict: Finding as dictionary with all fields.
        """
        return {
            "id": self.id,
            "severity": self.severity.value,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "cwe": self.cwe,
            "owasp_ref": self.owasp_ref,
            "mitre_ref": self.mitre_ref,
            "location": self.location,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ScanResult:
    """
    Container for scan results from a module.

    Attributes:
        module_name: Name of the module that produced results
        target: Target that was scanned
        findings: List of security findings
        errors: List of errors encountered during scan
        start_time: When the scan started
        end_time: When the scan ended
        duration_ms: Scan duration in milliseconds
        status: Scan status (success, partial, failed)
        metadata: Additional metadata (version, config, etc.)
    """

    module_name: str
    target: str
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    duration_ms: int = 0
    status: str = "success"  # success, partial, failed
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the results."""
        self.findings.append(finding)
        logger.debug(f"Added finding: {finding.id} ({finding.severity.value})")

    def add_error(self, error: str) -> None:
        """Add an error to the results."""
        self.errors.append(error)
        logger.warning(f"Scan error: {error}")

    def finalize(self) -> None:
        """
        Finalize the scan result with timing and status.

        Should be called when scan completes.
        """
        self.end_time = datetime.utcnow()
        duration = self.end_time - self.start_time
        self.duration_ms = int(duration.total_seconds() * 1000)

        if self.errors and not self.findings:
            self.status = "failed"
        elif self.errors:
            self.status = "partial"
        else:
            self.status = "success"

        logger.info(
            f"Scan finalized: {self.module_name} - {self.status} "
            f"({len(self.findings)} findings, {len(self.errors)} errors)"
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert scan result to dictionary for JSON serialization.

        Returns:
            Dict: Scan result as dictionary.
        """
        return {
            "module_name": self.module_name,
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_ms": self.duration_ms,
            "status": self.status,
            "metadata": self.metadata,
        }

    def get_summary(self) -> Dict[str, int]:
        """
        Get summary counts by severity.

        Returns:
            Dict: Counts per severity level.
        """
        summary = {
            "total": len(self.findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for finding in self.findings:
            if finding.severity == Severity.CRITICAL:
                summary["critical"] += 1
            elif finding.severity == Severity.HIGH:
                summary["high"] += 1
            elif finding.severity == Severity.MEDIUM:
                summary["medium"] += 1
            elif finding.severity == Severity.LOW:
                summary["low"] += 1
            else:
                summary["info"] += 1

        return summary


class BaseModule(ABC, Generic[ConfigT]):
    """
    Abstract base class for all security scanning modules.

    All modules must inherit from this class and implement:
    - scan(): Execute the security scan
    - Optional: customize behavior via constructor parameters

    Usage:
        module = PromptInjectionModule(config)
        result = module.scan(target="https://api.example.com")
        result.finalize()
        findings = result.findings
    """

    def __init__(self, config: Optional[ConfigT] = None) -> None:
        """
        Initialize the security module.

        Args:
            config: Module-specific configuration dataclass.

        Note: Child classes should set self.config BEFORE calling super().__init__().
              The base class will NOT set self.config - each child must set it.
        """
        # Derive module name from class name
        # Handles both "*Module" (MisconfigurationsModule) and
        # "*Scanner" (ToolHijackingScanner, SecretScanner, etc.)
        class_name = self.__class__.__name__
        name = class_name.replace("Module", "").replace("Scanner", "")
        # Convert PascalCase to snake_case: RAGSecurity -> rag_security
        # Handles consecutive capitals: RAGSecurity -> rag_security (not r_a_g_security)
        import re

        s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
        self.module_name = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", s1).lower()
        self.logger = logger.bind(module=self.module_name)
        self.logger.debug(f"Module initialized: {self.module_name}")

    @abstractmethod
    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """
        Execute the security scan on the target.

        Must be implemented by all child modules.

        Args:
            target: Target to scan (URL, file path, agent identifier)
            **kwargs: Additional module-specific parameters

        Returns:
            ScanResult: Container with findings, errors, and metadata.

        Raises:
            NotImplementedError: If not overridden by child class.
        """
        raise NotImplementedError("scan() must be implemented by child class")

    def _generate_finding_id(self) -> str:
        """
        Generate a unique finding identifier.

        Format: FIND-<module>-<uuid_short>
        Example: FIND-pi-a1b2c3d4

        Returns:
            str: Unique finding ID.
        """
        short_uuid = str(uuid.uuid4())[:8]
        return f"FIND-{self.module_name}-{short_uuid}"

    def _create_finding(
        self,
        severity: Severity,
        title: str,
        description: str,
        category: Optional[str] = None,
        **kwargs: Any,
    ) -> Finding:
        """
        Convenience method to create a Finding with module context.

        Args:
            severity: Severity level
            title: Finding title
            description: Finding description
            category: Override category (default: module_name)
            **kwargs: Additional Finding attributes

        Returns:
            Finding: Created finding with module context.
        """
        return Finding(
            id=self._generate_finding_id(),
            severity=severity,
            category=category or self.module_name,
            title=title,
            description=description,
            **kwargs,
        )

    def pre_scan(self, target: str) -> bool:
        """
        Pre-scan validation hook.

        Override in child classes to validate target before scanning.

        Args:
            target: Target to validate

        Returns:
            bool: True if scan should proceed, False to abort
        """
        self.logger.debug(f"Pre-scan validation for: {target}")
        return True

    def post_scan(self, result: ScanResult) -> None:
        """
        Post-scan hook for cleanup or logging.

        Override in child classes for post-processing.

        Args:
            result: Scan result to process
        """
        self.logger.debug(f"Post-scan hook: {result.status}")

    def get_supported_targets(self) -> List[str]:
        """
        Get list of supported target types.

        Override in child classes to specify what can be scanned.

        Returns:
            List[str]: Supported target types (url, file, api, etc.)
        """
        return ["url", "api_endpoint", "agent_config"]

    async def _fetch_url(
        self,
        url: str,
        session: aiohttp.ClientSession,
        method: str = "GET",
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 10,
    ) -> Optional[Dict[str, Any]]:
        """
        Shared HTTP client helper for all scanners.

        Provides consistent request handling with proper error handling,
        timeout management, and response parsing.

        Args:
            url: Target URL to fetch
            session: aiohttp ClientSession (managed by caller)
            method: HTTP method (GET, POST, etc.)
            data: Request body data (for POST requests)
            headers: Additional HTTP headers
            timeout: Request timeout in seconds

        Returns:
            Dict with keys: url, status, headers, body, json (if applicable)
            None if request fails
        """
        import aiohttp

        try:
            async with session.request(
                method=method,
                url=url,
                json=data,
                headers=headers,
                timeout=timeout,
            ) as response:
                body = await response.text()
                result = {
                    "url": url,
                    "status": response.status,
                    "headers": dict(response.headers),
                    "body": body,
                    "ok": response.ok,
                }
                # Try to parse JSON if response appears to be JSON
                content_type = response.headers.get("content-type", "").lower()
                if "application/json" in content_type or "text/json" in content_type:
                    try:
                        result["json"] = await response.json()
                    except (aiohttp.ClientPayloadError, ValueError):
                        result["json"] = None
                else:
                    result["json"] = None
                return result
        except asyncio.TimeoutError:
            self.logger.warning(f"Timeout fetching {url}")
            return None
        except aiohttp.ClientError as e:
            self.logger.warning(f"Error fetching {url}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error fetching {url}: {e}")
            return None

    def _run_scan_async(self, scan_func: Callable[..., Any], **kwargs: Any) -> ScanResult:
        """
        Shared async scan runner for consistent event loop handling.

        Handles both async and sync contexts automatically, creating
        a new event loop if needed.

        Args:
            scan_func: Async function to run (takes session, kwargs)
            **kwargs: Additional arguments passed to scan_func

        Returns:
            ScanResult: The scan results
        """
        import asyncio
        import aiohttp

        async def run() -> ScanResult:
            async with aiohttp.ClientSession() as session:
                return cast(ScanResult, await scan_func(session, **kwargs))

        try:
            asyncio.get_running_loop()
            # Running in async context - create new loop
            new_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(new_loop)
            try:
                return new_loop.run_until_complete(run())
            finally:
                new_loop.close()
                asyncio.set_event_loop(None)
        except RuntimeError:
            # No event loop running - safe to use asyncio.run
            return asyncio.run(run())
