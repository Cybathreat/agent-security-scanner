"""
Scan lifecycle manager for the web dashboard.

Manages scan execution in background threads, publishes progress events
via asyncio.Queue for WebSocket broadcasting, and persists results to SQLite.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from loguru import logger

from ..core.config import load_config
from ..core.engine import ScanEngine
from ..core.quality_gate import GateThreshold, evaluate as evaluate_gate
from ..modules.base import Severity
from ..output.json_report import JSONReport
from . import db
from .models import ModuleStatus, ModuleStatusInfo, ScanStatus


class ScanManager:
    """Manages scan lifecycle for the web dashboard."""

    def __init__(self, max_workers: int = 2) -> None:
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._active_scans: Dict[str, Dict[str, Any]] = {}
        self._event_queues: Dict[str, List[asyncio.Queue]] = {}
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Set the event loop for cross-thread communication."""
        self._loop = loop

    async def start_scan(
        self,
        target: str,
        modules: Optional[List[str]] = None,
        timeout: int = 30,
        fail_on_severity: str = "critical",
        max_findings: Optional[int] = None,
        max_risk_score: Optional[int] = None,
    ) -> str:
        """Start a new scan in a background thread. Returns scan_id."""
        scan_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat() + "Z"

        # Store initial state
        self._active_scans[scan_id] = {
            "scan_id": scan_id,
            "target": target,
            "modules": modules or [],
            "status": ScanStatus.RUNNING,
            "started_at": started_at,
            "module_statuses": {},
            "findings_count": 0,
        }

        # Save to DB
        await db.save_scan(
            scan_id=scan_id,
            target=target,
            modules=modules or [],
            status=ScanStatus.RUNNING,
            started_at=started_at,
        )

        # Build quality gate threshold
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        gate_threshold = GateThreshold(
            fail_on_severity=severity_map.get(fail_on_severity.lower(), Severity.CRITICAL),
            max_findings=max_findings,
            max_risk_score=max_risk_score,
        )

        # Run scan in thread pool
        if self._loop is None:
            self._loop = asyncio.get_running_loop()

        self._executor.submit(
            self._run_scan,
            scan_id,
            target,
            modules,
            timeout,
            gate_threshold,
        )

        return scan_id

    def _run_scan(
        self,
        scan_id: str,
        target: str,
        modules: Optional[List[str]],
        timeout: int,
        gate_threshold: GateThreshold,
    ) -> None:
        """Run scan in background thread. Publishes events via event loop."""
        try:
            config = load_config()
            engine = ScanEngine(config)
            module_list = modules if modules else None

            # Publish module started events
            if self._loop and not self._loop.is_closed():
                asyncio.run_coroutine_threadsafe(
                    self._publish_event(scan_id, "scan_started", {"target": target}),
                    self._loop,
                )

            # Check if scan was cancelled before running
            if scan_id in self._active_scans and self._active_scans[scan_id].get("status") == "cancelled":
                logger.info(f"Scan {scan_id} cancelled, aborting")
                return

            # Run scan (synchronous)
            results = engine.run(target, modules=module_list, timeout=timeout)

            # Build JSON report
            json_reporter = JSONReport(pretty_print=False)
            report = json_reporter.generate(results, gate_threshold=gate_threshold)
            report_json = json.dumps(report, default=str)

            # Evaluate quality gate
            gate_result = evaluate_gate(results, gate_threshold)

            # Build summary
            summary = report.get("summary", {})

            # Publish findings as they complete
            for result in results:
                # Check if scan was cancelled between module iterations
                if scan_id in self._active_scans and self._active_scans[scan_id].get("status") == "cancelled":
                    logger.info(f"Scan {scan_id} cancelled, aborting")
                    break

                if self._loop and not self._loop.is_closed():
                    asyncio.run_coroutine_threadsafe(
                        self._publish_event(
                            scan_id,
                            "module_completed",
                            {
                                "module_name": result.module_name,
                                "status": result.status,
                                "findings_count": len(result.findings),
                                "duration_ms": result.duration_ms,
                            },
                        ),
                        self._loop,
                    )

                    for finding in result.findings:
                        asyncio.run_coroutine_threadsafe(
                            self._publish_event(
                                scan_id,
                                "finding_discovered",
                                finding.to_dict(),
                            ),
                            self._loop,
                        )

            # Update DB with results
            completed_at = datetime.now(timezone.utc).isoformat() + "Z"
            total_duration = sum(r.duration_ms for r in results)

            # Schedule DB updates on the event loop
            if self._loop and not self._loop.is_closed():
                asyncio.run_coroutine_threadsafe(
                    self._save_completed_scan(
                        scan_id,
                        results,
                        report_json,
                        summary,
                        completed_at,
                        total_duration,
                        gate_result.passed,
                        gate_result.reason,
                        gate_result.exit_code,
                    ),
                    self._loop,
                )

                # Publish completion event
                asyncio.run_coroutine_threadsafe(
                    self._publish_event(
                        scan_id,
                        "scan_completed",
                        {
                            "status": "completed",
                            "findings_count": summary.get("total", 0),
                            "risk_score": summary.get("risk_score", 0),
                            "gate_passed": gate_result.passed,
                            "gate_reason": gate_result.reason,
                        },
                    ),
                    self._loop,
                )

        except Exception as e:
            logger.exception(f"Scan {scan_id} failed: {e}")
            if self._loop and not self._loop.is_closed():
                asyncio.run_coroutine_threadsafe(
                    self._publish_event(scan_id, "scan_error", {"error": str(e)}),
                    self._loop,
                )
                asyncio.run_coroutine_threadsafe(
                    db.update_scan_status(scan_id, status="failed"),
                    self._loop,
                )

    async def _save_completed_scan(
        self,
        scan_id: str,
        results: list,
        report_json: str,
        summary: dict,
        completed_at: str,
        duration_ms: int,
        gate_passed: bool,
        gate_reason: str,
        gate_exit_code: int,
    ) -> None:
        """Save completed scan results to DB."""
        await db.update_scan_status(
            scan_id,
            status=ScanStatus.COMPLETED,
            completed_at=completed_at,
            duration_ms=duration_ms,
            result_json=report_json,
            summary_json=json.dumps(summary),
            gate_passed=gate_passed,
            gate_reason=gate_reason,
            gate_exit_code=gate_exit_code,
        )

        # Save individual findings
        all_findings = [f.to_dict() for r in results for f in r.findings]
        if all_findings:
            await db.save_findings(scan_id, all_findings)

        # Remove from active scans
        self._active_scans.pop(scan_id, None)

    async def _publish_event(self, scan_id: str, event: str, data: Any) -> None:
        """Publish an event to all subscribed WebSocket clients."""
        queues = self._event_queues.get(scan_id, [])
        for q in queues:
            try:
                await q.put({"event": event, "scan_id": scan_id, "data": data})
            except asyncio.QueueFull:
                logger.warning(f"Dropped event for scan {scan_id}: queue full")

    def subscribe(self, scan_id: str) -> asyncio.Queue:
        """Subscribe to scan progress events. Returns a queue."""
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        if scan_id not in self._event_queues:
            self._event_queues[scan_id] = []
        self._event_queues[scan_id].append(q)
        return q

    def unsubscribe(self, scan_id: str, queue: asyncio.Queue) -> None:
        """Unsubscribe from scan progress events."""
        if scan_id in self._event_queues:
            try:
                self._event_queues[scan_id].remove(queue)
            except ValueError:
                pass
            if not self._event_queues[scan_id]:
                del self._event_queues[scan_id]

    async def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get current scan status."""
        # Check active scans first
        if scan_id in self._active_scans:
            return self._active_scans[scan_id]

        # Then check DB
        return await db.get_scan(scan_id)

    async def list_scans(self, limit: int = 20, offset: int = 0) -> List[Dict[str, Any]]:
        """List all scans."""
        return await db.list_scans(limit=limit, offset=offset)

    async def get_scan_result(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get full scan result with findings."""
        scan = await db.get_scan(scan_id)
        if scan is None:
            return None

        result_json = scan.get("result_json")
        if result_json:
            return json.loads(result_json)
        return None

    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan."""
        if scan_id in self._active_scans:
            # Mark as cancelled — the thread will check and stop
            self._active_scans[scan_id]["status"] = ScanStatus.CANCELLED
            await db.update_scan_status(scan_id, status=ScanStatus.CANCELLED)
            # Publish cancellation event
            if self._loop and not self._loop.is_closed():
                await self._publish_event(scan_id, "scan_error", {"error": "cancelled"})
            return True
        return False


# Singleton instance
scan_manager = ScanManager()