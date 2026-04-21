"""
WebSocket endpoint for real-time scan progress.

WS /ws/scans/{scan_id}/progress — Subscribe to scan progress events
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .. import db
from ..scan_manager import scan_manager

router = APIRouter(tags=["websocket"])

HEARTBEAT_INTERVAL = 30  # seconds


@router.websocket("/scans/{scan_id}/progress")
async def scan_progress(websocket: WebSocket, scan_id: str) -> None:
    """
    WebSocket endpoint for real-time scan progress updates.

    Sends events: module_started, module_completed, finding_discovered,
    scan_completed, scan_error. Sends heartbeat pings every 30s.
    """
    await websocket.accept()

    queue = scan_manager.subscribe(scan_id)

    try:
        # Catch-up: replay stored findings and module completions from DB
        scan_data = await db.get_scan(scan_id)
        if scan_data and scan_data.get("result_json"):
            import json as _json
            report = _json.loads(scan_data["result_json"]) if isinstance(scan_data["result_json"], str) else scan_data["result_json"]
            # Replay module completions
            for module_name, module_data in report.get("modules", {}).items():
                await websocket.send_json({
                    "event": "module_completed",
                    "scan_id": scan_id,
                    "data": {
                        "module_name": module_name,
                        "status": module_data.get("status", "completed"),
                        "findings_count": len(module_data.get("findings", [])),
                    },
                    "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
                })
            # Replay individual findings
            for finding in report.get("findings", []):
                await websocket.send_json({
                    "event": "finding_discovered",
                    "scan_id": scan_id,
                    "data": finding,
                    "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
                })

        # Send initial connection confirmation
        await websocket.send_json(
            {
                "event": "connected",
                "scan_id": scan_id,
                "data": {"message": "Subscribed to scan progress"},
                "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            }
        )

        # Main loop: send events and heartbeats
        while True:
            try:
                # Wait for events with timeout for heartbeat
                event = await asyncio.wait_for(queue.get(), timeout=HEARTBEAT_INTERVAL)
                await websocket.send_json(
                    {
                        "event": event.get("event"),
                        "scan_id": event.get("scan_id", scan_id),
                        "data": event.get("data", {}),
                        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
                    }
                )

                # If scan completed, close connection after sending
                if event.get("event") in ("scan_completed", "scan_error"):
                    break

            except asyncio.TimeoutError:
                # Send heartbeat
                try:
                    await websocket.send_json(
                        {
                            "event": "heartbeat",
                            "scan_id": scan_id,
                            "data": {},
                            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
                        }
                    )
                except Exception:
                    break

    except WebSocketDisconnect:
        pass
    except Exception as e:
        # Send error before closing
        try:
            await websocket.send_json(
                {
                    "event": "error",
                    "scan_id": scan_id,
                    "data": {"error": str(e)},
                    "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
                }
            )
        except Exception:
            pass
    finally:
        scan_manager.unsubscribe(scan_id, queue)
        try:
            await websocket.close()
        except Exception:
            pass