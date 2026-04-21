"""
SQLite database for scan history storage.

Stores completed scan results for history, comparison, and quality gate evaluation.
Uses aiosqlite for async access.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiosqlite
from loguru import logger

_ASS_DATA_DIR = os.environ.get("ASS_DATA_DIR")
DB_DIR = Path(_ASS_DATA_DIR) if _ASS_DATA_DIR else Path(__file__).resolve().parent.parent.parent.parent / "data"
DB_PATH = DB_DIR / "scan_history.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    modules TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    started_at TEXT NOT NULL,
    completed_at TEXT,
    duration_ms INTEGER DEFAULT 0,
    result_json TEXT,
    summary_json TEXT,
    gate_passed INTEGER,
    gate_reason TEXT,
    gate_exit_code INTEGER
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    cwe TEXT,
    owasp_ref TEXT,
    mitre_ref TEXT,
    location TEXT,
    evidence TEXT,
    recommendation TEXT,
    confidence TEXT DEFAULT 'high',
    timestamp TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
"""


async def init_db(db_path: Optional[str] = None) -> None:
    """Initialize the database and create tables."""
    path = Path(db_path) if db_path else DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    async with aiosqlite.connect(path) as db:
        await db.executescript(SCHEMA)
        await db.commit()

    logger.info(f"Database initialized: {path}")


async def get_connection(db_path: Optional[str] = None) -> aiosqlite.Connection:
    """Get an async database connection."""
    path = Path(db_path) if db_path else DB_PATH
    db = await aiosqlite.connect(path)
    db.row_factory = aiosqlite.Row
    return db


# ---------------------------------------------------------------------------
# Scan CRUD
# ---------------------------------------------------------------------------


async def save_scan(
    scan_id: str,
    target: str,
    modules: List[str],
    status: str,
    started_at: str,
    result_json: Optional[str] = None,
    summary_json: Optional[str] = None,
    completed_at: Optional[str] = None,
    duration_ms: int = 0,
    gate_passed: Optional[bool] = None,
    gate_reason: Optional[str] = None,
    gate_exit_code: Optional[int] = None,
    db_path: Optional[str] = None,
) -> None:
    """Insert or update a scan record."""
    path = Path(db_path) if db_path else DB_PATH
    async with aiosqlite.connect(path) as db:
        await db.execute(
            """INSERT OR REPLACE INTO scans
               (id, target, modules, status, started_at, completed_at,
                duration_ms, result_json, summary_json, gate_passed, gate_reason, gate_exit_code)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                target,
                json.dumps(modules),
                status,
                started_at,
                completed_at,
                duration_ms,
                result_json,
                summary_json,
                1 if gate_passed else (0 if gate_passed is False else None),
                gate_reason,
                gate_exit_code,
            ),
        )
        await db.commit()


async def update_scan_status(
    scan_id: str,
    status: str,
    completed_at: Optional[str] = None,
    duration_ms: int = 0,
    result_json: Optional[str] = None,
    summary_json: Optional[str] = None,
    gate_passed: Optional[bool] = None,
    gate_reason: Optional[str] = None,
    gate_exit_code: Optional[int] = None,
    db_path: Optional[str] = None,
) -> None:
    """Update scan status and results."""
    path = Path(db_path) if db_path else DB_PATH
    async with aiosqlite.connect(path) as db:
        sets = ["status = ?"]
        vals: list[Any] = [status]

        if completed_at is not None:
            sets.append("completed_at = ?")
            vals.append(completed_at)
        if duration_ms:
            sets.append("duration_ms = ?")
            vals.append(duration_ms)
        if result_json is not None:
            sets.append("result_json = ?")
            vals.append(result_json)
        if summary_json is not None:
            sets.append("summary_json = ?")
            vals.append(summary_json)
        if gate_passed is not None:
            sets.append("gate_passed = ?")
            vals.append(1 if gate_passed else 0)
        if gate_reason is not None:
            sets.append("gate_reason = ?")
            vals.append(gate_reason)
        if gate_exit_code is not None:
            sets.append("gate_exit_code = ?")
            vals.append(gate_exit_code)

        vals.append(scan_id)
        await db.execute(f"UPDATE scans SET {', '.join(sets)} WHERE id = ?", vals)
        await db.commit()


async def save_findings(
    scan_id: str,
    findings: List[Dict[str, Any]],
    db_path: Optional[str] = None,
) -> None:
    """Save findings for a scan."""
    path = Path(db_path) if db_path else DB_PATH
    async with aiosqlite.connect(path) as db:
        for f in findings:
            await db.execute(
                """INSERT OR REPLACE INTO findings
                   (id, scan_id, severity, category, title, description,
                    cwe, owasp_ref, mitre_ref, location, evidence,
                    recommendation, confidence, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    f["id"],
                    scan_id,
                    f["severity"],
                    f["category"],
                    f["title"],
                    f["description"],
                    f.get("cwe"),
                    f.get("owasp_ref"),
                    f.get("mitre_ref"),
                    f.get("location"),
                    json.dumps(f.get("evidence", [])),
                    f.get("recommendation", ""),
                    f.get("confidence", "high"),
                    f.get("timestamp", ""),
                ),
            )
        await db.commit()


async def get_scan(scan_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Get a scan by ID."""
    path = Path(db_path) if db_path else DB_PATH
    async with aiosqlite.connect(path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = await cursor.fetchone()
        if row is None:
            return None
        return dict(row)


async def list_scans(
    limit: int = 20,
    offset: int = 0,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List scans ordered by most recent first."""
    path = Path(db_path) if db_path else DB_PATH
    async with aiosqlite.connect(path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def delete_scan(scan_id: str, db_path: Optional[str] = None) -> bool:
    """Delete a scan and its findings."""
    path = Path(db_path) if db_path else DB_PATH
    async with aiosqlite.connect(path) as db:
        await db.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        cursor = await db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        await db.commit()
        return cursor.rowcount > 0


async def get_findings(
    scan_id: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Query findings with optional filters."""
    path = Path(db_path) if db_path else DB_PATH
    async with aiosqlite.connect(path) as db:
        db.row_factory = aiosqlite.Row

        conditions = []
        params: list[Any] = []

        if scan_id:
            conditions.append("scan_id = ?")
            params.append(scan_id)
        if severity:
            conditions.append("severity = ?")
            params.append(severity.upper())
        if category:
            conditions.append("category = ?")
            params.append(category)
        if search:
            conditions.append("(title LIKE ? OR description LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        cursor = await db.execute(
            f"SELECT * FROM findings {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_finding(finding_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Get a single finding by ID."""
    path = Path(db_path) if db_path else DB_PATH
    async with aiosqlite.connect(path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None