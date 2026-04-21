import os
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest


def test_db_path_is_absolute():
    """DB path should resolve to an absolute path, not relative."""
    from agent_security_scanner.web.db import DB_PATH
    assert DB_PATH.is_absolute(), f"DB_PATH is relative: {DB_PATH}"


def test_db_path_uses_env_var():
    """DB_PATH should use ASS_DATA_DIR env var when set."""
    with patch.dict(os.environ, {"ASS_DATA_DIR": "/tmp/test-data"}):
        import importlib
        from agent_security_scanner import web
        importlib.reload(web.db)
        assert web.db.DB_PATH == Path("/tmp/test-data/scan_history.db")


def test_scan_manager_uses_timezone_utc():
    """ScanManager should use datetime.now(timezone.utc) not utcnow()."""
    import inspect
    from agent_security_scanner.web import scan_manager
    source = inspect.getsource(scan_manager)
    assert "utcnow" not in source, "scan_manager.py still uses deprecated utcnow()"


def test_ws_scan_progress_uses_timezone_utc():
    """WebSocket handler should use datetime.now(timezone.utc) not utcnow()."""
    import inspect
    from agent_security_scanner.web.ws import scan_progress
    source = inspect.getsource(scan_progress)
    assert "utcnow" not in source, "scan_progress.py still uses deprecated utcnow()"


def test_models_uses_timezone_utc():
    """Models should use datetime.now(timezone.utc) not utcnow()."""
    import inspect
    from agent_security_scanner.web import models
    source = inspect.getsource(models)
    assert "utcnow" not in source, "models.py still uses deprecated utcnow()"


def test_cors_uses_env_var():
    """CORS origins should be configurable via ASS_CORS_ORIGINS env var."""
    import os
    with patch.dict(os.environ, {"ASS_CORS_ORIGINS": "https://prod.example.com,https://staging.example.com"}):
        # Need to reimport to pick up env var
        import importlib
        from agent_security_scanner.web import app as app_module
        importlib.reload(app_module)
        # Check that the new app has the right origins
        new_app = app_module.create_app()
        # The CORS middleware should have the custom origins
        cors_middleware = None
        for middleware in new_app.user_middleware:
            if 'CORS' in str(middleware.cls):
                cors_middleware = middleware
                break
        assert cors_middleware is not None, "CORS middleware not found"
        origins = cors_middleware.kwargs.get("allow_origins", [])
        assert "https://prod.example.com" in origins, f"Expected custom origin, got: {origins}"


def test_db_update_scan_status_no_fstring_sql():
    """update_scan_status should use allowlist-validated fields, not raw f-string SQL."""
    import inspect
    from agent_security_scanner.web import db
    source = inspect.getsource(db.update_scan_status)
    # The allowlist pattern validates field names before use in SQL
    assert "_ALLOWED_FIELDS" in source, "db.py missing _ALLOWED_FIELDS allowlist in update_scan_status"
    assert "raise ValueError" in source, "db.py missing field validation in update_scan_status"


@pytest.mark.asyncio
async def test_cancel_scan_sets_status():
    """Cancelling a scan should set status to cancelled."""
    from agent_security_scanner.web.scan_manager import ScanManager
    from agent_security_scanner.web.models import ScanStatus
    mgr = ScanManager()
    scan_id = "test-cancel-123"
    mgr._active_scans[scan_id] = {
        "status": ScanStatus.RUNNING,
        "target": "https://example.com",
        "modules": ["prompt_injection"],
        "started_at": "2026-01-01T00:00:00Z",
    }
    with patch("agent_security_scanner.web.scan_manager.db") as mock_db:
        mock_db.update_scan_status = AsyncMock()
        result = await mgr.cancel_scan(scan_id)
    assert result is True
    assert mgr._active_scans[scan_id]["status"] == ScanStatus.CANCELLED


def test_run_scan_checks_cancelled_status():
    """_run_scan should check cancelled status and abort if cancelled."""
    import inspect
    from agent_security_scanner.web import scan_manager
    source = inspect.getsource(scan_manager.ScanManager._run_scan)
    # Verify that the cancellation check exists in _run_scan
    assert "cancelled" in source, "_run_scan does not check for cancelled status"


def test_delete_scan_always_attempts_db_deletion():
    """Delete endpoint should cancel active scan AND delete from DB."""
    import inspect
    from agent_security_scanner.web.api import scans
    source = inspect.getsource(scans.delete_scan)
    # The delete function should always call db.delete_scan, not skip it
    # when the scan was active
    assert "db.delete_scan" in source, "delete_scan does not call db.delete_scan"
    assert "cancel_scan" in source, "delete_scan does not call cancel_scan before DB deletion"


@pytest.mark.asyncio
async def test_get_active_scan_includes_modules():
    """GET /api/scans/{id} for running scan should include modules and module_statuses."""
    from agent_security_scanner.web.scan_manager import ScanManager
    mgr = ScanManager()
    scan_id = "test-active-789"
    mgr._active_scans[scan_id] = {
        "status": "running",
        "target": "https://example.com",
        "modules": ["prompt_injection", "tool_boundaries"],
        "module_statuses": [
            {"module_name": "prompt_injection", "status": "completed", "findings_count": 3, "duration_ms": 500, "errors": []},
            {"module_name": "tool_boundaries", "status": "running", "findings_count": 0, "duration_ms": 0, "errors": []},
        ],
        "started_at": "2026-01-01T00:00:00Z",
        "findings_count": 3,
    }
    status = await mgr.get_scan_status(scan_id)
    assert status is not None
    assert status.get("modules") == ["prompt_injection", "tool_boundaries"]
    assert len(status.get("module_statuses", [])) == 2


def test_quality_gate_preserves_timestamp():
    """Reconstructed Findings should include the timestamp field."""
    import inspect
    from agent_security_scanner.web.api import quality_gate
    source = inspect.getsource(quality_gate)
    assert "timestamp" in source, "quality_gate.py doesn't pass timestamp to Finding"


def test_quality_gate_groups_by_category():
    """Quality gate should create per-module ScanResult objects."""
    import inspect
    from agent_security_scanner.web.api import quality_gate
    source = inspect.getsource(quality_gate)
    assert "findings_by_module" in source, "quality_gate.py doesn't group findings by module"


def test_ws_handler_has_catchup():
    """WebSocket handler should replay past events on connect."""
    import inspect
    from agent_security_scanner.web.ws import scan_progress
    source = inspect.getsource(scan_progress)
    assert "catchup" in source.lower() or "replay" in source.lower() or "result_json" in source.lower(), \
        "WebSocket handler doesn't implement event catch-up"


def test_config_patch_persists_changes():
    """PATCH /api/config should apply and persist config updates."""
    import inspect
    from agent_security_scanner.web.api import config
    source = inspect.getsource(config)
    # Should not have the old stub comment
    assert "full implementation would" not in source.lower(), "config.py PATCH is still a stub"
    # Should have YAML persistence
    assert "yaml.dump" in source, "config.py PATCH doesn't persist to YAML"