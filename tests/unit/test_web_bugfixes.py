import os
from pathlib import Path
from unittest.mock import patch

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