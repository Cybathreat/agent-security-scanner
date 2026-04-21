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