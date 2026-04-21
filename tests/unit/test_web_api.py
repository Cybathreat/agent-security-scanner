"""
Tests for the web dashboard API endpoints.

Tests REST API endpoints using FastAPI TestClient.
"""

import json
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent_security_scanner.modules.base import Finding, ScanResult, Severity
from agent_security_scanner.web.app import create_app
from agent_security_scanner.web import db as db_module


@pytest.fixture(autouse=True)
def isolate_db(tmp_path):
    """Use a temp database for each test to avoid cross-test pollution."""
    test_db = tmp_path / "test_scans.db"
    original_path = db_module.DB_PATH
    db_module.DB_PATH = test_db
    yield
    db_module.DB_PATH = original_path


@pytest.fixture
def client():
    """Create test client with isolated DB."""
    app = create_app()
    with TestClient(app) as c:
        yield c


@pytest.fixture
def sample_finding():
    """Create a sample finding."""
    return Finding(
        id="FIND-test-abc123",
        severity=Severity.HIGH,
        category="test_category",
        title="Test Finding",
        description="A test finding for API tests",
        cwe="CWE-94",
        owasp_ref="OWASP LLM01:2024",
        mitre_ref="MITRE ATLAS - TA0045",
    )


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    def test_health_check(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["version"] == "0.2.0"


# ---------------------------------------------------------------------------
# Scans API
# ---------------------------------------------------------------------------


class TestScansAPI:
    def test_list_scans_empty(self, client):
        response = client.get("/api/scans")
        assert response.status_code == 200
        assert response.json() == []

    def test_get_nonexistent_scan(self, client):
        response = client.get("/api/scans/nonexistent-id")
        assert response.status_code == 404

    def test_delete_nonexistent_scan(self, client):
        response = client.delete("/api/scans/nonexistent-id")
        # Cancel returns False, then DB delete returns False
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# Modules API
# ---------------------------------------------------------------------------


class TestModulesAPI:
    def test_list_modules(self, client):
        response = client.get("/api/modules")
        assert response.status_code == 200
        modules = response.json()
        assert len(modules) == 11
        names = [m["name"] for m in modules]
        assert "misconfigurations" in names
        assert "prompt_injection" in names
        assert "secret_scanner" in names

    def test_get_module_detail(self, client):
        response = client.get("/api/modules/prompt_injection")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "prompt_injection"
        assert data["display_name"] == "Prompt Injection"
        assert data["category"] == "Injection"

    def test_get_nonexistent_module(self, client):
        response = client.get("/api/modules/nonexistent")
        assert response.status_code == 404

    def test_module_has_description(self, client):
        response = client.get("/api/modules/rag_security")
        assert response.status_code == 200
        data = response.json()
        assert "description" in data
        assert len(data["description"]) > 0


# ---------------------------------------------------------------------------
# Findings API
# ---------------------------------------------------------------------------


class TestFindingsAPI:
    def test_list_findings_empty(self, client):
        response = client.get("/api/findings")
        assert response.status_code == 200
        assert response.json() == []

    def test_get_nonexistent_finding(self, client):
        response = client.get("/api/findings/FIND-nonexistent")
        assert response.status_code == 404

    def test_findings_filter_by_severity(self, client):
        response = client.get("/api/findings?severity=CRITICAL")
        assert response.status_code == 200

    def test_findings_filter_by_category(self, client):
        response = client.get("/api/findings?category=prompt_injection")
        assert response.status_code == 200

    def test_findings_search(self, client):
        response = client.get("/api/findings?search=injection")
        assert response.status_code == 200

    def test_findings_pagination(self, client):
        response = client.get("/api/findings?limit=10&offset=0")
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# Config API
# ---------------------------------------------------------------------------


class TestConfigAPI:
    def test_get_config(self, client):
        response = client.get("/api/config")
        assert response.status_code == 200
        data = response.json()
        assert "scanner" in data
        assert "quality_gate" in data

    def test_patch_config(self, client):
        response = client.patch("/api/config", json={})
        assert response.status_code == 200
        data = response.json()
        assert "scanner" in data


# ---------------------------------------------------------------------------
# Quality Gate API
# ---------------------------------------------------------------------------


class TestQualityGateAPI:
    def test_evaluate_nonexistent_scan(self, client):
        response = client.post(
            "/api/quality-gate/evaluate",
            json={
                "scan_id": "nonexistent",
                "fail_on_severity": "critical",
            },
        )
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# Scan lifecycle (integration-style with mocked ScanEngine)
# ---------------------------------------------------------------------------


class TestScanLifecycle:
    @patch("agent_security_scanner.web.scan_manager.ScanEngine")
    @patch("agent_security_scanner.web.scan_manager.load_config")
    def test_start_scan(self, mock_load_config, mock_engine_cls, client):
        """Test starting a scan via the API."""
        mock_load_config.return_value = MagicMock()
        mock_engine = MagicMock()
        mock_engine.run.return_value = [
            ScanResult(
                module_name="test_module",
                target="https://test.local",
                findings=[],
            )
        ]
        mock_engine_cls.return_value = mock_engine

        response = client.post(
            "/api/scans",
            json={
                "target": "https://test.local",
                "modules": ["misconfigurations"],
                "timeout": 30,
                "fail_on_severity": "high",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert "scan_id" in data
        assert len(data["scan_id"]) > 0


# ---------------------------------------------------------------------------
# Attack Surface API
# ---------------------------------------------------------------------------


class TestAttackSurfaceAPI:
    def test_attack_surface_route_registered(self):
        """Verify attack-surface route is registered in the app."""
        from agent_security_scanner.web.app import create_app

        app = create_app()
        routes = [r.path for r in app.routes]
        assert any("attack-surface" in str(r) for r in routes), "Attack surface route not registered"

    def test_attack_surface_nonexistent_scan(self, client):
        """Attack surface for nonexistent scan returns 404."""
        response = client.get("/api/scans/nonexistent-id/attack-surface")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_attack_surface_with_findings(self, tmp_path):
        """Test attack surface graph generation with actual findings."""
        from agent_security_scanner.web import db as db_module
        from agent_security_scanner.web.app import create_app

        test_db = tmp_path / "test_attack.db"
        db_module.DB_PATH = test_db
        await db_module.init_db()

        # Create a scan
        await db_module.save_scan(
            scan_id="scan-as-001",
            target="https://target.example.com",
            modules=["prompt_injection", "tool_boundaries"],
            status="completed",
            started_at="2026-01-01T00:00:00Z",
            completed_at="2026-01-01T00:01:00Z",
        )

        # Save findings for different categories
        await db_module.save_findings(
            scan_id="scan-as-001",
            findings=[
                {
                    "id": "FIND-pi-001",
                    "severity": "HIGH",
                    "category": "prompt_injection",
                    "title": "Direct injection",
                    "description": "Test",
                    "cwe": None,
                    "owasp_ref": None,
                    "mitre_ref": None,
                    "location": None,
                    "evidence": [],
                    "recommendation": "",
                    "confidence": "high",
                    "timestamp": "2026-01-01T00:00:30Z",
                },
                {
                    "id": "FIND-tb-001",
                    "severity": "CRITICAL",
                    "category": "tool_boundaries",
                    "title": "Tool escape",
                    "description": "Test",
                    "cwe": None,
                    "owasp_ref": None,
                    "mitre_ref": None,
                    "location": None,
                    "evidence": [],
                    "recommendation": "",
                    "confidence": "high",
                    "timestamp": "2026-01-01T00:00:45Z",
                },
            ],
        )

        db_module.DB_PATH = test_db
        app = create_app()
        with TestClient(app) as c:
            response = c.get("/api/scans/scan-as-001/attack-surface")
            assert response.status_code == 200
            data = response.json()

            assert data["scan_id"] == "scan-as-001"
            assert len(data["nodes"]) >= 3  # at least target + src/tgt nodes per category
            assert len(data["edges"]) >= 2  # at least one edge per category

            # Check that the target endpoint node exists
            node_ids = [n["id"] for n in data["nodes"]]
            assert "endpoint:target" in node_ids

            # Check that prompt_injection source node has findings
            pi_src_nodes = [n for n in data["nodes"] if n["id"] == "endpoint:prompt_injection_src"]
            assert len(pi_src_nodes) == 1
            assert pi_src_nodes[0]["findings_count"] == 1
            assert pi_src_nodes[0]["max_severity"] == "HIGH"
            assert "FIND-pi-001" in pi_src_nodes[0]["finding_ids"]

            # Check that tool_boundaries source node has CRITICAL severity
            tb_src_nodes = [n for n in data["nodes"] if n["id"] == "endpoint:tool_boundaries_src"]
            assert len(tb_src_nodes) == 1
            assert tb_src_nodes[0]["max_severity"] == "CRITICAL"

            # Check edges
            edge_labels = [e["label"] for e in data["edges"]]
            assert "prompt_injection" in edge_labels
            assert "tool_boundaries" in edge_labels

        # Cleanup
        db_module.DB_PATH = tmp_path / "original.db"


# ---------------------------------------------------------------------------
# Finding Annotations (PATCH) API
# ---------------------------------------------------------------------------


class TestFindingAnnotationAPI:
    @pytest.mark.asyncio
    async def test_patch_finding_annotation(self, tmp_path):
        """Test PATCH /api/findings/{id} to annotate a finding."""
        from agent_security_scanner.web import db as db_module
        from agent_security_scanner.web.app import create_app

        test_db = tmp_path / "test_annotate.db"
        db_module.DB_PATH = test_db
        await db_module.init_db()

        # Create a scan and finding
        await db_module.save_scan(
            scan_id="scan-ann-001",
            target="https://ann.example.com",
            modules=["prompt_injection"],
            status="completed",
            started_at="2026-01-01T00:00:00Z",
            completed_at="2026-01-01T00:01:00Z",
        )
        await db_module.save_findings(
            scan_id="scan-ann-001",
            findings=[
                {
                    "id": "FIND-ann-001",
                    "severity": "HIGH",
                    "category": "prompt_injection",
                    "title": "Direct injection",
                    "description": "Test finding",
                    "cwe": None,
                    "owasp_ref": None,
                    "mitre_ref": None,
                    "location": None,
                    "evidence": [],
                    "recommendation": "",
                    "confidence": "high",
                    "timestamp": "2026-01-01T00:00:30Z",
                },
            ],
        )

        db_module.DB_PATH = test_db
        app = create_app()
        with TestClient(app) as c:
            # Patch the finding with annotations
            response = c.patch(
                "/api/findings/FIND-ann-001",
                json={
                    "is_false_positive": True,
                    "notes": "Confirmed false positive by security team",
                    "assigned_to": "alice",
                    "status": "resolved",
                },
            )
            assert response.status_code == 200
            data = response.json()
            assert data["id"] == "FIND-ann-001"
            assert data["is_false_positive"] is True
            assert data["notes"] == "Confirmed false positive by security team"
            assert data["assigned_to"] == "alice"
            assert data["status"] == "resolved"

    @pytest.mark.asyncio
    async def test_patch_finding_partial_annotation(self, tmp_path):
        """Test PATCH with only some fields updates only those fields."""
        from agent_security_scanner.web import db as db_module
        from agent_security_scanner.web.app import create_app

        test_db = tmp_path / "test_partial.db"
        db_module.DB_PATH = test_db
        await db_module.init_db()

        await db_module.save_scan(
            scan_id="scan-partial-001",
            target="https://partial.example.com",
            modules=["prompt_injection"],
            status="completed",
            started_at="2026-01-01T00:00:00Z",
        )
        await db_module.save_findings(
            scan_id="scan-partial-001",
            findings=[
                {
                    "id": "FIND-partial-001",
                    "severity": "MEDIUM",
                    "category": "prompt_injection",
                    "title": "Partial test",
                    "description": "Partial update test",
                    "cwe": None,
                    "owasp_ref": None,
                    "mitre_ref": None,
                    "location": None,
                    "evidence": [],
                    "recommendation": "",
                    "confidence": "high",
                    "timestamp": "2026-01-01T00:00:30Z",
                },
            ],
        )

        db_module.DB_PATH = test_db
        app = create_app()
        with TestClient(app) as c:
            # Only update notes
            response = c.patch(
                "/api/findings/FIND-partial-001",
                json={"notes": "Investigating"},
            )
            assert response.status_code == 200
            data = response.json()
            assert data["notes"] == "Investigating"
            assert data["status"] == "open"  # default unchanged
            assert data["is_false_positive"] is False  # default unchanged

    def test_patch_nonexistent_finding(self, client):
        """Patching a nonexistent finding returns 404."""
        response = client.patch(
            "/api/findings/FIND-nonexistent",
            json={"status": "resolved"},
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_get_finding_includes_annotations(self, tmp_path):
        """Test that GET /api/findings/{id} includes annotation fields."""
        from agent_security_scanner.web import db as db_module
        from agent_security_scanner.web.app import create_app

        test_db = tmp_path / "test_get_ann.db"
        db_module.DB_PATH = test_db
        await db_module.init_db()

        await db_module.save_scan(
            scan_id="scan-getann-001",
            target="https://getann.example.com",
            modules=["prompt_injection"],
            status="completed",
            started_at="2026-01-01T00:00:00Z",
        )
        await db_module.save_findings(
            scan_id="scan-getann-001",
            findings=[
                {
                    "id": "FIND-getann-001",
                    "severity": "LOW",
                    "category": "prompt_injection",
                    "title": "Get annotation test",
                    "description": "Testing annotation fields in GET",
                    "cwe": None,
                    "owasp_ref": None,
                    "mitre_ref": None,
                    "location": None,
                    "evidence": [],
                    "recommendation": "",
                    "confidence": "medium",
                    "timestamp": "2026-01-01T00:00:30Z",
                },
            ],
        )

        db_module.DB_PATH = test_db
        app = create_app()
        with TestClient(app) as c:
            response = c.get("/api/findings/FIND-getann-001")
            assert response.status_code == 200
            data = response.json()
            assert "is_false_positive" in data
            assert data["is_false_positive"] is False
            assert "notes" in data
            assert data["notes"] == ""
            assert "assigned_to" in data
            assert data["assigned_to"] == ""
            assert "status" in data
            assert data["status"] == "open"


# ---------------------------------------------------------------------------
# Replay API
# ---------------------------------------------------------------------------


class TestReplayAPI:
    @pytest.mark.asyncio
    async def test_replay_nonexistent_finding(self, tmp_path):
        """Replaying a nonexistent finding returns 404."""
        from agent_security_scanner.web import db as db_module
        from agent_security_scanner.web.app import create_app

        test_db = tmp_path / "test_replay_404.db"
        db_module.DB_PATH = test_db
        await db_module.init_db()

        db_module.DB_PATH = test_db
        app = create_app()
        with TestClient(app) as c:
            response = client_patch_replay(c, "FIND-nonexistent")
            assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_replay_finding_success(self, tmp_path):
        """Test POST /api/findings/{id}/replay starts a new scan."""
        from agent_security_scanner.web import db as db_module
        from agent_security_scanner.web.app import create_app

        test_db = tmp_path / "test_replay_ok.db"
        db_module.DB_PATH = test_db
        await db_module.init_db()

        await db_module.save_scan(
            scan_id="scan-replay-001",
            target="https://replay.example.com",
            modules=["prompt_injection"],
            status="completed",
            started_at="2026-01-01T00:00:00Z",
        )
        await db_module.save_findings(
            scan_id="scan-replay-001",
            findings=[
                {
                    "id": "FIND-replay-001",
                    "severity": "HIGH",
                    "category": "prompt_injection",
                    "title": "Replay test",
                    "description": "Testing replay endpoint",
                    "cwe": None,
                    "owasp_ref": None,
                    "mitre_ref": None,
                    "location": None,
                    "evidence": [],
                    "recommendation": "",
                    "confidence": "high",
                    "timestamp": "2026-01-01T00:00:30Z",
                },
            ],
        )

        db_module.DB_PATH = test_db
        app = create_app()

        with patch("agent_security_scanner.web.scan_manager.ScanEngine"), \
             patch("agent_security_scanner.web.scan_manager.load_config"):
            with TestClient(app) as c:
                response = c.post(
                    "/api/findings/FIND-replay-001/replay",
                    json={"params": {}},
                )
                assert response.status_code == 200
                data = response.json()
                assert "replay_id" in data
                assert "scan_id" in data
                assert data["status"] == "pending"
                assert "prompt_injection" in data["message"]


def client_patch_replay(client, finding_id):
    """Helper to post a replay request (used for 404 test)."""
    return client.post(
        f"/api/findings/{finding_id}/replay",
        json={"params": {}},
    )