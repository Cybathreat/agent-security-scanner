"""Unit tests for MisconfigurationsModule delegation logic."""

from __future__ import annotations

from typing import Any, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from singularity.core.config import MisconfigurationsConfig
from singularity.modules.base import Finding, ScanResult, Severity
from singularity.modules.misconfig_submodules.auth_scanner import (
    AuthScanner,
    AuthScannerConfig,
)
from singularity.modules.misconfig_submodules.cors_scanner import (
    CORSScanner,
    CORSScannerConfig,
)
from singularity.modules.misconfig_submodules.info_disclosure_scanner import (
    InfoDisclosureScanner,
    InfoDisclosureScannerConfig,
)
from singularity.modules.misconfig_submodules.rate_limit_scanner import (
    RateLimitScanner,
    RateLimitScannerConfig,
)
from singularity.modules.misconfigurations import MisconfigurationsModule


# ---------------------------------------------------------------------------
# Init / module_name tests
# ---------------------------------------------------------------------------


class TestMisconfigurationsModule:
    def test_init_default_config(self):
        mod = MisconfigurationsModule()
        assert isinstance(mod.config, MisconfigurationsConfig)
        assert mod.config.check_auth is True
        assert mod.config.check_cors is True
        assert mod.config.check_rate_limiting is True
        assert mod.config.check_info_disclosure is True

    def test_init_custom_config(self):
        config = MisconfigurationsConfig(
            check_auth=False,
            check_cors=False,
            check_rate_limiting=False,
            check_info_disclosure=False,
        )
        mod = MisconfigurationsModule(config=config)
        assert mod.config.check_auth is False
        assert mod.config.check_cors is False
        assert mod.config.check_rate_limiting is False
        assert mod.config.check_info_disclosure is False

    def test_module_name(self):
        mod = MisconfigurationsModule()
        assert mod.module_name == "misconfigurations"

    def test_init_with_submodule_configs(self):
        auth_cfg = AuthScannerConfig(enabled=False)
        cors_cfg = CORSScannerConfig(enabled=False)
        rl_cfg = RateLimitScannerConfig(enabled=False)
        info_cfg = InfoDisclosureScannerConfig(enabled=False)
        mod = MisconfigurationsModule(
            auth_scanner_config=auth_cfg,
            cors_scanner_config=cors_cfg,
            rate_limit_scanner_config=rl_cfg,
            info_disclosure_scanner_config=info_cfg,
        )
        assert mod._auth_scanner_config is auth_cfg
        assert mod._cors_scanner_config is cors_cfg
        assert mod._rate_limit_scanner_config is rl_cfg
        assert mod._info_disclosure_scanner_config is info_cfg


# ---------------------------------------------------------------------------
# Delegation tests
# ---------------------------------------------------------------------------


class TestScanDelegation:
    def test_auth_submodule_called(self):
        """When check_auth is True, AuthScanner.scan() is called."""
        mod = MisconfigurationsModule(
            config=MisconfigurationsConfig(
                check_auth=True,
                check_cors=False,
                check_rate_limiting=False,
                check_info_disclosure=False,
            ),
        )
        mock_sub_result = ScanResult(module_name="auth", target="http://test.com")

        with patch.object(
            AuthScanner, "scan", return_value=mock_sub_result
        ) as mock_scan:
            # Also patch the async debug-endpoint check so scan() completes
            with patch.object(
                mod, "_check_debug_endpoints", new_callable=AsyncMock
            ):
                result = mod.scan("http://test.com")

        mock_scan.assert_called_once_with("http://test.com")
        assert result.module_name == "misconfigurations"

    def test_cors_submodule_called(self):
        """When check_cors is True, CORSScanner.scan() is called."""
        mod = MisconfigurationsModule(
            config=MisconfigurationsConfig(
                check_auth=False,
                check_cors=True,
                check_rate_limiting=False,
                check_info_disclosure=False,
            ),
        )
        mock_sub_result = ScanResult(module_name="cors", target="http://test.com")

        with patch.object(
            CORSScanner, "scan", return_value=mock_sub_result
        ) as mock_scan:
            with patch.object(
                mod, "_check_debug_endpoints", new_callable=AsyncMock
            ):
                result = mod.scan("http://test.com")

        mock_scan.assert_called_once_with("http://test.com")

    def test_rate_limit_submodule_called(self):
        """When check_rate_limiting is True, RateLimitScanner.scan() is called."""
        mod = MisconfigurationsModule(
            config=MisconfigurationsConfig(
                check_auth=False,
                check_cors=False,
                check_rate_limiting=True,
                check_info_disclosure=False,
            ),
        )
        mock_sub_result = ScanResult(
            module_name="rate_limit", target="http://test.com"
        )

        with patch.object(
            RateLimitScanner, "scan", return_value=mock_sub_result
        ) as mock_scan:
            with patch.object(
                mod, "_check_debug_endpoints", new_callable=AsyncMock
            ):
                result = mod.scan("http://test.com")

        mock_scan.assert_called_once_with("http://test.com")

    def test_info_disclosure_submodule_called(self):
        """When check_info_disclosure is True, InfoDisclosureScanner.scan() is called."""
        mod = MisconfigurationsModule(
            config=MisconfigurationsConfig(
                check_auth=False,
                check_cors=False,
                check_rate_limiting=False,
                check_info_disclosure=True,
            ),
        )
        mock_sub_result = ScanResult(
            module_name="info_disclosure", target="http://test.com"
        )

        with patch.object(
            InfoDisclosureScanner, "scan", return_value=mock_sub_result
        ) as mock_scan:
            with patch.object(
                mod, "_check_debug_endpoints", new_callable=AsyncMock
            ):
                result = mod.scan("http://test.com")

        mock_scan.assert_called_once_with("http://test.com")

    def test_disabled_flags_skip_submodules(self):
        """When all check_* flags are False, no submodules are instantiated."""
        mod = MisconfigurationsModule(
            config=MisconfigurationsConfig(
                check_auth=False,
                check_cors=False,
                check_rate_limiting=False,
                check_info_disclosure=False,
            ),
        )

        with patch.object(AuthScanner, "scan") as mock_auth:
            with patch.object(CORSScanner, "scan") as mock_cors:
                with patch.object(RateLimitScanner, "scan") as mock_rl:
                    with patch.object(InfoDisclosureScanner, "scan") as mock_info:
                        with patch.object(
                            mod,
                            "_check_debug_endpoints",
                            new_callable=AsyncMock,
                        ):
                            result = mod.scan("http://test.com")

        mock_auth.assert_not_called()
        mock_cors.assert_not_called()
        mock_rl.assert_not_called()
        mock_info.assert_not_called()
        assert len(result.findings) == 0

    def test_finding_aggregation(self):
        """Findings from submodules are aggregated into the delegator's result."""
        mod = MisconfigurationsModule(
            config=MisconfigurationsConfig(
                check_auth=True,
                check_cors=True,
                check_rate_limiting=False,
                check_info_disclosure=False,
            ),
        )

        # Build a mock ScanResult with one finding for AuthScanner
        auth_result = ScanResult(module_name="auth", target="http://test.com")
        auth_result.add_finding(
            Finding(
                id="FIND-auth-test1",
                severity=Severity.HIGH,
                category="auth",
                title="Auth issue",
                description="desc",
            )
        )

        # Build a mock ScanResult with one finding for CORSScanner
        cors_result = ScanResult(module_name="cors", target="http://test.com")
        cors_result.add_finding(
            Finding(
                id="FIND-cors-test1",
                severity=Severity.CRITICAL,
                category="cors",
                title="CORS issue",
                description="desc",
            )
        )

        with patch.object(AuthScanner, "scan", return_value=auth_result):
            with patch.object(CORSScanner, "scan", return_value=cors_result):
                with patch.object(
                    mod,
                    "_check_debug_endpoints",
                    new_callable=AsyncMock,
                ):
                    result = mod.scan("http://test.com")

        assert len(result.findings) == 2
        assert result.findings[0].id == "FIND-auth-test1"
        assert result.findings[1].id == "FIND-cors-test1"

    def test_error_aggregation(self):
        """Errors from submodules are aggregated into the delegator's result."""
        mod = MisconfigurationsModule(
            config=MisconfigurationsConfig(
                check_auth=True,
                check_cors=False,
                check_rate_limiting=False,
                check_info_disclosure=False,
            ),
        )

        auth_result = ScanResult(module_name="auth", target="http://test.com")
        auth_result.add_error("Failed to fetch: http://test.com")

        with patch.object(AuthScanner, "scan", return_value=auth_result):
            with patch.object(
                mod, "_check_debug_endpoints", new_callable=AsyncMock
            ):
                result = mod.scan("http://test.com")

        assert len(result.errors) == 1
        assert "Failed to fetch" in result.errors[0]

    def test_all_four_submodules_called(self):
        """When all flags are True, all four submodules are invoked."""
        mod = MisconfigurationsModule(
            config=MisconfigurationsConfig(
                check_auth=True,
                check_cors=True,
                check_rate_limiting=True,
                check_info_disclosure=True,
            ),
        )

        empty_result = ScanResult(module_name="sub", target="http://test.com")

        with patch.object(AuthScanner, "scan", return_value=empty_result) as mock_auth:
            with patch.object(CORSScanner, "scan", return_value=empty_result) as mock_cors:
                with patch.object(RateLimitScanner, "scan", return_value=empty_result) as mock_rl:
                    with patch.object(InfoDisclosureScanner, "scan", return_value=empty_result) as mock_info:
                        with patch.object(
                            mod,
                            "_check_debug_endpoints",
                            new_callable=AsyncMock,
                        ):
                            mod.scan("http://test.com")

        mock_auth.assert_called_once()
        mock_cors.assert_called_once()
        mock_rl.assert_called_once()
        mock_info.assert_called_once()


# ---------------------------------------------------------------------------
# Debug endpoints tests
# ---------------------------------------------------------------------------


class TestDebugEndpoints:
    @pytest.mark.asyncio
    async def test_debug_endpoint_creates_finding(self):
        """_check_debug_endpoints creates a HIGH finding when a debug path returns 200."""
        mod = MisconfigurationsModule()
        result = ScanResult(
            module_name=mod.module_name, target="http://test.com"
        )

        # Return 200 for /debug, None for all other paths
        async def mock_fetch(url, session, **kwargs):
            if "/debug" in url:
                return {"status": 200, "headers": {}, "body": "debug page"}
            return None

        with patch.object(mod, "_fetch_url", side_effect=mock_fetch):
            await mod._check_debug_endpoints(
                "http://test.com", MagicMock(), result
            )

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH
        assert "Exposed Debug Endpoint" in result.findings[0].title
        assert result.findings[0].cwe == "CWE-489"

    @pytest.mark.asyncio
    async def test_no_debug_endpoint_no_finding(self):
        """_check_debug_endpoints creates no finding when debug paths return non-200."""
        mod = MisconfigurationsModule()
        result = ScanResult(
            module_name=mod.module_name, target="http://test.com"
        )

        async def mock_fetch(url, session, **kwargs):
            return {"status": 404, "headers": {}, "body": "not found"}

        with patch.object(mod, "_fetch_url", side_effect=mock_fetch):
            await mod._check_debug_endpoints(
                "http://test.com", MagicMock(), result
            )

        assert len(result.findings) == 0

    def test_debug_endpoints_runs_in_scan(self):
        """The scan() method invokes _check_debug_endpoints."""
        mod = MisconfigurationsModule(
            config=MisconfigurationsConfig(
                check_auth=False,
                check_cors=False,
                check_rate_limiting=False,
                check_info_disclosure=False,
            ),
        )

        with patch.object(
            mod, "_check_debug_endpoints", new_callable=AsyncMock
        ) as mock_debug:
            result = mod.scan("http://test.com")

        mock_debug.assert_called_once()
        assert result.status != "failed" or len(result.errors) > 0


# ---------------------------------------------------------------------------
# Scan lifecycle tests
# ---------------------------------------------------------------------------


class TestScanLifecycle:
    def test_scan_finalizes_result(self):
        """scan() calls result.finalize() before returning."""
        mod = MisconfigurationsModule(
            config=MisconfigurationsConfig(
                check_auth=False,
                check_cors=False,
                check_rate_limiting=False,
                check_info_disclosure=False,
            ),
        )
        with patch.object(
            mod, "_check_debug_endpoints", new_callable=AsyncMock
        ):
            result = mod.scan("http://test.com")

        assert result.end_time is not None
        assert result.duration_ms >= 0

    def test_pre_scan_failure(self):
        """scan() returns early with error when pre_scan returns False."""
        mod = MisconfigurationsModule()
        with patch.object(mod, "pre_scan", return_value=False):
            result = mod.scan("http://test.com")

        assert len(result.errors) == 1
        assert "Pre-scan validation failed" in result.errors[0]

    def test_scan_returns_misconfigurations_module_name(self):
        """The result module_name is 'misconfigurations', not a submodule name."""
        mod = MisconfigurationsModule(
            config=MisconfigurationsConfig(
                check_auth=False,
                check_cors=False,
                check_rate_limiting=False,
                check_info_disclosure=False,
            ),
        )
        with patch.object(
            mod, "_check_debug_endpoints", new_callable=AsyncMock
        ):
            result = mod.scan("http://test.com")

        assert result.module_name == "misconfigurations"