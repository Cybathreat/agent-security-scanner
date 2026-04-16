"""
Integration test for full scan workflow.

Tests end-to-end scanning with mock HTTP server.
Simulates real API responses for security modules.

Run: pytest tests/integration/test_full_scan.py -v
"""

import pytest
from contextlib import ExitStack
from unittest.mock import AsyncMock, patch

from agent_security_scanner.modules import (
    MisconfigurationsModule,
    PromptInjectionModule,
    ToolBoundariesModule,
    RAGSecurityModule,
)
from agent_security_scanner.modules.base import Finding, ScanResult, Severity
from agent_security_scanner.output.json_report import JSONReport
from agent_security_scanner.output.markdown_report import MarkdownReport


def _empty_scan_result(module_name: str, target: str) -> ScanResult:
    """Create an empty finalized ScanResult for mocking submodules."""
    r = ScanResult(module_name=module_name, target=target)
    r.finalize()
    return r


# --- Submodule patch paths for each delegator ---

MISCONFIG_SUBMODULE_PATCHES = [
    "agent_security_scanner.modules.misconfig_submodules.auth_scanner.AuthScanner.scan",
    "agent_security_scanner.modules.misconfig_submodules.cors_scanner.CORSScanner.scan",
    "agent_security_scanner.modules.misconfig_submodules.rate_limit_scanner.RateLimitScanner.scan",
    "agent_security_scanner.modules.misconfig_submodules.info_disclosure_scanner.InfoDisclosureScanner.scan",
]

PROMPT_INJECTION_SUBMODULE_PATCHES = [
    "agent_security_scanner.modules.prompt_injection_submodules.direct_injection.DirectInjectionScanner.scan",
    "agent_security_scanner.modules.prompt_injection_submodules.obfuscation.ObfuscationScanner.scan",
    "agent_security_scanner.modules.prompt_injection_submodules.multi_turn.MultiTurnScanner.scan",
    "agent_security_scanner.modules.prompt_injection_submodules.crescendo.CrescendoAttackScanner.scan",
    "agent_security_scanner.modules.prompt_injection_submodules.many_shot.ManyShotJailbreakingScanner.scan",
    "agent_security_scanner.modules.prompt_injection_submodules.skeleton_key.SkeletonKeyAttackScanner.scan",
    "agent_security_scanner.modules.prompt_injection_submodules.adaptive_generator.AdaptiveGeneratorScanner.scan",
    "agent_security_scanner.modules.prompt_injection_submodules.tap.TAPAttackScanner.scan",
    "agent_security_scanner.modules.prompt_injection_submodules.payload_splitting.PayloadSplittingScanner.scan",
    "agent_security_scanner.modules.prompt_injection_submodules.guardrail_fingerprinting.GuardrailFingerprintingScanner.scan",
    "agent_security_scanner.modules.prompt_injection_submodules.virtualization.VirtualizationScanner.scan",
    "agent_security_scanner.modules.prompt_injection_submodules.encoding_bypass.EncodingBypassScanner.scan",
    "agent_security_scanner.modules.prompt_injection_submodules.multilingual.MultilingualScanner.scan",
    "agent_security_scanner.modules.prompt_injection_submodules.token_smuggling.TokenSmugglingScanner.scan",
    "agent_security_scanner.modules.prompt_injection_submodules.grammar_constrained.GrammarConstrainedScanner.scan",
    "agent_security_scanner.modules.prompt_injection_submodules.perplexity_evasion.PerplexityEvasionScanner.scan",
    "agent_security_scanner.modules.prompt_injection_submodules.timing_sidechannels.TimingSidechannelsScanner.scan",
    "agent_security_scanner.modules.prompt_injection_submodules.rate_limit_evasion.RateLimitEvasionScanner.scan",
    "agent_security_scanner.modules.prompt_injection_submodules.waf_fingerprinting.WAFFingerprintingScanner.scan",
    "agent_security_scanner.modules.prompt_injection_submodules.canary_tokens.CanaryTokensScanner.scan",
    "agent_security_scanner.modules.prompt_injection_submodules.output_filter_probing.OutputFilterProbingScanner.scan",
]

TOOL_BOUNDARIES_SUBMODULE_PATCHES = [
    "agent_security_scanner.modules.tool_boundaries_submodules.permission_scanner.PermissionScanner.scan",
    "agent_security_scanner.modules.tool_boundaries_submodules.sandbox_scanner.SandboxScanner.scan",
    "agent_security_scanner.modules.tool_boundaries_submodules.tool_chains.ToolChainsScanner.scan",
    "agent_security_scanner.modules.tool_boundaries_submodules.mcp_scanner.MCPScanner.scan",
    "agent_security_scanner.modules.tool_boundaries_submodules.confused_deputy.ConfusedDeputyScanner.scan",
]

RAG_SECURITY_SUBMODULE_PATCHES = [
    "agent_security_scanner.modules.rag_security_submodules.document_poisoning.DocumentPoisoningScanner.scan",
    "agent_security_scanner.modules.rag_security_submodules.exfiltration.ExfiltrationScanner.scan",
    "agent_security_scanner.modules.rag_security_submodules.vector_db.VectorDBScanner.scan",
    "agent_security_scanner.modules.rag_security_submodules.embedding_attacks.EmbeddingAttacksScanner.scan",
    "agent_security_scanner.modules.rag_security_submodules.multi_tenant.MultiTenantScanner.scan",
    "agent_security_scanner.modules.rag_security_submodules.phantom_document.PhantomDocumentScanner.scan",
    "agent_security_scanner.modules.rag_security_submodules.chunk_boundary.ChunkBoundaryScanner.scan",
]


def _patch_submodules(stack: ExitStack, patches: list[str], overrides: dict[str, ScanResult], target: str) -> None:
    """Apply patches for submodule scan() methods using ExitStack.

    Args:
        stack: ExitStack context manager.
        patches: List of dotted paths to submodule scan() methods.
        overrides: Dict mapping patch paths to specific ScanResult overrides.
        target: Target URL for empty results.
    """
    empty = _empty_scan_result("empty", target)
    for patch_path in patches:
        result = overrides.get(patch_path, empty)
        stack.enter_context(patch(patch_path, return_value=result))


class TestMisconfigurationsModuleIntegration:
    """Test misconfigurations module with mock responses."""

    def test_scan_missing_auth(self):
        """Test detection of missing authentication."""
        from agent_security_scanner.core.config import MisconfigurationsConfig
        module = MisconfigurationsModule(MisconfigurationsConfig())

        auth_result = ScanResult(module_name="auth", target="https://api.test.com/agent")
        auth_result.add_finding(Finding(
            id="FIND-auth-test",
            severity=Severity.HIGH,
            category="auth",
            title="Unauthenticated Access Enabled",
            description="Missing authentication",
        ))
        auth_result.finalize()

        auth_patch = MISCONFIG_SUBMODULE_PATCHES[0]
        with ExitStack() as stack:
            _patch_submodules(
                stack, MISCONFIG_SUBMODULE_PATCHES,
                {auth_patch: auth_result},
                "https://api.test.com/agent",
            )
            result = module.scan("https://api.test.com/agent", timeout=5)

        auth_findings = [
            f for f in result.findings
            if "authentication" in f.title.lower() or "unauthenticated" in f.title.lower()
        ]
        assert len(auth_findings) >= 1
        assert auth_findings[0].severity == Severity.HIGH

    def test_scan_cors_wildcard(self):
        """Test detection of wildcard CORS."""
        from agent_security_scanner.core.config import MisconfigurationsConfig
        module = MisconfigurationsModule(MisconfigurationsConfig())

        cors_result = ScanResult(module_name="cors", target="https://api.test.com/agent")
        cors_result.add_finding(Finding(
            id="FIND-cors-test",
            severity=Severity.CRITICAL,
            category="cors",
            title="Wildcard CORS Origin with Credentials",
            description="CORS wildcard",
        ))
        cors_result.finalize()

        cors_patch = MISCONFIG_SUBMODULE_PATCHES[1]
        with ExitStack() as stack:
            _patch_submodules(
                stack, MISCONFIG_SUBMODULE_PATCHES,
                {cors_patch: cors_result},
                "https://api.test.com/agent",
            )
            result = module.scan("https://api.test.com/agent", timeout=5)

        cors_findings = [
            f for f in result.findings
            if "CORS" in f.title
        ]
        assert len(cors_findings) >= 1

    def test_scan_missing_rate_limit(self):
        """Test detection of missing rate limiting."""
        from agent_security_scanner.core.config import MisconfigurationsConfig
        module = MisconfigurationsModule(MisconfigurationsConfig())

        rate_result = ScanResult(module_name="rate_limit", target="https://api.test.com/agent")
        rate_result.add_finding(Finding(
            id="FIND-rate-test",
            severity=Severity.MEDIUM,
            category="rate_limit",
            title="Missing Rate Limiting Headers",
            description="No rate limit headers found",
        ))
        rate_result.finalize()

        rate_patch = MISCONFIG_SUBMODULE_PATCHES[2]
        with ExitStack() as stack:
            _patch_submodules(
                stack, MISCONFIG_SUBMODULE_PATCHES,
                {rate_patch: rate_result},
                "https://api.test.com/agent",
            )
            result = module.scan("https://api.test.com/agent", timeout=5)

        rate_limit_findings = [
            f for f in result.findings
            if "rate limit" in f.title.lower()
        ]
        assert len(rate_limit_findings) >= 1


class TestPromptInjectionModuleIntegration:
    """Test prompt injection module with mock responses."""

    def test_scan_direct_injection(self):
        """Test detection of direct prompt injection."""
        from agent_security_scanner.core.config import PromptInjectionConfig
        module = PromptInjectionModule(PromptInjectionConfig())

        direct_result = ScanResult(module_name="direct_injection", target="https://api.test.com/agent")
        direct_result.add_finding(Finding(
            id="FIND-direct-test",
            severity=Severity.HIGH,
            category="direct_injection",
            title="Direct Prompt Injection Bypass",
            description="Agent complied with injected instructions",
        ))
        direct_result.finalize()

        direct_patch = PROMPT_INJECTION_SUBMODULE_PATCHES[0]
        with ExitStack() as stack:
            _patch_submodules(
                stack, PROMPT_INJECTION_SUBMODULE_PATCHES,
                {direct_patch: direct_result},
                "https://api.test.com/agent",
            )
            result = module.scan("https://api.test.com/agent", timeout=5)

        injection_findings = [
            f for f in result.findings
            if "injection" in f.title.lower()
        ]
        assert len(injection_findings) >= 1
        assert injection_findings[0].severity == Severity.HIGH

    def test_scan_prompt_leaking(self):
        """Test detection of prompt leakage."""
        from agent_security_scanner.core.config import PromptInjectionConfig
        module = PromptInjectionModule(PromptInjectionConfig())

        leak_result = ScanResult(module_name="direct_injection", target="https://api.test.com/agent")
        leak_result.add_finding(Finding(
            id="FIND-leak-test",
            severity=Severity.HIGH,
            category="prompt_leakage",
            title="Prompt Leakage Detected",
            description="Agent leaked system prompt contents",
        ))
        leak_result.finalize()

        direct_patch = PROMPT_INJECTION_SUBMODULE_PATCHES[0]
        with ExitStack() as stack:
            _patch_submodules(
                stack, PROMPT_INJECTION_SUBMODULE_PATCHES,
                {direct_patch: leak_result},
                "https://api.test.com/agent",
            )
            result = module.scan("https://api.test.com/agent", timeout=5)

        leak_findings = [
            f for f in result.findings
            if "leak" in f.title.lower() or "prompt" in f.title.lower()
        ]
        assert len(leak_findings) >= 1


class TestToolBoundariesModuleIntegration:
    """Test tool boundaries module with mock responses."""

    def test_scan_dangerous_tools(self):
        """Test detection of dangerous tools without auth."""
        from agent_security_scanner.core.config import ToolBoundariesConfig
        module = ToolBoundariesModule(ToolBoundariesConfig())

        perm_result = ScanResult(module_name="permission_scanner", target="https://api.test.com/tools/config")
        perm_result.add_finding(Finding(
            id="FIND-perm-test",
            severity=Severity.HIGH,
            category="permissions",
            title="Unrestricted Tool Permissions",
            description="Dangerous tools available without restrictions",
        ))
        perm_result.finalize()

        perm_patch = TOOL_BOUNDARIES_SUBMODULE_PATCHES[0]
        with ExitStack() as stack:
            _patch_submodules(
                stack, TOOL_BOUNDARIES_SUBMODULE_PATCHES,
                {perm_patch: perm_result},
                "https://api.test.com/tools/config",
            )
            # Also mock aiohttp for the local _check_allowed_denied_lists
            stack.enter_context(patch("aiohttp.ClientSession.get"))
            result = module.scan("https://api.test.com/tools/config", timeout=5)

        dangerous_findings = [
            f for f in result.findings
            if "unrestricted" in f.title.lower() or "dangerous" in f.title.lower()
        ]
        assert len(dangerous_findings) >= 1

    def test_scan_tool_chain(self):
        """Test detection of dangerous tool chains."""
        from agent_security_scanner.core.config import ToolBoundariesConfig
        module = ToolBoundariesModule(ToolBoundariesConfig())

        chain_result = ScanResult(module_name="tool_chains", target="https://api.test.com/tools/config")
        chain_result.add_finding(Finding(
            id="FIND-chain-test",
            severity=Severity.HIGH,
            category="tool_chains",
            title="Dangerous Tool Chain Detected",
            description="Tool chain can be exploited for data exfiltration",
        ))
        chain_result.finalize()

        chain_patch = TOOL_BOUNDARIES_SUBMODULE_PATCHES[2]
        with ExitStack() as stack:
            _patch_submodules(
                stack, TOOL_BOUNDARIES_SUBMODULE_PATCHES,
                {chain_patch: chain_result},
                "https://api.test.com/tools/config",
            )
            stack.enter_context(patch("aiohttp.ClientSession.get"))
            result = module.scan("https://api.test.com/tools/config", timeout=5)

        chain_findings = [
            f for f in result.findings
            if "chain" in f.title.lower()
        ]
        assert len(chain_findings) >= 1


class TestRAGSecurityModuleIntegration:
    """Test RAG security module with mock responses."""

    def test_scan_document_poisoning(self):
        """Test detection of document poisoning vulnerability."""
        from agent_security_scanner.core.config import RAGSecurityConfig
        module = RAGSecurityModule(RAGSecurityConfig())

        poison_result = ScanResult(module_name="document_poisoning", target="https://api.test.com/rag/config")
        poison_result.add_finding(Finding(
            id="FIND-poison-test",
            severity=Severity.HIGH,
            category="document_poisoning",
            title="Document Poisoning Vulnerability",
            description="No input validation for RAG documents",
        ))
        poison_result.finalize()

        poison_patch = RAG_SECURITY_SUBMODULE_PATCHES[0]
        with ExitStack() as stack:
            _patch_submodules(
                stack, RAG_SECURITY_SUBMODULE_PATCHES,
                {poison_patch: poison_result},
                "https://api.test.com/rag/config",
            )
            result = module.scan("https://api.test.com/rag/config", timeout=5)

        poisoning_findings = [
            f for f in result.findings
            if "poison" in f.title.lower() or "validation" in f.title.lower()
        ]
        assert len(poisoning_findings) >= 1

    def test_scan_exfiltration_risk(self):
        """Test detection of exfiltration risk."""
        from agent_security_scanner.core.config import RAGSecurityConfig
        module = RAGSecurityModule(RAGSecurityConfig())

        exfil_result = ScanResult(module_name="exfiltration", target="https://api.test.com/rag/config")
        exfil_result.add_finding(Finding(
            id="FIND-exfil-test",
            severity=Severity.HIGH,
            category="exfiltration",
            title="Data Exfiltration Risk",
            description="No egress filtering on RAG responses",
        ))
        exfil_result.finalize()

        exfil_patch = RAG_SECURITY_SUBMODULE_PATCHES[1]
        with ExitStack() as stack:
            _patch_submodules(
                stack, RAG_SECURITY_SUBMODULE_PATCHES,
                {exfil_patch: exfil_result},
                "https://api.test.com/rag/config",
            )
            result = module.scan("https://api.test.com/rag/config", timeout=5)

        exfil_findings = [
            f for f in result.findings
            if "exfiltration" in f.title.lower() or "egress" in f.title.lower()
        ]
        assert len(exfil_findings) >= 1


class TestFullScanWorkflow:
    """Test complete scan workflow with all modules."""

    def test_full_scan_all_modules(self):
        """Test running all modules on a target."""
        from agent_security_scanner.core.config import (
            MisconfigurationsConfig,
            PromptInjectionConfig,
            ToolBoundariesConfig,
            RAGSecurityConfig,
        )

        modules = [
            MisconfigurationsModule(MisconfigurationsConfig()),
            PromptInjectionModule(PromptInjectionConfig()),
            ToolBoundariesModule(ToolBoundariesConfig()),
            RAGSecurityModule(RAGSecurityConfig()),
        ]

        all_results = []
        target = "https://api.test.com/agent"

        # Patch all submodules to return empty results + aiohttp for local checks
        all_patches = (
            MISCONFIG_SUBMODULE_PATCHES
            + PROMPT_INJECTION_SUBMODULE_PATCHES
            + TOOL_BOUNDARIES_SUBMODULE_PATCHES
            + RAG_SECURITY_SUBMODULE_PATCHES
        )

        with ExitStack() as stack:
            _patch_submodules(stack, all_patches, {}, target)
            stack.enter_context(patch("aiohttp.ClientSession.get"))
            stack.enter_context(patch("aiohttp.ClientSession.post"))

            for module in modules:
                result = module.scan(target, timeout=5)
                all_results.append(result)

        # Verify all modules ran
        assert len(all_results) == 4
        assert all_results[0].module_name == "misconfigurations"
        assert "prompt" in all_results[1].module_name
        assert "tool" in all_results[2].module_name
        assert "rag" in all_results[3].module_name

    def test_full_scan_generate_json_report(self):
        """Test generating JSON report from scan results."""
        results = [
            ScanResult(module_name="test", target="https://api.test.com")
        ]
        results[0].add_finding(Finding(
            id="FIND-test-001",
            severity=Severity.MEDIUM,
            category="test",
            title="Test Finding",
            description="Test",
        ))
        results[0].finalize()

        reporter = JSONReport()
        report = reporter.generate(results)

        assert report["summary"]["total"] == 1
        assert len(report["findings"]) == 1

    def test_full_scan_generate_markdown_report(self):
        """Test generating Markdown report from scan results."""
        results = [
            ScanResult(module_name="test", target="https://api.test.com")
        ]
        results[0].add_finding(Finding(
            id="FIND-test-002",
            severity=Severity.HIGH,
            category="test",
            title="High Finding",
            description="Test",
        ))
        results[0].finalize()

        reporter = MarkdownReport()
        report = reporter.generate(results, "https://api.test.com")

        assert "# 🔒 Agent Security Scan Report" in report
        assert "High Finding" in report


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "asyncio"])