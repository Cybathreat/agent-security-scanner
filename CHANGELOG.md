# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Added

#### CI/CD Quality Gates
- `core/quality_gate.py` — `GateThreshold`, `GateResult` dataclasses, `evaluate()` function for configurable pass/fail evaluation
- `QualityGateConfig` in `core/config.py` — `fail_on_severity`, `max_findings`, `max_risk_score` with YAML and `ASS_QUALITY_GATE_*` env var overrides
- CLI flags: `--fail-on` (critical/high/medium/low/info), `--max-findings`, `--max-risk-score`
- Exit codes: 0 (pass), 1 (error), 2 (quality gate failed) — backward compatible with previous behavior
- Quality gate results in JSON reports (`quality_gate` section with passed, exit_code, reason, summary, risk_score)
- Scan summary now shows per-severity counts and risk score with PASSED/FAILED verdict
- Pre-commit hooks: `.pre-commit-config.yaml` (ruff lint + format, mypy)
- CI workflow: lint job (ruff + mypy), coverage enforcement (`--cov-fail-under=70`), `fail_ci_if_error: true` for codecov, security gate demo job
- `SEVERITY_WEIGHT` and `SEVERITY_LEVELS` added to `modules/base.py` as canonical definitions
- Tests: `test_quality_gate.py` (36 tests), `test_cli.py` (25 tests)

---

## [0.2.0] - 2026-04-12

### Added

#### Advanced Prompt Injection (Phase 1)
- `CrescendoAttackScanner` — 10-level gradual escalation from benign to malicious requests
- `ManyShotJailbreakingScanner` — long-context attacks with 200+ demonstration pairs across 3 contexts (harmful, jailbreak, data_extraction)
- `SkeletonKeyAttackScanner` — 5 bypass modes detecting disclaim-then-comply pattern

#### Security Hardening
- `core/validators.py` — SSRF protection blocking internal IPs, localhost, AWS metadata endpoints
- Path traversal protection in CLI and report generators
- Input validation framework for URLs, paths, and module names

### Changed
- `PromptInjectionConfig` — added `test_crescendo`, `test_many_shot`, `test_skeleton_key` flags and associated parameters
- `ROADMAP.md` — Phase 1 progress table with module-level status tracking

---

## [0.1.0] - 2026-03-23

### Added

#### Core
- `ScanEngine` class in `agent_security_scanner/core/engine.py` — orchestrates module selection, instantiation, and result aggregation
- `Config` dataclass hierarchy in `agent_security_scanner/core/config.py` — hierarchical configuration loading from YAML files and `ASS_*` environment variable overrides
- Structured logging setup via loguru in `agent_security_scanner/core/logging.py`

#### Security Modules
- `MisconfigurationsModule` — detects missing authentication, CORS misconfigurations, missing rate limiting, information disclosure, and exposed debug endpoints
- `PromptInjectionModule` — tests for direct prompt injection, system prompt leakage, obfuscation/homoglyph bypass, and instruction hijacking
- `ToolBoundariesModule` — audits tool permission boundaries, sandbox configuration, dangerous tool chains, and missing allow/deny lists
- `RAGSecurityModule` — checks for document poisoning, data exfiltration risk, vector database misconfigurations, retrieval manipulation, context window attacks, and embedding vulnerabilities

#### Output
- `JSONReport` — structured JSON reports with flat findings list, severity summary, risk score, and OWASP/MITRE framework mappings
- `MarkdownReport` — human-readable reports with executive summary, findings overview table, detailed findings, module status, and prioritised remediation guidance

#### CLI
- `scan` command with `--target`, `--modules`, `--output`, `--format`, `--config`, `--timeout`, `--verbose`, `--log-level`, `--dry-run` flags
- `config --generate` command to generate a default `config.yaml`

#### Project
- `pyproject.toml` — PyPI packaging, entry point (`agent-security-scanner` CLI command), and build configuration
- Published to PyPI: `pip install agent-security-scanner`
- MIT License
- README with usage, architecture, output examples, and PyPI install instructions
- Contributing guide
- Changelog
- 67 unit and integration tests
