# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

---

## [0.1.0] - 2026-03-23

### Added

#### Core
- `ScanEngine` class in `src/core/engine.py` — orchestrates module selection, instantiation, and result aggregation
- `Config` dataclass hierarchy in `src/core/config.py` — hierarchical configuration loading from YAML files and `ASS_*` environment variable overrides
- Structured logging setup via loguru in `src/core/logging.py`

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
