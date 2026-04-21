# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Commands

```bash
# Install dependencies (Python 3.10+)
pip install -r requirements.txt

# Tests
pytest tests/ -v --cov=agent_security_scanner --cov-report=html  # All tests with coverage
pytest tests/unit/ -v                           # Unit tests only
pytest tests/integration/ -v                    # Integration tests only
pytest tests/unit/test_base.py -v               # Single test file

# Lint & type check
ruff check agent_security_scanner/
mypy agent_security_scanner/

# Run the scanner
python -m agent_security_scanner.cli scan --target <url> --output output/
python -m agent_security_scanner.cli scan --target <url> --modules prompt_injection,rag_security
python -m agent_security_scanner.cli scan --target <url> --fail-on high --max-findings 10
python -m agent_security_scanner.cli config --generate

# Pre-commit hooks
pre-commit install
pre-commit run --all-files
```

## Architecture

**Entry point:** `agent_security_scanner.cli:main()` — argparse-based CLI with `scan` and `config` subcommands. PyPI entry point: `agent-security-scanner` command.

### Module hierarchy

The scanner uses a two-tier module system. **Top-level modules** are registered in `ALL_MODULES` and instantiated by `ScanEngine._build_module()`. Many top-level modules delegate internally to **submodules** in their respective `*_submodules/` directories.

```
agent_security_scanner/
├── core/
│   ├── engine.py      # ScanEngine — ALL_MODULES list, _build_module(), _build_submodule()
│   ├── config.py      # Config dataclasses (one per module), load_config(), env overrides (ASS_ prefix)
│   ├── quality_gate.py # GateThreshold, GateResult, evaluate() — CI/CD quality gate evaluation
│   └── logging.py     # loguru setup_logger() — console + rotating file + optional JSON
├── modules/
│   ├── base.py        # BaseModule[ConfigT], Finding, ScanResult, Severity, Sensitivity, SEVERITY_WEIGHT, SEVERITY_LEVELS
│   ├── misconfigurations.py        # delegates to misconfig_submodules/
│   │   └── misconfig_submodules/   # auth_scanner, cors_scanner, rate_limit_scanner, info_disclosure_scanner
│   ├── prompt_injection.py         # delegates to prompt_injection_submodules/
│   │   └── prompt_injection_submodules/  # direct_injection, obfuscation, multi_turn, adaptive_generator, crescendo, many_shot, skeleton_key
│   ├── tool_boundaries.py          # delegates to tool_boundaries_submodules/
│   │   └── tool_boundaries_submodules/   # permission_scanner, sandbox_scanner, tool_chains, mcp_scanner
│   ├── rag_security.py             # delegates to rag_security_submodules/
│   │   └── rag_security_submodules/      # document_poisoning, exfiltration, vector_db, embedding_attacks, multi_tenant
│   ├── agent/                      # standalone agent attack modules
│   │   ├── tool_hijacking.py
│   │   ├── recursive_agents.py
│   │   ├── memory_poisoning.py
│   │   └── planning_attacks.py
│   └── infrastructure/             # standalone infrastructure modules
│       ├── secret_scanner.py
│       ├── dependency_audit.py
│       └── plugin_security.py
├── output/
│   ├── json_report.py
│   └── markdown_report.py
└── cli.py
```

The 11 registered modules in `ALL_MODULES` (engine.py): `misconfigurations`, `prompt_injection`, `tool_boundaries`, `rag_security`, `tool_hijacking`, `recursive_agents`, `memory_poisoning`, `planning_attacks`, `secret_scanner`, `dependency_audit`, `plugin_security`.

### Key patterns

**BaseModule[ConfigT] is generic.** Child classes must set `self.config` *before* calling `super().__init__()`, because `__init__` derives `self.module_name` from the class name (strips "Module"/"Scanner", converts PascalCase → snake_case) and creates `self.logger = logger.bind(module=...)`.

**Finding IDs** follow `FIND-{module_name}-{uuid8}` (e.g., `FIND-prompt_injection-a1b2c3d4`).

**Async scan pattern.** Modules use `aiohttp.ClientSession` for HTTP requests. The `BaseModule._run_scan_async()` helper handles the event loop edge case (running inside or outside an existing loop). Individual modules that manage their own async also duplicate this pattern — see `prompt_injection.py:scan()` for the canonical example.

**Config loading order:** defaults → YAML file → env vars (`ASS_` prefix, e.g., `ASS_SCANNER_TIMEOUT`, `ASS_LOG_LEVEL`, `ASS_OUTPUT_FORMAT`, `ASS_QUALITY_GATE_FAIL_ON_SEVERITY`).

**Quality gate evaluation.** CLI flags `--fail-on`, `--max-findings`, `--max-risk-score` map to `GateThreshold`. The `evaluate()` function in `core/quality_gate.py` flattens findings, computes risk score (sum of `SEVERITY_WEIGHT` values), and returns `GateResult` with `passed`, `exit_code` (0 or 2), and `reason`. CLI args override config file values. Default `--fail-on critical` is backward compatible with previous hardcoded behavior.

### Adding a new module

1. Create module class in `agent_security_scanner/modules/` inheriting `BaseModule[YourConfig]` — set `self.config` before `super().__init__()`, implement `scan(target, **kwargs) -> ScanResult`
2. Add config dataclass in `agent_security_scanner/core/config.py`, add field to `ModulesConfig`, add to `Config.to_dict()`
3. Register in `agent_security_scanner/core/engine.py`:
   - Add name to `ALL_MODULES` list
   - Add deferred import + registry entry in `_build_module()` mapping name → `(Class, self.config.modules.your_module)`
   - If it's a submodule, also add to `ALL_SUBMODULES` dict and `_build_submodule()`
4. Export from `agent_security_scanner/modules/__init__.py`
5. Add tests in `tests/unit/` and `tests/integration/`
6. Update CLI `--modules` help text in `agent_security_scanner/cli.py`

### Security frameworks referenced in findings

Findings map to OWASP LLM Top 10, MITRE ATLAS, and ANSSI Generative AI Referential via `cwe`, `owasp_ref`, and `mitre_ref` fields on `Finding`.

## Configuration

Default config at `config/config.yaml`. Generate via `python -m agent_security_scanner.cli config --generate`.