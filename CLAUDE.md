# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Agent Security Scanner is a security auditing tool for LLM agents, RAG pipelines, and agent frameworks. It scans for prompt injection, tool boundary violations, RAG security issues, and misconfigurations.

**Author:** Ahmed Chiboub (Cybathreat) - CEO & Founder, Cyberian Defenses

## Common Commands

### Installation
```bash
pip install -r requirements.txt
```

### Running Tests
```bash
pytest tests/ -v --cov=src --cov-report=html  # All tests with coverage
pytest tests/unit/ -v                           # Unit tests only
pytest tests/integration/ -v                    # Integration tests only
```

### Running the Scanner
```bash
python -m src.cli scan --target <url> --output output/
python -m src.cli scan --target <url> --modules prompt_injection,rag_security
python -m src.cli config --generate  # Generate default config
```

### Code Quality
```bash
ruff check .          # Lint with ruff
mypy src/             # Type check
```

## Architecture

```
src/
├── core/
│   ├── engine.py      # ScanEngine - orchestrates module selection and lifecycle
│   ├── config.py      # load_config() - YAML + env var configuration loader
│   └── logging.py     # loguru-based structured logging
├── modules/
│   ├── base.py        # BaseModule ABC, Finding, ScanResult, Severity dataclasses
│   ├── misconfigurations.py
│   ├── prompt_injection.py
│   ├── tool_boundaries.py
│   └── rag_security.py
├── output/
│   ├── json_report.py
│   └── markdown_report.py
└── cli.py
```

**Entry point:** `src.cli:main()`

### Key Classes
- `ScanEngine` (src/core/engine.py): Run scans programmatically via `engine.run(target, modules, timeout)`
- `BaseModule` (src/modules/base.py): Abstract base for all scanner modules - implement `scan(target, **kwargs) -> ScanResult`
- `Finding`, `ScanResult` (src/modules/base.py): Result dataclasses with severity, CWE, OWASP/MITRE mappings

### Adding New Modules
1. Create module class inheriting from `BaseModule` in `src/modules/`
2. Implement `scan(target, **kwargs) -> ScanResult`
3. Register in `ALL_MODULES` dict and `_build_module()` in `src/core/engine.py`
4. Add config dataclass in `src/core/config.py`
5. Add tests in `tests/`

## Security Frameworks Referenced
- OWASP LLM Top 10
- MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
- ANSSI Generative AI Referential

## Configuration

Config loaded from `config/config.yaml` with environment variable overrides using `ASS_` prefix (e.g., `ASS_SCANNER_TIMEOUT=60`).
