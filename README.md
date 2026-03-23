# Agent Security Scanner

**v0.1** — Security auditing tool for LLM agents, RAG pipelines, and agent frameworks.

[![PyPI](https://img.shields.io/pypi/v/agent-security-scanner.svg)](https://pypi.org/project/agent-security-scanner/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Security Research](https://img.shields.io/badge/Security-Research-red.svg)]()

---

## Overview

Agent Security Scanner is an open-source security research tool designed to audit AI agents, LLM-powered applications, and RAG (Retrieval-Augmented Generation) pipelines for security misconfigurations and vulnerabilities.

This tool helps security teams, developers, and researchers identify potential security risks in AI systems before they reach production.

---

## Features

- **Security Misconfiguration Scanning**
  - Missing authentication/authorization controls
  - CORS misconfigurations
  - Missing rate limiting
  - Information disclosure in error responses
  - Exposed debug endpoints

- **Prompt Injection Detection**
  - Direct prompt injection
  - System prompt leakage
  - Obfuscation/homoglyph bypass
  - Instruction hijacking via context manipulation

- **Tool Calling Boundary Validation**
  - Overly permissive tool access
  - Dangerous tool combinations (e.g. read_file + http_request)
  - Sandbox misconfiguration
  - Missing allow/deny lists

- **RAG Pipeline Security**
  - Document poisoning detection
  - Data exfiltration risk analysis
  - Vector database security checks
  - Context window attack surface
  - Embedding model vulnerabilities

- **Comprehensive Reporting**
  - JSON structured reports with OWASP/MITRE framework mappings
  - Markdown human-readable summaries with remediation guidance
  - Severity-based risk scoring

---

## Installation

### From PyPI

```bash
pip install agent-security-scanner
```

### From Source

```bash
git clone https://github.com/Cybathreat/agent-security-scanner.git
cd agent-security-scanner

python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

pip install -r requirements.txt
```

---

## Quick Start

```bash
# Run a full scan (all modules)
python -m src.cli scan --target https://api.example.com/agent --output output/

# Run specific modules only
python -m src.cli scan --target https://api.example.com/agent --modules prompt_injection,rag_security

# JSON report only
python -m src.cli scan --target https://api.example.com/agent --format json --output output/

# Markdown report only
python -m src.cli scan --target https://api.example.com/agent --format markdown --output output/
```

---

## Usage

### Scan Command

```
python -m src.cli scan --target <url> [options]

Options:
  --target,  -t   Target URL or API endpoint (required)
  --modules, -m   Comma-separated modules to run (default: all)
                  Choices: misconfigurations, prompt_injection, tool_boundaries, rag_security
  --output,  -o   Output directory for reports (default: output)
  --format,  -f   Report format: json | markdown | both (default: both)
  --config,  -c   Path to YAML config file
  --timeout       Request timeout in seconds (default: 30)
  --verbose, -v   Enable verbose output (includes evidence in reports)
  --log-level     DEBUG | INFO | WARNING | ERROR (default: INFO)
  --dry-run       Load config and modules without executing scan
```

### Configuration

Generate a default config file:

```bash
python -m src.cli config --generate
```

Or create `config/config.yaml` manually:

```yaml
scanner:
  timeout: 30
  max_retries: 3
  rate_limit: 10.0   # requests per second
  verify_ssl: true

modules:
  prompt_injection:
    enabled: true
    sensitivity: high
    detect_obfuscation: true

  rag_security:
    enabled: true
    check_poisoning: true
    check_exfiltration: true
    vector_db_scan: true

  tool_boundaries:
    enabled: true
    check_permissions: true
    audit_sandbox: true

  misconfigurations:
    enabled: true
    check_auth: true
    check_cors: true
    check_rate_limiting: true
    check_info_disclosure: true

output:
  format: both
  output_dir: output
  verbose: false

logging:
  level: INFO
```

### Environment Variable Overrides

Configuration can be overridden via environment variables using the `ASS_` prefix:

```bash
export ASS_SCANNER_TIMEOUT=60
export ASS_SCANNER_VERIFY_SSL=false
export ASS_LOG_LEVEL=DEBUG
export ASS_OUTPUT_FORMAT=json
```

---

## Architecture

```
src/
├── core/
│   ├── engine.py        # Scan orchestration — module selection and lifecycle
│   ├── config.py        # YAML + environment variable configuration loader
│   └── logging.py       # Structured logging via loguru
├── modules/
│   ├── base.py          # BaseModule ABC, Finding, ScanResult, Severity
│   ├── misconfigurations.py
│   ├── prompt_injection.py
│   ├── tool_boundaries.py
│   └── rag_security.py
├── output/
│   ├── json_report.py   # Structured JSON reports
│   └── markdown_report.py  # Human-readable Markdown reports
└── cli.py               # Command-line interface
```

### ScanEngine

The `ScanEngine` class in `src/core/engine.py` can be used programmatically:

```python
from src.core.config import load_config
from src.core.engine import ScanEngine

config = load_config("config/config.yaml")
engine = ScanEngine(config)

results = engine.run(
    target="https://api.example.com/agent",
    modules=["prompt_injection", "misconfigurations"],
    timeout=30,
)
```

---

## Output Examples

### JSON Report

```json
{
  "$schema": "https://github.com/Cybathreat/agent-security-scanner/schema/report/v1",
  "report_id": "uuid",
  "generated_at": "2026-03-23T10:00:00Z",
  "scanner": { "name": "Agent Security Scanner", "version": "0.1.0" },
  "target": "https://api.example.com/agent",
  "summary": {
    "total": 5,
    "critical": 1,
    "high": 2,
    "medium": 1,
    "low": 1,
    "risk_score": 42
  },
  "findings": [
    {
      "id": "FIND-promptinjection-a1b2c3d4",
      "severity": "HIGH",
      "category": "promptinjection",
      "title": "Direct Prompt Injection Vulnerability",
      "description": "...",
      "cwe": "CWE-94",
      "owasp_ref": "OWASP LLM01:2024 - Prompt Injection",
      "mitre_ref": "MITRE ATLAS - TA0045 LLM Attack",
      "recommendation": "..."
    }
  ],
  "frameworks": {
    "owasp_llm_top_10": { "OWASP LLM01:2024 - Prompt Injection": ["FIND-..."] },
    "mitre_atlas": { "MITRE ATLAS - TA0045 LLM Attack": ["FIND-..."] }
  }
}
```

### Markdown Report

Reports include an executive summary, findings overview table, detailed findings with remediation guidance, and a module status summary. Pass `--verbose` to include raw evidence per finding.

---

## Security Frameworks Referenced

- **OWASP LLM Top 10** — Large Language Model security risks
- **MITRE ATLAS** — Adversarial Threat Landscape for AI Systems
- **ANSSI Generative AI Referential** — French cybersecurity agency guidelines

---

## Development

### Running Tests

```bash
# Run all tests with coverage
pytest tests/ -v --cov=src --cov-report=html

# Unit tests only
pytest tests/unit/ -v

# Integration tests only
pytest tests/integration/ -v
```

### Adding New Modules

1. Create a new class in `src/modules/` inheriting from `BaseModule`
2. Implement the `scan(target, **kwargs) -> ScanResult` method
3. Register it in `src/core/engine.py` — add to `ALL_MODULES` and `_build_module()`
4. Add the config dataclass in `src/core/config.py`
5. Add unit and integration tests

---

## Disclaimer

This tool is for security research and educational purposes. Use responsibly and only against systems you are authorised to test.
See [DISCLAIMER.md](./DISCLAIMER.md) for complete legal disclaimers.

---

## License

MIT License — see [LICENSE](./LICENSE) for details.

---

## Author

**Ahmed Chiboub (Cybathreat)**
- CEO & Founder, Cyberian Defenses
- GitHub: [@Cybathreat](https://github.com/cybathreat)
- LinkedIn: [Ahmed Chiboub](https://www.linkedin.com/in/ahmed-chiboub/)

---

## Contributing

Contributions welcome! Please read our contributing guidelines and submit PRs.
