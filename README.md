# Singularity

**v0.2** — Security auditing tool for LLM agents, RAG pipelines, and agent frameworks.

[![CI](https://github.com/Cybathreat/singularity/actions/workflows/ci.yml/badge.svg)](https://github.com/Cybathreat/singularity/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Cybathreat/singularity/branch/main/graph/badge.svg)](https://codecov.io/gh/Cybathreat/singularity)
[![PyPI](https://img.shields.io/pypi/v/singularity.svg)](https://pypi.org/project/singularity/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Security Research](https://img.shields.io/badge/Security-Research-red.svg)]()

---

## Overview

Singularity is an open-source security research tool designed to audit AI agents, LLM-powered applications, and RAG (Retrieval-Augmented Generation) pipelines for security misconfigurations and vulnerabilities.

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
  - Multi-turn injection
  - Adaptive payload generation
  - Crescendo attacks (gradual escalation)
  - Many-shot jailbreaking (long-context manipulation)
  - Skeleton key bypass (disclaim-then-comply)

- **Tool Calling Boundary Validation**
  - Overly permissive tool access
  - Dangerous tool combinations (e.g. read_file + http_request)
  - Sandbox misconfiguration
  - MCP server security
  - Missing allow/deny lists

- **RAG Pipeline Security**
  - Document poisoning detection
  - Data exfiltration risk analysis
  - Vector database security checks
  - Embedding model vulnerabilities
  - Multi-tenant isolation
  - Context window attack surface

- **Agent Attack Scanning**
  - Tool-use hijacking (argument injection, parameter manipulation)
  - Recursive agent exploitation (shared context poisoning)
  - Memory poisoning (persistent false memories across sessions)
  - Planning manipulation (chain-of-thought redirection)

- **Infrastructure Security**
  - Secret scanning (credentials in prompts, responses, headers)
  - Dependency audit (CVE, malicious packages, outdated deps)
  - Plugin/extension security (manifest, permissions, unsigned plugins)

- **Comprehensive Reporting**
  - JSON structured reports with OWASP/MITRE framework mappings
  - Markdown human-readable summaries with remediation guidance
  - Severity-based risk scoring

- **CI/CD Quality Gates**
  - Configurable fail-on-severity thresholds (critical, high, medium, low, info)
  - Maximum findings limits
  - Maximum risk score limits
  - Exit codes: 0 (pass), 1 (error), 2 (gate failed)
  - Pre-commit hooks for ruff and mypy

---

## Installation

### From PyPI

```bash
pip install singularity
```

### From Source

```bash
git clone https://github.com/Cybathreat/singularity.git
cd singularity

python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

pip install -r requirements.txt
```

---

## Quick Start

```bash
# Run a full scan (all modules)
python -m singularity.cli scan --target https://api.example.com/agent --output output/

# Run specific modules only
python -m singularity.cli scan --target https://api.example.com/agent --modules prompt_injection,rag_security

# JSON report only
python -m singularity.cli scan --target https://api.example.com/agent --format json --output output/

# Markdown report only
python -m singularity.cli scan --target https://api.example.com/agent --format markdown --output output/

# Quality gate: fail on HIGH severity or above
python -m singularity.cli scan --target https://api.example.com/agent --fail-on high

# Quality gate: fail if more than 10 findings or risk score exceeds 50
python -m singularity.cli scan --target https://api.example.com/agent --max-findings 10 --max-risk-score 50
```

---

## Usage

### Scan Command

```
python -m singularity.cli scan --target <url> [options]

Options:
  --target,  -t   Target URL or API endpoint (required)
  --modules, -m   Comma-separated modules to run (default: all)
                  Choices: misconfigurations, prompt_injection, tool_boundaries,
                           rag_security, tool_hijacking, recursive_agents,
                           memory_poisoning, planning_attacks, secret_scanner,
                           dependency_audit, plugin_security
  --output,  -o   Output directory for reports (default: output)
  --format,  -f   Report format: json | markdown | both (default: both)
  --config,  -c   Path to YAML config file
  --timeout       Request timeout in seconds (default: 30)
  --verbose, -v   Enable verbose output (includes evidence in reports)
  --log-level     DEBUG | INFO | WARNING | ERROR (default: INFO)
  --dry-run       Load config and modules without executing scan
  --fail-on       Minimum severity to fail the build (critical|high|medium|low|info, default: critical)
  --max-findings  Maximum total findings allowed (default: no limit)
  --max-risk-score Maximum aggregate risk score allowed (default: no limit)
```

### Configuration

Generate a default config file:

```bash
python -m singularity.cli config --generate
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

quality_gate:
  fail_on_severity: critical
  # max_findings: 50
  # max_risk_score: 100

logging:
  level: INFO
```

### Environment Variable Overrides

Configuration can be overridden via environment variables using the `SINGULARITY_` prefix:

```bash
export SINGULARITY_SCANNER_TIMEOUT=60
export SINGULARITY_SCANNER_VERIFY_SSL=false
export SINGULARITY_LOG_LEVEL=DEBUG
export SINGULARITY_OUTPUT_FORMAT=json
export SINGULARITY_QUALITY_GATE_FAIL_ON_SEVERITY=high
export SINGULARITY_QUALITY_GATE_MAX_FINDINGS=50
export SINGULARITY_QUALITY_GATE_MAX_RISK_SCORE=100
```

---

## Architecture

```
singularity/
├── core/
│   ├── engine.py                          # Scan orchestration — module selection and lifecycle
│   ├── config.py                          # YAML + environment variable configuration loader
│   ├── quality_gate.py                    # CI/CD quality gate evaluation (fail_on_severity, max_findings, max_risk_score)
│   ├── validators.py                      # Input validation (SSRF, path traversal protection)
│   └── logging.py                         # Structured logging via loguru
├── modules/
│   ├── base.py                            # BaseModule ABC, Finding, ScanResult, Severity, SEVERITY_WEIGHT, SEVERITY_LEVELS
│   ├── misconfigurations.py               # → misconfig_submodules/
│   │   └── misconfig_submodules/          # auth_scanner, cors_scanner, rate_limit_scanner, info_disclosure_scanner
│   ├── prompt_injection.py                # → prompt_injection_submodules/
│   │   └── prompt_injection_submodules/   # direct_injection, obfuscation, multi_turn, adaptive_generator,
│   │                                       # crescendo, many_shot, skeleton_key
│   ├── tool_boundaries.py                 # → tool_boundaries_submodules/
│   │   └── tool_boundaries_submodules/    # permission_scanner, sandbox_scanner, tool_chains, mcp_scanner
│   ├── rag_security.py                    # → rag_security_submodules/
│   │   └── rag_security_submodules/       # document_poisoning, exfiltration, vector_db, embedding_attacks, multi_tenant
│   ├── agent/                             # Agent-specific attack modules
│   │   ├── tool_hijacking.py
│   │   ├── recursive_agents.py
│   │   ├── memory_poisoning.py
│   │   └── planning_attacks.py
│   └── infrastructure/                    # Infrastructure security modules
│       ├── secret_scanner.py
│       ├── dependency_audit.py
│       └── plugin_security.py
├── output/
│   ├── json_report.py                     # Structured JSON reports (includes quality_gate section)
│   └── markdown_report.py                 # Human-readable Markdown reports
└── cli.py                                 # Command-line interface (with quality gate exit codes)
```

### ScanEngine

The `ScanEngine` class in `singularity/core/engine.py` can be used programmatically:

```python
from singularity.core.config import load_config
from singularity.core.engine import ScanEngine

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
  "$schema": "https://github.com/Cybathreat/singularity/schema/report/v1",
  "report_id": "uuid",
  "generated_at": "2026-03-23T10:00:00Z",
  "scanner": { "name": "Singularity", "version": "0.2.0" },
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
      "id": "FIND-prompt_injection-a1b2c3d4",
      "severity": "HIGH",
      "category": "prompt_injection",
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
  },
  "quality_gate": {
    "passed": false,
    "exit_code": 2,
    "reason": "Quality gate FAILED: 3 findings at or above HIGH severity (1 CRITICAL, 2 HIGH)",
    "summary": { "total": 5, "critical": 1, "high": 2, "medium": 1, "low": 1, "info": 0 },
    "risk_score": 42
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
pytest tests/ -v --cov=singularity --cov-report=html

# Unit tests only
pytest tests/unit/ -v

# Integration tests only
pytest tests/integration/ -v
```

### Adding New Modules

1. Create a new class in `singularity/modules/` inheriting from `BaseModule`
2. Implement the `scan(target, **kwargs) -> ScanResult` method
3. Register it in `singularity/core/engine.py` — add to `ALL_MODULES` and `_build_module()`
4. Add the config dataclass in `singularity/core/config.py`
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

## Roadmap

See [ROADMAP.md](./ROADMAP.md) for planned enhancements across detection, infrastructure attacks, web dashboard, and autonomous red-teaming.

---

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.