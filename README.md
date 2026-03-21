# Agent Security Scanner

**MVP v0.1** — AI Security Tool for auditing LLM agents, RAG pipelines, and agent frameworks.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Security Research](https://img.shields.io/badge/Security-Research-red.svg)]()

---

## Overview

Agent Security Scanner is an open-source security research tool designed to audit AI agents, LLM-powered applications, and RAG (Retrieval-Augmented Generation) pipelines for security misconfigurations and vulnerabilities.

This tool helps security teams, developers, and researchers identify potential security risks in AI systems before they reach production.

---

## Features (MVP v0.1)

- **Agent Security Misconfiguration Scanning**
  - Detect insecure default configurations
  - Identify missing authentication/authorization controls
  - Check for exposed API endpoints

- **Prompt Injection Detection**
  - Scan for vulnerable prompt templates
  - Identify injection points in user input handling
  - Check for proper input sanitization

- **Tool Calling Boundary Validation**
  - Audit tool permission boundaries
  - Detect overly permissive tool access
  - Validate sandboxing configurations

- **RAG Pipeline Security**
  - Document poisoning detection
  - Data exfiltration risk analysis
  - Vector database security checks

- **Comprehensive Reporting**
  - JSON structured reports
  - Markdown human-readable summaries
  - Framework references (OWASP LLM Top 10, MITRE ATLAS, ANSSI)

---

## Installation

```bash
# Clone the repository
git clone https://github.com/Cybathreat/agent-security-scanner.git
cd agent-security-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

---

## Quick Start

```bash
# Run a basic scan
python -m src.cli scan --target <agent_endpoint> --output output/

# Run with specific modules
python -m src.cli scan --target <agent_endpoint> --modules prompt_injection,rag_security

# Generate JSON report
python -m src.cli scan --target <agent_endpoint> --format json --output report.json

# Generate Markdown summary
python -m src.cli scan --target <agent_endpoint> --format markdown --output summary.md
```

---

## Usage

### Basic Commands

```bash
# Show help
python -m src.cli --help

# Scan with verbose output
python -m src.cli scan --target <target> --verbose

# Scan specific security categories
python -m src.cli scan --target <target> --categories misconfigurations,prompt_injection

# Set log level
python -m src.cli scan --target <target> --log-level DEBUG
```

### Configuration

Create a `config.yaml` file in the `config/` directory:

```yaml
scanner:
  timeout: 30
  max_retries: 3
  rate_limit: 10  # requests per second

modules:
  prompt_injection:
    enabled: true
    sensitivity: high
  
  rag_security:
    enabled: true
    check_poisoning: true
    check_exfiltration: true
```

---

## Module Architecture

```
src/
├── core/           # Core engine and utilities
│   ├── engine.py   # Main scanning engine
│   ├── config.py   # Configuration loader
│   └── logging.py  # Structured logging
├── modules/        # Security scanning modules
│   ├── base.py     # Base module class
│   ├── misconfigurations.py
│   ├── prompt_injection.py
│   ├── tool_boundaries.py
│   └── rag_security.py
├── output/         # Reporting modules
│   ├── json_report.py
│   └── markdown_report.py
└── cli.py          # Command-line interface
```

---

## Security Frameworks Referenced

This tool references the following security frameworks:

- **OWASP LLM Top 10** — Large Language Model security risks
- **MITRE ATLAS** — Adversarial Threat Landscape for AI Systems
- **ANSSI Generative AI Referential** — French cybersecurity agency guidelines

---

## Development

### Running Tests

```bash
# Run unit tests
pytest tests/unit/ -v --cov=src --cov-report=html

# Run integration tests
pytest tests/integration/ -v

# Check code style
ruff check src/
mypy src/
```

### Adding New Modules

1. Create a new module class in `src/modules/`
2. Inherit from `BaseModule`
3. Implement `scan()` method
4. Register in module registry
5. Add unit tests

---

## Output Examples

### JSON Report

```json
{
  "scan_id": "uuid",
  "timestamp": "2026-03-21T06:00:00Z",
  "target": "https://api.example.com/agent",
  "findings": [
    {
      "id": "FIND-001",
      "severity": "HIGH",
      "category": "prompt_injection",
      "description": "Unsanitized user input in system prompt",
      "cwe": "CWE-94",
      "owasp_ref": "LLM01:2024 - Prompt Injection",
      "recommendation": "Implement input validation and sanitization"
    }
  ],
  "summary": {
    "total": 5,
    "critical": 1,
    "high": 2,
    "medium": 1,
    "low": 1
  }
}
```

---

## Disclaimer

This tool is for security research and educational purposes. Use responsibly.
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

---

## Version

**MVP v0.1** — Initial release
