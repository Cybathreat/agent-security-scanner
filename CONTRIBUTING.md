# Contributing to Singularity

Thank you for your interest in contributing. This document covers how to get started, submit changes, and maintain code quality.

---

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Submitting Changes](#submitting-changes)
- [Adding New Modules](#adding-new-modules)
- [Code Style](#code-style)
- [Testing](#testing)
- [Reporting Issues](#reporting-issues)

---

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone git@github.com:<your-username>/singularity.git
   cd singularity
   ```
3. Add the upstream remote:
   ```bash
   git remote add upstream git@github.com:Cybathreat/singularity.git
   ```

---

## Development Setup

```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

pip install -r requirements.txt
```

Verify everything works:

```bash
pytest tests/ -v
```

---

## Project Structure

```
singularity/
├── core/
│   ├── engine.py          # Scan orchestration
│   ├── config.py          # Configuration loader (includes QualityGateConfig)
│   ├── quality_gate.py    # CI/CD quality gate evaluation
│   ├── validators.py      # Input validation (SSRF, path traversal)
│   └── logging.py         # Structured logging
├── modules/
│   ├── base.py            # BaseModule ABC, Finding, ScanResult, Severity, SEVERITY_WEIGHT
│   ├── misconfigurations.py
│   ├── prompt_injection.py
│   │   └── submodules/    # Advanced injection techniques
│   │       ├── crescendo.py
│   │       ├── many_shot.py
│   │       └── skeleton_key.py
│   ├── tool_boundaries.py
│   └── rag_security.py
├── output/
│   ├── json_report.py     # Includes quality_gate section when threshold provided
│   └── markdown_report.py
└── cli.py
tests/
├── unit/
└── integration/
```

---

## Submitting Changes

1. Create a branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and write tests.

3. Run the full test suite before committing:
   ```bash
   pytest tests/ -v
   ```

4. Commit with a clear message describing what and why:
   ```bash
   git commit -m "Add X to fix Y"
   ```

5. Push and open a pull request against `main`:
   ```bash
   git push origin feature/your-feature-name
   ```

6. In the PR description, include:
   - What the change does
   - Why it is needed
   - How it was tested

---

## Adding New Modules

New security modules must follow the existing pattern:

### 1. Create the module class

```python
# singularity/modules/your_module.py
from .base import BaseModule, ScanResult, Severity

class YourModule(BaseModule):

    def __init__(self, config=None):
        super().__init__()
        self.config = config or YourModuleConfig()

    def scan(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module_name=self.module_name, target=target)

        # implement checks here
        # use self._create_finding(...) to add findings

        result.finalize()
        return result
```

### 2. Add a config dataclass

```python
# singularity/core/config.py
@dataclass
class YourModuleConfig:
    enabled: bool = True
    # add module-specific options
```

Add it to `ModulesConfig` and `Config.to_dict()`.

### 3. Register in the engine

```python
# singularity/core/engine.py
ALL_MODULES = [..., "your_module"]

# in _build_module():
from ..modules.your_module import YourModule
registry["your_module"] = (YourModule, self.config.modules.your_module)
```

### 4. Export from the modules package

```python
# singularity/modules/__init__.py
from .your_module import YourModule
```

### 5. Write tests

- `tests/unit/test_your_module.py` — test finding logic with mock responses
- `tests/integration/test_full_scan.py` — add an integration test class

---

## Code Style

- Type hints on all function signatures
- Docstrings on all public classes and methods
- Use `self.logger` (bound loguru logger) inside modules, not `print()`
- Follow existing naming conventions: `snake_case` for functions/variables, `PascalCase` for classes

Lint and type check before submitting:

```bash
ruff check singularity/
ruff format --check singularity/
mypy singularity/ --ignore-missing-imports
```

Pre-commit hooks are available:

```bash
pre-commit install   # Auto-run ruff + mypy on every commit
pre-commit run --all-files   # Run manually on all files
```

---

## Testing

| Command | Purpose |
|---------|---------|
| `pytest tests/ -v` | Run all tests |
| `pytest tests/unit/ -v` | Unit tests only |
| `pytest tests/integration/ -v` | Integration tests only |
| `pytest tests/ --cov=singularity --cov-report=html` | Coverage report |
| `pytest tests/ --cov-fail-under=70` | CI coverage gate (70% minimum) |

### Quality Gates

The scanner supports CI/CD quality gates:

```bash
# Fail on HIGH severity or above (default: critical)
python -m singularity.cli scan --target <url> --fail-on high

# Fail if more than 10 findings or risk score exceeds 50
python -m singularity.cli scan --target <url> --max-findings 10 --max-risk-score 50

# Exit codes: 0 = pass, 1 = error, 2 = quality gate failed
echo $?  # Check exit code
```

- All tests must pass before a PR is merged
- New modules require both unit and integration tests
- Mock all HTTP calls in tests — do not make real network requests

---

## Reporting Issues

Open an issue on GitHub with:

- A clear description of the problem
- Steps to reproduce
- Expected vs actual behaviour
- Python version and OS

For security vulnerabilities in the scanner itself, please report privately via GitHub's security advisory feature rather than opening a public issue.

---

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](./LICENSE).
