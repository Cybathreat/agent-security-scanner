# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Commands

```bash
# Install dependencies (Python 3.10+)
pip install -r requirements.txt

# Tests
pytest tests/ -v --cov=singularity --cov-report=html  # All tests with coverage (70% gate)
pytest tests/unit/ -v                           # Unit tests only
pytest tests/integration/ -v                    # Integration tests only
pytest tests/unit/test_base.py -v               # Single test file
pytest tests/ -k "test_prompt_injection" -v     # Filter by name
pytest tests/ -m integration -v                 # Filter by marker

# Lint & type check
ruff check singularity/
mypy singularity/

# Run the CLI scanner
python -m singularity.cli scan --target <url> --output output/
python -m singularity.cli scan --target <url> --modules prompt_injection,rag_security
python -m singularity.cli scan --target <url> --fail-on high --max-findings 10
python -m singularity.cli config --generate

# Run the web server (FastAPI backend)
python -m singularity.cli web --port 8000 --host 0.0.0.0
# or directly:
uvicorn singularity.web.app:create_app --factory --host 0.0.0.0 --port 8000 --reload

# Run the dashboard (Next.js frontend) — requires Node.js
cd dashboard
npm install
npm run dev      # Dev server on :3000
npm run build    # Production build
npm run lint     # ESLint

# Pre-commit hooks
pre-commit install
pre-commit run --all-files
```

## Architecture

The project has two runtime surfaces: a **CLI scanner** and a **web app** (FastAPI backend + Next.js dashboard).

**Entry point:** `singularity.cli:main()` — argparse-based CLI with `scan`, `config`, and `web` subcommands. PyPI entry point: `singularity` command.

**Exit codes:** 0 = pass, 1 = error, 2 = quality gate failed.

### CLI scanner module hierarchy

The scanner uses a two-tier module system. **Top-level modules** are registered in `ALL_MODULES` and instantiated by `ScanEngine._build_module()`. Many top-level modules delegate internally to **submodules** in their respective `*_submodules/` directories.

```
singularity/
├── core/
│   ├── engine.py      # ScanEngine — ALL_MODULES list, _build_module(), _build_submodule()
│   ├── config.py      # Config dataclasses (one per module), load_config(), env overrides (SINGULARITY_ prefix)
│   ├── quality_gate.py # GateThreshold, GateResult, evaluate() — CI/CD quality gate evaluation
│   └── logging.py     # loguru setup_logger() — console + rotating file + optional JSON
├── modules/
│   ├── base.py        # BaseModule[ConfigT], Finding, ScanResult, Severity, Sensitivity, SEVERITY_WEIGHT, SEVERITY_LEVELS
│   ├── misconfigurations.py        # delegates to misconfig_submodules/ (4 submodules)
│   ├── prompt_injection.py         # delegates to prompt_injection_submodules/ (21 submodules)
│   ├── tool_boundaries.py          # delegates to tool_boundaries_submodules/ (5 submodules)
│   ├── rag_security.py             # delegates to rag_security_submodules/ (7 submodules)
│   ├── agent/                      # tool_hijacking, recursive_agents, memory_poisoning, planning_attacks
│   └── infrastructure/             # secret_scanner, dependency_audit, plugin_security
├── web/                            # FastAPI backend (see Web Stack below)
├── output/
│   ├── json_report.py
│   └── markdown_report.py
└── cli.py
```

The 11 registered modules in `ALL_MODULES` (engine.py): `misconfigurations`, `prompt_injection`, `tool_boundaries`, `rag_security`, `tool_hijacking`, `recursive_agents`, `memory_poisoning`, `planning_attacks`, `secret_scanner`, `dependency_audit`, `plugin_security`.

Modules are **deferred-imported** — only loaded when instantiated by `_build_module()` to keep CLI startup fast.

### Key patterns

**BaseModule[ConfigT] is generic.** Child classes must set `self.config` *before* calling `super().__init__()`, because `__init__` derives `self.module_name` from the class name (strips "Module"/"Scanner", converts PascalCase → snake_case) and creates `self.logger = logger.bind(module=...)`.

**Finding IDs** follow `FIND-{module_name}-{uuid8}` (e.g., `FIND-prompt_injection-a1b2c3d4`).

**Async scan pattern.** Modules use `aiohttp.ClientSession` for HTTP requests. The `BaseModule._run_scan_async()` helper handles the event loop edge case (running inside or outside an existing loop). See `prompt_injection.py:scan()` for the canonical example.

**Config loading order:** defaults → YAML file → env vars (`SINGULARITY_` prefix, e.g., `SINGULARITY_SCANNER_TIMEOUT`, `SINGULARITY_LOG_LEVEL`, `SINGULARITY_OUTPUT_FORMAT`, `SINGULARITY_QUALITY_GATE_FAIL_ON_SEVERITY`).

**Quality gate evaluation.** CLI flags `--fail-on`, `--max-findings`, `--max-risk-score` map to `GateThreshold`. The `evaluate()` function in `core/quality_gate.py` computes risk score as sum of `SEVERITY_WEIGHT` values (critical=100, high=50, medium=10, low=1, info=0) and returns `GateResult` with `passed`, `exit_code`, and `reason`. Default `--fail-on critical`.

### Adding a new module

1. Create module class in `singularity/modules/` inheriting `BaseModule[YourConfig]` — set `self.config` before `super().__init__()`, implement `scan(target, **kwargs) -> ScanResult`
2. Add config dataclass in `singularity/core/config.py`, add field to `ModulesConfig`, add to `Config.to_dict()`
3. Register in `singularity/core/engine.py`:
   - Add name to `ALL_MODULES` list
   - Add deferred import + registry entry in `_build_module()` mapping name → `(Class, self.config.modules.your_module)`
   - If it's a submodule, also add to `ALL_SUBMODULES` dict and `_build_submodule()`
4. Export from `singularity/modules/__init__.py`
5. Add tests in `tests/unit/` and `tests/integration/`
6. Update CLI `--modules` help text in `singularity/cli.py`

### Security frameworks referenced in findings

Findings map to OWASP LLM Top 10, MITRE ATLAS, and ANSSI Generative AI Referential via `cwe`, `owasp_ref`, and `mitre_ref` fields on `Finding`.

## Web Stack

The `singularity web` command starts a **FastAPI** backend that persists scans to SQLite and exposes a REST + WebSocket API consumed by a **Next.js** dashboard.

### Backend (`singularity/web/`)

| File | Purpose |
|------|---------|
| `app.py` | FastAPI factory (`create_app`), lifespan context manager, CORS middleware |
| `db.py` | aiosqlite schema — tables: `scans`, `findings`, `annotations`, `report_sections` |
| `scan_manager.py` | Runs scans in a `ThreadPoolExecutor` (max 2 workers); publishes progress to an `asyncio.Queue` consumed by WebSocket subscribers |
| `models.py` | Pydantic schemas: `ScanRequest`, `ScanDetailResponse`, `FindingResponse`, etc. |
| `api/` | Routers: `scans`, `findings`, `modules`, `quality_gate`, `config`, `replay`, `attack_surface` |
| `ws/scan_progress.py` | WebSocket broadcaster — real-time progress stream per scan |

**Key API routes:**
- `POST /api/scans` — start a scan; `GET /api/scans/{id}` — poll status/results; `DELETE /api/scans/{id}`
- `GET /api/findings` — list with filter by severity/category; `PATCH /api/findings/{id}` — annotate (false positive, notes, assigned_to)
- `GET /api/modules` — available modules
- `WS /ws/scans/{scan_id}/progress` — real-time progress stream

**Background scan flow:** `POST /api/scans` → `ScanManager.start_scan()` enqueues to ThreadPoolExecutor → worker thread runs `ScanEngine.scan()` → publishes `ScanProgressEvent` objects to `asyncio.Queue` → WebSocket handler streams them to the browser.

### Frontend (`dashboard/`)

Next.js 16 + React 19 + TypeScript + Tailwind CSS 4. API requests are proxied via `next.config.ts` rewrites: `/api/*` → `http://localhost:8000/api/*`, `/ws/*` → `http://localhost:8000/ws/*`.

| Route | Purpose |
|-------|---------|
| `/` | Dashboard — KPI cards, recent scans, recent findings |
| `/scans` | New scan form; `/scans/[id]` — live progress (WebSocket) + findings |
| `/findings` | Finding explorer — filter, search, annotate |
| `/comparison` | Side-by-side scan diff |
| `/attack-surface` | Interactive React Flow graph |
| `/replay` | Re-run findings with editable parameters |
| `/reports` | Drag-and-drop report builder (PDF/HTML/JSON export) |
| `/settings` | Quality gate config, module toggles, CI/CD snippet generator |

Key libraries: React Query 5 (data fetching), React Flow 12 (graph), Recharts (charts), html2pdf.js (PDF export), @dnd-kit (drag-drop in report builder).

## Configuration

Default config at `config/config.yaml`. Generate via `python -m singularity.cli config --generate`.

Selected environment variables (full prefix `SINGULARITY_`):

```
SINGULARITY_SCANNER_TIMEOUT        # HTTP timeout per request (default: 10s)
SINGULARITY_SCANNER_VERIFY_SSL     # SSL verification (default: true)
SINGULARITY_LOG_LEVEL              # DEBUG|INFO|WARNING|ERROR
SINGULARITY_LOG_FORMAT             # json|text
SINGULARITY_OUTPUT_FORMAT          # json|markdown
SINGULARITY_QUALITY_GATE_FAIL_ON_SEVERITY   # critical|high|medium|low|info
SINGULARITY_QUALITY_GATE_MAX_FINDINGS       # integer
SINGULARITY_QUALITY_GATE_MAX_RISK_SCORE     # integer
SINGULARITY_CORS_ORIGINS           # comma-separated origins for web server
SINGULARITY_DATA_DIR               # SQLite DB directory (default: ./data)
SINGULARITY_ADAPTIVE_GENERATOR_LLM_API_KEY  # LLM key for adaptive_generator submodule
```
