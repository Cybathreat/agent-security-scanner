# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Commands

```bash
# Install dependencies (Python 3.10+)
pip install -r requirements.txt
# or with optional groups (pyproject.toml):
pip install -e ".[web]"    # web server deps
pip install -e ".[dev]"    # dev/test deps

# Tests
pytest tests/ -v --cov=singularity --cov-report=html  # All tests with coverage (70% gate)
pytest tests/unit/ -v                           # Unit tests only
pytest tests/integration/ -v                    # Integration tests only
pytest tests/unit/test_base.py -v               # Single test file
pytest tests/ -k "test_prompt_injection" -v     # Filter by name
pytest tests/ -m integration -v                 # Filter by marker
# asyncio_mode = "auto" (set in pyproject.toml) — no @pytest.mark.asyncio needed

# Lint & type check
ruff check singularity/        # line-length=100, target py310
mypy singularity/

# Run the CLI scanner
python -m singularity.cli scan --target <url> --output output/
python -m singularity.cli scan --target <url> --modules prompt_injection,rag_security
python -m singularity.cli scan --target <url> --fail-on high --max-findings 10
python -m singularity.cli scan --target <url> --bearer-token <token>
python -m singularity.cli scan --target <url> --auth-header "X-API-Key: abc" --api-format openai
python -m singularity.cli config --generate

# Run the autonomous agent scanner
python -m singularity.cli agent --target <url> --agent-model anthropic/claude-opus-4-8 --agent-key <key>
python -m singularity.cli agent --target <url> --agent-model openai/gpt-4o --agent-key <key> --max-iterations 30

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

The project has three runtime surfaces: a **CLI scanner**, an **autonomous agent scanner**, and a **web app** (FastAPI backend + Next.js dashboard). Entry point: `singularity.cli:main()` — argparse CLI with `scan`, `agent`, `config`, and `web` subcommands. PyPI entry point: `singularity` command (pyproject.toml).

**Exit codes:** 0 = pass, 1 = error, 2 = quality gate failed.

### CLI scanner module hierarchy

The scanner uses a two-tier module system. **Top-level modules** are registered in `ALL_MODULES` and instantiated by `ScanEngine._build_module()`. Most delegate internally to **submodules** in their `*_submodules/` directories.

```
singularity/
├── core/
│   ├── engine.py      # ScanEngine — ALL_MODULES, _build_module(), _build_submodule(), _run_gateway_discovery()
│   ├── config.py      # Config dataclasses (one per module/submodule), load_config(), env overrides
│   ├── quality_gate.py # GateThreshold, GateResult, evaluate()
│   └── logging.py     # loguru setup_logger() — console + rotating file + optional JSON
├── modules/
│   ├── base.py        # BaseModule[ConfigT], Finding, ScanResult, Severity, Sensitivity, SEVERITY_WEIGHT
│   ├── gateway_discovery.py          # Phase 0 — LLM endpoint fingerprinting (run before main modules)
│   ├── misconfigurations.py          # → misconfig_submodules/ (auth, cors, rate_limit, info_disclosure)
│   ├── prompt_injection.py           # → prompt_injection_submodules/ (21 submodules)
│   ├── tool_boundaries.py            # → tool_boundaries_submodules/ (permission, sandbox, tool_chains, mcp, confused_deputy)
│   ├── rag_security.py               # → rag_security_submodules/ (document_poisoning, exfiltration, vector_db, embedding_attacks, multi_tenant, phantom_document, chunk_boundary)
│   ├── agent/                        # tool_hijacking, recursive_agents, memory_poisoning, planning_attacks
│   └── infrastructure/               # secret_scanner, dependency_audit, plugin_security, model_provenance
├── agent/             # Autonomous agent scanner (see Agent Scanner section)
├── web/               # FastAPI backend (see Web Stack section)
├── output/
│   ├── json_report.py
│   └── markdown_report.py
└── cli.py
```

The 11 registered modules in `ALL_MODULES` (engine.py): `misconfigurations`, `prompt_injection`, `tool_boundaries`, `rag_security`, `tool_hijacking`, `recursive_agents`, `memory_poisoning`, `planning_attacks`, `secret_scanner`, `dependency_audit`, `plugin_security`.

**Phase 0** (`gateway_discovery`) runs before all modules via `ScanEngine._run_gateway_discovery()` and returns an `LLMGatewayProfile` (endpoint format, auth scheme, model fingerprint) that informs subsequent modules. It is not in `ALL_MODULES` and cannot be selected via `--modules`.

Modules are **deferred-imported** — only loaded when instantiated by `_build_module()`.

### Key patterns

**BaseModule[ConfigT] is generic.** Child classes must set `self.config` *before* calling `super().__init__()`, because `__init__` derives `self.module_name` from the class name (strips "Module"/"Scanner", converts PascalCase → snake_case) and creates `self.logger = logger.bind(module=...)`.

**Finding IDs** follow `FIND-{module_name}-{uuid8}` (e.g., `FIND-prompt_injection-a1b2c3d4`).

**Async scan pattern.** Modules use `aiohttp.ClientSession` for HTTP requests. The `BaseModule._run_scan_async()` helper handles the event loop edge case (running inside or outside an existing loop). See `prompt_injection.py:scan()` for the canonical example.

**Config loading order:** defaults → YAML file → env vars (`SINGULARITY_` prefix, e.g., `SINGULARITY_SCANNER_TIMEOUT`, `SINGULARITY_LOG_LEVEL`, `SINGULARITY_OUTPUT_FORMAT`, `SINGULARITY_QUALITY_GATE_FAIL_ON_SEVERITY`).

**Quality gate evaluation.** CLI flags `--fail-on`, `--max-findings`, `--max-risk-score` map to `GateThreshold`. The `evaluate()` function in `core/quality_gate.py` computes risk score as sum of `SEVERITY_WEIGHT` values (critical=100, high=50, medium=10, low=1, info=0) and returns `GateResult` with `passed`, `exit_code`, and `reason`. Default `--fail-on critical`.

### Agent scanner (`singularity/agent/`)

The `agent` CLI subcommand runs an **autonomous ReAct-style security research loop** driven by an LLM via [litellm](https://docs.litellm.ai/) (supports Anthropic, OpenAI, Ollama, OpenRouter, KIMI — pass any litellm model string to `--agent-model`).

| File | Purpose |
|------|---------|
| `loop.py` | `AgentLoop` — appends messages, calls LLM, dispatches tools, loops until "SCAN COMPLETE" or `max_iterations` |
| `tools.py` | 9 async tools: `http_request`, `idor_header_test`, `run_auth_scan`, `run_rate_limit_test`, `run_prompt_injection_scan`, `tool_schema_injection`, `run_tool_boundary_test`, `behavioral_comparison`, `save_finding` |
| `llm_client.py` | `LLMClient` — thin litellm wrapper, normalises provider-specific kwargs |
| `system_prompt.py` | `SYSTEM_PROMPT` constant — 7-phase methodology: Reconnaissance, Auth, Rate Limiting, Prompt Injection, Tool Schema Injection, Tool Boundary, Synthesis |
| `findings.py` | `AgentFinding` dataclass — mirrors `Finding` but sourced from agent tool calls |

Agent config lives in `AgentConfig` → `AgentLLMConfig` + `AgentLoopConfig` in `core/config.py`, and under the `agent:` key in `config/config.yaml`.

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
- `GET /api/config`, `PATCH /api/config` — read/update scanner configuration at runtime
- `POST /api/replay` — replay a finding with modified parameters
- `GET /api/attack-surface` — graph data for the attack surface map
- `WS /ws/scans/{scan_id}/progress` — real-time progress stream

**Background scan flow:** `POST /api/scans` → `ScanManager.start_scan()` enqueues to `ThreadPoolExecutor` → worker thread runs `ScanEngine.scan()` → publishes `ScanProgressEvent` objects to `asyncio.Queue` → WebSocket handler streams them to the browser.

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
