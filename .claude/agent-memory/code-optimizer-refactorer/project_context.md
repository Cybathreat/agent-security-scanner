---
name: project_context
description: Agent Security Scanner project overview for vulnerability assessment work
type: project
---

The agent-security-scanner is a security auditing tool for LLM agents, RAG pipelines, and agent frameworks. It scans for:
- Prompt injection vulnerabilities
- Tool boundary violations
- RAG security issues
- Misconfigurations (auth, CORS, rate limiting, info disclosure)

**Architecture:**
- `agent_security_scanner/` - Main package
- `src/` - Another copy of source (appears to be duplicate)
- Tests use pytest with mocks, located in `tests/`

**Entry point:** `python -m src.cli scan --target <url>`

**Key modules that were modified:**
- Added `core/validators.py` with SSRF and path traversal protection
- All scanning modules (`misconfigurations`, `prompt_injection`, `rag_security`, `tool_boundaries`) now validate URLs before making HTTP requests
- Report generators and CLI now validate paths before file operations
