# Roadmap

## Current State — v0.2

- Security misconfiguration scanning (auth, CORS, rate limiting, info disclosure)
- Prompt injection detection (17 static payloads + advanced techniques)
- **Advanced injection: Crescendo attacks, Many-shot jailbreaking, Skeleton key bypass**
- Tool calling boundary validation (permissions, dangerous combinations, sandbox, allow/deny lists)
- RAG pipeline security (document poisoning, exfiltration risk, vector DB checks, context window, embedding models)
- JSON + Markdown reporting with OWASP/MITRE mappings and risk scoring
- **SSRF protection** — blocks scanning of internal services, AWS metadata, private IPs
- **Path traversal protection** — validates output paths in reports and configs
- Input validation framework (`core/validators.py`)

---

## Phase 1 — Advanced Detection Engine

**Goal:** Dramatically increase detection capability with realistic, modern attack techniques.

### 1.1 Advanced Prompt Injection Techniques

Replace static payload list with a comprehensive, categorized attack library:

| Technique | Status | Module |
|-----------|--------|--------|
| Multi-turn injection | ✅ Done | `multi_turn.py` |
| Payload splitting | ❌ Pending | — |
| Crescendo attacks | ✅ Done | `crescendo.py` |
| Tree-of-attacks (TAP) | ✅ Done | `tap.py` |
| Many-shot jailbreaking | ✅ Done | `many_shot.py` |
| Skeleton key attacks | ✅ Done | `skeleton_key.py` |
| Virtualization / roleplay | ❌ Pending | — |
| Base64 / rot13 / hex encoding | ❌ Pending | — |
| Multilingual injection | ❌ Pending | — |
| Token smuggling | ❌ Pending | — |
| Grammar-constrained generation | ❌ Pending | — |

### 1.2 LLM-Powered Adaptive Payload Generation

- Integrate an attacker LLM to dynamically generate novel injection payloads tailored to each target
- Mutation loop: if a payload is blocked, auto-modify and retry with variations
- Feedback-driven fuzzing: use response signals to guide payload evolution

### 1.3 Multi-Turn & Crescendo Injection Tests

- Stateful session support: maintain conversation context across multiple turns
- Crescendo attack sequencing: build automated escalation chains
- Session replay and branching: explore multiple attack paths from a common starting state

---

## Phase 2 — Agent-Specific & Advanced Infrastructure Attacks

**Goal:** Cover attack surfaces unique to agentic systems and modern AI infrastructure.

### 2.1 Tool-Use Hijacking

| Scan | Description |
|------|-------------|
| Tool-use hijacking | Inject instructions that cause the agent to call tools with attacker-controlled arguments |
| Recursive agent exploitation | In multi-agent systems, compromise one agent to attack others through shared context |
| Memory poisoning | For agents with persistent memory, inject false memories that persist across sessions |
| Planning manipulation | Alter the agent's chain-of-thought / planning to redirect multi-step workflows |
| MCP server impersonation | Test if tool servers can be spoofed or if the agent validates tool server identity |
| Confused deputy attacks | Trick a privileged agent into performing actions on behalf of an unprivileged user |

### 2.2 Advanced RAG Attacks

| Scan | Description |
|------|-------------|
| Embedding collision attacks | Craft adversarial documents semantically close to target queries in embedding space but containing malicious content |
| Phantom document injection | Test if fake documents can be injected that are only retrieved for specific queries |
| Cross-tenant data leakage | In multi-tenant RAG, test if one tenant's queries can retrieve another tenant's documents |
| Embedding inversion | Test if stored embeddings can be reversed to reconstruct original sensitive text |
| Chunk boundary exploitation | Craft payloads that split across chunk boundaries to evade per-chunk content filters |

### 2.3 Evasion & Defense Bypass Testing

| Technique | Description |
|-----------|-------------|
| Perplexity-based evasion | Craft prompts with low perplexity to dodge statistical anomaly detectors |
| Guardrail fingerprinting | Probe to identify which guardrail system is in use (Lakera, NeMo, Llama Guard, etc.) then use known bypasses |
| Timing side-channels | Measure response latency differences between blocked vs. processed requests to detect shadow filtering |
| Rate limit evasion | Test header spoofing, session rotation, distributed requests |
| WAF fingerprinting & bypass | Identify web application firewalls and test known bypass techniques |
| Canary token detection | Check if the system uses canary tokens / tripwires and test if they can be neutralized |
| Output filter probing | Systematically map what the output filter blocks vs. allows |

### 2.4 Supply Chain & Infrastructure

| Scan | Description |
|------|-------------|
| Model provenance verification | Verify the model hasn't been fine-tuned with backdoors (sleeper agent detection) |
| Dependency audit | Scan agent dependencies for known CVEs and malicious packages |
| API key / secret scanning | Detect leaked credentials in prompts, configs, logs, and error messages |
| Plugin / extension security | Audit third-party plugins and extensions for malicious behavior |

---

## Phase 3 — Intelligence & Automation

**Goal:** Move from point-in-time scanning to continuous, autonomous security intelligence.

**Stack:** React / Next.js frontend + FastAPI backend, WebSocket for real-time updates.

| View | Features |
|------|----------|
| Scan Dashboard | Real-time scan progress with animated attack tree visualization, live finding feed |
| Attack Surface Map | Interactive graph showing all endpoints, tools, data flows — click to drill into findings |
| Finding Explorer | Filterable / sortable table with severity, CWE, OWASP mapping, evidence, and remediation |
| Comparison View | Side-by-side diff of scan results over time — track regression / improvement |
| Replay Console | Replay any attack payload interactively, modify parameters, re-test in real time |
| Report Builder | Drag-and-drop report customization, export to PDF / HTML / JSON, executive summary generator |
| CI/CD Integration Panel | Configure GitHub Actions / GitLab CI hooks, set quality gates (fail build on CRITICAL) |

**Interactive features:**
- Live attack visualization — watch payloads flow through the system in real time
- Finding annotation — mark as false positive, add notes, assign to team members
- Remediation tracking — link findings to fix PRs, track resolution status
- Dark mode

---

## Phase 4 — Web Dashboard (Final Phase)

**Goal:** Replace CLI-only workflow with an interactive dashboard for teams.

**Stack:** React / Next.js frontend + FastAPI backend, WebSocket for real-time updates.

| View | Features |
|------|----------|
| Scan Dashboard | Real-time scan progress with animated attack tree visualization, live finding feed |
| Attack Surface Map | Interactive graph showing all endpoints, tools, data flows — click to drill into findings |
| Finding Explorer | Filterable / sortable table with severity, CWE, OWASP mapping, evidence, and remediation |
| Comparison View | Side-by-side diff of scan results over time — track regression / improvement |
| Replay Console | Replay any attack payload interactively, modify parameters, re-test in real time |
| Report Builder | Drag-and-drop report customization, export to PDF / HTML / JSON, executive summary generator |
| CI/CD Integration Panel | Configure GitHub Actions / GitLab CI hooks, set quality gates (fail build on CRITICAL) |

**Interactive features:**
- Live attack visualization — watch payloads flow through the system in real time
- Finding annotation — mark as false positive, add notes, assign to team members
- Remediation tracking — link findings to fix PRs, track resolution status
- Dark mode

---

## Priority Order

1. Payload splitting — complete Phase 1 injection techniques
2. ~~Tree-of-attacks (TAP)~~ — ✅ Done (static + LLM-powered modes, pruning, 3 attack goals)
3. LLM-powered adaptive payload generation — biggest leap in detection capability
4. Tool-use hijacking scans — critical gap for agentic systems
5. Guardrail fingerprinting & evasion — practical offensive value
6. CI/CD integration — shift-left security adoption driver
7. Cross-tenant RAG leakage testing — high-impact for enterprise
8. Web dashboard with real-time visualization — massive UX improvement (final phase)

---

## Security Hardening (Completed)

| Vulnerability | Severity | Fix |
|---------------|----------|-----|
| SSRF | CRITICAL | URL validation blocks internal IPs, localhost, AWS metadata |
| Path Traversal | HIGH | Path validation in CLI and report generators |
| Missing Input Validation | MEDIUM | New `core/validators.py` framework |

**Confirmed Safe:** No `eval()`, `exec()`, `pickle`, `subprocess`, `yaml.unsafe_load()`, or hardcoded credentials found.
