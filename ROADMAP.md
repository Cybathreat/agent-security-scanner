# Roadmap

## Current State — v0.2

- Security misconfiguration scanning (auth, CORS, rate limiting, info disclosure)
- Prompt injection detection (17 static payloads + advanced techniques)
- **Advanced injection: Crescendo attacks, Many-shot jailbreaking, Skeleton key bypass**
- **Phase 1 techniques: Virtualization, encoding bypass, multilingual, token smuggling, grammar-constrained**
- Tool calling boundary validation (permissions, dangerous combinations, sandbox, allow/deny lists)
- RAG pipeline security (document poisoning, exfiltration, vector DB, embedding attacks, multi-tenant)
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
| Payload splitting | ✅ Done | `payload_splitting.py` |
| Crescendo attacks | ✅ Done | `crescendo.py` |
| Tree-of-attacks (TAP) | ✅ Done | `tap.py` |
| Many-shot jailbreaking | ✅ Done | `many_shot.py` |
| Skeleton key attacks | ✅ Done | `skeleton_key.py` |
| Virtualization / roleplay | ✅ Done | `virtualization.py` |
| Base64 / rot13 / hex encoding | ✅ Done | `encoding_bypass.py` |
| Multilingual injection | ✅ Done | `multilingual.py` |
| Token smuggling | ✅ Done | `token_smuggling.py` |
| Grammar-constrained generation | ✅ Done | `grammar_constrained.py` |

### 1.2 LLM-Powered Adaptive Payload Generation ✅ Done

- Integrate an attacker LLM to dynamically generate novel injection payloads tailored to each target
- Mutation loop: if a payload is blocked, auto-modify and retry with variations
- Feedback-driven fuzzing: use response signals to guide payload evolution
- Dual-mode: static (8 mutation strategies) + optional LLM-powered refinement, heuristic scoring, pruning

### 1.3 Multi-Turn & Crescendo Injection Tests

- Stateful session support: maintain conversation context across multiple turns
- Crescendo attack sequencing: build automated escalation chains
- Session replay and branching: explore multiple attack paths from a common starting state

---

## Phase 2 — Agent-Specific & Advanced Infrastructure Attacks

**Goal:** Cover attack surfaces unique to agentic systems and modern AI infrastructure.

### 2.1 Tool-Use Hijacking

| Scan | Status | Module |
|------|--------|--------|
| Tool-use hijacking | ✅ Done | `tool_hijacking.py` (6 arg injection + 3 param manipulation + 3 tool validation payloads) |
| Recursive agent exploitation | ✅ Done | `recursive_agents.py` (3 shared context + 3 agent validation + 3 context poisoning payloads) |
| Memory poisoning | ✅ Done | `memory_poisoning.py` (4 memory injection + 3 session integrity + 3 history poisoning payloads) |
| Planning manipulation | ✅ Done | `planning_attacks.py` (3 plan validation + 3 step injection + 3 goal manipulation payloads) |
| MCP server impersonation | ✅ Done | `mcp_scanner.py` (3 server impersonation + 3 token forgery + 3 auth bypass payloads) |
| Confused deputy attacks | ✅ Done | `confused_deputy.py` (3 privilege escalation + 3 cross-user + 3 context manipulation payloads) |

### 2.2 Advanced RAG Attacks

| Scan | Status | Module |
|------|--------|--------|
| Embedding collision attacks | ✅ Done | `embedding_attacks.py` (3 adversarial + 3 inversion + 3 collision + 3 fine-tune payloads) |
| Phantom document injection | ✅ Done | `phantom_document.py` (3 phantom injection + 3 retrieval manipulation + 3 context injection payloads) |
| Cross-tenant data leakage | ✅ Done | `multi_tenant.py` (3 tenant isolation + 3 query filtering + 3 tenant awareness payloads) |
| Embedding inversion | ✅ Done | Covered in `embedding_attacks.py` |
| Data exfiltration | ✅ Done | `exfiltration.py` (3 exfil indicators + 3 egress control + 3 query monitoring payloads) |
| Vector DB injection | ✅ Done | `vector_db.py` (3 auth bypass + 3 encryption + 3 public access + 3 vector injection payloads) |
| Chunk boundary exploitation | ✅ Done | `chunk_boundary.py` (3 cross-chunk + 3 boundary evasion + 3 reassembly payloads) |

### 2.3 Evasion & Defense Bypass Testing

| Technique | Status | Module |
|-----------|--------|--------|
| Perplexity-based evasion | ✅ Done | `perplexity_evasion.py` (3 low-perplexity + 3 statistical mimicry + 3 fluency payloads) |
| Guardrail fingerprinting | ✅ Done | `guardrail_fingerprinting.py` |
| Timing side-channels | ✅ Done | `timing_sidechannels.py` (3 latency probing + 3 shadow filter + 3 threshold mapping payloads) |
| Rate limit evasion | ✅ Done | `rate_limit_evasion.py` (3 header spoofing + 3 session rotation + 3 distributed request payloads) |
| WAF fingerprinting & bypass | ✅ Done | `waf_fingerprinting.py` (3 WAF detection + 3 bypass testing + 3 encoding tricks payloads) |
| Canary token detection | ✅ Done | `canary_tokens.py` (3 token discovery + 3 neutralization + 3 bypass payloads) |
| Output filter probing | ✅ Done | `output_filter_probing.py` (3 filter mapping + 3 boundary testing + 3 encoding bypass payloads) |

### 2.4 Supply Chain & Infrastructure

| Scan | Status | Module |
|------|--------|--------|
| Model provenance verification | ✅ Done | `model_provenance.py` (3 sleeper agent + 3 model fingerprint + 3 backdoor payloads) |
| Dependency audit | ✅ Done | `dependency_audit.py` (3 CVE + 3 malicious package + 3 outdated dependency payloads) |
| API key / secret scanning | ✅ Done | `secret_scanner.py` (3 prompt extraction + 3 response extraction + 3 header extraction payloads) |
| Plugin / extension security | ✅ Done | `plugin_security.py` (3 manifest + 3 permission + 3 unsigned plugin payloads) |

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

1. ~~Payload splitting~~ — ✅ Done (5 strategies: message, field, token, header, multi-payload; 4 attack goals)
2. ~~Tree-of-attacks (TAP)~~ — ✅ Done (static + LLM-powered modes, pruning, 3 attack goals)
3. ~~LLM-powered adaptive payload generation~~ — ✅ Done (static + LLM-powered dual mode, 8 mutation strategies, 4 attack goals, heuristic scoring with pruning)
4. ~~Tool-use hijacking scans~~ — ✅ Done (payload-based: 6 arg injection + 3 param manipulation + 3 tool validation payloads)
5. ~~Guardrail fingerprinting & evasion~~ — ✅ Done (5 guardrail signatures, 6 evasion techniques, fingerprint + bypass)
6. ~~Memory poisoning~~ — ✅ Done (4 memory injection + 3 session integrity + 3 history poisoning payloads)
7. ~~Recursive agent exploitation~~ — ✅ Done (3 shared context + 3 agent validation + 3 context poisoning payloads)
8. ~~Planning manipulation~~ — ✅ Done (3 plan validation + 3 step injection + 3 goal manipulation payloads)
9. ~~Embedding attacks~~ — ✅ Done (3 adversarial + 3 inversion + 3 collision + 3 fine-tune payloads)
10. ~~Multi-tenant leakage~~ — ✅ Done (3 tenant isolation + 3 query filtering + 3 tenant awareness payloads)
11. ~~Exfiltration~~ — ✅ Done (3 exfil indicators + 3 egress control + 3 query monitoring payloads)
12. ~~Vector DB security~~ — ✅ Done (3 auth bypass + 3 encryption + 3 public access + 3 vector injection payloads)
13. ~~Dependency audit~~ — ✅ Done (3 CVE + 3 malicious package + 3 outdated dependency payloads)
14. ~~Plugin security~~ — ✅ Done (3 manifest + 3 permission + 3 unsigned plugin payloads)
15. ~~Secret scanner~~ — ✅ Done (3 prompt extraction + 3 response extraction + 3 header extraction payloads)
16. ~~MCP server impersonation~~ — ✅ Done (3 server impersonation + 3 token forgery + 3 auth bypass payloads)
17. ~~Confused deputy attacks~~ — ✅ Done (3 privilege escalation + 3 cross-user + 3 context manipulation payloads)
18. ~~Phantom document injection~~ — ✅ Done (3 phantom injection + 3 retrieval manipulation + 3 context injection payloads)
19. ~~Chunk boundary exploitation~~ — ✅ Done (3 cross-chunk + 3 boundary evasion + 3 reassembly payloads)
20. ~~Model provenance verification~~ — ✅ Done (3 sleeper agent + 3 model fingerprint + 3 backdoor payloads)
21. ~~Perplexity evasion~~ — ✅ Done (3 low-perplexity + 3 statistical mimicry + 3 fluency payloads)
22. ~~Timing side-channels~~ — ✅ Done (3 latency probing + 3 shadow filter + 3 threshold mapping payloads)
23. ~~Rate limit evasion~~ — ✅ Done (3 header spoofing + 3 session rotation + 3 distributed request payloads)
24. ~~WAF fingerprinting~~ — ✅ Done (3 WAF detection + 3 bypass testing + 3 encoding tricks payloads)
25. ~~Canary token detection~~ — ✅ Done (3 token discovery + 3 neutralization + 3 bypass payloads)
26. ~~Output filter probing~~ — ✅ Done (3 filter mapping + 3 boundary testing + 3 encoding bypass payloads)
27. CI/CD integration — shift-left security adoption driver
28. Web dashboard with real-time visualization — massive UX improvement (final phase)

---

## Security Hardening (Completed)

| Vulnerability | Severity | Fix |
|---------------|----------|-----|
| SSRF | CRITICAL | URL validation blocks internal IPs, localhost, AWS metadata |
| Path Traversal | HIGH | Path validation in CLI and report generators |
| Missing Input Validation | MEDIUM | New `core/validators.py` framework |

**Confirmed Safe:** No `eval()`, `exec()`, `pickle`, `subprocess`, `yaml.unsafe_load()`, or hardcoded credentials found.
