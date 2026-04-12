---
name: security_fixes_applied
description: Security vulnerabilities found and fixed in agent-security-scanner
type: reference
---

## Security Vulnerabilities Fixed

### 1. SSRF (Server-Side Request Forgery) - CRITICAL
**Files affected:** All 4 scanner modules
**Issue:** Targets passed to scan() were not validated before making HTTP requests. An attacker could scan internal services (localhost, AWS metadata at 169.254.169.254, etc.)

**Fix:** Added `core/validators.py` with `validate_url()` function that blocks:
- localhost, 127.0.0.1, ::1, 0.0.0.0
- Private IP ranges (10.x, 172.16-31.x, 192.168.x)
- Link-local addresses (including AWS metadata 169.254.x.x)
- Cloud metadata endpoints (GCP, Azure)
- Non-HTTP/HTTPS schemes

**Applied to:**
- `misconfigurations.py` - `scan()` and `_fetch_url()`
- `prompt_injection.py` - `scan()` and `_send_payload()`
- `rag_security.py` - `scan()` and `_fetch_rag_config()`
- `tool_boundaries.py` - `scan()` and `_fetch_tool_config()`

### 2. Path Traversal - HIGH
**Files affected:** `cli.py`, `json_report.py`, `markdown_report.py`
**Issue:** Output paths were not validated before file operations. Attacker could use `../` to write files outside intended directory.

**Fix:** Added `validate_path()` function that blocks `..` traversal sequences. Applied to:
- `cli.py` - `generate_reports()` and `generate_config()`
- `json_report.py` - `save()`
- `markdown_report.py` - `save()`

### 3. Input Validation - MEDIUM
**Issue:** No input validation on targets, payloads, or file paths
**Fix:** All user inputs are now validated before use

## Verification
- All 67 tests pass after fixes applied
- URL validation correctly blocks: localhost, 127.0.0.1, 169.254.169.254, ftp://, javascript:
- Path validation correctly blocks: `output/../etc/passwd`, `output/..`
