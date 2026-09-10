# AI SOC Investigator — Public Demo Release Checklist

This checklist confirms that the application is hardened and verified safe for public sharing (e.g. LinkedIn, portfolio demos, recruiter assessments).

---

## 1. Public Access & Scope
- [x] **Production Domain**: Publicly accessible without requiring private internal VPNs or secret URLs.
- [x] **Preview Deployments**: Protected or disabled to prevent internal testing builds from being publicly scraped.
- [x] **Demo Mode Support**: Seamless exploration enabled for recruiters without captcha frustration or false-positive rate-limit locks.
- [x] **Zero Debug Backdoors**: All development tracebacks, database consoles, and debug flags disabled in production.

---

## 2. Secrets & Credential Isolation
- [x] **Zero Code Secrets**: No hardcoded API keys, JWT signing keys, passwords, or tokens in source code.
- [x] **Zero Frontend Leakage**: Client JavaScript bundles contain zero backend credentials or connection strings.
- [x] **Git Cleanliness**: `.gitignore` and `.dockerignore` prevent committing or containerizing `.env`, local certificates, or keys.
- [x] **Dynamic Secrets**: Secrets injected strictly via server-side environment variables (`JWT_SECRET_KEY`, `SOC_AGENT_API_KEY`).

---

## 3. API & Ingress Hardening
- [x] **Authentication & RBAC**: Stateful operations require valid JWT tokens with `ADMIN`, `ANALYST`, or `AGENT` roles.
- [x] **Abuse & Rate Limiting**: Global sliding-window limiter (150 req/min) and per-operation caps (AI hunts, uploads, replays).
- [x] **Payload Caps**: 25MB maximum upload limit (`HTTP 413`), 2000-character input caps, and 64KB event payload bounds.
- [x] **Safe Error Masking**: Generic error details with `X-Request-ID` correlation; zero stack traces, server paths, or SQL details exposed.

---

## 4. Real-Time Telemetry & Agent Gateway
- [x] **Agent Authentication**: Only authenticated Linux agents or admins can post events to `/api/v1/events`.
- [x] **Anti-Impersonation**: Agent registration identity is cryptographically bound to caller identity.
- [x] **Replay & Sequence Guards**: Monotonic sequence checking rejects duplicate and out-of-order event delivery.
- [x] **Zero Remote Code Execution**: Telemetry agent is purely outbound, read-only, and standard-library based.

---

## 5. AI Threat Hunter & Tool Gateway
- [x] **Prompt Injection Defense**: Security telemetry marked untrusted; multi-pattern scanner detects instruction overrides.
- [x] **Strict Tool Allowlist**: Only approved read-only analytical tools can be invoked by the AI investigator.
- [x] **Zero Shell Execution**: Tool Gateway checks arguments against shell injection operators (`;`, `&&`, `||`, `$( )`).
- [x] **SSRF Protection**: Outbound requests to cloud metadata (`169.254.169.254`) and loopback interfaces are blocked.
- [x] **Evidence Grounding**: Conclusions cite verified evidence IDs with four-level verdicts (`CONFIRMED`, `LIKELY`, `POSSIBLE`, `INSUFFICIENT EVIDENCE`).

---

## 6. Dataset Ingestion & Uploads
- [x] **Executable Upload Rejection**: Rejects Windows PE (`MZ`), Linux ELF (`\x7fELF`), Mach-O, scripts (`#!`), and bytecode.
- [x] **Path Traversal Elimination**: `sanitize_filename` strips directory paths, null bytes (`\x00`), and relative traversals (`../`).
- [x] **Capacity Controls**: Maximum 50 datasets stored with automatic retention capacity pruning (`MAX_STORED_DATASETS = 50`).

---

## 7. Database & Storage Security
- [x] **Server-Side Only**: Storage layers and SQLite/in-memory repositories accessed strictly through backend Python services.
- [x] **IDOR / BOLA Prevention**: Cross-tenant resource modification blocked with `403 Forbidden`.
- [x] **Stale ID Protection**: Deleted resources tombstoned to return `404 Not Found` on subsequent requests.

---

## 8. Browser & Transport Security
- [x] **Strict-Transport-Security (HSTS)**: `max-age=31536000; includeSubDomains; preload`.
- [x] **Content-Security-Policy (CSP)**: `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: https:; connect-src 'self' http://localhost:8000 ws://localhost:8000 wss: https:; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self';`
- [x] **Clickjacking & XSS Protection**: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `X-XSS-Protection: 1; mode=block`.
- [x] **CORS Isolation**: Explicit allowed origins list; credential sharing disabled if wildcard is used.

---

## 9. Automated Test Verification
- [x] **Backend Pytest Suite**: 223 / 223 unit and integration tests passing (`backend/venv/bin/pytest backend/tests -v`).
- [x] **Frontend Production Build**: Clean compilation with zero errors (`npm run build`).
