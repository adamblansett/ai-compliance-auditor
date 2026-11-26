# AI Compliance & Regulatory Auditor

> Open-source, self-hosted AI compliance and regulatory auditor for SOC 2, HIPAA, and GDPR data governance checks, policy scanning, signed audit trail compilation, Policy RAG, and continuous drift alerting.

**Roadmap Stage:** Phase 2 — Administrative, Quality & Specialized Additions · **Status:** Phase 2 Complete

## Core Capabilities

- **Control Mapping (`backend/app/controls/`):** Declarative 18-control baseline registry covering SOC 2 TSC, HIPAA Safeguards, and GDPR Articles, custom control registration, automated evaluation against scan & privacy evidence, and HITL risk waiver workflows.
- **Single-Artifact, Multi-File Repo & Live URL Scanners (`backend/app/scanners/`):** Deterministic collectors for `config` (`CFG-001..004`), `encryption` (`ENC-001..004`), `logging` (`LOG-001..004`), `rbac` (`RBAC-001..004`), and `sop` (`SOP-001..004`) via inline text, file upload, full directory/repo scanning, SSRF-guarded live HTTP/TLS probes, and recurring scheduled drift scans (with optional Celery worker bridge).
- **Signed Audit Trail & Evidence Bundles (`backend/app/evidence/`):** Append-only SHA-256 hash-chained `audit_events` log, HMAC-SHA256 signed evidence bundle compiler, multi-page executive PDF attestation (`/report.pdf`), downloadable signed ZIP package (`/export-zip`) with zero-dependency offline CLI verifier (`verify_bundle.py`), and 4 HITL approval gates.
- **Policy RAG (`backend/app/rag/`):** Heading-aware chunking, PII/PHI scrubbing before persistence, deterministic 384-dim or Ollama vector embeddings, automatic control citation mapping, and citation-grounded compliance Q&A.
- **DSAR, Legal Hold & Retention Workflows (`backend/app/privacy/`):** 30-day statutory DSAR SLA tracking, automatic legal-hold erasure blocking (`409 Conflict` when held) with dynamic unblock upon hold release, retention ceiling verification, and time-bounded retention exception approvals.
- **Continuous Drift Alerting & Production Security (`backend/app/alerts/`, `backend/app/core/`):** Automated alerts for control regressions, expiring waivers, and DSAR SLAs dispatched to HMAC-signed webhooks, PBKDF2 user registration/JWT login/refresh (`/api/v1/auth/*`), sliding-window rate limiting, and OpenTelemetry tracing middleware.

## Architecture & Engineering Standards

- **Backend (`backend/`):** Python 3.12+, FastAPI, SQLAlchemy 2.0 async ORM + Alembic migrations (`0001_initial_schema` → `0002_phase2_features`, 17 tables), Pydantic v2, PBKDF2 + HMAC-SHA256 JWT auth & RBAC (`viewer`, `auditor`, `compliance_officer`, `admin`), optional Separation of Duties enforcement, rate limiting, OpenTelemetry instrumentation, and pure ASGI security headers.
- **Frontend (`frontend/`):** React 18, TypeScript, Vite, Tailwind CSS, and Vitest + Testing Library 8-tab workspace covering Overview, Controls, Scanners (Single/Repo/URL/Schedules), Evidence & Audit (Signed ZIP/PDF + tamper simulator + PII sandbox), Policy RAG, Privacy & DSARs, Drift Alerts & Webhooks, and HITL Approvals, plus JWT Sign In.
- **Privacy & AI Guardrails:** Offline deterministic `mock` mode for CI/dev, local-first Ollama support, and mandatory outbound cloud PII/PHI/PCI/secret redaction (`LLM_REDACT_PII_FOR_CLOUD=true`).
- **Containers & CI (`.github/workflows/ci.yml`):** Multi-stage Dockerfiles, PostgreSQL (`pgvector`) + Redis + optional `worker`/`ollama` Compose profiles, Ruff + Mypy + Pytest checks, TypeScript + Vitest + Vite build, `npm audit`, and Trivy filesystem scanning.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the database schema, HITL gates, and cryptographic specification.

## Quickstart

### Backend (Local Dev & Tests)

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

Load the prebuilt SOC 2 / HIPAA / GDPR demo dataset from the UI **"Load Demo Dataset"** button or via API:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/seed/demo
```

Demo JWT login accounts created by the seed (`POST /api/v1/auth/login`):
- `officer@acme-compliance.local` / `ComplianceDemo!2026` (`compliance_officer`)
- `auditor@acme-compliance.local` / `ComplianceDemo!2026` (`auditor`)
- `viewer@acme-compliance.local` / `ComplianceDemo!2026` (`viewer`)

Verify lint, strict types, and tests:

```bash
ruff check app tests
mypy app
pytest -v
```

### Frontend (Local Dev & Tests)

```bash
cd frontend
npm ci
npm run dev
```

Verify typecheck, unit tests, production bundle, and dependency audit:

```bash
npx tsc --noEmit
npm run test
npm run build
npm audit --omit=dev --audit-level=high
```

### Docker Compose

```bash
docker compose up --build
```

- Frontend UI: `http://localhost:3000`
- Backend API & OpenAPI Docs: `http://localhost:8000/docs`

---

## Key API Endpoints (`/api/v1`)

| Module | Endpoints |
| :--- | :--- |
| Health & Auth | `GET /health`, `/health/live`, `/health/ready`, `GET /auth/me`, `POST /auth/token`, `POST /auth/register`, `POST /auth/login`, `POST /auth/refresh`, `GET /auth/users` |
| Overview & Seed | `GET /overview`, `POST /seed/demo?reset=false\|true` |
| Controls | `GET/POST /controls`, `POST /controls/seed-catalog`, `POST /controls/evaluate`, `GET /controls/posture`, `GET /controls/{id}/evaluations`, `POST /controls/{id}/waiver` |
| Scanners & Schedules | `GET /scanners/presets`, `GET /scanners/runs`, `GET /scanners/runs/{id}`, `GET /scanners/findings`, `POST /scanners/scan`, `POST /scanners/upload`, `POST /scanners/scan-repo`, `POST /scanners/probe-url`, `GET/POST /scanners/schedules`, `POST /scanners/schedules/{id}/run`, `POST /scanners/schedules/run-due` |
| Evidence & Exports | `GET /evidence/bundles`, `POST /evidence/bundles/compile`, `GET /evidence/bundles/{id}/verify`, `GET /evidence/bundles/{id}/export`, `GET /evidence/bundles/{id}/report.pdf`, `GET /evidence/bundles/{id}/export-zip`, `POST /evidence/bundles/verify-payload`, `GET /evidence/audit-events`, `GET /evidence/audit-events/verify`, `GET /evidence/approvals`, `POST /evidence/approvals/{id}/decide`, `POST /evidence/pii/redact` |
| Policy RAG | `GET/POST /rag/documents`, `POST /rag/documents/upload`, `POST /rag/query`, `GET /rag/controls/{code}/citations` |
| Privacy & DSARs | `GET/POST /privacy/dsars`, `POST /privacy/dsars/{id}/prepare-fulfillment`, `GET/POST /privacy/legal-holds`, `POST /privacy/legal-holds/{id}/release`, `GET/POST /privacy/retention-policies`, `POST /privacy/retention-policies/verify`, `GET /privacy/retention-exceptions`, `POST /privacy/retention-policies/{id}/exceptions` |
| Drift Alerts | `GET /alerts`, `POST /alerts/evaluate`, `POST /alerts/{id}/acknowledge`, `POST /alerts/{id}/resolve`, `GET/POST /alerts/webhooks`, `DELETE /alerts/webhooks/{id}` |

## License

Licensed under the [MIT License](LICENSE).
