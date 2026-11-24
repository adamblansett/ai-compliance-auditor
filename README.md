# AI Compliance & Regulatory Auditor

> Open-source, self-hosted AI compliance and regulatory auditor for SOC 2, HIPAA, and GDPR data governance checks, policy scanning, and audit trail compilation.

**Roadmap Stage:** Phase 2 — Administrative, Quality & Specialized Additions · **Status:** Implemented MVP

## Implemented Core Capabilities

- **Control Mapping (`backend/app/controls/`):** Declarative 18-control baseline registry covering SOC 2 TSC, HIPAA Safeguards, and GDPR Articles, custom control registration, automated evaluation against scan & privacy evidence, and HITL risk waiver workflows.
- **Policy Adherence Scanning (`backend/app/scanners/`):** Deterministic collectors for `config` (`CFG-001..004`), `encryption` (`ENC-001..004`), `logging` (`LOG-001..004`), `rbac` (`RBAC-001..004`), and `sop` (`SOP-001..004`) via inline text or multipart file upload, with automatic PII/PHI redaction and SHA-256 artifact provenance.
- **Audit Trail & Evidence Bundle Compilation (`backend/app/evidence/`):** Append-only SHA-256 hash-chained `audit_events` log, tamper-evident evidence bundle compiler with JSON export, an independent manifest tamper verifier (`/api/v1/evidence/bundles/verify-payload`), and 4 Human-in-the-Loop (HITL) approval gates.
- **DSAR, Legal Hold & Retention Workflows (`backend/app/privacy/`):** 30-day statutory DSAR SLA tracking, automatic legal-hold erasure blocking (`409 Conflict` when held) with dynamic unblock upon hold release, retention ceiling verification, and time-bounded retention exception approvals.

## Architecture & Engineering Standards

- **Backend (`backend/`):** Python 3.12+, FastAPI, SQLAlchemy 2.0 async ORM + Alembic migrations (`alembic/`), Pydantic v2, HMAC-SHA256 bearer auth & RBAC (`viewer`, `auditor`, `compliance_officer`, `admin`), optional Separation of Duties enforcement, and pure ASGI security headers.
- **Frontend (`frontend/`):** React 18, TypeScript, Vite, Tailwind CSS, and Vitest + Testing Library workspace covering Overview, Controls, Scanners, Evidence & Audit (with tamper simulator & PII sandbox), Privacy & DSARs, and HITL Approvals.
- **Privacy & AI Guardrails:** Offline deterministic `mock` mode for CI/dev, local-first Ollama support, and mandatory outbound cloud PII/PHI/PCI/secret redaction (`LLM_REDACT_PII_FOR_CLOUD=true`).
- **Containers & CI (`.github/workflows/ci.yml`):** Multi-stage Dockerfiles, PostgreSQL (`pgvector`) + Redis Compose topology, Ruff + Mypy + Pytest checks, TypeScript + Vitest + Vite build, `npm audit`, and Trivy filesystem scanning.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the database schema, HITL gates, and cryptographic chain specification.

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
| Health & Auth | `GET /health`, `GET /health/live`, `GET /health/ready`, `GET /auth/me`, `POST /auth/token` |
| Overview & Seed | `GET /overview`, `POST /seed/demo?reset=false\|true` |
| Controls | `GET/POST /controls`, `POST /controls/seed-catalog`, `POST /controls/evaluate`, `GET /controls/posture`, `GET /controls/{id}/evaluations`, `POST /controls/{id}/waiver` |
| Scanners | `GET /scanners/presets`, `GET /scanners/runs`, `GET /scanners/runs/{id}`, `GET /scanners/findings`, `POST /scanners/scan`, `POST /scanners/upload` |
| Evidence & HITL | `GET /evidence/bundles`, `POST /evidence/bundles/compile`, `GET /evidence/bundles/{id}/verify`, `GET /evidence/bundles/{id}/export`, `POST /evidence/bundles/verify-payload`, `GET /evidence/audit-events`, `GET /evidence/audit-events/verify`, `GET /evidence/approvals`, `POST /evidence/approvals/{id}/decide`, `POST /evidence/pii/redact` |
| Privacy & DSARs | `GET/POST /privacy/dsars`, `POST /privacy/dsars/{id}/prepare-fulfillment`, `GET/POST /privacy/legal-holds`, `POST /privacy/legal-holds/{id}/release`, `GET/POST /privacy/retention-policies`, `POST /privacy/retention-policies/verify`, `GET /privacy/retention-exceptions`, `POST /privacy/retention-policies/{id}/exceptions` |

## License

Licensed under the [MIT License](LICENSE).
