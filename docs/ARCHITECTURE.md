# AI Compliance & Regulatory Auditor — Architecture Blueprint

## Overview

Open-source, self-hosted AI compliance and regulatory auditor for SOC 2, HIPAA, and GDPR data governance checks, policy scanning, and tamper-evident audit trail compilation.

## Implemented Backend Module Tree (`backend/app/`)

```text
backend/app/
├── api/v1/
│   ├── auth.py          # GET /auth/me, POST /auth/token (disabled in production)
│   ├── health.py        # Liveness & SQL SELECT 1 database readiness probes
│   ├── overview.py      # Executive compliance posture & metrics aggregator
│   └── router.py        # Unified /api/v1 router registration
├── controls/
│   ├── catalog.py       # 18 baseline SOC 2, HIPAA, and GDPR declarative controls
│   ├── evaluator.py     # Control evaluator against scan & privacy rules + waiver requester
│   ├── router.py        # Controls CRUD, posture, evaluation & waiver endpoints
│   └── schemas.py
├── core/
│   ├── auth.py          # HMAC-SHA256 bearer verification, dev-header fallback, RBAC guards
│   ├── config.py        # Pydantic v2 Settings + production fail-fast security checks
│   └── middleware.py    # Pure ASGI X-Request-ID & HTTP security headers
├── db/
│   ├── base.py          # SQLAlchemy DeclarativeBase & UTC normalization helpers
│   ├── models.py        # 11 async ORM tables
│   └── session.py       # AsyncEngine/AsyncSession factory & lazy schema init
├── evidence/
│   ├── approvals.py     # HITL approval gate processor with Separation of Duties checks
│   ├── chain.py         # Canonical JSON SHA-256 audit chain & bundle manifest verifier
│   ├── compiler.py      # Hash-chained evidence package compiler
│   ├── router.py        # Bundles, tamper verifier, audit events, approvals & PII sandbox
│   └── schemas.py
├── llm/
│   ├── pii.py           # PII/PHI/PCI/credential scrubber (SSN, MRN, DOB, IP, cards, keys)
│   └── router.py        # Mock -> local Ollama -> PII-scrubbed cloud Gemini fallback router
├── privacy/
│   ├── holds.py         # Active legal hold matcher for DSAR & purge enforcement
│   ├── router.py        # DSAR, legal hold, retention policy & exception endpoints
│   ├── schemas.py
│   └── service.py       # DSAR fulfillment packager, hold placement/release, retention verifier
├── scanners/
│   ├── collectors.py    # 5 deterministic collectors (config, encryption, logging, rbac, sop)
│   ├── engine.py        # Scan runner, SHA-256 hashing, snippet redaction & control re-eval
│   ├── router.py        # Presets, scan runs, findings, inline scan & file upload endpoints
│   └── schemas.py
└── seed/
    ├── demo_data.py     # Idempotent & resettable multi-framework compliance demo dataset
    └── router.py        # POST /seed/demo
```

## Database Schema (`alembic/versions/0001_initial_schema.py`)

1. `controls` — Declarative framework controls mapped to scanner rule IDs and privacy rules.
2. `control_evaluations` — Point-in-time evaluation snapshots with AI rationale.
3. `scan_runs` — Executed artifact scans with SHA-256 provenance and risk score.
4. `scan_findings` — Scrubbed rule checks (`CFG-*`, `ENC-*`, `LOG-*`, `RBAC-*`, `SOP-*`).
5. `audit_events` — Append-only SHA-256 hash-chained compliance event ledger.
6. `approval_requests` — Human-in-the-loop governance gates (`pending` / `approved` / `rejected`).
7. `evidence_bundles` — Hash-chained auditor export packages and release metadata.
8. `dsar_requests` — Subject access/erasure requests with statutory SLA dates and hold flags.
9. `legal_holds` — Active preservation holds blocking erasure and automated purges.
10. `retention_policies` — Data retention schedules and observed record-age verification.
11. `retention_exceptions` — Time-bounded retention extension requests.

## Cryptographic Integrity & Tamper Detection

- **Audit Event Chain (`audit_events`):** Each event computes `event_hash = sha256(canonical_json({sequence_no, event_type, actor_email, actor_role, entity_type, entity_id, action, details, prev_hash}))` starting from `prev_hash = "GENESIS"` at `sequence_no = 1`.
- **Evidence Bundle Chain (`evidence_bundles.manifest_json`):** Each evidence item computes `item_hash = sha256(canonical_json({item_seq, item_type, item_ref, payload, prev_hash}))` starting from `"GENESIS"`, with `manifest_sha256` sealing the full canonical JSON manifest. Any 1-character mutation in an exported manifest fails `verify_evidence_bundle_manifest()` and identifies the exact `broken_item_seq`.

## Security & Human-in-the-Loop Invariants

1. **Fail-Fast Production Validation:** `validate_production_security()` refuses startup in `APP_ENV=production` if default dev secrets or wildcard CORS origins remain active; `POST /api/v1/auth/token` returns `403`, and bearer authentication is enforced.
2. **Cloud & Storage PII/PHI Scrubbing:** Outbound cloud LLM prompts run `redact_pii()` when `LLM_REDACT_PII_FOR_CLOUD=true`. Stored scan previews and finding snippets are scrubbed before DB persistence.
3. **4 Mandatory HITL Approval Gates (`compliance_officer` / `admin` only):**
   - `control_waiver` — Time-bounded risk waiver on a failing/warning control.
   - `evidence_bundle` — External auditor package release sign-off.
   - `dsar_fulfillment` — DSAR export/erasure execution (re-checks active legal holds before approval and returns `409 Conflict` if blocked).
   - `retention_exception` — Time-bounded data retention ceiling extension.
4. **Separation of Duties (`ENFORCE_SEPARATION_OF_DUTIES=true`):** Prevents the requesting actor from deciding their own HITL approval (`403 Forbidden`).
5. **Non-Root Containers:** Both FastAPI API and Nginx frontend images run as unprivileged users with `/api/v1/health/live` and `/api/v1/health/ready` (`SELECT 1`) probes.
