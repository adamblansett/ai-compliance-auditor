# AI Compliance & Regulatory Auditor — Architecture Blueprint

## Overview

Open-source, self-hosted AI compliance and regulatory auditor for SOC 2, HIPAA, and GDPR data governance checks, policy & repository scanning, signed evidence compilation, citation-grounded Policy RAG, and continuous drift alerting.

## Implemented Backend Module Tree (`backend/app/`)

```text
backend/app/
├── alerts/
│   ├── router.py        # Alert evaluation, ack/resolve & HMAC webhook CRUD
│   ├── schemas.py
│   └── service.py       # Drift detection + SSRF-safe signed webhook dispatcher
├── api/v1/
│   ├── auth.py          # PBKDF2 login/register/refresh JWTs + dev token + users list
│   ├── health.py        # Liveness & SQL SELECT 1 database readiness probes
│   ├── overview.py      # Executive compliance posture, alerts, RAG & DSAR metrics
│   └── router.py        # Unified /api/v1 router registration
├── controls/
│   ├── catalog.py       # 18 baseline SOC 2, HIPAA, and GDPR declarative controls
│   ├── evaluator.py     # Control evaluator against scan & privacy rules + waiver requester
│   ├── router.py        # Controls CRUD, posture, evaluation & waiver endpoints
│   └── schemas.py
├── core/
│   ├── auth.py          # PBKDF2 hashing, HMAC-SHA256 access/refresh JWTs & RBAC guards
│   ├── config.py        # Pydantic v2 Settings + production fail-fast security checks
│   ├── middleware.py    # Pure ASGI security headers & sliding-window RateLimitMiddleware
│   └── telemetry.py     # Pure ASGI OpenTelemetry span & latency TelemetryMiddleware
├── db/
│   ├── base.py          # SQLAlchemy DeclarativeBase & UTC normalization helpers
│   ├── models.py        # 17 async ORM tables
│   └── session.py       # AsyncEngine/AsyncSession factory & lazy schema init
├── evidence/
│   ├── approvals.py     # HITL approval gate processor with Separation of Duties checks
│   ├── chain.py         # Canonical JSON SHA-256 audit chain & bundle manifest verifier
│   ├── compiler.py      # Signed hash-chained evidence package compiler
│   ├── packager.py      # Signed auditor ZIP builder + standalone verify_bundle.py CLI
│   ├── pdf_report.py    # Pure-Python multi-page PDF-1.4 executive attestation generator
│   ├── router.py        # Bundles, PDF/ZIP exports, verifier, audit events & PII sandbox
│   ├── schemas.py
│   └── signing.py       # HMAC-SHA256 manifest & chain head signature helpers
├── llm/
│   ├── pii.py           # PII/PHI/PCI/credential scrubber (SSN, MRN, DOB, IP, cards, keys)
│   └── router.py        # Mock -> local Ollama -> PII-scrubbed cloud Gemini fallback router
├── privacy/
│   ├── holds.py         # Active legal hold matcher for DSAR & purge enforcement
│   ├── router.py        # DSAR, legal hold, retention policy & exception endpoints
│   ├── schemas.py
│   └── service.py       # DSAR fulfillment packager, hold placement/release, retention verifier
├── rag/
│   ├── embeddings.py    # Deterministic 384-dim & Ollama vector embedders + cosine similarity
│   ├── router.py        # Policy ingestion, file upload, RAG Q&A & control citations
│   ├── schemas.py
│   └── service.py       # PII-scrubbed heading-aware chunker & auto control mapper
├── scanners/
│   ├── collectors.py    # 5 deterministic collectors (config, encryption, logging, rbac, sop)
│   ├── engine.py        # Single-artifact scan runner, SHA-256 hashing & control re-eval
│   ├── repo_and_url.py  # Multi-file repository scanner & SSRF-guarded live URL/TLS probe
│   ├── router.py        # Presets, runs, findings, repo scan, URL probe & schedules
│   ├── scheduler.py     # Scheduled drift scan CRUD & execution engine
│   └── schemas.py
├── seed/
│   ├── demo_data.py     # Idempotent & resettable multi-framework compliance demo dataset
│   └── router.py        # POST /seed/demo
└── worker.py            # Optional Celery worker task bridge with inline async fallback
```

## Database Schema (`alembic/versions/0001_initial_schema.py` & `0002_phase2_features.py`)

1. `controls` — Declarative framework controls mapped to scanner rule IDs and privacy rules.
2. `control_evaluations` — Point-in-time evaluation snapshots with AI rationale.
3. `scan_runs` — Executed single-artifact, repo-bundle, and live URL probe scan runs.
4. `scan_findings` — Scrubbed rule checks (`CFG-*`, `ENC-*`, `LOG-*`, `RBAC-*`, `SOP-*`).
5. `audit_events` — Append-only SHA-256 hash-chained compliance event ledger.
6. `approval_requests` — Human-in-the-loop governance gates (`pending` / `approved` / `rejected`).
7. `evidence_bundles` — HMAC-signed, hash-chained auditor export packages and release metadata.
8. `dsar_requests` — Subject access/erasure requests with statutory SLA dates and hold flags.
9. `legal_holds` — Active preservation holds blocking erasure and automated purges.
10. `retention_policies` — Data retention schedules and observed record-age verification.
11. `retention_exceptions` — Time-bounded retention extension requests.
12. `users` — Registered local user accounts with PBKDF2-HMAC-SHA256 password hashes & roles.
13. `scheduled_scans` — Recurring continuous compliance drift scan definitions.
14. `policy_documents` — Indexed policy/SOP metadata with SHA-256 & PII redaction counts.
15. `policy_chunks` — PII-scrubbed policy sections, 384-dim embeddings & mapped controls.
16. `alert_events` — Deduplicated drift, waiver-expiry, and DSAR SLA alerts.
17. `alert_webhooks` — HMAC-signed webhook subscriptions for alert delivery.

## Cryptographic Integrity, Signing & Offline Verification

- **Audit Event Chain (`audit_events`):** Each event computes `event_hash = sha256(canonical_json({sequence_no, event_type, actor_email, actor_role, entity_type, entity_id, action, details, prev_hash}))` starting from `prev_hash = "GENESIS"` at `sequence_no = 1`.
- **Signed Evidence Bundles (`evidence_bundles`):** Each evidence item chains via `item_hash` from `"GENESIS"`, sealed by `manifest_sha256` and signed with `HMAC-SHA256` over `"{manifest_sha256}:{chain_head_hash}"`. Exported ZIPs bundle `manifest.json`, `signature.json`, `attestation-report.pdf`, and standalone `verify_bundle.py`.

## Security & Human-in-the-Loop Invariants

1. **Fail-Fast Production Validation:** `validate_production_security()` refuses startup in `APP_ENV=production` if default dev secrets or wildcard CORS origins remain active; `POST /api/v1/auth/token` returns `403`, and bearer authentication is enforced.
2. **Cloud & Storage PII/PHI Scrubbing:** Outbound cloud LLM prompts run `redact_pii()` when `LLM_REDACT_PII_FOR_CLOUD=true`. Stored scan previews, finding snippets, and Policy RAG chunks are scrubbed before DB persistence.
3. **4 Mandatory HITL Approval Gates (`compliance_officer` / `admin` only):** `control_waiver`, `evidence_bundle`, `dsar_fulfillment` (with live legal-hold guard returning `409 Conflict` if blocked), and `retention_exception`.
4. **Separation of Duties (`ENFORCE_SEPARATION_OF_DUTIES=true`):** Prevents the requesting actor from deciding their own HITL approval (`403 Forbidden`).
5. **SSRF, Rate Limiting & Telemetry:** URL probes and alert webhooks block metadata/link-local targets; `RateLimitMiddleware` enforces per-client sliding-window limits; `TelemetryMiddleware` records OpenTelemetry spans and `X-Trace-ID` headers when `OTEL_ENABLED=true`.
