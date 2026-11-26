from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from tests.conftest import AUDITOR_HEADERS, VIEWER_HEADERS, make_test_app


@pytest.mark.asyncio
async def test_policy_rag_ingest_scrubs_pii_maps_controls_and_cites(tmp_path: Path) -> None:
    test_app = make_test_app(tmp_path)
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/api/v1/controls/seed-catalog", headers=AUDITOR_HEADERS)

        raw_ssn = "123-45-6789"
        raw_mrn = "MRN-884411"
        policy_md = (
            "# Breach Notification & Incident Response\n"
            "All confirmed security incidents trigger supervisory notification within 72 hours "
            "and escalation to the Compliance Officer.\n\n"
            "# Encryption & ePHI Safeguards\n"
            "Production workloads enforce TLS 1.3 and AES-256-GCM encryption at rest. "
            f"Never store raw identifiers like {raw_ssn} or {raw_mrn} in logs.\n"
        )
        ingest = await client.post(
            "/api/v1/rag/documents",
            headers=AUDITOR_HEADERS,
            json={
                "title": "Security & Privacy Master SOP",
                "filename": "master-sop.md",
                "framework": "ALL",
                "version": "2.0",
                "content": policy_md,
            },
        )
        assert ingest.status_code == 201
        doc = ingest.json()
        assert doc["chunk_count"] == 2
        assert doc["pii_redaction_count"] == 2

        docs_list = await client.get("/api/v1/rag/documents", headers=VIEWER_HEADERS)
        assert docs_list.status_code == 200
        assert len(docs_list.json()) == 1

        query_resp = await client.post(
            "/api/v1/rag/query",
            headers=VIEWER_HEADERS,
            json={
                "query": "What is our 72-hour breach notification requirement and TLS standard?",
                "top_k": 2,
            },
        )
        assert query_resp.status_code == 200
        qdata = query_resp.json()
        assert "Citation-Grounded Policy Answer" in qdata["answer"]
        assert len(qdata["citations"]) == 2
        combined_excerpts = " ".join(c["excerpt"] for c in qdata["citations"])
        assert raw_ssn not in combined_excerpts
        assert raw_mrn not in combined_excerpts
        assert "[REDACTED_SSN]" in combined_excerpts

        ctrl_cites = await client.get(
            "/api/v1/rag/controls/GDPR-ART33/citations",
            headers=VIEWER_HEADERS,
        )
        assert ctrl_cites.status_code == 200
        assert len(ctrl_cites.json()) >= 1
