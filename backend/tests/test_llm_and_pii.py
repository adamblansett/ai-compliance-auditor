import pytest

from app.core.config import Settings
from app.llm.pii import redact_pii
from app.llm.router import LLMRouter


def test_pii_phi_pci_and_secret_redaction_covers_all_categories() -> None:
    sample = (
        "SSN 123-45-6789 | EIN 12-3456789 | MRN: MRN-998812 | "
        "Member ID: MEM-445511 | DOB: 1988-03-21 | Email alice@clinic.org | "
        "Phone (555) 234-5678 | IP 192.168.10.25 | IBAN DE89370400440532013000 | "
        "Card 4111-1111-1111-1111 | Key sk-live1234567890abcdef12"
    )
    res = redact_pii(sample)
    assert "123-45-6789" not in res.redacted_text
    assert "12-3456789" not in res.redacted_text
    assert "MRN-998812" not in res.redacted_text
    assert "MEM-445511" not in res.redacted_text
    assert "1988-03-21" not in res.redacted_text
    assert "alice@clinic.org" not in res.redacted_text
    assert "234-5678" not in res.redacted_text
    assert "192.168.10.25" not in res.redacted_text
    assert "DE89370400440532013000" not in res.redacted_text
    assert "4111-1111-1111-1111" not in res.redacted_text
    assert "sk-live1234567890abcdef12" not in res.redacted_text

    cats = {f.category for f in res.findings}
    assert {
        "ssn",
        "ein",
        "mrn",
        "health_plan_id",
        "dob",
        "email",
        "phone",
        "ipv4",
        "iban",
        "payment_card",
        "secret_token",
    }.issubset(cats)


@pytest.mark.asyncio
async def test_llm_router_redacts_cloud_prompts_and_falls_back_to_mock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_prompts: list[str] = []

    class FakeGeminiAdapter:
        provider_name = "gemini"
        model_name = "gemini-2.5-flash"

        async def generate(self, prompt: str, system_prompt: str, task_type: str) -> str:
            _ = (system_prompt, task_type)
            captured_prompts.append(prompt)
            return "Cloud compliance summary"

    cfg = Settings(
        llm_default_provider="gemini",
        llm_fallback_providers="gemini,mock",
        llm_redact_pii_for_cloud=True,
    )
    router = LLMRouter(cfg)
    router.adapters["gemini"] = FakeGeminiAdapter()

    res = await router.generate(
        prompt="Audit note for user bob@acme.org with SSN 123-45-6789 and MRN: MRN-112233",
        task_type="control_evaluation",
    )
    assert res.provider == "gemini"
    assert res.pii_redacted is True
    assert res.redaction_count == 3
    assert "bob@acme.org" not in captured_prompts[0]
    assert "123-45-6789" not in captured_prompts[0]
    assert "MRN-112233" not in captured_prompts[0]

    # When ollama & gemini fail (empty key / unreachable), router falls back cleanly to mock
    fallback_cfg = Settings(
        llm_default_provider="ollama",
        llm_fallback_providers="ollama,gemini,mock",
        ollama_base_url="http://127.0.0.1:1",
        gemini_api_key="",
    )
    fallback_router = LLMRouter(fallback_cfg)

    async def _fail_ollama(prompt: str, system_prompt: str, task_type: str) -> str:
        _ = (prompt, system_prompt, task_type)
        raise RuntimeError("Ollama offline")

    monkeypatch.setattr(fallback_router.adapters["ollama"], "generate", _fail_ollama)
    fb_res = await fallback_router.generate(
        "Check control SOC2-CC6.1",
        task_type="control_evaluation",
    )
    assert fb_res.provider == "mock"
    assert "Deterministic Control Evaluation" in fb_res.content
