import hashlib
import math
import re
from typing import Protocol

import httpx

from app.core.config import Settings

_TOKEN_RE = re.compile(r"[a-z0-9]{2,}")


class Embedder(Protocol):
    """Protocol implemented by deterministic and Ollama vector embedders."""

    dimensions: int

    async def embed(self, text: str) -> list[float]:
        ...


class DeterministicEmbedder:
    """Zero-dependency normalized feature-hashing vector embedder."""

    def __init__(self, dimensions: int = 384) -> None:
        self.dimensions = max(32, dimensions)

    def embed_sync(self, text: str) -> list[float]:
        vec = [0.0] * self.dimensions
        tokens = _TOKEN_RE.findall(text.lower())
        if not tokens:
            return vec

        terms = list(tokens)
        for idx in range(len(tokens) - 1):
            terms.append(f"{tokens[idx]}_{tokens[idx + 1]}")

        for term in terms:
            digest = hashlib.blake2b(term.encode("utf-8"), digest_size=8).digest()
            val = int.from_bytes(digest, "big")
            bucket = val % self.dimensions
            sign = 1.0 if ((val >> 8) & 1) == 0 else -1.0
            vec[bucket] += sign

        norm = math.sqrt(sum(v * v for v in vec))
        if norm > 0.0:
            vec = [round(v / norm, 6) for v in vec]
        return vec

    async def embed(self, text: str) -> list[float]:
        return self.embed_sync(text)


class OllamaEmbedder:
    """Local Ollama embedding adapter with deterministic fallback."""

    def __init__(self, base_url: str, model_name: str, dimensions: int = 384) -> None:
        self.base_url = base_url.rstrip("/")
        self.model_name = model_name
        self.dimensions = dimensions
        self._fallback = DeterministicEmbedder(dimensions=dimensions)

    async def embed(self, text: str) -> list[float]:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    f"{self.base_url}/api/embeddings",
                    json={"model": self.model_name, "prompt": text},
                )
                resp.raise_for_status()
                raw = resp.json().get("embedding")
                if isinstance(raw, list) and len(raw) > 0:
                    vec = [float(x) for x in raw]
                    norm = math.sqrt(sum(v * v for v in vec))
                    if norm > 0.0:
                        return [round(v / norm, 6) for v in vec]
        except Exception:
            pass
        return self._fallback.embed_sync(text)


def get_embedder(settings: Settings) -> Embedder:
    """Return configured vector embedder."""
    if settings.embedding_provider == "ollama":
        return OllamaEmbedder(
            base_url=settings.ollama_base_url,
            model_name=settings.ollama_default_model,
            dimensions=settings.embedding_dimensions,
        )
    return DeterministicEmbedder(dimensions=settings.embedding_dimensions)


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two embedding vectors."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return round(dot / (na * nb), 4)
