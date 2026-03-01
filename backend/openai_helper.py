import asyncio
import logging
from typing import List, Optional, Protocol

import httpx

logger = logging.getLogger(__name__)


class EmbeddingGenerationError(Exception):
    pass


class EmbeddingClient(Protocol):
    async def create_embedding(self, text: str, retries: int = 3) -> List[float]:
        ...


class OpenAIEmbeddingClient:
    def __init__(self, api_key: str, model: str = "text-embedding-3-small"):
        self.api_key = api_key
        self.model = model
        self.base_url = "https://api.openai.com/v1"

    async def create_embedding(self, text: str, retries: int = 3) -> List[float]:
        last_error: Optional[str] = None
        for attempt in range(1, retries + 1):
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.post(
                        f"{self.base_url}/embeddings",
                        headers={
                            "Authorization": f"Bearer {self.api_key}",
                            "Content-Type": "application/json",
                        },
                        json={
                            "input": text,
                            "model": self.model,
                        },
                    )
                    response.raise_for_status()
                    data = response.json()
                    return data["data"][0]["embedding"]
            except httpx.HTTPStatusError as e:
                status = e.response.status_code if e.response is not None else "unknown"
                body = e.response.text[:300] if e.response is not None else str(e)
                last_error = f"HTTP {status}: {body}"
                logger.warning(
                    "OpenAI embedding status error attempt %s/%s: %s",
                    attempt,
                    retries,
                    last_error,
                )
            except Exception as e:
                last_error = str(e)
                logger.warning(
                    "OpenAI embedding error attempt %s/%s: %s",
                    attempt,
                    retries,
                    last_error,
                )
            if attempt < retries:
                await asyncio.sleep(0.5 * attempt)

        raise EmbeddingGenerationError(
            f"Embedding generation failed after {retries} attempts: {last_error}"
        )


class GeminiEmbeddingClient:
    def __init__(
        self,
        api_keys: List[str],
        model: str = "gemini-embedding-001",
        output_dimensionality: int = 1536,
    ):
        if not api_keys:
            raise ValueError("At least one Gemini API key is required")
        self.api_keys = api_keys
        self.model = model
        self.output_dimensionality = output_dimensionality
        self.base_url = "https://generativelanguage.googleapis.com/v1beta"

    async def create_embedding(self, text: str, retries: int = 3) -> List[float]:
        last_error: Optional[str] = None
        total_attempts = max(retries, 1) * len(self.api_keys)
        for attempt in range(1, total_attempts + 1):
            api_key = self.api_keys[(attempt - 1) % len(self.api_keys)]
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.post(
                        f"{self.base_url}/models/{self.model}:embedContent",
                        params={"key": api_key},
                        headers={"Content-Type": "application/json"},
                        json={
                            "model": f"models/{self.model}",
                            "content": {"parts": [{"text": text}]},
                            "outputDimensionality": self.output_dimensionality,
                        },
                    )
                    response.raise_for_status()
                    data = response.json()
                    embedding = data.get("embedding", {}).get("values")
                    if not isinstance(embedding, list) or not embedding:
                        raise ValueError("Gemini embedding response missing values")
                    return embedding
            except httpx.HTTPStatusError as e:
                status = e.response.status_code if e.response is not None else "unknown"
                body = e.response.text[:300] if e.response is not None else str(e)
                last_error = f"HTTP {status}: {body}"
                logger.warning(
                    "Gemini embedding status error attempt %s/%s: %s",
                    attempt,
                    total_attempts,
                    last_error,
                )
            except Exception as e:
                last_error = str(e)
                logger.warning(
                    "Gemini embedding error attempt %s/%s: %s",
                    attempt,
                    total_attempts,
                    last_error,
                )
            if attempt < total_attempts:
                await asyncio.sleep(0.5 * attempt)

        raise EmbeddingGenerationError(
            f"Embedding generation failed after {total_attempts} attempts: {last_error}"
        )


def build_embedding_client(
    provider: str,
    openai_api_key: Optional[str],
    gemini_api_key: Optional[str],
    gemini_api_keys: Optional[List[str]] = None,
    openai_model: str = "text-embedding-3-small",
    gemini_model: str = "gemini-embedding-001",
    gemini_output_dimensionality: int = 1536,
) -> EmbeddingClient:
    normalized = provider.strip().lower()
    if normalized == "gemini":
        keys: List[str] = []
        if gemini_api_keys:
            keys.extend([k for k in gemini_api_keys if k])
        if gemini_api_key and gemini_api_key not in keys:
            keys.append(gemini_api_key)
        if not keys:
            raise ValueError(
                "GEMINI_API_KEY or GEMINI_API_KEYS is required when EMBEDDING_PROVIDER=gemini"
            )
        return GeminiEmbeddingClient(
            api_keys=keys,
            model=gemini_model,
            output_dimensionality=gemini_output_dimensionality,
        )

    if normalized == "openai":
        if not openai_api_key:
            raise ValueError("OPENAI_API_KEY (or EMERGENT_LLM_KEY) is required when EMBEDDING_PROVIDER=openai")
        return OpenAIEmbeddingClient(
            api_key=openai_api_key,
            model=openai_model,
        )

    raise ValueError("EMBEDDING_PROVIDER must be 'openai' or 'gemini'")
