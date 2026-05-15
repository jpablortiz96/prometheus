from __future__ import annotations

import asyncio

from prometheus.core.config import Settings
from prometheus.models.domain import StructuredPrediction
from prometheus.services.gemini_router import GeminiRouter


class FakeResponse:
    def __init__(self, text: str) -> None:
        self.text = text


class FakeModelsAPI:
    def __init__(self, handler) -> None:
        self._handler = handler

    def generate_content(self, *, model: str, contents: str, config) -> FakeResponse:
        return self._handler(model=model, contents=contents, config=config)


class FakeClient:
    def __init__(self, handler) -> None:
        self.models = FakeModelsAPI(handler)


def build_router() -> GeminiRouter:
    settings = Settings(
        gemini_api_key="test-key",
        gemini_reasoning_model="reasoning-model",
        gemini_fast_model="fast-model",
        gemini_lite_model="lite-model",
    )
    return GeminiRouter(settings)


def test_probe_falls_back_to_second_model_after_transient_failures() -> None:
    router = build_router()
    calls: list[str] = []

    def handler(*, model: str, contents: str, config) -> FakeResponse:
        calls.append(model)
        if model == "lite-model":
            raise RuntimeError("503 UNAVAILABLE")
        return FakeResponse('{"ok": true}')

    router.client = FakeClient(handler)

    result = asyncio.run(router.probe())

    assert result is True
    assert router.connected is True
    assert router.last_error is None
    assert calls[:3] == ["lite-model", "lite-model", "lite-model"]
    assert calls[3] == "fast-model"


def test_generate_structured_uses_fallback_model_before_deterministic_fallback() -> None:
    router = build_router()
    calls: list[str] = []

    def handler(*, model: str, contents: str, config) -> FakeResponse:
        calls.append(model)
        if model == "fast-model":
            raise RuntimeError("503 UNAVAILABLE")
        return FakeResponse(
            '{"predicted_action":"chunk.index","divergence_score":0.91,"confidence":0.83,"explanation":"fallback model succeeded"}'
        )

    router.client = FakeClient(handler)

    payload, model_used = asyncio.run(
        router.generate_structured(
            task="fast",
            prompt="test prompt",
            schema=StructuredPrediction,
            fallback=lambda: StructuredPrediction(
                predicted_action="deterministic",
                divergence_score=0.25,
                confidence=0.5,
                explanation="fallback",
            ),
        )
    )

    assert payload.predicted_action == "chunk.index"
    assert model_used == "lite-model"
    assert router.connected is True
    assert router.last_error is None
    assert calls[:3] == ["fast-model", "fast-model", "fast-model"]
    assert calls[3] == "lite-model"
