from __future__ import annotations

import asyncio
import json
import logging
from typing import Callable, Literal, TypeVar

from google import genai
from google.genai import types as genai_types
from pydantic import ValidationError

from prometheus.core.config import Settings
from prometheus.models.domain import PrometheusModel


logger = logging.getLogger(__name__)

StructuredModel = TypeVar("StructuredModel", bound=PrometheusModel)
GeminiTask = Literal["reasoning", "fast", "lite"]


class GeminiRouter:
    TRANSIENT_ERROR_MARKERS = (
        "429",
        "503",
        "RESOURCE_EXHAUSTED",
        "UNAVAILABLE",
        "HIGH DEMAND",
        "TRY AGAIN LATER",
        "DEADLINE_EXCEEDED",
        "TIMEOUT",
    )

    # Powered by Gemini model routing.
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.connected = False
        self.last_error: str | None = None
        self.client = (
            genai.Client(api_key=settings.gemini_api_key)
            if settings.gemini_api_key
            else None
        )

    @property
    def configured(self) -> bool:
        return self.client is not None

    @property
    def enabled(self) -> bool:
        return self.configured

    @property
    def available(self) -> bool:
        return self.connected

    def model_for(self, task: GeminiTask) -> str:
        if task == "reasoning":
            return self.settings.gemini_reasoning_model
        if task == "lite":
            return self.settings.gemini_lite_model
        return self.settings.gemini_fast_model

    def candidate_models(self, task: GeminiTask) -> list[str]:
        primary = self.model_for(task)
        ordered = [primary]
        if task == "reasoning":
            ordered.extend(
                [self.settings.gemini_fast_model, self.settings.gemini_lite_model]
            )
        elif task == "fast":
            ordered.extend(
                [self.settings.gemini_lite_model, self.settings.gemini_reasoning_model]
            )
        else:
            ordered.extend(
                [self.settings.gemini_fast_model, self.settings.gemini_reasoning_model]
            )

        unique_models: list[str] = []
        for model_name in ordered:
            if model_name and model_name not in unique_models:
                unique_models.append(model_name)
        return unique_models

    def _safe_error_message(self, exc: Exception) -> str:
        message = f"{type(exc).__name__}: {exc}".strip()
        if self.settings.gemini_api_key:
            message = message.replace(self.settings.gemini_api_key, "[redacted]")
        message = " ".join(message.split())
        if len(message) > 240:
            return f"{message[:237]}..."
        return message

    def _set_error(self, prefix: str, exc: Exception) -> None:
        self.last_error = f"{prefix}: {self._safe_error_message(exc)}"

    def _is_transient_error(self, exc: Exception) -> bool:
        message = self._safe_error_message(exc).upper()
        return any(marker in message for marker in self.TRANSIENT_ERROR_MARKERS)

    async def _invoke_with_retries(
        self,
        *,
        model_name: str,
        operation: Callable[[str], StructuredModel | bool | tuple[StructuredModel, str]],
        timeout_seconds: int,
        purpose: str,
    ) -> StructuredModel | bool | tuple[StructuredModel, str]:
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                return await asyncio.wait_for(
                    asyncio.to_thread(operation, model_name),
                    timeout=timeout_seconds,
                )
            except Exception as exc:
                transient = self._is_transient_error(exc)
                logger.warning(
                    "Gemini %s failed for %s (attempt %s/%s): %s",
                    purpose,
                    model_name,
                    attempt,
                    max_attempts,
                    exc,
                )
                if not transient or attempt == max_attempts:
                    raise
                await asyncio.sleep(0.6 * attempt)

    async def probe(self) -> bool:
        if not self.configured:
            self.connected = False
            self.last_error = None
            return False

        def invoke(model_name: str) -> bool:
            response = self.client.models.generate_content(
                model=model_name,
                contents='Reply with strict JSON: {"ok": true}',
                config=genai_types.GenerateContentConfig(
                    temperature=0.0,
                    response_mime_type="application/json",
                ),
            )
            payload = json.loads((response.text or "{}").strip() or "{}")
            if not payload.get("ok"):
                raise ValueError(f"Probe returned non-ok payload for {model_name}")
            return True

        for model_name in self.candidate_models("lite"):
            try:
                result = await self._invoke_with_retries(
                    model_name=model_name,
                    operation=invoke,
                    timeout_seconds=4,
                    purpose="probe",
                )
                self.connected = bool(result)
                self.last_error = None
                if self.connected:
                    return True
            except Exception as exc:  # pragma: no cover - defensive fallback
                self.connected = False
                self._set_error(f"Probe failed for {model_name}", exc)
        return self.connected

    async def generate_structured(
        self,
        *,
        task: GeminiTask,
        prompt: str,
        schema: type[StructuredModel],
        fallback: Callable[[], StructuredModel],
    ) -> tuple[StructuredModel, str]:
        if not self.enabled:
            self.connected = False
            self.last_error = None
            return fallback(), "deterministic-demo"

        def invoke(model_name: str) -> tuple[StructuredModel, str]:
            response = self.client.models.generate_content(
                model=model_name,
                contents=prompt,
                config=genai_types.GenerateContentConfig(
                    temperature=0.1,
                    response_mime_type="application/json",
                ),
            )
            raw_text = (response.text or "{}").strip() or "{}"
            payload = json.loads(raw_text)
            return schema.model_validate(payload), model_name

        for model_name in self.candidate_models(task):
            try:
                payload = await self._invoke_with_retries(
                    model_name=model_name,
                    operation=invoke,
                    timeout_seconds=8,
                    purpose="request",
                )
                self.connected = True
                self.last_error = None
                return payload  # type: ignore[return-value]
            except json.JSONDecodeError as exc:
                logger.warning("Gemini JSON decode failed for %s: %s", model_name, exc)
                self._set_error(f"Invalid JSON from {model_name}", exc)
            except ValidationError as exc:
                logger.warning("Gemini schema validation failed for %s: %s", model_name, exc)
                self._set_error(f"Schema validation failed for {model_name}", exc)
            except Exception as exc:  # pragma: no cover - defensive fallback
                logger.warning("Gemini request failed for %s: %s", model_name, exc)
                self._set_error(f"Request failed for {model_name}", exc)
        self.connected = False
        return fallback(), "deterministic-demo"
