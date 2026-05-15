from __future__ import annotations

from prometheus.models.domain import (
    AgentRecord,
    Prediction,
    Scenario,
    StructuredPrediction,
    WatcherInspection,
)
from prometheus.services.gemini_router import GeminiRouter


class ProphetService:
    def __init__(self, router: GeminiRouter) -> None:
        self.router = router

    async def predict(
        self,
        *,
        agent: AgentRecord,
        scenario: Scenario,
        inspection: WatcherInspection,
    ) -> Prediction:
        fallback = self._fallback(agent=agent, scenario=scenario, inspection=inspection)

        prompt = f"""
Return strict JSON with keys predicted_action, divergence_score, confidence, explanation.
You are The Prophet inside PROMETHEUS.
Agent id: {agent.id}
Agent role: {agent.role}
Behavior baseline: {agent.baseline}
Observed prompt: {scenario.user_prompt}
Observed action: {scenario.observed_action}
Declared intent: {scenario.declared_intent}
Detected intent: {scenario.detected_intent}
Watcher floor decision: {inspection.floor_decision}
Policy signals: {[signal.label for signal in inspection.policy_signals]}
"""

        payload, model_used = await self.router.generate_structured(
            task="fast",
            prompt=prompt,
            schema=StructuredPrediction,
            fallback=lambda: fallback,
        )

        return Prediction(
            predicted_action=payload.predicted_action,
            divergence_score=payload.divergence_score,
            confidence=payload.confidence,
            explanation=payload.explanation,
            model_used=model_used,
        )

    def _fallback(
        self,
        *,
        agent: AgentRecord,
        scenario: Scenario,
        inspection: WatcherInspection,
    ) -> StructuredPrediction:
        divergence = round(max(scenario.risk_score, 0.15), 2)
        if inspection.floor_decision == "ALLOW":
            divergence = min(divergence, 0.28)

        explanation = (
            f"{agent.name} normally performs {scenario.predicted_action}; "
            f"observed {scenario.observed_action} diverges from that baseline."
        )

        return StructuredPrediction(
            predicted_action=scenario.predicted_action,
            divergence_score=divergence,
            confidence=0.88 if divergence >= 0.8 else 0.74,
            explanation=explanation,
        )
