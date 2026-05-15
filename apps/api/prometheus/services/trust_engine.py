from __future__ import annotations

from collections.abc import Iterable

from prometheus.models.domain import AgentRecord, EventRecord, KPISet, Prediction


class TrustEngine:
    def apply_decision(
        self,
        *,
        agent: AgentRecord,
        prediction: Prediction,
        decision: str,
    ) -> AgentRecord:
        alpha = 50
        beta = 30
        gamma = 20
        delta = 1

        blocked_penalty = alpha if decision == "BLOCK" else 0
        quarantine_penalty = beta if decision == "QUARANTINE" else 0
        divergence_penalty = int(gamma * prediction.divergence_score)
        compliant_credit = delta if decision == "ALLOW" else 0

        next_score = max(
            420,
            min(
                1000,
                agent.trust_score
                - blocked_penalty
                - quarantine_penalty
                - divergence_penalty
                + compliant_credit,
            ),
        )
        delta_score = next_score - agent.trust_score

        if decision == "BLOCK":
            status = "blocked"
        elif decision == "QUARANTINE":
            status = "quarantine"
        elif prediction.divergence_score >= 0.4:
            status = "watching"
        else:
            status = "normal"

        sparkline = [*agent.sparkline[-7:], next_score]

        return agent.model_copy(
            update={
                "trust_score": next_score,
                "trust_delta": delta_score,
                "status": status,
                "divergence_score": prediction.divergence_score,
                "sparkline": sparkline,
            }
        )

    def rebuild_kpis(self, *, agents: Iterable[AgentRecord], events: list[EventRecord]) -> KPISet:
        agents_list = list(agents)
        blocked = sum(1 for event in events if event.decision == "BLOCK")
        quarantined = sum(1 for event in events if event.decision == "QUARANTINE")
        avg_latency = 187 if not events else 180 + min(85, len(events) * 3)
        trust_floor = min(agent.trust_score for agent in agents_list)
        return KPISet(
            attacks_blocked=blocked,
            quarantined=quarantined,
            active_agents=len(agents_list),
            average_latency_ms=avg_latency,
            trust_floor=trust_floor,
            incidents_24h=len(events),
        )

    def roll_kpis(
        self,
        *,
        current: KPISet,
        agents: Iterable[AgentRecord],
        decision: str,
        latency_ms: int,
    ) -> KPISet:
        agents_list = list(agents)
        incidents = current.incidents_24h + 1
        weighted_latency = round(
            ((current.average_latency_ms * current.incidents_24h) + latency_ms) / incidents
        )
        return KPISet(
            attacks_blocked=current.attacks_blocked + (1 if decision == "BLOCK" else 0),
            quarantined=current.quarantined + (1 if decision == "QUARANTINE" else 0),
            active_agents=current.active_agents,
            average_latency_ms=weighted_latency,
            trust_floor=min(agent.trust_score for agent in agents_list),
            incidents_24h=incidents,
        )
