"""Minimal stub runtime for unit tests only.

This is NOT part of the ACES package.  It provides a deterministic
runtime that doesn't require an LLM, so unit tests can exercise the
engine, services, and database without network calls or API keys.

Production code uses LLMAgentRuntime or OpenClawRuntime — both backed
by real LLMs.
"""

from __future__ import annotations

import random
from typing import Any

from aces.models import (
    Action, AgentObservation, AgentState, AgentStatus,
    ClaimJobAction, CompleteJobAction, NoOpAction,
    RespondDelegationAction, SendMailAction,
)
from aces.runtime import AgentRuntime


class StubRuntime(AgentRuntime):
    """Deterministic rule-based stub for testing."""

    def __init__(self, rng: random.Random | None = None):
        self.rng = rng or random.Random()

    def decide(self, obs: AgentObservation,
               max_actions: int = 3) -> list[Action]:
        agent = obs.agent
        actions: list[Action] = []

        if agent.status == AgentStatus.QUARANTINED:
            return [NoOpAction(agent_id=agent.id, reason="quarantined")]

        # Respond to delegations.
        for deleg in obs.pending_delegations[:max_actions]:
            actions.append(RespondDelegationAction(
                agent_id=agent.id, delegation_id=deleg.id,
                accept=True, response="ok",
            ))
            if len(actions) >= max_actions:
                return actions

        # Reply to mail.
        for msg in obs.inbox[:1]:
            actions.append(SendMailAction(
                agent_id=agent.id, recipient_id=msg.sender_id,
                subject=f"Re: {msg.subject}", body="Acknowledged.",
            ))
            if len(actions) >= max_actions:
                return actions

        # Complete current jobs.
        for job in obs.my_jobs:
            if self.rng.random() < 0.6:
                actions.append(CompleteJobAction(
                    agent_id=agent.id, job_id=job.id,
                    result="done", tokens_spent=self.rng.randint(50, 300),
                ))
                if len(actions) >= max_actions:
                    return actions

        # Claim a new job.
        if len(obs.my_jobs) < 2 and obs.available_jobs:
            for job in obs.available_jobs:
                if job.required_role and job.required_role != agent.role:
                    continue
                actions.append(ClaimJobAction(agent_id=agent.id, job_id=job.id))
                break

        return actions[:max_actions] or [
            NoOpAction(agent_id=agent.id, reason="idle"),
        ]
