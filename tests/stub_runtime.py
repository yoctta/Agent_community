"""Minimal stub runtime for unit tests only.

This is NOT part of the ACES package.  It provides a deterministic
runtime that doesn't require an LLM, so unit tests can exercise the
engine, services, and database without network calls or API keys.

Decisions are a pure function of the (seed, agent_id, sim_day,
sim_tick) tuple, so the async engine — which runs ``decide`` calls
concurrently via ``asyncio.to_thread`` — produces the same result
as the serial engine without any cross-turn rng race.

Production code uses LLMAgentRuntime or OpenClawRuntime — both backed
by real LLMs.
"""

from __future__ import annotations

import hashlib
import random
import struct

from aces.models import (
    Action, AgentObservation, AgentStatus,
    ClaimJobAction, CompleteJobAction, NoOpAction,
    RespondDelegationAction, SendMailAction,
)
from aces.runtime import AgentRuntime


class StubRuntime(AgentRuntime):
    """Deterministic rule-based stub for testing."""

    def __init__(self, rng: random.Random | None = None, seed: int = 0):
        # ``rng`` is retained for backwards compatibility with tests
        # that pass one in; its state is folded into ``_base_seed`` so
        # the same seed produces the same decisions regardless of
        # whether the engine runs sync or async.
        if rng is not None:
            self._base_seed = rng.randint(0, 2**31 - 1)
        else:
            self._base_seed = seed
        # Kept around so legacy callers that poke at ``.rng`` don't
        # break; NOT used inside decide() anymore.
        self.rng = rng or random.Random(self._base_seed)

    def _turn_rng(self, agent_id: str, sim_day: int,
                   sim_tick: int) -> random.Random:
        h = hashlib.blake2b(digest_size=16)
        h.update(struct.pack("<iii", self._base_seed, sim_day, sim_tick))
        h.update(agent_id.encode("utf-8"))
        return random.Random(int.from_bytes(h.digest(), "big"))

    def decide(self, obs: AgentObservation,
               max_actions: int = 3) -> list[Action]:
        agent = obs.agent
        turn_rng = self._turn_rng(agent.id, obs.sim_day, obs.sim_tick)
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
            if turn_rng.random() < 0.6:
                actions.append(CompleteJobAction(
                    agent_id=agent.id, job_id=job.id,
                    result="done", tokens_spent=turn_rng.randint(50, 300),
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
