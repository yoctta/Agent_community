"""Defense mechanisms: segmentation enforcement, spend caps, clarification
gates, loop detection, quarantine, trust decay, and key rotation."""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass

from .config import DefenseOverrides
from .database import Database
from .models import (
    AgentState, AgentStatus, Event, EventType, LedgerEntry,
    LedgerEntryType, _uid,
)
from .services import ServiceRegistry

log = logging.getLogger(__name__)


class DefenseManager:
    """Runs active defenses during the barrier phase of each day."""

    def __init__(self, defenses: DefenseOverrides, db: Database,
                 services: ServiceRegistry, rng: random.Random):
        self.defenses = defenses
        self.db = db
        self.svc = services
        self.rng = rng
        self._loop_counters: dict[str, int] = {}  # agent_id → consecutive noop count

    def run(self, sim_day: int, agents: list[AgentState]) -> None:
        """Execute all active defense checks for the day.

        Order matters:
        1. Spend cap / loop detection — may degrade healthy agents.
        2. Key rotation — rotate keys for compromised/quarantined agents.
        3. Trust decay — erode trust for compromised/degraded/distracted,
           *recover* trust for quarantined (isolation earns trust back).
        4. Quarantine — quarantine compromised agents with low trust.
        5. Recovery — release distracted/degraded/quarantined agents
           whose trust has been sufficiently restored.
        """
        for agent in agents:
            agent_fresh = self.db.get_agent(agent.id)
            if agent_fresh is None:
                continue

            self._check_spend_cap(agent_fresh, sim_day)
            self._check_loop_detection(agent_fresh, sim_day)
            self._check_key_rotation(agent_fresh, sim_day)
            self._check_trust_decay(agent_fresh, sim_day)
            self._check_quarantine(agent_fresh, sim_day)
            self._check_recovery(agent_fresh, sim_day)

    # ------------------------------------------------------------------
    # Spend cap
    # ------------------------------------------------------------------

    def _check_spend_cap(self, agent: AgentState, sim_day: int) -> None:
        if not self.defenses.spend_cap_enabled:
            return
        # Sum today's token costs.
        today_entries = self.db.get_ledger_for_day(sim_day)
        agent_costs = sum(
            abs(e.amount) for e in today_entries
            if e.agent_id == agent.id and e.entry_type == LedgerEntryType.TOKEN_COST
        )
        if agent_costs > self.defenses.spend_cap_per_day:
            if self.defenses.spend_cap_action == "block":
                if agent.status == AgentStatus.HEALTHY:
                    agent.status = AgentStatus.DEGRADED
                    self.db.update_agent(agent)
                    self.db.append_event(Event(
                        event_type=EventType.DEFENSE_ACTIVATED,
                        agent_id=agent.id, sim_day=sim_day, sim_tick=0,
                        payload={"defense": "spend_cap", "action": "block",
                                 "amount": agent_costs},
                    ))
                    log.info("spend cap: blocked agent %s (spent %.2f)",
                             agent.id, agent_costs)
            else:  # downgrade
                self.db.append_event(Event(
                    event_type=EventType.DEFENSE_ACTIVATED,
                    agent_id=agent.id, sim_day=sim_day, sim_tick=0,
                    payload={"defense": "spend_cap", "action": "downgrade",
                             "amount": agent_costs},
                ))

    # ------------------------------------------------------------------
    # Loop detection
    # ------------------------------------------------------------------

    def _check_loop_detection(self, agent: AgentState, sim_day: int) -> None:
        if not self.defenses.loop_detection:
            return
        # Count consecutive noop events for this agent.
        events = self.db.get_events(sim_day=sim_day, agent_id=agent.id,
                                     event_type=EventType.AGENT_TURN_END.value)
        noop_streak = 0
        for e in reversed(events):
            if e.payload and e.payload.get("actions", 1) == 0:
                noop_streak += 1
            else:
                break
        key = agent.id
        self._loop_counters[key] = self._loop_counters.get(key, 0) + noop_streak
        if self._loop_counters[key] >= self.defenses.loop_max_repeats:
            if agent.status == AgentStatus.HEALTHY:
                agent.status = AgentStatus.DEGRADED
                self.db.update_agent(agent)
                self.db.append_event(Event(
                    event_type=EventType.DEFENSE_ACTIVATED,
                    agent_id=agent.id, sim_day=sim_day, sim_tick=0,
                    payload={"defense": "loop_detection",
                             "streak": self._loop_counters[key]},
                ))
                log.info("loop detection: degraded agent %s (streak=%d)",
                         agent.id, self._loop_counters[key])
            self._loop_counters[key] = 0

    # ------------------------------------------------------------------
    # Trust decay
    # ------------------------------------------------------------------

    def _check_trust_decay(self, agent: AgentState, sim_day: int) -> None:
        if not self.defenses.recovery_trust_decay:
            return
        old = agent.trust_score
        if agent.status in (AgentStatus.COMPROMISED, AgentStatus.DEGRADED,
                            AgentStatus.DISTRACTED):
            # Active compromise / degradation erodes trust.
            agent.trust_score = max(0.0, agent.trust_score - self.defenses.trust_decay_rate)
        elif agent.status == AgentStatus.QUARANTINED:
            # Quarantined agents are isolated — trust slowly recovers
            # (the agent can't do further damage while quarantined).
            agent.trust_score = min(1.0, agent.trust_score + self.defenses.trust_decay_rate * 0.3)
        elif agent.status == AgentStatus.HEALTHY:
            # Healthy agents recover trust at a moderate rate.
            agent.trust_score = min(1.0, agent.trust_score + self.defenses.trust_decay_rate * 0.5)
        if agent.trust_score != old:
            self.db.update_agent(agent)
            self.db.append_event(Event(
                event_type=EventType.DEFENSE_ACTIVATED,
                agent_id=agent.id, sim_day=sim_day, sim_tick=0,
                payload={"defense": "trust_decay",
                         "old": old, "new": agent.trust_score},
            ))

    # ------------------------------------------------------------------
    # Quarantine
    # ------------------------------------------------------------------

    def _check_quarantine(self, agent: AgentState, sim_day: int) -> None:
        if not self.defenses.recovery_quarantine:
            return
        # Quarantine compromised agents with low trust.
        if (agent.status == AgentStatus.COMPROMISED
                and agent.trust_score < 0.3):
            agent.status = AgentStatus.QUARANTINED
            self.db.update_agent(agent)
            self.db.append_event(Event(
                event_type=EventType.QUARANTINE_APPLIED,
                agent_id=agent.id, sim_day=sim_day, sim_tick=0,
                payload={"trust_score": agent.trust_score},
            ))
            log.info("quarantine: agent %s (trust=%.2f)", agent.id, agent.trust_score)

    # ------------------------------------------------------------------
    # Key rotation
    # ------------------------------------------------------------------

    def _check_key_rotation(self, agent: AgentState, sim_day: int) -> None:
        if not self.defenses.recovery_key_rotation:
            return
        if self.svc.vault is None:
            return
        # Rotate credentials for compromised/quarantined agents.
        if agent.status in (AgentStatus.COMPROMISED, AgentStatus.QUARANTINED):
            count = self.svc.vault.rotate(agent.id, sim_day=sim_day)
            if count > 0:
                self.db.append_event(Event(
                    event_type=EventType.KEY_ROTATION,
                    agent_id=agent.id, sim_day=sim_day, sim_tick=0,
                    payload={"rotated_count": count},
                ))
                log.info("key rotation: rotated %d keys for agent %s", count, agent.id)
        # Periodic rotation for all agents.
        elif (self.defenses.credential_rotation
              and sim_day % self.defenses.rotation_interval_days == 0):
            count = self.svc.vault.rotate(agent.id, sim_day=sim_day)
            if count > 0:
                self.db.append_event(Event(
                    event_type=EventType.KEY_ROTATION,
                    agent_id=agent.id, sim_day=sim_day, sim_tick=0,
                    payload={"rotated_count": count, "periodic": True},
                ))

    # ------------------------------------------------------------------
    # Recovery (distracted/degraded → healthy)
    # ------------------------------------------------------------------

    def _check_recovery(self, agent: AgentState, sim_day: int) -> None:
        """Probabilistic recovery for distracted/degraded agents."""
        if agent.status == AgentStatus.DISTRACTED:
            if self.rng.random() < 0.5:
                agent.status = AgentStatus.HEALTHY
                self.db.update_agent(agent)
                self.db.append_event(Event(
                    event_type=EventType.AGENT_STATUS_CHANGE,
                    agent_id=agent.id, sim_day=sim_day, sim_tick=0,
                    payload={"old": "distracted", "new": "healthy",
                             "reason": "natural_recovery"},
                ))
        elif agent.status == AgentStatus.DEGRADED:
            if self.rng.random() < 0.3:
                agent.status = AgentStatus.HEALTHY
                self.db.update_agent(agent)
                self.db.append_event(Event(
                    event_type=EventType.AGENT_STATUS_CHANGE,
                    agent_id=agent.id, sim_day=sim_day, sim_tick=0,
                    payload={"old": "degraded", "new": "healthy",
                             "reason": "natural_recovery"},
                ))
        elif agent.status == AgentStatus.QUARANTINED:
            # Quarantined agents can only recover if trust is restored
            # and key rotation has been done.
            if self.defenses.recovery_quarantine and agent.trust_score >= 0.5:
                agent.status = AgentStatus.HEALTHY
                self.db.update_agent(agent)
                self.db.append_event(Event(
                    event_type=EventType.AGENT_STATUS_CHANGE,
                    agent_id=agent.id, sim_day=sim_day, sim_tick=0,
                    payload={"old": "quarantined", "new": "healthy",
                             "reason": "trust_restored"},
                ))
