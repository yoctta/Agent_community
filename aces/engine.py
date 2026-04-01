"""Simulation engine: main loop, job generation, turns, and barrier phase."""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass, field
from typing import Any

from .config import ACESConfig, DefenseOverrides, EnterpriseConfig
from .database import Database
from .models import (
    AccessCredentialAction, Action, AdvancePhaseAction, AgentObservation,
    AgentState, AgentStatus, AgentRole, ApproveJobAction, ClaimJobAction,
    CompleteJobAction, DelegateAction, DelegationType, Event, EventType,
    FailJobAction, Job, JobStatus, JobType, LedgerEntry, LedgerEntryType,
    Message, MetricSnapshot, MoltbookAction, NoOpAction, ReadDocAction,
    RespondDelegationAction, RunRecord, SendMailAction, UpdateDocAction,
    Zone, _now, _uid,
)
from .network import AccessControl
from .runtime import AgentRuntime
from .services import ServiceRegistry

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Job generator
# ---------------------------------------------------------------------------

class JobGenerator:
    """Creates routine jobs from templates each simulated day."""

    def __init__(self, enterprise: EnterpriseConfig, rng: random.Random):
        self.templates = enterprise.job_templates
        self.rng = rng
        self._counter = 0

    def generate(self, sim_day: int) -> list[Job]:
        jobs: list[Job] = []
        for tmpl in self.templates:
            # Poisson-distributed count with mean = frequency.
            count = self._poisson(tmpl.frequency)
            for _ in range(count):
                self._counter += 1
                title = tmpl.title_pattern or f"{tmpl.job_type} #{self._counter}"
                job = Job(
                    title=title,
                    description=f"Auto-generated {tmpl.job_type} for day {sim_day}",
                    job_type=JobType(tmpl.job_type),
                    zone=Zone(tmpl.zone),
                    required_role=AgentRole(tmpl.required_role) if tmpl.required_role else None,
                    priority=tmpl.priority,
                    reward=tmpl.reward,
                    penalty=tmpl.penalty,
                    deadline_day=sim_day + tmpl.deadline_days,
                    created_day=sim_day,
                    phases=list(tmpl.phases),
                    requires_approval=tmpl.requires_approval,
                )
                jobs.append(job)
        return jobs

    def _poisson(self, lam: float) -> int:
        """Simple Poisson sample using inverse-transform."""
        import math
        L = math.exp(-lam)
        k = 0
        p = 1.0
        while True:
            k += 1
            p *= self.rng.random()
            if p <= L:
                return k - 1


# ---------------------------------------------------------------------------
# Turn manager
# ---------------------------------------------------------------------------

@dataclass
class TurnResult:
    agent_id: str
    actions: list[Action]
    tokens_spent: int = 0
    tools_used: int = 0


class TurnManager:
    """Executes a single agent turn: observe → decide → act."""

    def __init__(self, db: Database, services: ServiceRegistry,
                 runtime: AgentRuntime, acl: AccessControl,
                 defenses: DefenseOverrides, rng: random.Random,
                 token_cost_per_1k: float = 0.50):
        self.db = db
        self.svc = services
        self.runtime = runtime
        self.acl = acl
        self.defenses = defenses
        self.rng = rng
        self.token_cost_per_1k = token_cost_per_1k

    def execute_turn(self, agent: AgentState, sim_day: int,
                     sim_tick: int, max_actions: int,
                     all_agents: list[AgentState]) -> TurnResult:
        """Run one turn for *agent*."""
        # -- Build observation --
        obs = self._build_observation(agent, sim_day, sim_tick)

        self.db.append_event(Event(
            event_type=EventType.AGENT_TURN_START, agent_id=agent.id,
            sim_day=sim_day, sim_tick=sim_tick, zone=agent.zone,
        ))

        # -- Agent decides --
        actions = self.runtime.decide(obs, max_actions)

        # -- Execute actions --
        tokens = 0
        tools = 0
        executed: list[Action] = []
        for action in actions:
            ok, t, tl = self._execute_action(action, agent, sim_day, sim_tick, all_agents)
            if ok:
                executed.append(action)
            tokens += t
            tools += tl

        self.db.append_event(Event(
            event_type=EventType.AGENT_TURN_END, agent_id=agent.id,
            sim_day=sim_day, sim_tick=sim_tick, zone=agent.zone,
            payload={"actions": len(executed), "tokens": tokens},
        ))

        return TurnResult(agent.id, executed, tokens, tools)

    def _build_observation(self, agent: AgentState, sim_day: int,
                           sim_tick: int) -> AgentObservation:
        inbox = self.svc.mail.read_inbox(agent, sim_day, sim_tick) if self.svc.mail else []
        # Show jobs from all zones the agent can reach (not just home zone).
        reachable = self.acl.topology.reachable_zones(agent.zone.value, agent)
        available_jobs: list[Job] = []
        seen_ids: set[str] = set()
        for zone in reachable:
            for job in self.db.get_pending_jobs(zone=zone, role=agent.role.value):
                if job.id not in seen_ids:
                    available_jobs.append(job)
                    seen_ids.add(job.id)
        my_jobs = self.db.get_agent_jobs(agent.id)
        pending_delegations = self.db.get_pending_delegations(agent.id)
        outgoing_delegations = self.db.get_agent_outgoing_delegations(agent.id)
        visible_docs = self.db.get_documents_in_zone(agent.zone.value)
        memory = self.db.get_agent_memory(agent.id)
        # Managers see jobs that need their approval across reachable zones.
        approval_jobs: list[Job] = []
        if agent.role == AgentRole.MANAGER:
            for zone in reachable:
                approval_jobs.extend(self.db.get_jobs_needing_approval(zone))
        return AgentObservation(
            agent=agent, sim_day=sim_day, sim_tick=sim_tick,
            inbox=inbox, available_jobs=available_jobs,
            my_jobs=my_jobs, pending_delegations=pending_delegations,
            my_delegations_out=outgoing_delegations,
            visible_documents=visible_docs,
            jobs_needing_approval=approval_jobs,
            memory=memory,
        )

    def _execute_action(self, action: Action, agent: AgentState,
                        sim_day: int, sim_tick: int,
                        all_agents: list[AgentState]) -> tuple[bool, int, int]:
        """Execute *action*. Returns (success, tokens_spent, tools_used)."""
        tokens = 0
        tools = 0

        if isinstance(action, NoOpAction):
            return True, 0, 0

        if isinstance(action, SendMailAction):
            if self.svc.mail:
                recipient = action.recipient_id
                # Resolve empty recipient: pick a manager for status
                # updates, or a random peer for other mail.
                if not recipient:
                    managers = [a for a in all_agents
                                if a.role.value == "manager" and a.id != agent.id]
                    if managers:
                        recipient = self.rng.choice(managers).id
                    else:
                        peers = [a for a in all_agents if a.id != agent.id]
                        recipient = self.rng.choice(peers).id if peers else ""
                if not recipient:
                    return False, 0, 0
                msg = self.svc.mail.send(
                    agent, recipient, action.subject, action.body,
                    sim_day=sim_day, sim_tick=sim_tick,
                )
                return msg is not None, 0, 1
            return False, 0, 0

        if isinstance(action, ClaimJobAction):
            ok = self.db.claim_job(action.job_id, agent.id)
            if ok:
                self.db.append_event(Event(
                    event_type=EventType.JOB_CLAIMED, agent_id=agent.id,
                    sim_day=sim_day, sim_tick=sim_tick,
                    payload={"job_id": action.job_id},
                ))
            return ok, 0, 1

        if isinstance(action, CompleteJobAction):
            # Validate agent owns this job.
            my_jobs = self.db.get_agent_jobs(agent.id)
            if not any(j.id == action.job_id for j in my_jobs):
                return False, 0, 0
            # Fetch reward before marking complete (status will change).
            job = self.db.get_job(action.job_id)
            reward = job.reward if job else 10.0
            self.db.complete_job(action.job_id)
            agent.jobs_completed += 1
            self.db.insert_ledger_entry(LedgerEntry(
                agent_id=agent.id, entry_type=LedgerEntryType.REWARD,
                amount=reward, description=f"job {action.job_id}",
                sim_day=sim_day,
            ))
            agent.wallet_balance += reward
            tokens = action.tokens_spent
            agent.tokens_used += tokens
            token_cost = (tokens / 1000.0) * self.token_cost_per_1k
            agent.wallet_balance -= token_cost
            self.db.insert_ledger_entry(LedgerEntry(
                agent_id=agent.id, entry_type=LedgerEntryType.TOKEN_COST,
                amount=-token_cost, description=f"tokens for job {action.job_id}",
                sim_day=sim_day,
            ))
            self.db.update_agent(agent)
            self.db.append_event(Event(
                event_type=EventType.JOB_COMPLETED, agent_id=agent.id,
                sim_day=sim_day, sim_tick=sim_tick,
                payload={"job_id": action.job_id, "tokens": tokens, "reward": reward},
            ))
            return True, tokens, 1

        if isinstance(action, ApproveJobAction):
            self.db.approve_job(action.job_id, agent.id)
            self.db.append_event(Event(
                event_type=EventType.JOB_COMPLETED,
                agent_id=agent.id, sim_day=sim_day, sim_tick=sim_tick,
                payload={"job_id": action.job_id, "approved": True},
            ))
            return True, 0, 1

        if isinstance(action, AdvancePhaseAction):
            my_jobs = self.db.get_agent_jobs(agent.id)
            if not any(j.id == action.job_id for j in my_jobs):
                return False, 0, 0
            advanced = self.db.advance_job_phase(action.job_id)
            if advanced:
                job = self.db.get_job(action.job_id)
                phase_name = (job.phases[job.current_phase]
                              if job and job.phases and job.current_phase < len(job.phases)
                              else "next")
                self.db.append_event(Event(
                    event_type=EventType.JOB_CLAIMED,  # reuse for phase advance
                    agent_id=agent.id, sim_day=sim_day, sim_tick=sim_tick,
                    payload={"job_id": action.job_id, "phase": phase_name,
                             "advance": True},
                ))
            return advanced, 0, 1

        if isinstance(action, FailJobAction):
            my_jobs = self.db.get_agent_jobs(agent.id)
            if not any(j.id == action.job_id for j in my_jobs):
                return False, 0, 0
            self.db.fail_job(action.job_id)
            agent.jobs_failed += 1
            self.db.update_agent(agent)
            self.db.append_event(Event(
                event_type=EventType.JOB_FAILED, agent_id=agent.id,
                sim_day=sim_day, sim_tick=sim_tick,
                payload={"job_id": action.job_id, "reason": action.reason},
            ))
            return True, 0, 0

        if isinstance(action, DelegateAction):
            if self.svc.delegation:
                delegate_id = action.delegate_id
                # Resolve empty delegate_id: match by job's required role,
                # or by delegation type (reviews go to peers).
                if not delegate_id:
                    candidates = [a for a in self.db.get_all_agents()
                                  if a.id != agent.id
                                  and a.status not in (AgentStatus.QUARANTINED, AgentStatus.COMPROMISED)]
                    # Prefer role-matched candidates.
                    if action.job_id:
                        job = self.db.get_job(action.job_id)
                        if job and job.required_role:
                            role_matched = [c for c in candidates
                                            if c.role == job.required_role]
                            if role_matched:
                                candidates = role_matched
                    # Reviews go to same-role peers.
                    if action.delegation_type == DelegationType.REVIEW:
                        peers = [c for c in candidates if c.role == agent.role]
                        if peers:
                            candidates = peers
                    if candidates:
                        delegate_id = self.rng.choice(candidates).id
                    else:
                        return False, 0, 0
                deleg = self.svc.delegation.request(
                    agent, delegate_id, action.delegation_type,
                    action.description, job_id=action.job_id,
                    sim_day=sim_day, sim_tick=sim_tick,
                )
                return deleg is not None, 0, 1
            return False, 0, 0

        if isinstance(action, RespondDelegationAction):
            if self.svc.delegation:
                self.svc.delegation.respond(
                    agent, action.delegation_id, action.accept,
                    sim_day=sim_day, sim_tick=sim_tick,
                )
                return True, 0, 1
            return False, 0, 0

        if isinstance(action, ReadDocAction):
            if self.svc.wiki:
                doc = self.svc.wiki.read(agent, action.document_id)
                return doc is not None, 0, 1
            return False, 0, 0

        if isinstance(action, UpdateDocAction):
            if self.svc.wiki:
                ok = self.svc.wiki.update(
                    agent, action.document_id, action.new_content,
                    sim_day=sim_day, sim_tick=sim_tick,
                )
                return ok, 0, 1
            return False, 0, 0

        if isinstance(action, AccessCredentialAction):
            if self.svc.vault:
                val = self.svc.vault.access(
                    agent, action.credential_id, agent.zone.value,
                    sim_day=sim_day, sim_tick=sim_tick,
                )
                return val is not None, 0, 1
            return False, 0, 0

        if isinstance(action, MoltbookAction):
            if self.svc.moltbook is None:
                return False, 0, 0
            mb = self.svc.moltbook
            p = action.params
            if action.moltbook_action == "read_moltbook_feed":
                posts = mb.read_feed(
                    agent, submolt=p.get("submolt"),
                    limit=p.get("limit", 10),
                    sim_day=sim_day, sim_tick=sim_tick,
                )
                return len(posts) > 0, 0, 1
            elif action.moltbook_action == "post_to_moltbook":
                post = mb.create_post(
                    agent, p.get("submolt", "enterprise"),
                    p.get("title", ""), p.get("body", ""),
                    sim_day=sim_day, sim_tick=sim_tick,
                )
                return post is not None, 0, 1
            elif action.moltbook_action == "comment_on_moltbook":
                comment = mb.add_comment(
                    agent, p.get("post_id", ""), p.get("body", ""),
                    sim_day=sim_day, sim_tick=sim_tick,
                )
                return comment is not None, 0, 1
            return False, 0, 0

        log.warning("unknown action type: %s", type(action).__name__)
        return False, 0, 0


# ---------------------------------------------------------------------------
# Simulation engine
# ---------------------------------------------------------------------------

class SimulationEngine:
    """Main simulation loop: days → ticks → agent turns → barrier."""

    def __init__(self, cfg: ACESConfig, db: Database,
                 runtime: AgentRuntime, run_id: str,
                 rng: random.Random | None = None):
        self.cfg = cfg
        self.db = db
        self.runtime = runtime
        self.run_id = run_id
        self.rng = rng or random.Random()
        self.defenses = cfg.defenses

        # Build access control and services.
        self.acl = AccessControl.from_config(cfg.enterprise, cfg.defenses)
        self.services = ServiceRegistry.build(db, self.acl, cfg.defenses)
        self.job_gen = JobGenerator(cfg.enterprise, self.rng)
        self.turn_mgr = TurnManager(
            db, self.services, runtime, self.acl, cfg.defenses, self.rng,
            token_cost_per_1k=cfg.enterprise.token_cost_per_1k,
        )

        # Attack injector and defense manager are set externally.
        self.attack_injector: Any = None
        self.defense_manager: Any = None
        self.metrics_computer: Any = None

    # ------------------------------------------------------------------
    # World initialization
    # ------------------------------------------------------------------

    def init_world(self) -> None:
        """Create agents, credentials, initial memory, and documents."""
        from .models import MemoryEntry
        self.db.clear_run_data()
        for adef in self.cfg.enterprise.agents:
            agent = AgentState(
                id=adef.id, name=adef.name,
                role=AgentRole(adef.role), zone=Zone(adef.zone),
                wallet_balance=adef.initial_balance,
            )
            self.db.insert_agent(agent)
            self.db.append_event(Event(
                event_type=EventType.AGENT_CREATED, agent_id=agent.id,
                sim_day=0, sim_tick=0, zone=agent.zone,
                payload={"role": adef.role, "zone": adef.zone,
                         "specialization": adef.specialization,
                         "seniority": adef.seniority},
            ))
            # Issue initial credentials.
            if self.services.vault:
                self.services.vault.issue(
                    agent, f"{adef.role}_api_key",
                    scope=adef.zone if self.defenses.credential_scope == "scoped" else "global",
                    privilege_weight=1.0, sim_day=0,
                )
            # Seed known-agents as contact memory.
            for ka in adef.known_agents:
                self.db.upsert_memory(MemoryEntry(
                    agent_id=adef.id, category="contacts",
                    key=ka.id,
                    value=f"{ka.relationship}: {ka.notes}" if ka.notes else ka.relationship,
                    sim_day_created=0, sim_day_updated=0,
                ))
            # Seed world knowledge.
            for i, fact in enumerate(adef.world_knowledge):
                self.db.upsert_memory(MemoryEntry(
                    agent_id=adef.id, category="knowledge",
                    key=f"fact_{i}",
                    value=fact,
                    sim_day_created=0, sim_day_updated=0,
                ))
            # Seed initial memory.
            for mp in adef.initial_memory:
                self.db.upsert_memory(MemoryEntry(
                    agent_id=adef.id, category=mp.category,
                    key=mp.key, value=mp.value,
                    sim_day_created=0, sim_day_updated=0,
                ))

        log.info("world initialized with %d agents", len(self.cfg.enterprise.agents))

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(self, days: int | None = None) -> RunRecord:
        """Run the full simulation. Returns a RunRecord."""
        max_days = days or self.cfg.experiment.days_per_run
        run = RunRecord(
            id=self.run_id, experiment_id=self.cfg.experiment.name,
            condition_name="", seed=0, status="running", started_at=_now(),
        )
        self.db.insert_run(run)

        for day in range(1, max_days + 1):
            stop = self._run_day(day)
            if stop:
                log.info("early stop at day %d", day)
                run.final_day = day
                break
        else:
            run.final_day = max_days

        run.status = "completed"
        run.completed_at = _now()
        # Compute final metrics.
        if self.metrics_computer:
            run.final_metrics = self.metrics_computer.compute_final(self.run_id, run.final_day)
        self.db.update_run(run)
        return run

    def _run_day(self, day: int) -> bool:
        """Execute one simulated day. Returns True if early-stop triggered."""
        self.db.append_event(Event(
            event_type=EventType.DAY_START, sim_day=day, sim_tick=0,
            payload={"day": day},
        ))

        # Generate new jobs.
        new_jobs = self.job_gen.generate(day)
        for job in new_jobs:
            self.db.insert_job(job)
            self.db.append_event(Event(
                event_type=EventType.JOB_CREATED, sim_day=day, sim_tick=0,
                zone=job.zone, payload={"job_id": job.id, "type": job.job_type.value},
            ))

        # Inject attacks before agent turns so agents encounter attack
        # content (phishing mail, poisoned docs) during their turns.
        agents = self.db.get_all_agents()
        if self.attack_injector:
            self.attack_injector.inject(day, agents)

        # Active phase: ticks.
        for tick in range(1, self.cfg.enterprise.ticks_per_day + 1):
            # Deterministic but shuffled order per tick.
            order = list(agents)
            self.rng.shuffle(order)
            for agent in order:
                # Refresh agent state (may have changed).
                fresh = self.db.get_agent(agent.id)
                if fresh is None:
                    continue
                self.turn_mgr.execute_turn(
                    fresh, day, tick,
                    self.cfg.enterprise.max_actions_per_tick,
                    agents,
                )

        # Barrier phase.
        return self._barrier(day)

    def _barrier(self, day: int) -> bool:
        """End-of-day barrier: payroll, penalties, defenses, metrics."""
        self.db.append_event(Event(
            event_type=EventType.BARRIER_START, sim_day=day, sim_tick=0,
        ))

        # Pre-compute salary lookup once.
        salary_by_id: dict[str, float] = {}
        for adef in self.cfg.enterprise.agents:
            salary_by_id[adef.id] = adef.salary

        # 1. Settle payroll — persist each agent immediately.
        agents = self.db.get_all_agents()
        for agent in agents:
            if agent.status != AgentStatus.QUARANTINED:
                salary = salary_by_id.get(agent.id, self.cfg.enterprise.salary_per_day)
                self.db.insert_ledger_entry(LedgerEntry(
                    agent_id=agent.id, entry_type=LedgerEntryType.SALARY,
                    amount=salary, description=f"salary day {day}",
                    sim_day=day,
                ))
                agent.wallet_balance += salary
                self.db.update_agent(agent)

        # 2. Penalize overdue jobs.
        overdue = self.db.get_overdue_jobs(day)
        for job in overdue:
            if job.assigned_to:
                self.db.insert_ledger_entry(LedgerEntry(
                    agent_id=job.assigned_to, entry_type=LedgerEntryType.PENALTY,
                    amount=-job.penalty,
                    description=f"overdue job {job.id}",
                    sim_day=day,
                ))
                a = self.db.get_agent(job.assigned_to)
                if a:
                    a.wallet_balance -= job.penalty
                    self.db.update_agent(a)
            self.db.abandon_job(job.id)
            self.db.append_event(Event(
                event_type=EventType.JOB_ABANDONED, sim_day=day,
                agent_id=job.assigned_to,
                payload={"job_id": job.id},
            ))

        # 3. Run defenses (attack injection moved to start of day).
        if self.defense_manager:
            self.defense_manager.run(day, self.db.get_all_agents())

        # 4. Snapshot metrics.
        if self.metrics_computer:
            snap = self.metrics_computer.snapshot(self.run_id, day)
            self.db.insert_metric_snapshot(snap)

        self.db.append_event(Event(
            event_type=EventType.DAY_END, sim_day=day, sim_tick=0,
            payload={"day": day},
        ))

        # 5. Check early-stop conditions.
        return self._check_early_stop(day)

    def _check_early_stop(self, day: int) -> bool:
        agents = self.db.get_all_agents()
        # Insolvency: all agents below threshold.
        if self.cfg.experiment.early_stop_insolvency:
            if all(a.wallet_balance < self.cfg.experiment.insolvency_threshold
                   for a in agents):
                log.warning("early stop: all agents insolvent at day %d", day)
                return True
        # Full compromise.
        if self.cfg.experiment.early_stop_full_compromise:
            bad = sum(1 for a in agents if a.status in
                      (AgentStatus.COMPROMISED, AgentStatus.QUARANTINED))
            if bad == len(agents):
                log.warning("early stop: all agents compromised/quarantined at day %d", day)
                return True
        return False
