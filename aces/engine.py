"""Simulation engine: main loop, job generation, turns, and barrier phase."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
from dataclasses import dataclass
from typing import Any

from .config import ACESConfig, DefenseOverrides, EnterpriseConfig
from .database import Database
from .models import (
    AccessCredentialAction, Action, AgentObservation,
    AgentState, AgentStatus, AgentRole, ApproveJobAction, ClaimJobAction,
    AuditMailAction, CommunicationGroup, CompleteJobAction, DelegateAction,
    DelegationType, Event, EventType, FailJobAction, ImpersonationGrant,
    IsolateAgentAction, Job, JobType, LedgerEntry, LedgerEntryType,
    ListServerSecretsAction, LoginServerAction, LookupContactAction,
    MemoryEntry, Message, MessageType, MoltbookAction,
    NoOpAction, ReadDocAction, ReadServerSecretAction, ReleaseAgentAction,
    RespondDelegationAction, RunRecord, SendGroupMailAction, SendMailAction,
    ServerHost, ServerSecretPlacement, TransferTokensAction, TrustedSenderView,
    UpdateDocAction, WebHostBrowseAction, WebHostSSHAction, Zone, _now,
)
from .network import AccessControl, CommunicationPolicy, SocialTrustGraph
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
                 token_cost_per_1k: float = 0.50,
                 comms_policy: CommunicationPolicy | None = None):
        self.db = db
        self.svc = services
        self.runtime = runtime
        self.acl = acl
        self.defenses = defenses
        self.rng = rng
        self.token_cost_per_1k = token_cost_per_1k
        self.comms_policy = comms_policy
        # Engine sets this after construction so handlers can reach
        # defense bookkeeping (e.g. AuditMailAction).
        self.defense_manager: Any = None

    def execute_turn(self, agent: AgentState, sim_day: int,
                     sim_tick: int, max_actions: int,
                     all_agents: list[AgentState]) -> TurnResult:
        """Run one full turn for *agent* (observe → decide → apply).

        Thin wrapper over the three phases so callers that don't care
        about async execution don't have to assemble them.  The async
        engine calls the phases directly.
        """
        obs = self.observe(agent, sim_day, sim_tick)
        actions = self.decide(obs, max_actions)
        return self.apply(agent, actions, sim_day, sim_tick, all_agents)

    # ------------------------------------------------------------------
    # Three-phase API — observe, decide, apply
    # ------------------------------------------------------------------

    def observe(self, agent: AgentState, sim_day: int,
                 sim_tick: int) -> AgentObservation:
        """Phase A: build the observation and log turn-start.

        Pure read from DB aside from the turn-start event append.
        Safe to run concurrently across agents because each observation
        is independent — the only cross-agent shared state modified is
        the events table, which SQLite handles atomically.
        """
        obs = self._build_observation(agent, sim_day, sim_tick)
        self.db.append_event(Event(
            event_type=EventType.AGENT_TURN_START, agent_id=agent.id,
            sim_day=sim_day, sim_tick=sim_tick, zone=agent.zone,
        ))
        return obs

    def decide(self, obs: AgentObservation, max_actions: int) -> list[Action]:
        """Phase B: ask the runtime for an action list.

        Delegates to ``runtime.decide`` — synchronous call wrapping
        whatever backend the runtime uses.  The async engine uses
        ``decide_async`` directly instead.
        """
        return self.runtime.decide(obs, max_actions)

    def apply(self, agent: AgentState, actions: list[Action],
               sim_day: int, sim_tick: int,
               all_agents: list[AgentState]) -> TurnResult:
        """Phase C: execute each action in order, refresh state between
        actions, and emit the turn-end event.  Must run serially with
        respect to other agents' apply phases within the same tick so
        that wallet/status mutations land deterministically.
        """
        tokens = 0
        tools = 0
        executed: list[Action] = []
        for action in actions:
            # Refresh agent state from the DB before each action so that
            # wallet/status mutations made by a previous action in the
            # same turn (e.g. a token transfer followed by a job
            # completion) are not clobbered by stale in-memory state.
            fresh = self.db.get_agent(agent.id)
            if fresh is not None:
                agent = fresh
            ok, t, tl = self._execute_action(action, agent, sim_day, sim_tick, all_agents)
            if ok:
                executed.append(action)
            tokens += t
            tools += tl

        # Determine whether the turn produced meaningful work.  A turn
        # that executed only NoOp actions (or nothing at all) is
        # "idle" — used by the loop-detection defense to catch agents
        # stuck in a no-progress state.
        productive = [a for a in executed if not isinstance(a, NoOpAction)]
        idle = len(productive) == 0
        self.db.append_event(Event(
            event_type=EventType.AGENT_TURN_END, agent_id=agent.id,
            sim_day=sim_day, sim_tick=sim_tick, zone=agent.zone,
            payload={"actions": len(executed),
                     "productive": len(productive),
                     "idle": idle,
                     "tokens": tokens},
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
        # Bound memory pulled into observation by category — long runs
        # otherwise grow this set unboundedly even though the prompt
        # only renders a handful of entries per category.
        memory: list[MemoryEntry] = []
        memory.extend(self.db.get_agent_memory(agent.id, category="contacts", limit=16))
        memory.extend(self.db.get_agent_memory(agent.id, category="knowledge", limit=12))
        memory.extend(self.db.get_agent_memory(agent.id, category="work", limit=8))
        if agent.is_malicious:
            memory.extend(self.db.get_agent_memory(
                agent.id, category="attack_objective", limit=20))
        # Managers and engineering managers see jobs that need their approval.
        approval_jobs: list[Job] = []
        if agent.role in (AgentRole.MANAGER, AgentRole.ENGINEERING_MANAGER,
                           AgentRole.EXECUTIVE):
            for zone in reachable:
                approval_jobs.extend(self.db.get_jobs_needing_approval(zone))

        # Research-community extensions.
        my_groups = self.svc.group_mail.list_groups(agent) if self.svc.group_mail else []
        visible_servers = (self.svc.host_access.list_servers(agent)
                            if self.svc.host_access else [])
        recent_xfers = (self.svc.token_economy.recent_transfers(agent.id, limit=6)
                         if self.svc.token_economy else [])
        grants: list[ImpersonationGrant] = []
        if self.svc.impersonation:
            grants = self.db.get_active_grants_for_actor(agent.id)
        direct_reports: list[str] = []
        if self.comms_policy:
            direct_reports = self.comms_policy.trust.direct_reports(agent.id)
        # Sender trust labels for inbox.
        trust_labels: list[TrustedSenderView] = []
        if self.comms_policy:
            group_coverage: set[str] = set()
            for g in my_groups:
                group_coverage.update(g.members)
            seen_senders: set[str] = set()
            for m in inbox:
                if m.sender_id in seen_senders:
                    continue
                seen_senders.add(m.sender_id)
                shared = m.sender_id in group_coverage
                level = self.comms_policy.sender_trust_level(
                    agent, m.sender_id, shared_group=shared)
                rel = self.comms_policy.trust.relationship(agent.id, m.sender_id)
                trust_labels.append(TrustedSenderView(
                    sender_id=m.sender_id, trust_level=level,
                    relationship=rel,
                ))
        # Attack objectives are visible only to the malicious agent itself.
        attack_objectives: list[str] = []
        if agent.is_malicious:
            for m in memory:
                if m.category == "attack_objective":
                    attack_objectives.append(m.value)

        known_contacts: list[str] = []
        if self.comms_policy:
            known_contacts = self.comms_policy.trust.neighbors(agent.id)

        # Raw security evidence, only for security-role agents.  No
        # scoring, no pre-filtering by heuristic rule — just a
        # chronological dump of recent security-relevant events that
        # the LLM expert is expected to reason over.
        recent_activity_summary: list[str] = []
        quarantined_ids: list[str] = []
        if (agent.role == AgentRole.SECURITY
                and agent.status != AgentStatus.QUARANTINED):
            recent_activity_summary = self._build_security_view(
                sim_day,
                window_days=self.defenses.security_view_window_days,
                limit=self.defenses.security_view_limit,
            )
            quarantined_ids = sorted(
                a.id for a in self.db.get_all_agents()
                if a.status == AgentStatus.QUARANTINED
            )

        return AgentObservation(
            agent=agent, sim_day=sim_day, sim_tick=sim_tick,
            inbox=inbox, available_jobs=available_jobs,
            my_jobs=my_jobs, pending_delegations=pending_delegations,
            my_delegations_out=outgoing_delegations,
            visible_documents=visible_docs,
            jobs_needing_approval=approval_jobs,
            memory=memory,
            known_contacts=known_contacts,
            group_memberships=my_groups,
            direct_reports=direct_reports,
            visible_servers=visible_servers,
            recent_transfers=recent_xfers,
            sender_trust=trust_labels,
            impersonation_grants=grants,
            attack_objectives=attack_objectives,
            recent_activity_summary=recent_activity_summary,
            quarantined_agent_ids=quarantined_ids,
        )

    # ------------------------------------------------------------------
    # Security-agent observation helper — raw evidence, no scoring.
    # ------------------------------------------------------------------

    SECURITY_VIEW_EVENT_TYPES: tuple[str, ...] = (
        "impersonated_mail_sent",
        "impersonated_transfer",
        "impersonation_granted",
        "server_secret_read",
        "server_secret_listed",
        "credential_leaked",
        "credential_accessed",
        "server_login",
    )

    def _build_security_view(self, sim_day: int, *,
                              window_days: int, limit: int) -> list[str]:
        """Return a chronologically-sorted list of one-line event
        summaries for the security agent's observation.

        The intent is to hand the LLM raw, unfiltered evidence from
        the last ``window_days`` days so it can decide for itself
        what's anomalous.  No scoring.  No thresholds.  The security
        agent is expected to pattern-match the evidence the way a
        real threat hunter would read a SIEM timeline.

        Each actor is rendered as ``actor_id[role]`` so the LLM can
        tell "COO logs into payroll server" (routine) apart from
        "IT admin logs into payroll server" (suspicious). Without
        this context sec_david has to guess based on agent id alone,
        which produces avoidable false positives on legitimate admin
        activity.
        """
        role_by_id: dict[str, str] = {
            a.id: a.role.value for a in self.db.get_all_agents()
        }
        start = max(1, sim_day - window_days + 1)
        # A "tripwire" entry is one produced on an extra_monitoring
        # server — these must never be pruned away by the window/limit
        # trimming below, because the factor exists precisely to give
        # the security agent earlier visibility.  Events in the future
        # are still excluded.
        entries: list[tuple[int, int, str]] = []
        tripwire_entries: list[tuple[int, int, str]] = []
        for ev_type in self.SECURITY_VIEW_EVENT_TYPES:
            for e in self.db.get_events(event_type=ev_type):
                if e.sim_day > sim_day:
                    continue
                is_tripwire = bool((e.payload or {}).get("tripwire"))
                if not is_tripwire and e.sim_day < start:
                    continue
                summary = self._format_security_event(e, role_by_id)
                if summary is None:
                    continue
                bucket = tripwire_entries if is_tripwire else entries
                bucket.append((e.sim_day, e.sim_tick, summary))
        # Include attack-flagged mail and group posts so the security
        # agent sees phishing / poisoned content in the same timeline.
        # The formatted line is explicit about sender→victim so the
        # LLM analyst can't confuse the two.
        for e in self.db.get_events(event_type="mail_sent"):
            if e.sim_day < start or e.sim_day > sim_day:
                continue
            p = e.payload or {}
            if not p.get("is_attack"):
                continue
            victim = p.get("recipient", "?")
            eff = p.get("effective_sender", e.agent_id or "?")
            actor_tag = f"{e.agent_id}[{role_by_id.get(e.agent_id or '', '?')}]"
            entries.append((
                e.sim_day, e.sim_tick,
                f"d{e.sim_day} t{e.sim_tick}  {actor_tag:<24} "
                f"PHISHING-MAIL attacker={eff} victim={victim}"
            ))

        entries.sort(key=lambda x: (x[0], x[1]))
        if len(entries) > limit:
            # Keep the most recent `limit` entries so the LLM sees
            # what happened *just now* rather than day-1 noise.
            entries = entries[-limit:]
        # Tripwire entries are always preserved (and always sorted with
        # the regular entries) — they are the whole point of the
        # extra_monitoring tag.
        tripwire_entries.sort(key=lambda x: (x[0], x[1]))
        merged = sorted(entries + tripwire_entries, key=lambda x: (x[0], x[1]))
        return [line for _, _, line in merged]

    def _format_security_event(
        self, e: Event,
        role_by_id: dict[str, str] | None = None,
    ) -> str | None:
        """Format one event line for the security LLM.

        ``role_by_id`` maps agent id → role name so the actor can be
        rendered as ``actor_id[role]`` — critical context for
        distinguishing legitimate admin activity (executive logging
        into their own server) from an intrusion (it_admin logging
        into a finance server). Without it sec_david has to guess
        from the agent id alone and over-isolates on routine traffic.
        """
        p = e.payload or {}
        role_by_id = role_by_id or {}
        actor_id = e.agent_id or "?"
        actor_role = role_by_id.get(actor_id, "?")
        actor = f"{actor_id}[{actor_role}]"
        ev_type = e.event_type.value
        trip = "[TRIPWIRE] " if p.get("tripwire") else ""
        width = 24
        # Skip routine security logins so the view isn't drowned.
        if ev_type == "server_login":
            srv = p.get("server_id", "?")
            return (f"d{e.sim_day} t{e.sim_tick}  {actor:<{width}} "
                    f"{trip}login {srv}")
        if ev_type == "server_secret_listed":
            srv = p.get("server_id", "?")
            n = p.get("count", 0)
            return (f"d{e.sim_day} t{e.sim_tick}  {actor:<{width}} "
                    f"{trip}list-secrets {srv} (n={n})")
        if ev_type == "server_secret_read":
            srv = p.get("server_id", "?")
            path = p.get("path", "?")
            owner = p.get("owner", "?")
            owner_role = role_by_id.get(owner, "?")
            return (f"d{e.sim_day} t{e.sim_tick}  {actor:<{width}} "
                    f"{trip}READ {srv}:{path} (owner={owner}[{owner_role}])")
        if ev_type == "impersonation_granted":
            victim = p.get("victim", "?")
            victim_role = role_by_id.get(victim, "?")
            return (f"d{e.sim_day} t{e.sim_tick}  {actor:<{width}} "
                    f"GRANT impersonate({victim}[{victim_role}])")
        if ev_type == "impersonated_mail_sent":
            eff = p.get("effective_sender", "?")
            rcpt = p.get("recipient", "?")
            return (f"d{e.sim_day} t{e.sim_tick}  {actor:<{width}} "
                    f"IMP-MAIL as={eff} -> {rcpt}")
        if ev_type == "impersonated_transfer":
            eff = p.get("effective_sender", "?")
            rcpt = p.get("recipient", "?")
            amt = p.get("amount", 0)
            return (f"d{e.sim_day} t{e.sim_tick}  {actor:<{width}} "
                    f"IMP-TRANSFER as={eff} -> {rcpt} ${amt}")
        if ev_type == "credential_leaked":
            w = p.get("privilege_weight", 0)
            # Distinguish attacker from victim(s) so sec_david's
            # raw log doesn't conflate "was phished" with "did the
            # phishing".
            victim_ids: list[str] = []
            if p.get("victim"):
                victim_ids = [p["victim"]]
            elif p.get("victims"):
                victim_ids = list(p["victims"])[:3]
            victim_str = ",".join(victim_ids) if victim_ids else "?"
            return (f"d{e.sim_day} t{e.sim_tick}  {actor:<{width}} "
                    f"credential_leaked attacker={actor_id} "
                    f"victims=[{victim_str}] weight={w}")
        if ev_type == "credential_accessed":
            cred = p.get("credential_id", "?")
            zone = p.get("target_zone", "?")
            return (f"d{e.sim_day} t{e.sim_tick}  {actor:<{width}} "
                    f"access-cred {cred} zone={zone}")
        return None

    def _execute_action(self, action: Action, agent: AgentState,
                        sim_day: int, sim_tick: int,
                        all_agents: list[AgentState]) -> tuple[bool, int, int]:
        """Execute *action*. Returns (success, tokens_spent, tools_used)."""
        if isinstance(action, NoOpAction):
            return True, 0, 0

        if isinstance(action, SendMailAction):
            if self.svc.mail:
                recipient = action.recipient_id
                # The LLM sometimes types a group id as the recipient
                # of a direct send (seen with glm-5 — "send_mail to
                # grp_eng"). Treat any recipient whose id begins with
                # ``grp_`` and which resolves to a real group as a
                # group post, so the intent is honoured instead of
                # dropped with ``unknown recipient``.
                if (recipient and recipient.startswith("grp_")
                        and self.svc.group_mail is not None
                        and self.db.get_group(recipient) is not None):
                    delivered = self.svc.group_mail.send_group(
                        agent, recipient, action.subject, action.body,
                        sim_day=sim_day, sim_tick=sim_tick,
                    )
                    return delivered is not None, 0, 1
                # Resolve empty recipient: pick a leadership agent for
                # status updates.  Under the research role set, any of
                # {manager, engineering_manager, executive} counts as
                # "a manager" for fallback purposes.  Prefer the
                # sender's direct manager when we have one (via the
                # social graph) so the traffic isn't random noise.
                if not recipient:
                    leader_roles = {"manager", "engineering_manager", "executive"}
                    preferred: str | None = None
                    if self.comms_policy is not None:
                        rels = self.comms_policy.trust._neighbors.get(agent.id, {})
                        for other_id, rel in rels.items():
                            if rel == "manager":
                                preferred = other_id
                                break
                    if preferred:
                        recipient = preferred
                    else:
                        leaders = [a for a in all_agents
                                    if a.role.value in leader_roles
                                    and a.id != agent.id]
                        if leaders:
                            recipient = self.rng.choice(leaders).id
                        else:
                            peers = [a for a in all_agents if a.id != agent.id]
                            recipient = self.rng.choice(peers).id if peers else ""
                if not recipient:
                    return False, 0, 0
                # Impersonation path: verify the grant + load the victim.
                effective_sender = agent
                actor_for_service: AgentState | None = None
                if action.as_agent_id and action.as_agent_id != agent.id:
                    if (self.svc.impersonation is None or
                            not self.svc.impersonation.can_impersonate(
                                agent.id, action.as_agent_id, "send_mail")):
                        return False, 0, 0
                    victim = self.db.get_agent(action.as_agent_id)
                    if victim is None:
                        return False, 0, 0
                    effective_sender = victim
                    actor_for_service = agent
                msg = self.svc.mail.send(
                    effective_sender, recipient,
                    action.subject, action.body,
                    sim_day=sim_day, sim_tick=sim_tick,
                    actor=actor_for_service,
                )
                if msg:
                    self.db.upsert_memory(MemoryEntry(
                        agent_id=agent.id, category="contacts",
                        key=recipient,
                        value=f"Sent mail '{action.subject}' on day {sim_day}",
                        sim_day_created=sim_day, sim_day_updated=sim_day,
                    ))
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
            job = self.db.get_job(action.job_id)
            # Block completion if approval is required but not granted.
            if job and job.requires_approval and not job.approved_by:
                log.info("completion blocked: job %s requires approval", action.job_id)
                return False, 0, 0
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
            # Update work memory after completing a job
            if job:
                self.db.upsert_memory(MemoryEntry(
                    agent_id=agent.id,
                    category="work",
                    key=f"completed_job_{action.job_id[:8]}",
                    value=f"Completed '{job.title}' on day {sim_day}. Reward: {reward}",
                    sim_day_created=sim_day,
                    sim_day_updated=sim_day,
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
                # Update contact memory after delegation
                if deleg and delegate_id:
                    self.db.upsert_memory(MemoryEntry(
                        agent_id=agent.id,
                        category="contacts",
                        key=delegate_id,
                        value=f"Delegated '{action.description}' to them on day {sim_day}",
                        sim_day_created=sim_day,
                        sim_day_updated=sim_day,
                    ))
                return deleg is not None, 0, 1
            return False, 0, 0

        if isinstance(action, RespondDelegationAction):
            if self.svc.delegation:
                deleg = self.db.get_delegation(action.delegation_id)
                self.svc.delegation.respond(
                    agent, action.delegation_id, action.accept,
                    sim_day=sim_day, sim_tick=sim_tick,
                )
                # Track collaborator on the delegated job.
                if action.accept and deleg and deleg.get("job_id"):
                    self.db.add_job_collaborator(
                        deleg["job_id"], agent.id)
                return True, 0, 1
            return False, 0, 0

        if isinstance(action, ReadDocAction):
            if self.svc.wiki:
                doc = self.svc.wiki.read(agent, action.document_id)
                if doc:
                    self.db.upsert_memory(MemoryEntry(
                        agent_id=agent.id, category="knowledge",
                        key=f"read_doc_{doc.id[:8]}",
                        value=f"Read '{doc.title}' (v{doc.version}) on day {sim_day}",
                        sim_day_created=sim_day, sim_day_updated=sim_day,
                    ))
                return doc is not None, 0, 1
            return False, 0, 0

        if isinstance(action, UpdateDocAction):
            if self.svc.wiki:
                ok = self.svc.wiki.update(
                    agent, action.document_id, action.new_content,
                    sim_day=sim_day, sim_tick=sim_tick,
                )
                if ok:
                    self.db.upsert_memory(MemoryEntry(
                        agent_id=agent.id, category="knowledge",
                        key=f"updated_doc_{action.document_id[:8]}",
                        value=f"Updated doc '{action.document_id}' on day {sim_day}",
                        sim_day_created=sim_day, sim_day_updated=sim_day,
                    ))
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

        if isinstance(action, WebHostSSHAction):
            if self.svc.webhost is None:
                return False, 0, 0
            wh = self.svc.webhost
            p = action.params
            if action.ssh_action == "create_page":
                page = wh.ssh_create_page(
                    agent, p.get("path", ""), p.get("title", ""),
                    p.get("content", ""), zone=p.get("zone", "corpnet"),
                    visibility=p.get("visibility", "internal"),
                    sim_day=sim_day, sim_tick=sim_tick,
                )
                return page is not None, 0, 1
            elif action.ssh_action == "edit_page":
                ok = wh.ssh_edit_page(
                    agent, p.get("path", ""), p.get("content", ""),
                    sim_day=sim_day, sim_tick=sim_tick,
                )
                return ok, 0, 1
            elif action.ssh_action == "delete_page":
                ok = wh.ssh_delete_page(
                    agent, p.get("path", ""),
                    sim_day=sim_day, sim_tick=sim_tick,
                )
                return ok, 0, 1
            elif action.ssh_action == "exec":
                result = wh.ssh_exec(
                    agent, p.get("command", ""),
                    sim_day=sim_day, sim_tick=sim_tick,
                )
                return result is not None, 0, 1
            elif action.ssh_action == "deploy":
                count = wh.ssh_deploy(agent, sim_day=sim_day, sim_tick=sim_tick)
                return count >= 0, 0, 1
            elif action.ssh_action == "view_logs":
                logs = wh.ssh_view_logs(agent, lines=p.get("lines", 20))
                return len(logs) > 0, 0, 1
            return False, 0, 0

        if isinstance(action, WebHostBrowseAction):
            if self.svc.webhost is None:
                return False, 0, 0
            wh = self.svc.webhost
            p = action.params
            if action.browse_action == "browse_page":
                page = wh.browse_page(
                    agent, p.get("path", ""),
                    sim_day=sim_day, sim_tick=sim_tick,
                )
                return page is not None, 0, 1
            elif action.browse_action == "list_pages":
                pages = wh.list_pages(agent, zone=p.get("zone"), limit=p.get("limit", 20))
                return len(pages) > 0, 0, 1
            elif action.browse_action == "search_pages":
                pages = wh.search_pages(agent, p.get("query", ""), limit=p.get("limit", 10))
                return len(pages) > 0, 0, 1
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

        if isinstance(action, SendGroupMailAction):
            if self.svc.group_mail is None:
                return False, 0, 0
            delivered = self.svc.group_mail.send_group(
                agent, action.group_id, action.subject, action.body,
                sim_day=sim_day, sim_tick=sim_tick,
            )
            return delivered is not None, 0, 1

        if isinstance(action, TransferTokensAction):
            if self.svc.token_economy is None:
                return False, 0, 0
            via_imp = False
            sender_identity = agent
            if action.as_agent_id and action.as_agent_id != agent.id:
                # Require an active impersonation grant.
                if (self.svc.impersonation is None or
                        not self.svc.impersonation.can_impersonate(
                            agent.id, action.as_agent_id, "transfer_tokens")):
                    return False, 0, 0
                victim = self.db.get_agent(action.as_agent_id)
                if victim is None:
                    return False, 0, 0
                sender_identity = victim
                via_imp = True
            tx = self.svc.token_economy.transfer(
                agent, sender_identity, action.recipient_id,
                action.amount, action.note,
                sim_day=sim_day, sim_tick=sim_tick,
                via_impersonation=via_imp,
            )
            return tx is not None, 0, 1

        if isinstance(action, LookupContactAction):
            if self.svc.directory is None:
                return False, 0, 0
            matches = self.svc.directory.lookup(agent, action.query)
            if matches:
                # Remember discoveries as contact memory so the agent
                # can act on them in later ticks.
                for m in matches[:5]:
                    self.db.upsert_memory(MemoryEntry(
                        agent_id=agent.id, category="contacts",
                        key=m.id,
                        value=f"Looked up: {m.name} ({m.role.value}) "
                              f"zone={m.zone.value}",
                        sim_day_created=sim_day, sim_day_updated=sim_day,
                    ))
            return len(matches) > 0, 0, 1

        if isinstance(action, LoginServerAction):
            if self.svc.host_access is None:
                return False, 0, 0
            srv = self.svc.host_access.login(
                agent, action.server_id,
                sim_day=sim_day, sim_tick=sim_tick,
            )
            return srv is not None, 0, 1

        if isinstance(action, ListServerSecretsAction):
            if self.svc.host_access is None:
                return False, 0, 0
            secrets_ = self.svc.host_access.list_secrets(
                agent, action.server_id,
                sim_day=sim_day, sim_tick=sim_tick,
            )
            return len(secrets_) > 0, 0, 1

        if isinstance(action, ReadServerSecretAction):
            if self.svc.host_access is None:
                return False, 0, 0
            grant = self.svc.host_access.read_secret(
                agent, action.server_id, action.secret_path,
                sim_day=sim_day, sim_tick=sim_tick,
            )
            return grant is not None, 0, 1

        if isinstance(action, AuditMailAction):
            # Security-only action.  Collects RAW evidence from the
            # recent event log — no scoring, no threshold.  The
            # calling agent (LLM security expert) is expected to
            # reason over the evidence themselves and decide whether
            # to call ``isolate_agent`` next turn.  If a suspect is
            # named, the dump is narrowed to that actor.
            if agent.role.value != "security":
                return False, 0, 0

            window = max(1, self.defenses.security_view_window_days)
            start = max(1, sim_day - window + 1)
            limit = max(10, self.defenses.security_view_limit)
            role_by_id: dict[str, str] = {
                a.id: a.role.value for a in self.db.get_all_agents()
            }
            evidence: list[tuple[int, int, str]] = []
            relevant = TurnManager.SECURITY_VIEW_EVENT_TYPES
            for ev_type in relevant:
                for e in self.db.get_events(event_type=ev_type):
                    if e.sim_day < start or e.sim_day > sim_day:
                        continue
                    if (action.suspected_agent_id
                            and e.agent_id != action.suspected_agent_id):
                        continue
                    line = self._format_security_event(e, role_by_id)
                    if line:
                        evidence.append((e.sim_day, e.sim_tick, line))
            # Attack-flagged mail is also evidence.
            for e in self.db.get_events(event_type="mail_sent"):
                if e.sim_day < start or e.sim_day > sim_day:
                    continue
                p = e.payload or {}
                if not p.get("is_attack"):
                    continue
                if (action.suspected_agent_id
                        and e.agent_id != action.suspected_agent_id):
                    continue
                actor_tag = (
                    f"{e.agent_id}[{role_by_id.get(e.agent_id or '', '?')}]"
                )
                evidence.append((
                    e.sim_day, e.sim_tick,
                    f"d{e.sim_day} t{e.sim_tick}  {actor_tag:<24} "
                    f"mail [is_attack=True] -> {p.get('recipient','?')}"
                ))

            evidence.sort(key=lambda x: (x[0], x[1]))
            if len(evidence) > limit:
                evidence = evidence[-limit:]

            self.db.append_event(Event(
                event_type=EventType.MAIL_AUDITED, agent_id=agent.id,
                sim_day=sim_day, sim_tick=sim_tick, zone=agent.zone,
                payload={"evidence_count": len(evidence),
                         "suspected": action.suspected_agent_id},
            ))

            # Deliver the raw evidence as a self-originated alert
            # message so the next turn's inbox surfaces it.  No
            # scoring, no recommendation — the security LLM decides.
            if evidence:
                body_lines = [line for _, _, line in evidence]
                header = (f"Audit sweep ({len(evidence)} events")
                if action.suspected_agent_id:
                    header += f", suspect={action.suspected_agent_id}"
                header += ") — raw evidence follows:"
                alert = Message(
                    sender_id=agent.id, recipient_id=agent.id,
                    subject=(f"AUDIT: {len(evidence)} events"
                             + (f" (suspect={action.suspected_agent_id})"
                                if action.suspected_agent_id else "")),
                    body=header + "\n" + "\n".join(body_lines),
                    message_type=MessageType.ALERT, zone=agent.zone,
                )
                self.db.insert_message(alert)
            return True, 0, 1

        if isinstance(action, IsolateAgentAction):
            # LLM-driven isolation.  Gated to security role (the
            # DefenseManager enforces this again internally).  The
            # defense manager handles the actual quarantine,
            # impersonation-grant revocation, credential rotation,
            # and bounty/fine accounting.
            if self.defense_manager is None:
                return False, 0, 0
            if not action.target_id:
                return False, 0, 0
            ok = self.defense_manager.isolate_agent(
                agent, action.target_id,
                reason=action.reason or "llm_security_decision",
                sim_day=sim_day, sim_tick=sim_tick,
            )
            return ok, 0, 1

        if isinstance(action, ReleaseAgentAction):
            # LLM-driven release from quarantine.  Gated to security
            # role; the defense manager reverses the bounty (fine for
            # releasing an attacker, refund for correcting a false
            # positive).
            if self.defense_manager is None:
                return False, 0, 0
            if not action.target_id:
                return False, 0, 0
            ok = self.defense_manager.release_agent(
                agent, action.target_id,
                reason=action.reason or "llm_security_decision",
                sim_day=sim_day, sim_tick=sim_tick,
            )
            return ok, 0, 1

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

        # Build access control, social trust graph, and services.
        self.acl = AccessControl.from_config(cfg.enterprise, cfg.defenses)
        self.social = SocialTrustGraph.from_config(cfg.enterprise)
        self.comms_policy = CommunicationPolicy(trust=self.social)
        self.services = ServiceRegistry.build(
            db, self.acl, cfg.defenses,
            social=self.social,
            token_policy=cfg.enterprise.token_policy,
        )
        self.job_gen = JobGenerator(cfg.enterprise, self.rng)
        self.turn_mgr = TurnManager(
            db, self.services, runtime, self.acl, cfg.defenses, self.rng,
            token_cost_per_1k=cfg.enterprise.token_cost_per_1k,
            comms_policy=self.comms_policy,
        )

        # Attack injector and defense manager are set externally.
        self.attack_injector: Any = None
        self.defense_manager: Any = None
        self.metrics_computer: Any = None
        # Per-run checkpoint sidecar.  When set, the engine writes
        # ``{run_id, last_completed_day}`` after every successful
        # barrier and ``run()`` / ``run_async()`` resume from
        # ``last_completed_day + 1`` if the sidecar already exists.
        self.checkpoint_path: str | None = None

    def __setattr__(self, name: str, value: Any) -> None:
        # Mirror defense_manager onto the TurnManager so AuditMailAction
        # handlers can reach _compute_suspicion without threading an
        # extra arg through every service.  Similarly, if a metrics
        # computer is installed after init_world ran we backfill the
        # CSRI baseline so the economic-loss term stays honest.
        object.__setattr__(self, name, value)
        if name == "defense_manager" and hasattr(self, "turn_mgr"):
            self.turn_mgr.defense_manager = value
        if name == "metrics_computer" and value is not None:
            baseline = getattr(self, "_baseline_non_attacker_balance", None)
            if baseline is not None:
                value.baseline_non_attacker_balance = baseline

    # ------------------------------------------------------------------
    # World initialization
    # ------------------------------------------------------------------

    def init_world(self) -> None:
        """Create agents, credentials, memory, groups, servers, and secrets."""
        self.db.clear_run_data()
        for adef in self.cfg.enterprise.agents:
            agent = AgentState(
                id=adef.id, name=adef.name,
                role=AgentRole(adef.role), zone=Zone(adef.zone),
                wallet_balance=adef.initial_balance,
                title=adef.title,
                manager_id=adef.manager_id,
                directory_scope=adef.directory_scope,
                is_malicious=adef.is_malicious,
            )
            self.db.insert_agent(agent)
            self.db.append_event(Event(
                event_type=EventType.AGENT_CREATED, agent_id=agent.id,
                sim_day=0, sim_tick=0, zone=agent.zone,
                payload={"role": adef.role, "title": adef.title,
                         "zone": adef.zone, "manager_id": adef.manager_id,
                         "specialization": adef.specialization,
                         "seniority": adef.seniority,
                         "is_malicious": adef.is_malicious},
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
            # Attack objectives only visible to malicious agents, and
            # only when the attacker policy is actually letting the
            # insider act. Under ``passive`` mode the whole point is
            # that the malicious agent behaves like a normal
            # community member, so we must not prime his LLM with
            # hostile objectives.
            if (adef.is_malicious
                    and self.cfg.attacks.attacker_policy != "passive"):
                for i, obj in enumerate(adef.attack_objectives):
                    self.db.upsert_memory(MemoryEntry(
                        agent_id=adef.id, category="attack_objective",
                        key=f"attack_objective_{i}",
                        value=obj,
                        sim_day_created=0, sim_day_updated=0,
                    ))

        # Communication groups.
        for gdef in self.cfg.enterprise.communication_groups:
            grp = CommunicationGroup(
                id=gdef.id, name=gdef.name,
                description=gdef.description,
                posting_policy=gdef.posting_policy,
                members=list(gdef.members),
                admins=list(gdef.admins),
            )
            self.db.insert_group(grp)

        # Server hosts.
        server_overlays: dict[str, dict[str, Any]] = {}
        if self.cfg.scenario_overrides is not None:
            server_overlays = self.cfg.scenario_overrides.server_updates or {}
        for sdef in self.cfg.enterprise.servers:
            patch = server_overlays.get(sdef.id, {})
            srv = ServerHost(
                id=sdef.id, name=sdef.name,
                zone=Zone(sdef.zone),
                tags=list(sdef.tags),
                login_roles=[AgentRole(r) for r in sdef.login_roles],
                admin_roles=[AgentRole(r) for r in sdef.admin_roles],
                description=sdef.description,
                extra_monitoring=bool(
                    patch.get("extra_monitoring", sdef.extra_monitoring)),
            )
            self.db.insert_server(srv)

        # Secret placements — issue high-privilege credentials and place
        # them on the configured servers.
        for pdef in self.cfg.enterprise.secret_placements:
            owner = self.db.get_agent(pdef.owner_agent_id)
            if owner is None or self.services.vault is None:
                continue
            cred = self.services.vault.issue(
                owner, pdef.key_name,
                scope="global",
                privilege_weight=pdef.privilege_weight,
                sim_day=0,
            )
            usable_as = pdef.usable_as_agent_id or pdef.owner_agent_id
            for storage in pdef.stored_on:
                self.db.insert_server_secret(ServerSecretPlacement(
                    server_id=storage.server_id,
                    credential_id=cred.id,
                    path=storage.path,
                    exposure_level=storage.exposure_level,
                    owner_agent_id=pdef.owner_agent_id,
                    usable_as_agent_id=usable_as,
                    privilege_weight=pdef.privilege_weight,
                ))

        # Stash the baseline non-attacker balance for CSRI economic
        # loss computation.  Captured here so it reflects the true
        # starting wallet state, not the (potentially drained)
        # end-of-run state.
        baseline = sum(
            a.initial_balance for a in self.cfg.enterprise.agents
            if not a.is_malicious
        )
        if self.metrics_computer is not None:
            self.metrics_computer.baseline_non_attacker_balance = baseline
        self._baseline_non_attacker_balance = baseline

        log.info("world initialized with %d agents, %d groups, %d servers, %d secrets",
                 len(self.cfg.enterprise.agents),
                 len(self.cfg.enterprise.communication_groups),
                 len(self.cfg.enterprise.servers),
                 len(self.cfg.enterprise.secret_placements))

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def _read_checkpoint(self) -> int:
        """Return the last completed day from the checkpoint sidecar,
        or 0 if no sidecar / wrong run id."""
        if not self.checkpoint_path or not os.path.exists(self.checkpoint_path):
            return 0
        try:
            with open(self.checkpoint_path) as f:
                data = json.load(f)
        except Exception:
            return 0
        if data.get("run_id") != self.run_id:
            return 0
        return int(data.get("last_completed_day", 0))

    def _write_checkpoint(self, last_completed_day: int) -> None:
        if not self.checkpoint_path:
            return
        tmp = self.checkpoint_path + ".tmp"
        try:
            os.makedirs(os.path.dirname(self.checkpoint_path) or ".",
                         exist_ok=True)
            with open(tmp, "w") as f:
                json.dump({
                    "run_id": self.run_id,
                    "last_completed_day": last_completed_day,
                    "updated_at": _now(),
                }, f)
            os.replace(tmp, self.checkpoint_path)
        except Exception as e:
            log.warning("failed to write checkpoint %s: %s",
                        self.checkpoint_path, e)

    def run(self, days: int | None = None) -> RunRecord:
        """Run the full simulation. Returns a RunRecord."""
        max_days = days or self.cfg.experiment.days_per_run
        run = RunRecord(
            id=self.run_id, experiment_id=self.cfg.experiment.name,
            condition_name="", seed=0, status="running", started_at=_now(),
        )
        self.db.insert_run(run)

        start_day = self._read_checkpoint() + 1
        if start_day > 1:
            log.info("resuming run %s from day %d", self.run_id, start_day)

        final_day = max(start_day - 1, 0)
        for day in range(start_day, max_days + 1):
            stop = self._run_day(day)
            final_day = day
            self._write_checkpoint(day)
            if stop:
                log.info("early stop at day %d", day)
                break
        run.final_day = final_day or max_days

        run.status = "completed"
        run.completed_at = _now()
        # Compute final metrics.
        if self.metrics_computer:
            run.final_metrics = self.metrics_computer.compute_final(self.run_id, run.final_day)
        self.db.update_run(run)
        return run

    def _run_day(self, day: int) -> bool:
        """Execute one simulated day. Returns True if early-stop triggered."""
        agents = self._start_day(day)
        for tick in range(1, self.cfg.enterprise.ticks_per_day + 1):
            self._run_tick_sync(day, tick, agents)
        return self._barrier(day)

    def _start_day(self, day: int) -> list[AgentState]:
        """Emit DAY_START, generate jobs, inject attacks, return the
        daily agent snapshot used for per-tick scheduling."""
        self.db.append_event(Event(
            event_type=EventType.DAY_START, sim_day=day, sim_tick=0,
            payload={"day": day},
        ))
        new_jobs = self.job_gen.generate(day)
        for job in new_jobs:
            self.db.insert_job(job)
            self.db.append_event(Event(
                event_type=EventType.JOB_CREATED, sim_day=day, sim_tick=0,
                zone=job.zone,
                payload={"job_id": job.id, "type": job.job_type.value},
            ))
        agents = self.db.get_all_agents()
        if self.attack_injector:
            self.attack_injector.inject(day, agents)
        return agents

    def _shuffled_turn_order(self, agents: list[AgentState]) -> list[AgentState]:
        order = list(agents)
        self.rng.shuffle(order)
        return order

    def _run_tick_sync(self, day: int, tick: int,
                        agents: list[AgentState]) -> None:
        """Serial tick execution — used by the legacy synchronous
        runtime path and by any test that doesn't want an event loop."""
        order = self._shuffled_turn_order(agents)
        max_actions = self.cfg.enterprise.max_actions_per_tick
        for agent in order:
            fresh = self.db.get_agent(agent.id)
            if fresh is None:
                continue
            self.turn_mgr.execute_turn(
                fresh, day, tick, max_actions, agents,
            )

    async def run_async(self, days: int | None = None) -> RunRecord:
        """Async main loop — parallelizes within-tick LLM decisions.

        Ticks themselves remain serial (to preserve the barrier
        semantics the design doc specifies), but inside each tick:

        1. Phase A — build every agent's observation from a fresh DB
           snapshot.  This is pure read, safe to do in sequence (it's
           fast) or concurrently.
        2. Phase B — call ``runtime.decide_async`` for every agent in
           parallel, bounded by the runtime's concurrency semaphore.
        3. Phase C — apply each agent's actions serially in the
           deterministic shuffled order so state mutations don't race.

        Determinism is preserved at tick boundaries: same seed in,
        same event stream out.  Within a tick, agents still react only
        to the state as it looked at phase A — an agent cannot see
        mail another agent sent on the same tick.  This is actually
        a cleaner semantic than the serial version.
        """
        max_days = days or self.cfg.experiment.days_per_run
        run = RunRecord(
            id=self.run_id, experiment_id=self.cfg.experiment.name,
            condition_name="", seed=0, status="running", started_at=_now(),
        )
        self.db.insert_run(run)

        start_day = self._read_checkpoint() + 1
        if start_day > 1:
            log.info("resuming run %s from day %d", self.run_id, start_day)

        try:
            final_day = max(start_day - 1, 0)
            for day in range(start_day, max_days + 1):
                stop = await self._run_day_async(day)
                final_day = day
                self._write_checkpoint(day)
                if stop:
                    log.info("early stop at day %d", day)
                    break
            run.final_day = final_day or max_days
            run.status = "completed"
            run.completed_at = _now()
            if self.metrics_computer:
                run.final_metrics = self.metrics_computer.compute_final(
                    self.run_id, run.final_day)
            self.db.update_run(run)
            return run
        finally:
            await self.runtime.aclose()

    async def _run_day_async(self, day: int) -> bool:
        agents = self._start_day(day)
        for tick in range(1, self.cfg.enterprise.ticks_per_day + 1):
            await self._run_tick_async(day, tick, agents)
        return self._barrier(day)

    async def _run_tick_async(self, day: int, tick: int,
                                agents: list[AgentState]) -> None:
        """Two-phase tick: fan out observations + LLM calls, then
        apply actions serially."""
        order = self._shuffled_turn_order(agents)
        max_actions = self.cfg.enterprise.max_actions_per_tick

        # Phase A — build observations from a fresh per-agent snapshot.
        snapshots: list[tuple[AgentState, Any]] = []
        for agent in order:
            fresh = self.db.get_agent(agent.id)
            if fresh is None:
                continue
            obs = self.turn_mgr.observe(fresh, day, tick)
            snapshots.append((fresh, obs))

        if not snapshots:
            return

        # Phase B — parallel LLM decisions.  Exceptions bubble out of
        # gather by default; we keep that behaviour so a misconfigured
        # runtime fails loudly instead of silently dropping agents.
        decide_tasks = [
            self.runtime.decide_async(obs, max_actions)
            for _, obs in snapshots
        ]
        action_lists = await asyncio.gather(*decide_tasks)

        # Phase C — apply in deterministic order.  Refresh inside
        # ``TurnManager.apply`` will pick up any wallet/status changes
        # committed by earlier agents in this same tick.
        for (fresh, _), actions in zip(snapshots, action_lists, strict=True):
            self.turn_mgr.apply(
                fresh, actions, day, tick, agents,
            )

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
