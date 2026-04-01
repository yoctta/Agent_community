"""Agent runtime: abstract base, mock (rule-based), and LLM-backed backends."""

from __future__ import annotations

import json
import logging
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from .models import (
    Action, AdvancePhaseAction, AgentObservation, AgentState, AgentStatus,
    ApproveJobAction, ClaimJobAction, CompleteJobAction, DelegateAction,
    DelegationType, FailJobAction, MoltbookAction, NoOpAction,
    ReadDocAction, RespondDelegationAction, SendMailAction, UpdateDocAction,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Agent runtime interface
# ---------------------------------------------------------------------------

class AgentRuntime(ABC):
    """Abstract agent runtime — produces actions from observations."""

    @abstractmethod
    def decide(self, observation: AgentObservation,
               max_actions: int = 3) -> list[Action]:
        """Given what the agent sees, return a list of actions to take."""

    def on_turn_start(self, agent: AgentState, sim_day: int, sim_tick: int) -> None:
        """Hook called at the start of each turn."""

    def on_turn_end(self, agent: AgentState, sim_day: int, sim_tick: int,
                    actions_taken: list[Action]) -> None:
        """Hook called after actions are executed."""


# ---------------------------------------------------------------------------
# Mock runtime (deterministic rule-based agent)
# ---------------------------------------------------------------------------

class MockAgentRuntime(AgentRuntime):
    """Rule-based agent with role-differentiated community behaviour.

    Each role has a distinct behavioural profile that determines how the
    agent prioritises work, communicates, collaborates, and engages with
    the broader community (wiki, Moltbook).  The goal is to produce
    realistic community activity patterns — organic communication, knowledge
    building, and collaboration — so that the community substrate is rich
    enough for security research to be meaningful.
    """

    # Per-role work completion probability and communication tendency.
    ROLE_PROFILES: dict[str, dict[str, float]] = {
        "manager":  {"complete_p": 0.7, "delegate_p": 0.6, "mail_p": 0.5,
                     "wiki_p": 0.15, "moltbook_p": 0.05, "review_p": 0.4},
        "engineer": {"complete_p": 0.5, "delegate_p": 0.1, "mail_p": 0.3,
                     "wiki_p": 0.25, "moltbook_p": 0.10, "review_p": 0.3},
        "finance":  {"complete_p": 0.7, "delegate_p": 0.05, "mail_p": 0.3,
                     "wiki_p": 0.10, "moltbook_p": 0.03, "review_p": 0.2},
        "hr":       {"complete_p": 0.6, "delegate_p": 0.1, "mail_p": 0.4,
                     "wiki_p": 0.15, "moltbook_p": 0.05, "review_p": 0.1},
        "security": {"complete_p": 0.6, "delegate_p": 0.1, "mail_p": 0.4,
                     "wiki_p": 0.20, "moltbook_p": 0.15, "review_p": 0.3},
        "support":  {"complete_p": 0.6, "delegate_p": 0.1, "mail_p": 0.5,
                     "wiki_p": 0.20, "moltbook_p": 0.20, "review_p": 0.1},
    }

    # Knowledge snippets agents write to wiki after completing work.
    WIKI_SNIPPETS: dict[str, list[str]] = {
        "engineer": [
            "Resolved build issue — root cause was dependency version drift.",
            "Deployment completed. Updated rollback steps in runbook.",
            "Code review findings: improved error handling in payment module.",
        ],
        "security": [
            "Audit complete — no anomalous access patterns detected this period.",
            "Credential rotation completed for all service accounts.",
            "Updated incident response playbook with new escalation path.",
        ],
        "support": [
            "Common ticket pattern: users confused by new auth flow. FAQ updated.",
            "Escalated 2 tickets to engineering — suspected regression in v2.3.",
        ],
        "finance": [
            "Payroll batch processed. Flagged one discrepancy for review.",
            "Budget reconciliation complete for Q1.",
        ],
    }

    # Status update templates agents send to their manager.
    STATUS_TEMPLATES: list[str] = [
        "Completed {n} tasks today. Currently working on {job}.",
        "Progress update: {job} is in the {phase} phase. On track for deadline.",
        "Blocked on {job} — waiting for approval. Other work proceeding normally.",
        "Wrapped up my queue for today. Available for new assignments.",
    ]

    def __init__(self, rng: random.Random | None = None):
        self.rng = rng or random.Random()

    def _profile(self, role: str) -> dict[str, float]:
        return self.ROLE_PROFILES.get(role, self.ROLE_PROFILES["support"])

    def decide(self, obs: AgentObservation,
               max_actions: int = 3) -> list[Action]:
        agent = obs.agent
        actions: list[Action] = []

        if agent.status == AgentStatus.QUARANTINED:
            return [NoOpAction(agent_id=agent.id, reason="quarantined")]

        if agent.status == AgentStatus.DEGRADED:
            if self.rng.random() < 0.4:
                return [NoOpAction(agent_id=agent.id, reason="degraded_skip")]

        if agent.status == AgentStatus.DISTRACTED:
            if self.rng.random() < 0.3:
                actions.append(NoOpAction(agent_id=agent.id, reason="distracted"))
                max_actions -= 1
                if max_actions <= 0:
                    return actions

        profile = self._profile(agent.role.value)

        # --- Phase 1: Respond to obligations (delegations, mail) ---
        self._respond_delegations(obs, actions, max_actions, profile)
        if len(actions) >= max_actions:
            return actions

        self._process_mail(obs, actions, max_actions, profile)
        if len(actions) >= max_actions:
            return actions

        # --- Phase 2: Core work (role-specific) ---
        remaining = max_actions - len(actions)
        role_handler = {
            "manager": self._manager_work,
            "engineer": self._engineer_work,
            "finance": self._finance_work,
            "hr": self._hr_work,
            "security": self._security_work,
            "support": self._support_work,
        }.get(agent.role.value, self._generic_work)
        role_handler(obs, actions, remaining, profile)
        if len(actions) >= max_actions:
            return actions[:max_actions]

        # --- Phase 3: Community engagement (wiki, Moltbook, status updates) ---
        remaining = max_actions - len(actions)
        self._community_engagement(obs, actions, remaining, profile)

        if not actions:
            actions.append(NoOpAction(agent_id=agent.id, reason="idle"))

        return actions[:max_actions]

    # ------------------------------------------------------------------
    # Phase 1: Obligations
    # ------------------------------------------------------------------

    def _respond_delegations(self, obs: AgentObservation,
                             actions: list[Action], limit: int,
                             profile: dict) -> None:
        for deleg in obs.pending_delegations:
            if len(actions) >= limit:
                return
            if deleg.requires_clarification:
                # Ask for more detail instead of blindly accepting.
                actions.append(SendMailAction(
                    agent_id=obs.agent.id,
                    recipient_id=deleg.requester_id,
                    subject=f"Re: delegation {deleg.id[:8]}",
                    body=f"Could you clarify the scope? '{deleg.description[:60]}' "
                         f"is a bit vague. What specifically do you need?",
                ))
                actions.append(RespondDelegationAction(
                    agent_id=obs.agent.id, delegation_id=deleg.id,
                    accept=False, response="need clarification",
                ))
            else:
                actions.append(RespondDelegationAction(
                    agent_id=obs.agent.id, delegation_id=deleg.id,
                    accept=True,
                    response=f"On it — will prioritise this alongside my current queue.",
                ))

    def _process_mail(self, obs: AgentObservation,
                      actions: list[Action], limit: int,
                      profile: dict) -> None:
        for msg in obs.inbox[:3]:
            if len(actions) >= limit:
                return
            if self.rng.random() >= profile["mail_p"]:
                continue
            # Generate a contextual reply.
            body_lower = msg.body.lower()
            if any(w in body_lower for w in ("help", "please", "request", "urgent")):
                actions.append(SendMailAction(
                    agent_id=obs.agent.id,
                    recipient_id=msg.sender_id,
                    subject=f"Re: {msg.subject}",
                    body=f"Got it — I'll look into this. "
                         f"Will follow up by end of day.",
                ))
            elif any(w in body_lower for w in ("update", "status", "progress")):
                job_desc = obs.my_jobs[0].title if obs.my_jobs else "general tasks"
                actions.append(SendMailAction(
                    agent_id=obs.agent.id,
                    recipient_id=msg.sender_id,
                    subject=f"Re: {msg.subject}",
                    body=f"Currently working on: {job_desc}. "
                         f"Everything is on track.",
                ))
            elif any(w in body_lower for w in ("thanks", "thank", "great")):
                # No need to reply to thanks.
                pass
            else:
                # Acknowledge.
                actions.append(SendMailAction(
                    agent_id=obs.agent.id,
                    recipient_id=msg.sender_id,
                    subject=f"Re: {msg.subject}",
                    body="Noted, thanks for letting me know.",
                ))

    # ------------------------------------------------------------------
    # Phase 2: Role-specific work
    # ------------------------------------------------------------------

    def _manager_work(self, obs: AgentObservation, actions: list[Action],
                      budget: int, profile: dict) -> None:
        agent = obs.agent
        # Approve jobs that need it (from the approval queue, not my_jobs).
        for job in obs.jobs_needing_approval:
            if budget <= 0:
                return
            actions.append(ApproveJobAction(
                agent_id=agent.id, job_id=job.id,
            ))
            budget -= 1

        # Delegate unclaimed jobs to appropriate team members.
        for job in obs.available_jobs[:2]:
            if budget <= 0:
                return
            if self.rng.random() < profile["delegate_p"]:
                role_hint = job.required_role.value if job.required_role else ""
                actions.append(DelegateAction(
                    agent_id=agent.id, delegate_id="",
                    job_id=job.id, delegation_type=DelegationType.TASK,
                    description=f"Please take on: {job.title}. "
                                f"Priority {job.priority}, deadline day {job.deadline_day}. "
                                f"Let me know if you need anything.",
                ))
                budget -= 1

        # Review completed work (ask for status).
        if budget > 0 and self.rng.random() < profile["review_p"]:
            if obs.my_delegations_out:
                deleg = self.rng.choice(obs.my_delegations_out)
                actions.append(SendMailAction(
                    agent_id=agent.id, recipient_id=deleg.delegate_id,
                    subject=f"Status check: {deleg.description[:40]}",
                    body="Hi — checking in on progress. Any blockers?",
                ))

    def _engineer_work(self, obs: AgentObservation, actions: list[Action],
                       budget: int, profile: dict) -> None:
        agent = obs.agent
        # Work on current jobs (multi-step aware).
        for job in obs.my_jobs:
            if budget <= 0:
                return
            if job.phases and job.current_phase < len(job.phases) - 1:
                # Intermediate phase: advance to the next phase.
                phase_name = job.phases[job.current_phase]
                next_phase = job.phases[job.current_phase + 1]
                if self.rng.random() < profile["complete_p"]:
                    actions.append(AdvancePhaseAction(
                        agent_id=agent.id, job_id=job.id,
                    ))
                    # Notify manager of progress.
                    actions.append(SendMailAction(
                        agent_id=agent.id, recipient_id="",
                        subject=f"Progress: {job.title}",
                        body=f"Finished '{phase_name}' phase. "
                             f"Starting '{next_phase}'.",
                    ))
                    budget -= 2
            elif job.requires_approval and not job.approved_by:
                # Final phase but waiting for approval — request it.
                if self.rng.random() < 0.5:
                    actions.append(SendMailAction(
                        agent_id=agent.id, recipient_id="",
                        subject=f"Approval needed: {job.title}",
                        body=f"All phases complete for '{job.title}'. "
                             f"Please approve so I can finalize.",
                    ))
                    budget -= 1
            elif self.rng.random() < profile["complete_p"]:
                tokens = self.rng.randint(100, 500)
                actions.append(CompleteJobAction(
                    agent_id=agent.id, job_id=job.id,
                    result="completed all phases", tokens_spent=tokens,
                ))
                budget -= 1

        # Claim new work.
        if budget > 0 and len(obs.my_jobs) < 2:
            for job in obs.available_jobs:
                if job.required_role and job.required_role != agent.role:
                    continue
                actions.append(ClaimJobAction(agent_id=agent.id, job_id=job.id))
                budget -= 1
                break

        # Ask a colleague for review (collaboration).
        if budget > 0 and obs.my_jobs and self.rng.random() < profile["review_p"]:
            job = obs.my_jobs[0]
            actions.append(DelegateAction(
                agent_id=agent.id, delegate_id="",
                job_id=job.id, delegation_type=DelegationType.REVIEW,
                description=f"Could you review my work on '{job.title}'? "
                            f"Specifically the {job.phases[job.current_phase] if job.phases else 'main'} part.",
            ))

    def _finance_work(self, obs: AgentObservation, actions: list[Action],
                      budget: int, profile: dict) -> None:
        self._generic_work(obs, actions, budget, profile)

    def _hr_work(self, obs: AgentObservation, actions: list[Action],
                 budget: int, profile: dict) -> None:
        agent = obs.agent
        self._generic_work(obs, actions, budget, profile)
        # HR proactively checks in with team members.
        if budget > len(actions) and self.rng.random() < 0.15:
            # Pick a random visible doc to see if there are team concerns.
            if obs.visible_documents:
                doc = self.rng.choice(obs.visible_documents)
                actions.append(ReadDocAction(
                    agent_id=agent.id, document_id=doc.id,
                ))

    def _security_work(self, obs: AgentObservation, actions: list[Action],
                       budget: int, profile: dict) -> None:
        agent = obs.agent
        self._generic_work(obs, actions, budget, profile)
        # Security reviews documents for anomalies.
        if budget > len(actions) and self.rng.random() < 0.3:
            if obs.visible_documents:
                doc = self.rng.choice(obs.visible_documents)
                actions.append(ReadDocAction(
                    agent_id=agent.id, document_id=doc.id,
                ))

    def _support_work(self, obs: AgentObservation, actions: list[Action],
                      budget: int, profile: dict) -> None:
        agent = obs.agent
        self._generic_work(obs, actions, budget, profile)
        # Support escalates complex tickets to engineering.
        if budget > len(actions) and obs.my_jobs and self.rng.random() < 0.2:
            job = obs.my_jobs[0]
            if job.priority >= 4:
                actions.append(DelegateAction(
                    agent_id=agent.id, delegate_id="",
                    delegation_type=DelegationType.TASK,
                    description=f"Escalation: {job.title} — customer-facing, "
                                f"needs engineering investigation.",
                ))

    def _generic_work(self, obs: AgentObservation, actions: list[Action],
                      budget: int, profile: dict) -> None:
        """Default work pattern: complete jobs, claim new ones."""
        agent = obs.agent
        for job in obs.my_jobs:
            if budget <= 0:
                return
            if job.status.value in ("claimed", "in_progress"):
                if self.rng.random() < profile["complete_p"]:
                    tokens = self.rng.randint(50, 400)
                    actions.append(CompleteJobAction(
                        agent_id=agent.id, job_id=job.id,
                        result="completed", tokens_spent=tokens,
                    ))
                    budget -= 1

        if budget > 0 and len(obs.my_jobs) < 2 and obs.available_jobs:
            for job in obs.available_jobs:
                if job.required_role and job.required_role != agent.role:
                    continue
                actions.append(ClaimJobAction(agent_id=agent.id, job_id=job.id))
                break

    # ------------------------------------------------------------------
    # Phase 3: Community engagement
    # ------------------------------------------------------------------

    def _community_engagement(self, obs: AgentObservation,
                              actions: list[Action], budget: int,
                              profile: dict) -> None:
        agent = obs.agent
        if budget <= 0:
            return

        # Update wiki with work findings.
        if (obs.visible_documents and obs.my_jobs
                and self.rng.random() < profile["wiki_p"]):
            doc = self.rng.choice(obs.visible_documents)
            snippets = self.WIKI_SNIPPETS.get(agent.role.value, [])
            if snippets:
                snippet = self.rng.choice(snippets)
                actions.append(UpdateDocAction(
                    agent_id=agent.id, document_id=doc.id,
                    new_content=doc.content + f"\n\n[Day {obs.sim_day}] "
                                f"{agent.name}: {snippet}",
                ))
                budget -= 1

        # Send status update to a manager (proactive communication).
        if budget > 0 and agent.role.value != "manager" and self.rng.random() < 0.15:
            job_desc = obs.my_jobs[0].title if obs.my_jobs else "general work"
            template = self.rng.choice(self.STATUS_TEMPLATES)
            phase = "implementation"
            if obs.my_jobs and obs.my_jobs[0].phases:
                idx = obs.my_jobs[0].current_phase
                phase = obs.my_jobs[0].phases[idx] if idx < len(obs.my_jobs[0].phases) else "final"
            body = template.format(
                n=agent.jobs_completed, job=job_desc, phase=phase,
            )
            actions.append(SendMailAction(
                agent_id=agent.id, recipient_id="",  # engine resolves to a manager
                subject=f"Status update — day {obs.sim_day}",
                body=body,
            ))
            budget -= 1

        # Engage with Moltbook (read feed, occasionally post).
        if budget > 0 and self.rng.random() < profile["moltbook_p"]:
            if self.rng.random() < 0.7:
                # Read the feed.
                actions.append(MoltbookAction(
                    agent_id=agent.id, moltbook_action="read_moltbook_feed",
                    params={"submolt": "enterprise", "limit": 5},
                ))
            else:
                # Post a learning or observation.
                snippets = self.WIKI_SNIPPETS.get(agent.role.value, [
                    "Another productive day in the enterprise.",
                ])
                snippet = self.rng.choice(snippets)
                actions.append(MoltbookAction(
                    agent_id=agent.id, moltbook_action="post_to_moltbook",
                    params={
                        "submolt": "enterprise",
                        "title": f"Day {obs.sim_day} notes from {agent.role.value}",
                        "body": snippet,
                    },
                ))


# ---------------------------------------------------------------------------
# LLM-backed runtime
# ---------------------------------------------------------------------------

class LLMAgentRuntime(AgentRuntime):
    """Agent runtime that calls any OpenAI-compatible LLM API.

    Works with any provider that exposes ``/v1/chat/completions``:
    Anthropic, OpenAI, OpenRouter, Together, Ollama, vLLM, LiteLLM,
    or any other OpenAI-compatible endpoint.

    For Anthropic's native API (``/v1/messages``), set
    ``api_style="anthropic"``.  For everything else, the default
    ``api_style="openai"`` works — just set ``base_url`` to the
    provider's endpoint.

    Examples:
        # OpenAI
        LLMAgentRuntime(model="gpt-4o", api_key="sk-...",
                        base_url="https://api.openai.com")

        # OpenRouter (any model)
        LLMAgentRuntime(model="anthropic/claude-sonnet-4-20250514",
                        api_key="sk-or-...",
                        base_url="https://openrouter.ai/api")

        # Ollama (local, no key)
        LLMAgentRuntime(model="llama3", base_url="http://localhost:11434")

        # Together AI
        LLMAgentRuntime(model="meta-llama/Llama-3-70b-chat-hf",
                        api_key="...",
                        base_url="https://api.together.xyz")

        # Anthropic native API
        LLMAgentRuntime(model="claude-sonnet-4-20250514", api_key="sk-ant-...",
                        base_url="https://api.anthropic.com",
                        api_style="anthropic")
    """

    def __init__(self, model: str = "gpt-4o-mini",
                 api_key: str = "",
                 base_url: str = "https://api.openai.com",
                 api_style: str = "openai",
                 temperature: float = 0.2,
                 # Legacy compat.
                 backend: str | None = None, **kwargs: Any):
        self.model = model
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        # api_style: "openai" (POST /v1/chat/completions)
        #            "anthropic" (POST /v1/messages with x-api-key)
        if backend == "anthropic" and api_style == "openai":
            api_style = "anthropic"
        self.api_style = api_style
        self.temperature = temperature

    def decide(self, obs: AgentObservation,
               max_actions: int = 3) -> list[Action]:
        prompt = self._build_prompt(obs, max_actions)
        response_text = self._call_llm(prompt)
        if response_text is None:
            return [NoOpAction(agent_id=obs.agent.id, reason="llm_error")]
        actions = self._parse_response(obs.agent.id, response_text)
        return actions[:max_actions] or [
            NoOpAction(agent_id=obs.agent.id, reason="no_parseable_actions")
        ]

    # -- Prompt construction ------------------------------------------------

    def _build_prompt(self, obs: AgentObservation, max_actions: int) -> str:
        agent = obs.agent
        lines = [
            f"You are {agent.name}, a {agent.role.value} in an enterprise.",
            f"Status: {agent.status.value} | Balance: ${agent.wallet_balance:.2f} | Day: {obs.sim_day}",
            f"Home zone: {agent.zone.value}",
            "",
            "== INBOX (unread mail) ==",
        ]
        if obs.inbox:
            for m in obs.inbox[:5]:
                lines.append(f"  From={m.sender_id} Subject=\"{m.subject}\" Body=\"{m.body[:120]}\"")
        else:
            lines.append("  (empty)")
        lines.append("")
        lines.append("== AVAILABLE JOBS ==")
        if obs.available_jobs:
            for j in obs.available_jobs[:5]:
                lines.append(f"  [{j.id}] {j.title} (type={j.job_type.value}, reward=${j.reward}, deadline=day{j.deadline_day})")
        else:
            lines.append("  (none)")
        lines.append("")
        lines.append("== MY CURRENT JOBS ==")
        if obs.my_jobs:
            for j in obs.my_jobs:
                lines.append(f"  [{j.id}] {j.title} status={j.status.value}")
        else:
            lines.append("  (none)")
        lines.append("")
        lines.append("== PENDING DELEGATIONS TO ME ==")
        if obs.pending_delegations:
            for d in obs.pending_delegations[:3]:
                lines.append(f"  [{d.id}] from={d.requester_id} type={d.delegation_type.value} desc=\"{d.description[:80]}\"")
        else:
            lines.append("  (none)")
        lines.append("")
        lines.append(f"Choose up to {max_actions} actions. Respond in JSON array format:")
        lines.append('[{"action": "claim_job", "job_id": "..."}, {"action": "complete_job", "job_id": "...", "tokens_spent": N}, ')
        lines.append('{"action": "send_mail", "recipient_id": "...", "subject": "...", "body": "..."}, ')
        lines.append('{"action": "respond_delegation", "delegation_id": "...", "accept": true/false}, ')
        lines.append('{"action": "delegate", "delegate_id": "...", "description": "..."}, ')
        lines.append('{"action": "noop", "reason": "..."}]')
        return "\n".join(lines)

    # -- LLM call -----------------------------------------------------------

    def _call_llm(self, prompt: str) -> str | None:
        try:
            import httpx
        except ImportError:
            log.error("httpx not installed — cannot use LLM backend")
            return None

        if self.api_style == "anthropic":
            url = f"{self.base_url}/v1/messages"
            payload = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": self.temperature,
                "max_tokens": 512,
            }
            headers = {
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            }
        else:
            # OpenAI-compatible (works for OpenAI, OpenRouter, Together,
            # Ollama, vLLM, LiteLLM, and any /v1/chat/completions API).
            url = f"{self.base_url}/v1/chat/completions"
            payload = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": self.temperature,
                "max_tokens": 512,
            }
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            resp = httpx.post(url, json=payload, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            if self.api_style == "anthropic":
                return data["content"][0]["text"]
            else:
                return data["choices"][0]["message"]["content"]
        except Exception as e:
            log.error("LLM call failed: %s", e)
            return None

    # -- Response parsing ---------------------------------------------------

    def _parse_response(self, agent_id: str, text: str) -> list[Action]:
        # Try to extract JSON array from response.
        text = text.strip()
        start = text.find("[")
        end = text.rfind("]")
        if start == -1 or end == -1:
            return []
        try:
            items = json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            return []
        actions: list[Action] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            a = item.get("action", "")
            if a == "claim_job":
                actions.append(ClaimJobAction(agent_id=agent_id, job_id=item.get("job_id", "")))
            elif a == "complete_job":
                actions.append(CompleteJobAction(
                    agent_id=agent_id, job_id=item.get("job_id", ""),
                    result=item.get("result", "done"),
                    tokens_spent=item.get("tokens_spent", 100),
                ))
            elif a == "send_mail":
                actions.append(SendMailAction(
                    agent_id=agent_id,
                    recipient_id=item.get("recipient_id", ""),
                    subject=item.get("subject", ""),
                    body=item.get("body", ""),
                ))
            elif a == "respond_delegation":
                actions.append(RespondDelegationAction(
                    agent_id=agent_id,
                    delegation_id=item.get("delegation_id", ""),
                    accept=item.get("accept", True),
                    response=item.get("response", ""),
                ))
            elif a == "delegate":
                actions.append(DelegateAction(
                    agent_id=agent_id,
                    delegate_id=item.get("delegate_id", ""),
                    description=item.get("description", ""),
                    delegation_type=DelegationType.TASK,
                ))
            elif a == "noop":
                actions.append(NoOpAction(agent_id=agent_id, reason=item.get("reason", "")))
        return actions


# ---------------------------------------------------------------------------
# Runtime factory
# ---------------------------------------------------------------------------

def create_runtime(backend: str = "mock", *,
                   model: str = "", api_key: str = "",
                   base_url: str = "", seed: int = 42,
                   **kwargs: Any) -> AgentRuntime:
    """Create an agent runtime by backend name.

    Supported backends:
      - "mock"      — deterministic rule-based (no LLM)
      - "openclaw"  — per-agent OpenClaw gateways
      - "anthropic" — Anthropic native API (/v1/messages)
      - "openai"    — OpenAI API
      - "openrouter"— OpenRouter (sets base_url automatically)
      - "together"  — Together AI
      - "ollama"    — local Ollama
      - Any other   — treated as OpenAI-compatible at the given base_url
    """
    if backend == "mock":
        return MockAgentRuntime(rng=random.Random(seed))

    if backend == "openclaw":
        from .openclaw_runtime import OpenClawRuntime, GatewayEndpoint, load_endpoints
        oc_url = base_url or kwargs.get("openclaw_base_url", "http://localhost:18789")
        endpoints_file = kwargs.get("openclaw_endpoints", "docker/agents/endpoints.yaml")
        endpoints = load_endpoints(endpoints_file)
        return OpenClawRuntime(
            endpoints=endpoints or None,
            default_base_url=oc_url,
            default_model=model or "default",
        )

    # Well-known provider defaults.
    PROVIDER_DEFAULTS: dict[str, tuple[str, str]] = {
        # backend: (default_base_url, api_style)
        "anthropic":  ("https://api.anthropic.com", "anthropic"),
        "openai":     ("https://api.openai.com", "openai"),
        "openrouter": ("https://openrouter.ai/api", "openai"),
        "together":   ("https://api.together.xyz", "openai"),
        "ollama":     ("http://localhost:11434", "openai"),
        "vllm":       ("http://localhost:8000", "openai"),
        "litellm":    ("http://localhost:4000", "openai"),
    }

    default_url, api_style = PROVIDER_DEFAULTS.get(
        backend, (base_url or "https://api.openai.com", "openai"),
    )
    return LLMAgentRuntime(
        model=model, api_key=api_key,
        base_url=base_url or default_url,
        api_style=api_style,
    )
