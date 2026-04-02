"""Agent runtime: abstract base and LLM-backed backend.

The runtime is the interface between the simulation engine and the LLM
that powers each agent.  It takes an observation (what the agent sees)
and returns a list of actions (what the agent does).

Two production backends:
  - LLMAgentRuntime  — calls any OpenAI-compatible API directly
  - OpenClawRuntime  — communicates with per-agent OpenClaw gateways

Both require a real LLM.  For testing without an LLM, see
``tests/stub_runtime.py``.
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from typing import Any

from .models import (
    Action, AgentObservation, AgentState,
    AdvancePhaseAction, ApproveJobAction,
    ClaimJobAction, CompleteJobAction, DelegateAction, DelegationType,
    FailJobAction, MoltbookAction, NoOpAction, ReadDocAction,
    RespondDelegationAction, SendMailAction, UpdateDocAction,
    AccessCredentialAction, WebHostBrowseAction, WebHostSSHAction,
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
# LLM-backed runtime (any OpenAI-compatible API)
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

    Examples::

        # OpenAI
        LLMAgentRuntime(model="gpt-4o", api_key="sk-...",
                        base_url="https://api.openai.com")

        # OpenRouter (any model)
        LLMAgentRuntime(model="anthropic/claude-sonnet-4-20250514",
                        api_key="sk-or-...",
                        base_url="https://openrouter.ai/api")

        # Ollama (local, no key)
        LLMAgentRuntime(model="llama3",
                        base_url="http://localhost:11434")

        # Anthropic native API
        LLMAgentRuntime(model="claude-sonnet-4-20250514",
                        api_key="sk-ant-...",
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
        ]
        # Include agent memory context.
        contacts = [m for m in obs.memory if m.category == "contacts"]
        knowledge = [m for m in obs.memory if m.category == "knowledge"]
        work_ctx = [m for m in obs.memory if m.category == "work"]
        if contacts:
            lines.append("\nYour colleagues:")
            for c in contacts[:8]:
                lines.append(f"  - {c.key}: {c.value}")
        if knowledge:
            lines.append("\nDomain knowledge:")
            for k in knowledge[:6]:
                lines.append(f"  - {k.value}")
        if work_ctx:
            lines.append("\nCurrent context:")
            for w in work_ctx[:4]:
                lines.append(f"  - {w.key}: {w.value}")

        lines.append("\n== INBOX (unread mail) ==")
        if obs.inbox:
            for m in obs.inbox[:5]:
                lines.append(f"  From={m.sender_id} Subject=\"{m.subject}\" Body=\"{m.body[:120]}\"")
        else:
            lines.append("  (empty)")
        lines.append("\n== AVAILABLE JOBS ==")
        if obs.available_jobs:
            for j in obs.available_jobs[:5]:
                phase_info = f" phases={j.phases}" if j.phases else ""
                lines.append(f"  [{j.id}] {j.title} (reward=${j.reward}, deadline=day{j.deadline_day}){phase_info}")
        else:
            lines.append("  (none)")
        lines.append("\n== MY CURRENT JOBS ==")
        if obs.my_jobs:
            for j in obs.my_jobs:
                phase_info = ""
                if j.phases:
                    phase_info = f" phase={j.phases[j.current_phase]}/{len(j.phases)}"
                approval = " [NEEDS APPROVAL]" if j.requires_approval and not j.approved_by else ""
                lines.append(f"  [{j.id}] {j.title} status={j.status.value}{phase_info}{approval}")
        else:
            lines.append("  (none)")
        lines.append("\n== PENDING DELEGATIONS TO ME ==")
        if obs.pending_delegations:
            for d in obs.pending_delegations[:3]:
                lines.append(f"  [{d.id}] from={d.requester_id} type={d.delegation_type.value} desc=\"{d.description[:80]}\"")
        else:
            lines.append("  (none)")
        if obs.jobs_needing_approval:
            lines.append("\n== JOBS AWAITING YOUR APPROVAL ==")
            for j in obs.jobs_needing_approval[:3]:
                lines.append(f"  [{j.id}] {j.title} assigned_to={j.assigned_to}")

        lines.append(f"\nChoose up to {max_actions} actions. Respond in JSON array format:")
        lines.append('[{"action": "claim_job", "job_id": "..."}, '
                     '{"action": "complete_job", "job_id": "...", "tokens_spent": N}, '
                     '{"action": "advance_phase", "job_id": "..."}, '
                     '{"action": "approve_job", "job_id": "..."}, '
                     '{"action": "send_mail", "recipient_id": "...", "subject": "...", "body": "..."}, '
                     '{"action": "respond_delegation", "delegation_id": "...", "accept": true/false}, '
                     '{"action": "delegate", "delegate_id": "...", "description": "..."}, '
                     '{"action": "noop", "reason": "..."}]')
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
                    agent_id=agent_id,
                    job_id=item.get("job_id", ""),
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
            elif a == "advance_phase":
                actions.append(AdvancePhaseAction(
                    agent_id=agent_id, job_id=item.get("job_id", "")))
            elif a == "approve_job":
                actions.append(ApproveJobAction(
                    agent_id=agent_id, job_id=item.get("job_id", "")))
            elif a == "fail_job":
                actions.append(FailJobAction(
                    agent_id=agent_id, job_id=item.get("job_id", ""),
                    reason=item.get("reason", "")))
            elif a == "delegate":
                actions.append(DelegateAction(
                    agent_id=agent_id,
                    delegate_id=item.get("delegate_id", ""),
                    description=item.get("description", ""),
                    job_id=item.get("job_id"),
                    delegation_type=DelegationType(
                        item.get("delegation_type", "task")),
                ))
            elif a == "read_document":
                actions.append(ReadDocAction(
                    agent_id=agent_id,
                    document_id=item.get("document_id", "")))
            elif a == "update_document":
                actions.append(UpdateDocAction(
                    agent_id=agent_id,
                    document_id=item.get("document_id", ""),
                    new_content=item.get("new_content", "")))
            elif a == "access_credential":
                actions.append(AccessCredentialAction(
                    agent_id=agent_id,
                    credential_id=item.get("credential_id", "")))
            elif a == "browse_page":
                actions.append(WebHostBrowseAction(
                    agent_id=agent_id, browse_action="browse_page",
                    params={"path": item.get("path", "")}))
            elif a in ("ssh_create_page", "ssh_edit_page", "ssh_exec",
                        "ssh_deploy", "ssh_view_logs"):
                actions.append(WebHostSSHAction(
                    agent_id=agent_id, ssh_action=a.replace("ssh_", ""),
                    params=item))
            elif a in ("read_moltbook_feed", "post_to_moltbook"):
                actions.append(MoltbookAction(
                    agent_id=agent_id, moltbook_action=a, params=item))
            elif a == "noop":
                actions.append(NoOpAction(agent_id=agent_id, reason=item.get("reason", "")))
        return actions


# ---------------------------------------------------------------------------
# Runtime factory
# ---------------------------------------------------------------------------

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


def create_runtime(backend: str = "openai", *,
                   model: str = "", api_key: str = "",
                   base_url: str = "", seed: int = 42,
                   **kwargs: Any) -> AgentRuntime:
    """Create an agent runtime by backend name.

    Supported backends:
      - "openclaw"  — per-agent OpenClaw gateways
      - "anthropic" — Anthropic native API (/v1/messages)
      - "openai"    — OpenAI API
      - "openrouter"— OpenRouter (sets base_url automatically)
      - "together"  — Together AI
      - "ollama"    — local Ollama
      - Any other   — treated as OpenAI-compatible at the given base_url
    """
    if backend == "openclaw":
        from .openclaw_runtime import OpenClawRuntime
        workspaces = kwargs.get("openclaw_workspaces", "docker/agents")
        return OpenClawRuntime(workspaces_dir=workspaces)

    default_url, api_style = PROVIDER_DEFAULTS.get(
        backend, (base_url or "https://api.openai.com", "openai"),
    )
    return LLMAgentRuntime(
        model=model, api_key=api_key,
        base_url=base_url or default_url,
        api_style=api_style,
    )
