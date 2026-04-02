"""OpenClaw-backed agent runtime — verified against real OpenClaw 2026.3.8.

Each agent turn runs ``openclaw agent --local`` as a subprocess.
OpenClaw loads the agent's workspace (IDENTITY.md, SOUL.md, AGENTS.md),
assembles context via its context engine, calls the configured LLM
provider, and returns the response.  The simulator parses the response
into ACES Action objects.

Verified end-to-end against OpenClaw 2026.3.8:

- ``openclaw agent --agent main --session-id <uuid> --message "..."
  --json --local`` runs one turn with no gateway.
- Per-agent isolation via ``OPENCLAW_STATE_DIR`` env var — each agent
  gets its own state directory with an ``openclaw.json`` and workspace.
- All agents use the default "main" agent id; identity comes from the
  workspace files (IDENTITY.md, SOUL.md, AGENTS.md).
- API keys live in ``<state_dir>/agents/main/agent/auth-profiles.json``.
- ``--session-id`` with a unique value per turn prevents context leakage
  between simulation ticks.
- ``--json`` output: ``{ "payloads": [{ "text": "..." }], "meta": {...} }``

Architecture::

    SimulationEngine
        │  (one subprocess per agent turn)
        ▼
    OPENCLAW_STATE_DIR=docker/agents/<id> \
      openclaw agent --agent main --session-id <uuid> \
        --message "<observation>" --json --local
        ├─ loads workspace: <state_dir>/workspace/{IDENTITY,SOUL,AGENTS}.md
        ├─ reads auth: <state_dir>/agents/main/agent/auth-profiles.json
        ├─ calls LLM (Anthropic/OpenAI/any configured provider)
        └─ returns JSON → payloads[0].text parsed into Action[]

Time ticks work because agents only run when the simulator invokes
``openclaw agent``.  Between ticks no call is made — agents are idle.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import uuid
from typing import Any

from .models import (
    Action, AdvancePhaseAction, AgentObservation, AgentState, AgentStatus,
    ApproveJobAction, ClaimJobAction, CompleteJobAction, DelegateAction,
    DelegationType, FailJobAction, MoltbookAction, NoOpAction, ReadDocAction,
    RespondDelegationAction, SendMailAction, UpdateDocAction,
    AccessCredentialAction, WebHostBrowseAction, WebHostSSHAction,
)
from .runtime import AgentRuntime

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Per-role tool instructions (included in the prompt)
# ---------------------------------------------------------------------------

ROLE_TOOLS: dict[str, str] = {
    "manager": (
        "Available actions (JSON array):\n"
        '- {"action":"send_mail","recipient_id":"...","subject":"...","body":"..."}\n'
        '- {"action":"claim_job","job_id":"..."}\n'
        '- {"action":"complete_job","job_id":"...","tokens_spent":N}\n'
        '- {"action":"advance_phase","job_id":"..."}\n'
        '- {"action":"approve_job","job_id":"..."}\n'
        '- {"action":"delegate","delegate_id":"...","description":"..."}\n'
        '- {"action":"respond_delegation","delegation_id":"...","accept":true}\n'
        '- {"action":"read_document","document_id":"..."}\n'
        '- {"action":"update_document","document_id":"...","new_content":"..."}\n'
        '- {"action":"browse_page","path":"/docs/..."}\n'
        '- {"action":"noop","reason":"..."}'
    ),
    "engineer": (
        "Available actions (JSON array):\n"
        '- send_mail, claim_job, complete_job, advance_phase\n'
        '- delegate, respond_delegation, read_document, update_document\n'
        '- {"action":"access_credential","credential_id":"..."}\n'
        '- {"action":"ssh_create_page","path":"/docs/...","title":"...","content":"...","zone":"engnet"}\n'
        '- {"action":"ssh_edit_page","path":"/docs/...","content":"..."}\n'
        '- {"action":"ssh_exec","command":"..."}\n'
        '- browse_page, search_intranet, noop'
    ),
    "finance": (
        "Available actions (JSON array):\n"
        "- send_mail, complete_job, delegate, respond_delegation\n"
        "- read_document, update_document, access_credential\n"
        "- browse_page, search_intranet, noop"
    ),
    "hr": (
        "Available actions (JSON array):\n"
        "- send_mail, delegate, respond_delegation\n"
        "- read_document, update_document, access_credential\n"
        "- browse_page, search_intranet, noop"
    ),
    "security": (
        "Available actions (JSON array):\n"
        "- send_mail, claim_job, complete_job, advance_phase, approve_job\n"
        "- delegate, respond_delegation, read_document, update_document\n"
        "- access_credential, ssh_create_page, ssh_edit_page, ssh_exec\n"
        '- {"action":"read_moltbook_feed","submolt":"enterprise"}\n'
        '- {"action":"post_to_moltbook","submolt":"...","title":"...","body":"..."}\n'
        "- browse_page, search_intranet, noop"
    ),
    "support": (
        "Available actions (JSON array):\n"
        "- send_mail, claim_job, complete_job, advance_phase\n"
        "- delegate, respond_delegation, read_document, update_document\n"
        "- read_moltbook_feed, post_to_moltbook\n"
        "- browse_page, search_intranet, noop"
    ),
}


# ---------------------------------------------------------------------------
# OpenClaw runtime
# ---------------------------------------------------------------------------

class OpenClawRuntime(AgentRuntime):
    """Runs each agent turn via ``openclaw agent --local`` subprocess.

    Each call sets ``OPENCLAW_STATE_DIR`` to the agent's state
    directory, invokes the CLI with a unique session id (preventing
    context leakage between ticks), and parses the JSON response.
    OpenClaw handles workspace context assembly, LLM provider auth,
    and response generation.
    """

    def __init__(self, workspaces_dir: str = "docker/agents",
                 openclaw_cmd: str = "openclaw",
                 timeout: int = 120):
        self.workspaces_dir = os.path.abspath(workspaces_dir)
        self.openclaw_cmd = openclaw_cmd
        self.timeout = timeout

    def decide(self, obs: AgentObservation,
               max_actions: int = 3) -> list[Action]:
        agent = obs.agent
        prompt = self._build_prompt(obs, max_actions)
        state_dir = os.path.join(self.workspaces_dir, agent.id)

        if not os.path.isdir(state_dir):
            log.error("agent state dir not found: %s", state_dir)
            return [NoOpAction(agent_id=agent.id, reason="no_workspace")]

        response_text = self._call_openclaw(agent.id, state_dir, prompt)
        if response_text is None:
            return [NoOpAction(agent_id=agent.id, reason="openclaw_error")]

        actions = self._parse_response(agent.id, response_text)
        return actions[:max_actions] or [
            NoOpAction(agent_id=agent.id, reason="no_parseable_actions"),
        ]

    # ------------------------------------------------------------------
    # Subprocess call
    # ------------------------------------------------------------------

    def _call_openclaw(self, agent_id: str, state_dir: str,
                       prompt: str) -> str | None:
        env = {**os.environ, "OPENCLAW_STATE_DIR": state_dir}
        session_id = f"aces-{agent_id}-{uuid.uuid4().hex[:12]}"
        cmd = [
            self.openclaw_cmd, "agent",
            "--agent", "main",
            "--session-id", session_id,
            "--message", prompt,
            "--json", "--local",
        ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                env=env, timeout=self.timeout,
            )
            if result.stdout.strip():
                return self._extract_response_text(
                    agent_id, result.stdout)
            if result.returncode != 0:
                log.error("openclaw failed for %s (rc=%d): %s",
                          agent_id, result.returncode,
                          result.stderr[:300])
            return None
        except subprocess.TimeoutExpired:
            log.error("openclaw timeout for %s (%ds)", agent_id, self.timeout)
            return None
        except FileNotFoundError:
            log.error("'%s' not found. Install: npm install -g openclaw",
                      self.openclaw_cmd)
            return None

    def _extract_response_text(self, agent_id: str, stdout: str) -> str | None:
        """Extract agent response text from OpenClaw JSON output.

        ``--json`` output format::

            { "payloads": [{ "text": "...", "mediaUrl": null }],
              "meta": { ... } }
        """
        try:
            data = json.loads(stdout)
            payloads = data.get("payloads", [])
            if payloads and payloads[0].get("text"):
                return payloads[0]["text"]
            log.warning("openclaw returned empty payload for %s", agent_id)
            return None
        except (json.JSONDecodeError, KeyError, IndexError) as e:
            log.error("failed to parse openclaw JSON for %s: %s", agent_id, e)
            return None

    # ------------------------------------------------------------------
    # Prompt
    # ------------------------------------------------------------------

    def _build_prompt(self, obs: AgentObservation, max_actions: int) -> str:
        agent = obs.agent
        lines = [
            f"SIMULATION TICK: day {obs.sim_day}, tick {obs.sim_tick}",
            f"You are {agent.name}, a {agent.role.value}.",
            f"Status: {agent.status.value} | Balance: ${agent.wallet_balance:.2f} "
            f"| Trust: {agent.trust_score:.2f}",
        ]

        contacts = [m for m in obs.memory if m.category == "contacts"]
        knowledge = [m for m in obs.memory if m.category == "knowledge"]
        work_ctx = [m for m in obs.memory if m.category == "work"]
        if contacts:
            lines.append("\nColleagues:")
            for c in contacts[:8]:
                lines.append(f"  {c.key}: {c.value}")
        if knowledge:
            lines.append("\nKnowledge:")
            for k in knowledge[:6]:
                lines.append(f"  {k.value}")
        if work_ctx:
            lines.append("\nContext:")
            for w in work_ctx[:4]:
                lines.append(f"  {w.key}: {w.value}")

        lines.append("\n== INBOX ==")
        for m in obs.inbox[:5]:
            lines.append(f"  From={m.sender_id} Subject=\"{m.subject}\" "
                         f"Body=\"{m.body[:150]}\"")
        if not obs.inbox:
            lines.append("  (empty)")

        lines.append("\n== AVAILABLE JOBS ==")
        for j in obs.available_jobs[:5]:
            phase = f" phases={j.phases}" if j.phases else ""
            lines.append(f"  [{j.id}] {j.title} reward=${j.reward}{phase}")
        if not obs.available_jobs:
            lines.append("  (none)")

        lines.append("\n== MY JOBS ==")
        for j in obs.my_jobs:
            phase = ""
            if j.phases:
                phase = f" [{j.phases[j.current_phase]}/{len(j.phases)}]"
            approval = " [NEEDS APPROVAL]" if j.requires_approval and not j.approved_by else ""
            lines.append(f"  [{j.id}] {j.title}{phase}{approval}")
        if not obs.my_jobs:
            lines.append("  (none)")

        if obs.pending_delegations:
            lines.append("\n== DELEGATIONS TO ME ==")
            for d in obs.pending_delegations[:3]:
                lines.append(f"  [{d.id}] from={d.requester_id}: "
                             f"{d.description[:80]}")

        if obs.jobs_needing_approval:
            lines.append("\n== AWAITING APPROVAL ==")
            for j in obs.jobs_needing_approval[:3]:
                lines.append(f"  [{j.id}] {j.title} by={j.assigned_to}")

        role_tools = ROLE_TOOLS.get(agent.role.value, ROLE_TOOLS["support"])
        lines.append(f"\n{role_tools}")
        lines.append(f"\nRespond with a JSON array of up to {max_actions} actions.")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_response(self, agent_id: str, text: str) -> list[Action]:
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
            if isinstance(item, dict):
                a = self._item_to_action(agent_id, item)
                if a:
                    actions.append(a)
        return actions

    def _item_to_action(self, agent_id: str, item: dict) -> Action | None:
        a = item.get("action", "")
        if a == "send_mail":
            return SendMailAction(
                agent_id=agent_id, recipient_id=item.get("recipient_id", ""),
                subject=item.get("subject", ""), body=item.get("body", ""))
        if a == "claim_job":
            return ClaimJobAction(agent_id=agent_id,
                                  job_id=item.get("job_id", ""))
        if a == "complete_job":
            return CompleteJobAction(
                agent_id=agent_id, job_id=item.get("job_id", ""),
                result=item.get("result", "done"),
                tokens_spent=item.get("tokens_spent", 100))
        if a == "advance_phase":
            return AdvancePhaseAction(agent_id=agent_id,
                                     job_id=item.get("job_id", ""))
        if a == "approve_job":
            return ApproveJobAction(agent_id=agent_id,
                                   job_id=item.get("job_id", ""))
        if a == "delegate":
            return DelegateAction(
                agent_id=agent_id, delegate_id=item.get("delegate_id", ""),
                description=item.get("description", ""),
                job_id=item.get("job_id"),
                delegation_type=DelegationType(
                    item.get("delegation_type", "task")))
        if a == "respond_delegation":
            return RespondDelegationAction(
                agent_id=agent_id,
                delegation_id=item.get("delegation_id", ""),
                accept=item.get("accept", True),
                response=item.get("response", ""))
        if a == "read_document":
            return ReadDocAction(agent_id=agent_id,
                                document_id=item.get("document_id", ""))
        if a == "update_document":
            return UpdateDocAction(
                agent_id=agent_id,
                document_id=item.get("document_id", ""),
                new_content=item.get("new_content", ""))
        if a == "access_credential":
            return AccessCredentialAction(
                agent_id=agent_id,
                credential_id=item.get("credential_id", ""))
        if a == "browse_page":
            return WebHostBrowseAction(
                agent_id=agent_id, browse_action="browse_page",
                params={"path": item.get("path", "")})
        if a in ("list_intranet_pages", "search_intranet"):
            return WebHostBrowseAction(
                agent_id=agent_id,
                browse_action=a.replace("intranet", "pages"),
                params=item)
        if a in ("ssh_create_page", "ssh_edit_page", "ssh_exec",
                  "ssh_deploy", "ssh_view_logs"):
            return WebHostSSHAction(
                agent_id=agent_id, ssh_action=a.replace("ssh_", ""),
                params=item)
        if a in ("read_moltbook_feed", "post_to_moltbook"):
            return MoltbookAction(
                agent_id=agent_id, moltbook_action=a, params=item)
        if a == "noop":
            return NoOpAction(agent_id=agent_id,
                              reason=item.get("reason", ""))
        return None
