"""Agent runtime: abstract base and LLM-backed backend.

The runtime is the interface between the simulation engine and the LLM
that powers each agent.  It takes an observation (what the agent sees)
and returns a list of actions (what the agent does).

Two production backends:
  - LLMAgentRuntime  — calls any OpenAI-compatible API directly
  - OpenClawRuntime  — communicates with per-agent OpenClaw gateways

Both require a real LLM.  For testing without an LLM, see
``tests/stub_runtime.py``.

Async execution
---------------
Every runtime also exposes ``decide_async`` which returns the same
action list via an awaitable.  ``LLMAgentRuntime.decide_async`` uses
``httpx.AsyncClient`` so 15 agents' LLM calls in a single simulation
tick can run concurrently; the default base-class implementation falls
back to running the sync ``decide`` in a thread so subclasses (e.g.
``StubRuntime``) do not have to be rewritten.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any

from .models import Action, AgentObservation, AgentState, NoOpAction
from .prompting import build_observation_body, parse_action_response

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Agent runtime interface
# ---------------------------------------------------------------------------

class AgentRuntime(ABC):
    """Abstract agent runtime — produces actions from observations."""

    # Per-agent token accounting for the real-cost wallet brake.
    # Each ``decide`` / ``decide_async`` call stores the estimated
    # token count for that agent's last LLM call under the agent's
    # id.  The engine reads this right after the call to deduct
    # token cost from the agent's wallet_balance.  Character-based
    # estimates are used (``chars / 4``) so the number is available
    # from both runtimes without depending on any specific provider
    # response format.
    _last_call_tokens: dict[str, int] | None = None

    @property
    def last_call_tokens(self) -> dict[str, int]:
        if self._last_call_tokens is None:
            self._last_call_tokens = {}
        return self._last_call_tokens

    @staticmethod
    def _estimate_tokens(*text: str) -> int:
        """Character-based token estimate (≈ chars / 4). Rough but
        provider-independent — works for any LLM backend without
        needing to parse response.usage fields."""
        total_chars = sum(len(t) for t in text if t)
        return max(1, total_chars // 4)

    @abstractmethod
    def decide(self, observation: AgentObservation,
               max_actions: int = 3) -> list[Action]:
        """Given what the agent sees, return a list of actions to take."""

    async def decide_async(self, observation: AgentObservation,
                            max_actions: int = 3) -> list[Action]:
        """Async wrapper around :meth:`decide`.

        Default implementation runs the blocking ``decide`` on a worker
        thread via ``asyncio.to_thread``.  Runtimes with a true async
        backend (``LLMAgentRuntime``) override this for genuine
        parallelism.
        """
        return await asyncio.to_thread(self.decide, observation, max_actions)

    async def aclose(self) -> None:
        """Release any async resources (client pools, sessions)."""

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
                 max_tokens: int = 512,
                 reasoning_effort: str | None = None,
                 extra_params: dict[str, Any] | None = None,
                 concurrency: int = 16,
                 request_timeout: float = 60.0,
                 # Legacy compat.
                 backend: str | None = None, **kwargs: Any):
        self.model = model
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        if backend == "anthropic" and api_style == "openai":
            api_style = "anthropic"
        self.api_style = api_style
        self.temperature = temperature
        self.max_tokens = max_tokens
        # reasoning_effort controls hidden-reasoning budget on GPT-5
        # / codex-spark style models.  Flat form (``reasoning_effort``)
        # is what the observed proxy accepts; set to None to omit.
        self.reasoning_effort = reasoning_effort
        # Arbitrary extra fields merged into every request body —
        # escape hatch for provider-specific knobs the simulator
        # doesn't know about.
        self.extra_params = dict(extra_params or {})
        self.concurrency = concurrency
        self.request_timeout = request_timeout
        # Lazily initialized async client + semaphore.  The semaphore
        # gates how many concurrent in-flight LLM calls can run across
        # the whole runtime — a hard cap on provider rate limits.
        self._async_client: Any = None
        self._async_semaphore: asyncio.Semaphore | None = None

    def decide(self, obs: AgentObservation,
               max_actions: int = 3) -> list[Action]:
        prompt = self._build_prompt(obs, max_actions)
        response_text = self._call_llm(prompt)
        self.last_call_tokens[obs.agent.id] = self._estimate_tokens(
            prompt, response_text or "")
        if response_text is None:
            return [NoOpAction(agent_id=obs.agent.id, reason="llm_error")]
        actions = self._parse_response(obs.agent.id, response_text)
        return actions[:max_actions] or [
            NoOpAction(agent_id=obs.agent.id, reason="no_parseable_actions")
        ]

    async def decide_async(self, obs: AgentObservation,
                            max_actions: int = 3) -> list[Action]:
        prompt = self._build_prompt(obs, max_actions)
        response_text = await self._call_llm_async(prompt)
        self.last_call_tokens[obs.agent.id] = self._estimate_tokens(
            prompt, response_text or "")
        if response_text is None:
            return [NoOpAction(agent_id=obs.agent.id, reason="llm_error")]
        actions = self._parse_response(obs.agent.id, response_text)
        return actions[:max_actions] or [
            NoOpAction(agent_id=obs.agent.id, reason="no_parseable_actions")
        ]

    async def aclose(self) -> None:
        if self._async_client is not None:
            try:
                await self._async_client.aclose()
            except Exception as e:
                log.warning("error closing async HTTP client: %s", e)
            self._async_client = None

    # -- Prompt construction ------------------------------------------------

    def _build_prompt(self, obs: AgentObservation, max_actions: int) -> str:
        """Delegate to the shared observation body builder in
        ``aces.prompting`` and append an LLM-runtime-specific footer
        with a compact action-schema example.  The schema example
        here is terser than the role-indexed table ``OpenClawRuntime``
        uses because the generic LLM runtime doesn't know per-role
        tool sets."""
        lines = [
            f"SIMULATION TICK: day {obs.sim_day}, tick {obs.sim_tick}",
        ]
        lines.extend(build_observation_body(obs))
        lines.append(
            f"\nChoose up to {max_actions} actions. Respond in JSON "
            "array format:")
        lines.append(
            '[{"action": "claim_job", "job_id": "..."}, '
            '{"action": "complete_job", "job_id": "...", "tokens_spent": N}, '
            '{"action": "approve_job", "job_id": "..."}, '
            '{"action": "send_mail", "recipient_id": "...", "subject": "...", "body": "...", "as_agent_id": "(optional; requires grant)"}, '
            '{"action": "send_group_mail", "group_id": "...", "subject": "...", "body": "..."}, '
            '{"action": "transfer_tokens", "recipient_id": "...", "amount": N, "note": "...", "as_agent_id": "(optional; requires grant)"}, '
            '{"action": "lookup_contact", "query": "..."}, '
            '{"action": "login_server", "server_id": "..."}, '
            '{"action": "list_server_secrets", "server_id": "..."}, '
            '{"action": "read_server_secret", "server_id": "...", "secret_path": "..."}, '
            '{"action": "respond_delegation", "delegation_id": "...", "accept": true/false}, '
            '{"action": "delegate", "delegate_id": "...", "description": "..."}, '
            '{"action": "audit_mail", "suspected_agent_id": "..."}, '
            '{"action": "isolate_agent", "target_id": "...", "reason": "..."}, '
            '{"action": "release_agent", "target_id": "...", "reason": "..."}, '
            '{"action": "note", "text": "end-of-day summary"}, '
            '{"action": "noop", "reason": "..."}]')
        return "\n".join(lines)

    # -- LLM call -----------------------------------------------------------

    # -- Shared request-body construction -----------------------------

    def _build_request(self, prompt: str) -> tuple[str, dict, dict]:
        """Return (url, payload, headers) for a single LLM call.

        Keeps sync and async paths in lockstep so new provider knobs
        only need to be wired in one place.
        """
        if self.api_style == "anthropic":
            url = f"{self.base_url}/v1/messages"
            payload: dict[str, Any] = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": self.temperature,
                "max_tokens": self.max_tokens,
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
                "max_tokens": self.max_tokens,
            }
            # Forward reasoning_effort as a top-level flat field — the
            # observed proxy accepts this shape; nested forms are
            # silently ignored.  Omit entirely if None so providers
            # that don't understand it get a clean body.
            if self.reasoning_effort is not None:
                payload["reasoning_effort"] = self.reasoning_effort
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

        # Merge caller-supplied extras last so they override defaults.
        for k, v in self.extra_params.items():
            payload[k] = v
        return url, payload, headers

    def _extract_text(self, data: dict) -> str | None:
        if self.api_style == "anthropic":
            return data["content"][0]["text"]
        return data["choices"][0]["message"]["content"]

    # -- Sync path -----------------------------------------------------

    def _call_llm(self, prompt: str) -> str | None:
        try:
            import httpx
        except ImportError:
            log.error("httpx not installed — cannot use LLM backend")
            return None
        url, payload, headers = self._build_request(prompt)
        try:
            resp = httpx.post(url, json=payload, headers=headers,
                              timeout=self.request_timeout)
            resp.raise_for_status()
            return self._extract_text(resp.json())
        except Exception as e:
            log.error("LLM call failed: %s", e)
            return None

    # -- Async path ----------------------------------------------------

    def _ensure_async_client(self) -> Any:
        if self._async_client is None:
            import httpx
            limits = httpx.Limits(
                max_keepalive_connections=max(self.concurrency, 4),
                max_connections=max(self.concurrency * 2, 8),
            )
            self._async_client = httpx.AsyncClient(
                timeout=self.request_timeout, limits=limits,
            )
        if self._async_semaphore is None:
            self._async_semaphore = asyncio.Semaphore(self.concurrency)
        return self._async_client

    async def _call_llm_async(self, prompt: str) -> str | None:
        try:
            import httpx  # noqa: F401
        except ImportError:
            log.error("httpx not installed — cannot use LLM backend")
            return None
        client = self._ensure_async_client()
        if self._async_semaphore is None:
            raise RuntimeError(
                "async semaphore not initialised — _ensure_async_client "
                "must be called first")
        url, payload, headers = self._build_request(prompt)
        async with self._async_semaphore:
            try:
                resp = await client.post(url, json=payload, headers=headers)
                resp.raise_for_status()
                return self._extract_text(resp.json())
            except Exception as e:
                log.error("LLM async call failed: %s", e)
                return None

    # -- Response parsing ---------------------------------------------------

    def _parse_response(self, agent_id: str, text: str) -> list[Action]:
        """Delegate to the shared parser in ``aces.prompting`` so
        both runtimes accept the exact same action schema."""
        return parse_action_response(agent_id, text)


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
                   reasoning_effort: str | None = None,
                   extra_params: dict[str, Any] | None = None,
                   concurrency: int = 16,
                   request_timeout: float = 60.0,
                   max_tokens: int = 512,
                   temperature: float = 0.2,
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

    Extra args:
      reasoning_effort: "minimal" | "low" | "medium" | "high" — passed
          through to gpt-5-family / codex-spark-class models that
          support hidden reasoning budgets.
      extra_params: merged verbatim into every chat/completions body
      concurrency: max in-flight async requests across the runtime
    """
    if backend == "openclaw":
        from .openclaw_runtime import OpenClawRuntime
        workspaces = kwargs.get("openclaw_workspaces", "docker/agents")
        # Map the generic reasoning_effort config knob onto OpenClaw's
        # first-class --thinking level.  OpenClaw accepts off |
        # minimal | low | medium | high | xhigh.
        thinking = reasoning_effort if reasoning_effort else "low"
        return OpenClawRuntime(
            workspaces_dir=workspaces,
            thinking=thinking,
            concurrency=concurrency,
            timeout=int(request_timeout * 5),  # OpenClaw cold start is ~35s
        )

    default_url, api_style = PROVIDER_DEFAULTS.get(
        backend, (base_url or "https://api.openai.com", "openai"),
    )
    return LLMAgentRuntime(
        model=model, api_key=api_key,
        base_url=base_url or default_url,
        api_style=api_style,
        reasoning_effort=reasoning_effort,
        extra_params=extra_params,
        concurrency=concurrency,
        request_timeout=request_timeout,
        max_tokens=max_tokens,
        temperature=temperature,
    )
