"""Unit tests for OpenClawRuntime subprocess dispatch + JSON parsing.

These tests never fork a real ``openclaw`` binary.  Subprocess
invocation is monkey-patched so the tests verify:

1. The sync path reads the JSON payload from *either* stdout or stderr
   (OpenClaw 2026.4.2 emits ``--json`` on stderr; 2026.3.8 used stdout).
2. The async path parallelizes via ``asyncio.create_subprocess_exec``
   and honours the runtime's concurrency semaphore.
3. The ``--thinking`` flag is forwarded on every call.
4. Missing workspaces, parse failures, and timeouts all degrade to
   a ``NoOpAction`` instead of raising.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aces.models import AgentObservation, AgentState, AgentRole, NoOpAction, Zone
from aces.openclaw_runtime import OpenClawRuntime


def _obs(agent_id: str = "eng_kevin") -> AgentObservation:
    a = AgentState(id=agent_id, name=agent_id,
                    role=AgentRole.ENGINEER, zone=Zone.ENGNET)
    return AgentObservation(agent=a, sim_day=1, sim_tick=1)


def _payload_json(text: str) -> str:
    return json.dumps({
        "payloads": [{"text": text, "mediaUrl": None}],
        "meta": {"durationMs": 1, "agentMeta": {"provider": "openai-codex"}},
    })


# ---------------------------------------------------------------------------
# JSON extraction: stdout vs stderr (2026.3.8 vs 2026.4.2)
# ---------------------------------------------------------------------------

def test_extracts_payload_from_stdout_legacy_2026_3_8():
    rt = OpenClawRuntime(workspaces_dir="/tmp/fake")
    stdout = _payload_json('[{"action":"noop","reason":"stdout_path"}]')
    stderr = ""
    text = rt._extract_response_text("eng_kevin", stdout, stderr, 0)
    assert text == '[{"action":"noop","reason":"stdout_path"}]'


def test_extracts_payload_from_stderr_new_2026_4_2():
    rt = OpenClawRuntime(workspaces_dir="/tmp/fake")
    stdout = ""
    stderr = _payload_json('[{"action":"noop","reason":"stderr_path"}]')
    text = rt._extract_response_text("eng_kevin", stdout, stderr, 0)
    assert text == '[{"action":"noop","reason":"stderr_path"}]'


def test_extracts_payload_tolerates_ansi_prefix():
    rt = OpenClawRuntime(workspaces_dir="/tmp/fake")
    # Real 2026.4.2 sometimes emits a colored boot banner before the
    # JSON — the extractor must skip everything before the first `{`.
    stderr = "\x1b[33m[boot]\x1b[0m starting...\n" + _payload_json('[]')
    text = rt._extract_response_text("eng_kevin", "", stderr, 0)
    assert text == "[]"


def test_extract_returns_none_on_invalid_json():
    rt = OpenClawRuntime(workspaces_dir="/tmp/fake")
    assert rt._extract_response_text(
        "eng_kevin", "not json at all", "", 0) is None
    assert rt._extract_response_text(
        "eng_kevin", "", "garbage{not]closed", 0) is None


def test_extract_returns_none_on_empty_payloads():
    rt = OpenClawRuntime(workspaces_dir="/tmp/fake")
    stderr = json.dumps({"payloads": [], "meta": {}})
    assert rt._extract_response_text("eng_kevin", "", stderr, 0) is None


def test_extract_prefers_parseable_stream():
    """If stdout is garbage and stderr has the payload, use stderr."""
    rt = OpenClawRuntime(workspaces_dir="/tmp/fake")
    stdout = "[boot banner no json here]"
    stderr = _payload_json('[{"action":"noop"}]')
    assert rt._extract_response_text(
        "eng_kevin", stdout, stderr, 0) == '[{"action":"noop"}]'


# ---------------------------------------------------------------------------
# Sync decide: missing workspace + fake subprocess
# ---------------------------------------------------------------------------

def test_decide_returns_noop_when_workspace_missing(tmp_path):
    rt = OpenClawRuntime(workspaces_dir=str(tmp_path))
    actions = rt.decide(_obs("nonexistent_agent"), max_actions=3)
    assert len(actions) == 1
    assert isinstance(actions[0], NoOpAction)
    assert actions[0].reason == "no_workspace"


def test_decide_routes_through_fake_subprocess(tmp_path, monkeypatch):
    # Create a fake agent state dir the runtime will accept.
    agent_dir = tmp_path / "eng_kevin"
    agent_dir.mkdir()

    captured: dict = {}

    class _FakeResult:
        def __init__(self):
            self.stdout = ""
            self.stderr = _payload_json('[{"action":"noop","reason":"fake"}]')
            self.returncode = 0

    def _fake_run(cmd, capture_output, text, env, timeout):
        captured["cmd"] = cmd
        captured["env_state"] = env.get("OPENCLAW_STATE_DIR")
        captured["timeout"] = timeout
        return _FakeResult()

    monkeypatch.setattr("aces.openclaw_runtime.subprocess.run", _fake_run)

    rt = OpenClawRuntime(workspaces_dir=str(tmp_path), thinking="low")
    actions = rt.decide(_obs("eng_kevin"), max_actions=3)
    assert len(actions) == 1
    assert isinstance(actions[0], NoOpAction)
    assert actions[0].reason == "fake"

    # Verify the cmd carries --thinking low + --local + --json
    cmd = captured["cmd"]
    assert "--thinking" in cmd and cmd[cmd.index("--thinking") + 1] == "low"
    assert "--local" in cmd
    assert "--json" in cmd
    assert captured["env_state"] == str(agent_dir)


# ---------------------------------------------------------------------------
# Async decide + semaphore
# ---------------------------------------------------------------------------

def test_decide_async_dispatches_concurrently(tmp_path, monkeypatch):
    # Create 3 fake agent state dirs.
    for a_id in ("a1", "a2", "a3"):
        (tmp_path / a_id).mkdir()

    active: dict = {"count": 0, "peak": 0}

    class _FakeProc:
        def __init__(self, text: str):
            self._text = text
            self.returncode = 0

        async def communicate(self):
            active["count"] += 1
            active["peak"] = max(active["peak"], active["count"])
            await asyncio.sleep(0.05)
            active["count"] -= 1
            return b"", _payload_json(self._text).encode()

    async def _fake_exec(*cmd, stdout, stderr, env):
        # Pick which agent we're impersonating from the session id.
        sess_idx = cmd.index("--session-id") + 1
        sid = cmd[sess_idx]
        return _FakeProc(f'[{{"action":"noop","reason":"{sid}"}}]')

    monkeypatch.setattr(
        "aces.openclaw_runtime.asyncio.create_subprocess_exec", _fake_exec)

    rt = OpenClawRuntime(workspaces_dir=str(tmp_path), concurrency=3)

    async def _run():
        obs_list = [_obs(a) for a in ("a1", "a2", "a3")]
        return await asyncio.gather(*[
            rt.decide_async(o, max_actions=1) for o in obs_list
        ])

    results = asyncio.run(_run())
    # Each agent must have gotten at least a NoOp decision.
    assert len(results) == 3
    for r in results:
        assert len(r) == 1
    # With concurrency=3 and 3 agents, all three should have run at
    # the same time — peak must be 3, not 1.
    assert active["peak"] == 3, f"expected concurrent execution, got peak={active['peak']}"


def test_decide_async_semaphore_caps_concurrency(tmp_path, monkeypatch):
    for a_id in ("a1", "a2", "a3", "a4", "a5"):
        (tmp_path / a_id).mkdir()

    active = {"count": 0, "peak": 0}

    class _FakeProc:
        def __init__(self):
            self.returncode = 0

        async def communicate(self):
            active["count"] += 1
            active["peak"] = max(active["peak"], active["count"])
            await asyncio.sleep(0.05)
            active["count"] -= 1
            return b"", _payload_json('[]').encode()

    async def _fake_exec(*cmd, stdout, stderr, env):
        return _FakeProc()

    monkeypatch.setattr(
        "aces.openclaw_runtime.asyncio.create_subprocess_exec", _fake_exec)

    rt = OpenClawRuntime(workspaces_dir=str(tmp_path), concurrency=2)

    async def _run():
        obs_list = [_obs(a) for a in ("a1", "a2", "a3", "a4", "a5")]
        return await asyncio.gather(*[
            rt.decide_async(o, max_actions=1) for o in obs_list
        ])

    asyncio.run(_run())
    # Semaphore caps us at 2 concurrent, even though 5 coroutines
    # were launched.
    assert active["peak"] == 2


def test_decide_async_timeout_returns_noop(tmp_path, monkeypatch):
    (tmp_path / "eng_kevin").mkdir()

    class _HangProc:
        def __init__(self):
            self.returncode = 0

        async def communicate(self):
            await asyncio.sleep(5.0)
            return b"", b""

        def kill(self):
            pass

    async def _fake_exec(*cmd, stdout, stderr, env):
        return _HangProc()

    monkeypatch.setattr(
        "aces.openclaw_runtime.asyncio.create_subprocess_exec", _fake_exec)

    rt = OpenClawRuntime(workspaces_dir=str(tmp_path), timeout=1)

    async def _run():
        return await rt.decide_async(_obs("eng_kevin"), max_actions=1)

    actions = asyncio.run(_run())
    assert len(actions) == 1
    assert isinstance(actions[0], NoOpAction)
    assert actions[0].reason == "openclaw_error"


def test_decide_async_returns_noop_when_workspace_missing(tmp_path):
    rt = OpenClawRuntime(workspaces_dir=str(tmp_path))

    async def _run():
        return await rt.decide_async(_obs("ghost"), max_actions=1)

    actions = asyncio.run(_run())
    assert len(actions) == 1
    assert isinstance(actions[0], NoOpAction)
    assert actions[0].reason == "no_workspace"
