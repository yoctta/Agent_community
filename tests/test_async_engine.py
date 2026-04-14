"""Tests for the async two-phase tick engine, checkpoint/resume, and
the now-configurable research knobs.

These tests run entirely against ``StubRuntime`` (which supplies
``decide`` only — ``decide_async`` falls through to the base-class
``asyncio.to_thread`` wrapper).  No LLM calls are made.
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aces.config import (
    ACESConfig, DefenseOverrides, FactorDef, apply_condition_overrides,
    load_config,
)
from aces.database import Database
from aces.defenses import DefenseManager
from aces.engine import SimulationEngine
from aces.metrics import MetricsComputer
from aces.models import (
    AgentStatus, EventType, SendMailAction, TransferTokensAction,
)
from aces.runtime import AgentRuntime, LLMAgentRuntime
from tests.stub_runtime import StubRuntime


CFG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config")


def _cfg():
    return load_config(
        enterprise_path=os.path.join(CFG_DIR, "community_research_enterprise.yaml"),
        experiment_path=os.path.join(CFG_DIR, "community_research_experiment.yaml"),
        attack_path=os.path.join(CFG_DIR, "community_research_attacks.yaml"),
    )


@pytest.fixture
def cfg():
    return _cfg()


@pytest.fixture
def db():
    d = Database(":memory:")
    yield d
    d.close()


# ---------------------------------------------------------------------------
# decide_async default wrapper
# ---------------------------------------------------------------------------

def test_decide_async_default_wraps_sync_decide():
    """StubRuntime only implements sync decide; the base-class
    decide_async must dispatch through asyncio.to_thread and return
    the same result."""
    rt = StubRuntime(rng=random.Random(0))
    db = Database(":memory:")
    try:
        cfg = _cfg()
        engine = SimulationEngine(cfg=cfg, db=db, runtime=rt,
                                   run_id="async-default",
                                   rng=random.Random(0))
        engine.init_world()
        obs = engine.turn_mgr.observe(
            db.get_agent("eng_kevin"), sim_day=1, sim_tick=1)
        sync_actions = rt.decide(obs, max_actions=3)
        async_actions = asyncio.run(rt.decide_async(obs, max_actions=3))
        assert [type(a).__name__ for a in sync_actions] == \
               [type(a).__name__ for a in async_actions]
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Async engine produces a run record
# ---------------------------------------------------------------------------

def test_async_engine_runs_a_day(db, cfg):
    engine = SimulationEngine(
        cfg=cfg, db=db,
        runtime=StubRuntime(rng=random.Random(77)),
        run_id="async-day",
        rng=random.Random(77),
    )
    engine.metrics_computer = MetricsComputer(
        db, csri_weights=cfg.experiment.csri_weights)
    engine.defense_manager = DefenseManager(
        cfg.defenses, db, engine.services, random.Random(77))
    engine.init_world()
    record = asyncio.run(engine.run_async(days=2))
    assert record.status == "completed"
    assert record.final_day == 2
    assert record.final_metrics is not None
    assert "community_token_balance_excluding_attackers" in record.final_metrics


def test_async_engine_equivalent_to_sync_for_same_seed(cfg):
    """With the stub runtime (deterministic) the async and sync paths
    produce the same final metrics on short runs.

    The two-phase async tick has a slightly stricter semantic than
    the serial tick: an agent's observation reflects the world at
    tick start, not mid-tick mutations from earlier agents in the
    same tick.  Over a single day this distinction is invisible
    (no agent can cascade to another), so headline metrics match
    exactly.  Over multi-day runs with heavy cross-agent mail cascades
    the two paths can diverge by <1% on headline metrics — this is
    intentional and documented in docs/research_scenarios.md.
    """
    cfg.attacks.enabled_classes = []  # disable attacks for a clean comparison

    def _run(use_async: bool) -> dict:
        db = Database(":memory:")
        engine = SimulationEngine(
            cfg=cfg, db=db,
            runtime=StubRuntime(rng=random.Random(13)),
            run_id=("async" if use_async else "sync") + "-equiv",
            rng=random.Random(13),
        )
        engine.metrics_computer = MetricsComputer(
            db, csri_weights=cfg.experiment.csri_weights)
        engine.defense_manager = DefenseManager(
            cfg.defenses, db, engine.services, random.Random(13))
        engine.init_world()
        if use_async:
            record = asyncio.run(engine.run_async(days=1))
        else:
            record = engine.run(days=1)
        m = record.final_metrics or {}
        db.close()
        return m

    sync_metrics = _run(False)
    async_metrics = _run(True)
    assert sync_metrics["community_token_balance_excluding_attackers"] == \
           pytest.approx(
               async_metrics["community_token_balance_excluding_attackers"])
    assert sync_metrics["attacker_token_balance"] == \
           pytest.approx(async_metrics["attacker_token_balance"])


# ---------------------------------------------------------------------------
# Checkpoint / resume
# ---------------------------------------------------------------------------

def test_checkpoint_writes_after_each_day(cfg):
    with tempfile.TemporaryDirectory() as td:
        db = Database(os.path.join(td, "run.db"))
        engine = SimulationEngine(
            cfg=cfg, db=db,
            runtime=StubRuntime(rng=random.Random(21)),
            run_id="ckpt-run",
            rng=random.Random(21),
        )
        engine.metrics_computer = MetricsComputer(db)
        engine.defense_manager = DefenseManager(
            cfg.defenses, db, engine.services, random.Random(21))
        engine.init_world()
        engine.checkpoint_path = os.path.join(td, "run.checkpoint.json")
        engine.run(days=3)
        assert os.path.exists(engine.checkpoint_path)
        with open(engine.checkpoint_path) as f:
            data = json.load(f)
        assert data["run_id"] == "ckpt-run"
        assert data["last_completed_day"] == 3
        db.close()


def test_checkpoint_resume_skips_completed_days(cfg):
    with tempfile.TemporaryDirectory() as td:
        db_path = os.path.join(td, "run.db")
        ckpt_path = os.path.join(td, "run.checkpoint.json")

        # First session: run 2 days, then "crash".
        db = Database(db_path)
        engine = SimulationEngine(
            cfg=cfg, db=db,
            runtime=StubRuntime(rng=random.Random(22)),
            run_id="resume-run",
            rng=random.Random(22),
        )
        engine.metrics_computer = MetricsComputer(db)
        engine.defense_manager = DefenseManager(
            cfg.defenses, db, engine.services, random.Random(22))
        engine.init_world()
        engine.checkpoint_path = ckpt_path
        engine.run(days=2)
        db.close()

        # Second session: resume into the same SQLite and checkpoint.
        db2 = Database(db_path)
        engine2 = SimulationEngine(
            cfg=cfg, db=db2,
            runtime=StubRuntime(rng=random.Random(22)),
            run_id="resume-run",  # same run_id
            rng=random.Random(22),
        )
        engine2.metrics_computer = MetricsComputer(db2)
        engine2.defense_manager = DefenseManager(
            cfg.defenses, db2, engine2.services, random.Random(22))
        # init_world is idempotent in that it clears run data; skip it.
        engine2.checkpoint_path = ckpt_path
        record = engine2.run(days=4)
        assert record.final_day == 4
        with open(ckpt_path) as f:
            data = json.load(f)
        assert data["last_completed_day"] == 4
        db2.close()


# ---------------------------------------------------------------------------
# Config-ized knobs
# ---------------------------------------------------------------------------

def test_anomaly_threshold_is_configurable(db, cfg):
    # Force threshold to a very low value so a single server read
    # triggers detection.  Explicitly opt in to the rule-based
    # detector — it's disabled by default.
    cfg.defenses = DefenseOverrides(
        enable_rule_based_anomaly_detection=True,
        anomaly_threshold=0.5,
        anomaly_weight_secret_read=1.0,
        anomaly_weight_impersonated_mail=0.0,
        anomaly_weight_impersonated_transfer=0.0,
    )
    engine = SimulationEngine(
        cfg=cfg, db=db,
        runtime=StubRuntime(rng=random.Random(31)),
        run_id="anomaly-cfg", rng=random.Random(31),
    )
    engine.metrics_computer = MetricsComputer(db)
    engine.defense_manager = DefenseManager(
        cfg.defenses, db, engine.services, random.Random(31))
    engine.init_world()

    victor = db.get_agent("it_victor")
    engine.services.host_access.read_secret(
        victor, "srv_payroll_app", "/etc/payroll/signer.env",
        sim_day=1, sim_tick=1,
    )
    engine.defense_manager.run(sim_day=1, agents=db.get_all_agents())
    anomalies = db.get_events(event_type=EventType.ANOMALY_DETECTED.value)
    assert any(e.agent_id == "it_victor" for e in anomalies)


def test_bounty_amount_is_configurable(db, cfg):
    cfg.defenses = DefenseOverrides(bounty_amount=250.0, fine_amount=10.0)
    engine = SimulationEngine(
        cfg=cfg, db=db,
        runtime=StubRuntime(rng=random.Random(32)),
        run_id="bounty-cfg", rng=random.Random(32),
    )
    engine.metrics_computer = MetricsComputer(db)
    engine.defense_manager = DefenseManager(
        cfg.defenses, db, engine.services, random.Random(32))
    engine.init_world()

    david = db.get_agent("sec_david")
    before = david.wallet_balance
    engine.defense_manager.isolate_agent(
        david, "it_victor", reason="confirmed", sim_day=1)
    after = db.get_agent("sec_david").wallet_balance
    assert after == pytest.approx(before + 250.0)


def test_reasoning_effort_forwarded_on_llm_runtime():
    rt = LLMAgentRuntime(
        model="gpt-5.3-codex-spark",
        api_key="x",
        base_url="https://example.invalid",
        api_style="openai",
        reasoning_effort="low",
    )
    url, payload, headers = rt._build_request("test")
    assert payload["reasoning_effort"] == "low"
    # Ensure the auth header is present and model is as configured.
    assert headers["Authorization"] == "Bearer x"
    assert payload["model"] == "gpt-5.3-codex-spark"


def test_reasoning_effort_omitted_when_none():
    rt = LLMAgentRuntime(
        model="gpt-4o-mini",
        api_key="x",
        base_url="https://example.invalid",
        api_style="openai",
        reasoning_effort=None,
    )
    _, payload, _ = rt._build_request("test")
    assert "reasoning_effort" not in payload


def test_extra_params_merged_into_request_body():
    rt = LLMAgentRuntime(
        model="m", api_key="x",
        base_url="https://example.invalid",
        api_style="openai",
        extra_params={"top_p": 0.9, "seed": 123},
    )
    _, payload, _ = rt._build_request("test")
    assert payload["top_p"] == 0.9
    assert payload["seed"] == 123


# ---------------------------------------------------------------------------
# ScenarioOverrides serialize the new defense fields
# ---------------------------------------------------------------------------

def test_overlay_includes_new_defense_fields():
    base = DefenseOverrides()
    factors = [FactorDef(
        name="tune_anomaly",
        level1_overrides={
            "defenses": {
                "anomaly_threshold": 5.0,
                "bounty_amount": 999.0,
                "group_moderation": True,
            }
        },
    )]
    overlay = apply_condition_overrides(base, {"tune_anomaly": 1}, factors)
    assert overlay.resolved_defenses.anomaly_threshold == 5.0
    assert overlay.resolved_defenses.bounty_amount == 999.0
    assert overlay.resolved_defenses.group_moderation is True
    assert overlay.defenses["anomaly_threshold"] == 5.0
