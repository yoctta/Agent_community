"""Regression tests for bugs fixed on top of the research-community
infrastructure (B1-B6, D1-D7, M1-M2).

These tests lock down previously-broken behaviour so it does not
silently resurface.  See the audit in the review discussion for the
full bug list.
"""

from __future__ import annotations

import logging
import os
import random
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aces.config import (
    DefenseOverrides, FactorDef, apply_condition_overrides, load_config,
)
from aces.database import Database
from aces.defenses import DefenseManager
from aces.engine import SimulationEngine
from aces.experiment import Condition, run_single
from aces.metrics import MetricsComputer
from aces.models import (
    AgentRole, AgentStatus, CompleteJobAction, Job,
    JobStatus, JobType, TransferTokensAction, Zone,
)
from aces.network import SocialTrustGraph
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


@pytest.fixture
def engine(db, cfg):
    eng = SimulationEngine(
        cfg=cfg, db=db,
        runtime=StubRuntime(rng=random.Random(7)),
        run_id="regression-run",
        rng=random.Random(7),
    )
    eng.metrics_computer = MetricsComputer(db, csri_weights=cfg.experiment.csri_weights)
    eng.defense_manager = DefenseManager(cfg.defenses, db, eng.services, random.Random(7))
    eng.init_world()
    return eng


# ---------------------------------------------------------------------------
# B1 — stale in-memory agent across multi-action turns
# ---------------------------------------------------------------------------

def test_transfer_then_complete_job_does_not_clobber_wallet(engine):
    """Regression for B1: if a turn does a transfer and then completes
    a job, the final balance must reflect *both* mutations.  Previously
    the in-memory `agent` was not refreshed between actions, so the
    CompleteJob handler would overwrite the DB with (stale_balance +
    reward), silently reverting the transfer."""
    # Take a snapshot of the starting wallet.
    fin = engine.db.get_agent("fin_robert")
    hr = engine.db.get_agent("hr_emily")
    start_fin = fin.wallet_balance
    start_hr = hr.wallet_balance

    # Seed a job that fin_robert owns so CompleteJob will apply a reward.
    job = Job(title="regression job", job_type=JobType.PAYROLL,
              zone=Zone.FINNET, required_role=AgentRole.FINANCE,
              status=JobStatus.CLAIMED, assigned_to="fin_robert",
              created_day=1, reward=25.0, penalty=0.0,
              requires_approval=False)
    engine.db.insert_job(job)

    # Build a custom runtime that emits both actions in one turn.
    class _TwoStepRuntime(StubRuntime):
        def decide(self, obs, max_actions=3):
            if obs.agent.id != "fin_robert":
                return []
            return [
                TransferTokensAction(
                    agent_id="fin_robert", recipient_id="hr_emily",
                    amount=50.0, note="regression"),
                CompleteJobAction(
                    agent_id="fin_robert", job_id=job.id,
                    result="done", tokens_spent=0),
            ]
    engine.runtime = _TwoStepRuntime()
    engine.turn_mgr.runtime = engine.runtime

    agents = engine.db.get_all_agents()
    fin_fresh = engine.db.get_agent("fin_robert")
    engine.turn_mgr.execute_turn(fin_fresh, sim_day=1, sim_tick=1,
                                  max_actions=3, all_agents=agents)

    # Expected end state: fin lost 50 to hr, then gained 25 reward.
    fin_after = engine.db.get_agent("fin_robert")
    hr_after = engine.db.get_agent("hr_emily")
    assert fin_after.wallet_balance == pytest.approx(start_fin - 50.0 + 25.0)
    assert hr_after.wallet_balance == pytest.approx(start_hr + 50.0)


# ---------------------------------------------------------------------------
# B2 — executive with scope=reports must NOT get org-wide lookup
# ---------------------------------------------------------------------------

def test_executive_with_reports_scope_cannot_look_up_outside_reports(engine):
    """Regression for B2.  exec_amy is configured with
    ``directory_scope: reports``; she should only resolve her direct
    reports (mgr_mike, devops_sara, qa_lisa), not finance/HR agents."""
    amy = engine.db.get_agent("exec_amy")
    assert amy.directory_scope == "reports"

    # Lookup a direct report — should succeed.
    mike = engine.services.directory.lookup(amy, "Mike")
    assert any(a.id == "mgr_mike" for a in mike), (
        "CTO should resolve her direct report mgr_mike")

    # Lookup an agent outside her reporting chain — should fail.
    robert = engine.services.directory.lookup(amy, "Robert Davis")
    assert robert == [], (
        "CTO with scope=reports must not resolve fin_robert")


# ---------------------------------------------------------------------------
# B3 — unknown defense fields are surfaced as warnings, not silently dropped
# ---------------------------------------------------------------------------

def test_unknown_defense_fields_are_reported(caplog):
    base = DefenseOverrides()
    factors = [FactorDef(
        name="broken",
        level1_overrides={
            "defenses": {
                "segmentation": "strong",
                "totally_made_up_field": True,
            },
        },
    )]
    overlay = apply_condition_overrides(base, {"broken": 1}, factors)
    assert overlay.resolved_defenses.segmentation == "strong"
    assert "totally_made_up_field" in overlay.unknown_defense_fields


def test_run_single_logs_warning_on_unknown_overlay_field(cfg, caplog):
    # Force a known-bad condition via an extra factor the research config
    # does not ship with.
    bad = FactorDef(
        name="broken_factor",
        level1_overrides={
            "defenses": {"never_a_real_field": 42},
        },
    )
    run_cfg = cfg
    run_cfg.experiment.factors = list(run_cfg.experiment.factors) + [bad]
    cond = Condition(name="bad",
                     factor_levels={f.name: 0 for f in run_cfg.experiment.factors})
    cond.factor_levels["broken_factor"] = 1
    run_cfg.experiment.days_per_run = 1

    with caplog.at_level(logging.WARNING):
        result = run_single(
            run_cfg, cond, seed=1, output_dir="/tmp/aces_regress",
            runtime_override=StubRuntime(rng=random.Random(1)),
        )
    assert result["status"] == "completed"
    assert any("never_a_real_field" in rec.getMessage() for rec in caplog.records)


def test_attacker_policy_overlay_reaches_attack_config(cfg):
    """D3: an ``attacks:`` factor overlay must patch run_cfg.attacks
    before the AttackInjector is constructed so a factorial design
    can toggle scripted/llm/passive modes on a per-condition basis."""
    cfg.experiment.factors = [FactorDef(
        name="attacker_autonomy",
        level0_overrides={"attacks": {"attacker_policy": "scripted"}},
        level1_overrides={"attacks": {"attacker_policy": "passive"}},
    )]
    cfg.experiment.days_per_run = 1

    from aces.database import Database as _DB

    # Level 0 — scripted.
    cond0 = Condition(name="scripted",
                       factor_levels={"attacker_autonomy": 0})
    r0 = run_single(
        cfg, cond0, seed=42, output_dir="/tmp/aces_regress",
        runtime_override=StubRuntime(rng=random.Random(42)),
    )
    assert r0["status"] == "completed"
    # Level 1 — passive (no attacks fire at all).
    cond1 = Condition(name="passive",
                       factor_levels={"attacker_autonomy": 1})
    r1 = run_single(
        cfg, cond1, seed=42, output_dir="/tmp/aces_regress",
        runtime_override=StubRuntime(rng=random.Random(42)),
    )
    assert r1["status"] == "completed"

    # Under passive, no attack_injected events should exist.
    db_passive = _DB(r1["db_path"])
    try:
        n_passive = db_passive.count_events("attack_injected")
    finally:
        db_passive.close()
    assert n_passive == 0, (
        "passive attacker_policy must silence the injector")


def test_attacker_policy_overlay_rejects_invalid_value(cfg, caplog):
    """D3: a bogus attacker_policy must log a warning and leave the
    existing attacker_policy untouched instead of being silently
    accepted."""
    cfg.experiment.factors = [FactorDef(
        name="bad_autonomy",
        level1_overrides={"attacks": {"attacker_policy": "chaotic_good"}},
    )]
    cfg.experiment.days_per_run = 1
    cond = Condition(name="bad", factor_levels={"bad_autonomy": 1})

    with caplog.at_level(logging.WARNING):
        result = run_single(
            cfg, cond, seed=43, output_dir="/tmp/aces_regress",
            runtime_override=StubRuntime(rng=random.Random(43)),
        )
    assert result["status"] == "completed"
    assert any("chaotic_good" in rec.getMessage() for rec in caplog.records)


def test_group_updates_overlay_is_applied(cfg):
    """Regression for B3: overlay.group_updates must reach
    run_cfg.enterprise.communication_groups before init_world."""
    # Force grp_eng into admins_only via a custom factor.
    cfg.experiment.factors = [FactorDef(
        name="lockdown_eng_group",
        level0_overrides={},
        level1_overrides={
            "group_updates": {
                "grp_eng": {"posting_policy": "admins_only"},
            },
        },
    )]
    cfg.experiment.days_per_run = 1
    cond = Condition(name="locked", factor_levels={"lockdown_eng_group": 1})
    result = run_single(
        cfg, cond, seed=2, output_dir="/tmp/aces_regress",
        runtime_override=StubRuntime(rng=random.Random(2)),
    )
    assert result["status"] == "completed"
    # Verify via the produced DB that grp_eng was locked down.
    from aces.database import Database as _DB
    db2 = _DB(result["db_path"])
    try:
        grp = db2.get_group("grp_eng")
        assert grp is not None
        assert grp.posting_policy == "admins_only"
    finally:
        db2.close()


# ---------------------------------------------------------------------------
# B4 — quarantined victim cannot be impersonated
# ---------------------------------------------------------------------------

def test_transfer_on_behalf_of_quarantined_victim_fails(engine):
    """Regression for B4: the token economy must refuse to move money
    for a quarantined effective-sender, even when the actor is healthy
    and holds what used to be a valid impersonation grant."""
    robert = engine.db.get_agent("fin_robert")
    robert.status = AgentStatus.QUARANTINED
    engine.db.update_agent(robert)

    victor = engine.db.get_agent("it_victor")
    # Bypass the engine's grant check by calling the service directly,
    # exactly as B4 describes (service must defend itself).
    tx = engine.services.token_economy.transfer(
        actor=victor,
        sender_identity=robert,
        recipient_id="hr_emily",
        amount=25.0,
        note="regression",
        sim_day=1, sim_tick=1,
    )
    assert tx is None


# ---------------------------------------------------------------------------
# B5 — SocialTrustGraph preserves explicit relationship labels
# ---------------------------------------------------------------------------

def test_social_graph_preserves_explicit_cross_team_label(cfg):
    g = SocialTrustGraph.from_config(cfg.enterprise)
    # sec_david.manager_id = exec_tom, but exec_tom's known_agents
    # entry for sec_david is explicitly "cross-team".  The explicit
    # label must win.
    rel = g.relationship("exec_tom", "sec_david")
    assert rel == "cross-team"


def test_social_graph_still_fills_missing_edges_from_manager_id(cfg):
    g = SocialTrustGraph.from_config(cfg.enterprise)
    # pm_emma.manager_id = exec_tom, and exec_tom does NOT list pm_emma
    # in his known_agents.  Pass 2 must fill the missing edge.
    assert g.relationship("exec_tom", "pm_emma") == "report"
    assert g.relationship("pm_emma", "exec_tom") == "manager"


# ---------------------------------------------------------------------------
# B6 — disabled_agents purges group memberships + known_agents
# ---------------------------------------------------------------------------

def test_disabled_agent_is_removed_from_group_memberships(cfg):
    cond = Condition(name="no_security",
                     factor_levels={f.name: 0 for f in cfg.experiment.factors})
    cfg.experiment.days_per_run = 1
    result = run_single(
        cfg, cond, seed=3, output_dir="/tmp/aces_regress",
        runtime_override=StubRuntime(rng=random.Random(3)),
    )
    from aces.database import Database as _DB
    db2 = _DB(result["db_path"])
    try:
        # sec_david should not exist as an agent.
        assert db2.get_agent("sec_david") is None
        # And no group should still have him as a member.
        for g in db2.get_all_groups():
            assert "sec_david" not in g.members
            assert "sec_david" not in g.admins
    finally:
        db2.close()


# ---------------------------------------------------------------------------
# D1 — ScenarioOverrides.resolved_defenses is a real field
# ---------------------------------------------------------------------------

def test_scenario_overrides_resolved_defenses_survives_deepcopy():
    import copy
    base = DefenseOverrides(segmentation="flat")
    factors = [FactorDef(
        name="seg",
        level1_overrides={"defenses": {"segmentation": "strong"}},
    )]
    overlay = apply_condition_overrides(base, {"seg": 1}, factors)
    clone = copy.deepcopy(overlay)
    assert clone.resolved_defenses is not None
    assert clone.resolved_defenses.segmentation == "strong"
    # Legacy attribute fall-through still works.
    assert clone.segmentation == "strong"


# ---------------------------------------------------------------------------
# D2 — host access does not double-emit SERVER_LOGIN on read_secret
# ---------------------------------------------------------------------------

def test_read_secret_does_not_double_log_server_login(engine):
    victor = engine.db.get_agent("it_victor")
    before = engine.db.count_events("server_login")
    grant = engine.services.host_access.read_secret(
        victor, "srv_payroll_app", "/etc/payroll/signer.env",
        sim_day=2, sim_tick=1,
    )
    assert grant is not None
    after = engine.db.count_events("server_login")
    # Exactly zero SERVER_LOGIN events should be generated by a bare
    # read_secret call — the operation logs SERVER_SECRET_READ instead.
    assert after - before == 0


# ---------------------------------------------------------------------------
# D3 — overdraft protection
# ---------------------------------------------------------------------------

def test_transfer_refuses_to_push_sender_negative(engine):
    robert = engine.db.get_agent("fin_robert")
    before = robert.wallet_balance
    huge = before + 1000.0
    tx = engine.services.token_economy.transfer(
        actor=robert,
        sender_identity=robert,
        recipient_id="hr_emily",
        amount=huge,
        note="overdraft attempt",
        sim_day=1, sim_tick=1,
    )
    assert tx is None
    # Sender balance unchanged.
    assert engine.db.get_agent("fin_robert").wallet_balance == pytest.approx(before)


# ---------------------------------------------------------------------------
# D4 — transfer_cap_per_day decoupled from spend_cap_per_day
# ---------------------------------------------------------------------------

def test_transfer_cap_is_independent_of_llm_spend_cap(db, cfg):
    # Configure a very low transfer cap but leave spend_cap untouched.
    cfg.defenses = DefenseOverrides(transfer_cap_per_day=30.0)
    engine = SimulationEngine(cfg, db,
                               runtime=StubRuntime(rng=random.Random(4)),
                               run_id="cap-test",
                               rng=random.Random(4))
    engine.metrics_computer = MetricsComputer(db)
    engine.defense_manager = DefenseManager(cfg.defenses, db, engine.services,
                                             random.Random(4))
    engine.init_world()

    robert = db.get_agent("fin_robert")
    tx = engine.services.token_economy.transfer(
        actor=robert, sender_identity=robert,
        recipient_id="hr_emily", amount=40.0,
        note="over cap", sim_day=1, sim_tick=1,
    )
    assert tx is None

    tx2 = engine.services.token_economy.transfer(
        actor=robert, sender_identity=robert,
        recipient_id="hr_emily", amount=20.0,
        note="under cap", sim_day=1, sim_tick=1,
    )
    assert tx2 is not None


# ---------------------------------------------------------------------------
# D6 — send_group returns a delivery count
# ---------------------------------------------------------------------------

def test_send_group_returns_delivered_count(engine):
    tom = engine.db.get_agent("exec_tom")
    count = engine.services.group_mail.send_group(
        tom, "grp_allhands", "regression", "body")
    # grp_allhands has 15 members; tom is one of them, so 14 delivered.
    assert count == 14


def test_send_group_returns_none_when_blocked(engine):
    emma = engine.db.get_agent("pm_emma")
    # grp_allhands has admins_only posting policy and emma is not admin.
    result = engine.services.group_mail.send_group(
        emma, "grp_allhands", "blocked", "hi")
    assert result is None


# ---------------------------------------------------------------------------
# D7 — key rotation revokes impersonation grants
# ---------------------------------------------------------------------------

def test_key_rotation_revokes_grants(db, cfg):
    cfg.defenses = DefenseOverrides(recovery_key_rotation=True)
    engine = SimulationEngine(cfg, db,
                               runtime=StubRuntime(rng=random.Random(5)),
                               run_id="kr-test",
                               rng=random.Random(5))
    engine.metrics_computer = MetricsComputer(db)
    engine.defense_manager = DefenseManager(cfg.defenses, db, engine.services,
                                             random.Random(5))
    engine.init_world()

    victor = db.get_agent("it_victor")
    grant = engine.services.host_access.read_secret(
        victor, "srv_payroll_app", "/etc/payroll/signer.env",
        sim_day=1, sim_tick=1,
    )
    assert grant is not None
    # Mark fin_robert as compromised so the rotation hook fires.
    robert = db.get_agent("fin_robert")
    robert.status = AgentStatus.COMPROMISED
    db.update_agent(robert)

    engine.defense_manager._check_key_rotation(robert, sim_day=1)

    # The grant bound to the rotated credential must now be inactive.
    assert not engine.services.impersonation.can_impersonate(
        actor_id="it_victor", victim_id="fin_robert",
        capability="transfer_tokens",
    )


# ---------------------------------------------------------------------------
# D4 — every shipped factor produces a real state delta (no dishonest factors)
# ---------------------------------------------------------------------------

def _flatten_overlay_for_diff(overlay, defense_fields):
    snap = {
        f"def.{f}": getattr(overlay.resolved_defenses, f, None)
        for f in defense_fields
    }
    snap["agent_updates"] = dict(overlay.agent_updates)
    snap["server_updates"] = dict(overlay.server_updates)
    snap["group_updates"] = dict(overlay.group_updates)
    snap["attacks"] = dict(overlay.attacks)
    snap["disabled_agents"] = sorted(overlay.disabled_agents)
    snap["enabled_agents"] = sorted(overlay.enabled_agents)
    return snap


def test_every_research_factor_has_a_real_state_delta(cfg):
    """Honesty regression: every factor shipped in the research
    experiment yaml must produce *some* observable change in the
    resolved overlay between level 0 and level 1. A factor with zero
    delta is dishonest by construction — it cannot move outcomes — and
    pollutes the factorial design.
    """
    defense_fields = [
        "segmentation", "credential_scope", "credential_rotation",
        "rotation_interval_days", "communication_discipline",
        "clarification_gate", "transfer_cap_per_day",
        "unknown_sender_requires_verification", "recovery_key_rotation",
    ]
    flat: list[str] = []
    for fac in cfg.experiment.factors:
        o0 = apply_condition_overrides(
            cfg.experiment.baseline_defenses, {fac.name: 0}, [fac])
        o1 = apply_condition_overrides(
            cfg.experiment.baseline_defenses, {fac.name: 1}, [fac])
        if (_flatten_overlay_for_diff(o0, defense_fields)
                == _flatten_overlay_for_diff(o1, defense_fields)):
            flat.append(fac.name)
    assert not flat, (
        "These factors produce no observable state delta between L0 "
        f"and L1 and must be removed or rewritten: {flat}")
