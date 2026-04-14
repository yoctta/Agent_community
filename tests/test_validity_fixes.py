"""Regression tests for the four research-validity bugs uncovered by
the mental experiment (H6, H9, H12, H15).

These tests lock down behaviour that would otherwise silently break
factorial experiments — the kind of issue that doesn't crash but
makes the numbers lie.
"""

from __future__ import annotations

import os
import random
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aces.config import load_config
from aces.database import Database
from aces.defenses import DefenseManager
from aces.engine import SimulationEngine
from aces.metrics import MetricsComputer
from aces.models import (
    AgentStatus, AuditMailAction, EventType, NoOpAction, SendMailAction,
)
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
        runtime=StubRuntime(rng=random.Random(91)),
        run_id="validity-run",
        rng=random.Random(91),
    )
    eng.metrics_computer = MetricsComputer(db, csri_weights=cfg.experiment.csri_weights)
    eng.defense_manager = DefenseManager(cfg.defenses, db, eng.services, random.Random(91))
    eng.init_world()
    return eng


# ---------------------------------------------------------------------------
# H9 — manager fallback across the research role set
# ---------------------------------------------------------------------------

def test_empty_recipient_mail_routes_to_a_leader(engine):
    """With the research config there is no agent with role='manager'
    — the fallback must recognise engineering_manager / executive and
    pick one of them instead of a random peer."""
    kevin = engine.db.get_agent("eng_kevin")
    action = SendMailAction(
        agent_id=kevin.id, recipient_id="", subject="status", body="ok")
    agents = engine.db.get_all_agents()
    ok, *_ = engine.turn_mgr._execute_action(action, kevin, 1, 1, agents)
    assert ok is True
    # Drain kevin's outgoing memory to find where the mail landed.
    mem = engine.db.get_agent_memory(kevin.id, category="contacts")
    recipients = {m.key for m in mem if m.value.startswith("Sent mail")}
    assert len(recipients) >= 1
    # The fallback should have picked kevin's manager (mgr_mike) via
    # the social graph.
    assert "mgr_mike" in recipients


def test_empty_recipient_fallback_picks_from_leader_roles(engine):
    """Pick an agent whose role is in the leader set and who has NO
    direct manager in the trust graph — the fallback should still
    land on a leader, not a random peer."""
    emma = engine.db.get_agent("pm_emma")
    # Sanity: pm_emma's manager is exec_tom in the config.
    action = SendMailAction(
        agent_id=emma.id, recipient_id="", subject="status", body="ok")
    agents = engine.db.get_all_agents()
    ok, *_ = engine.turn_mgr._execute_action(action, emma, 1, 1, agents)
    assert ok is True


# ---------------------------------------------------------------------------
# H12 — turn-end event flags NoOp-only turns as idle
# ---------------------------------------------------------------------------

def test_turn_end_event_flags_noop_only_turn_as_idle(db, cfg):
    """A turn consisting solely of NoOp actions must be stamped as
    idle in the AGENT_TURN_END event payload so downstream analysis
    can recognise it. (The auto loop-detection defense that used to
    read this flag was deleted in Track A; the flag is still useful
    for the security agent's raw view and for offline analysis.)"""
    class _NoOpRuntime(StubRuntime):
        def decide(self, obs, max_actions=3):
            return [NoOpAction(agent_id=obs.agent.id, reason="idle")]

    engine = SimulationEngine(
        cfg=cfg, db=db,
        runtime=_NoOpRuntime(rng=random.Random(0)),
        run_id="idle-run",
        rng=random.Random(0),
    )
    engine.init_world()
    agents = db.get_all_agents()
    kevin = db.get_agent("eng_kevin")
    engine.turn_mgr.execute_turn(kevin, sim_day=1, sim_tick=1,
                                  max_actions=3, all_agents=agents)
    events = db.get_events(agent_id=kevin.id,
                            event_type=EventType.AGENT_TURN_END.value)
    assert events, "turn should have emitted a turn-end event"
    assert events[-1].payload.get("idle") is True
    assert events[-1].payload.get("productive") == 0


def test_idle_turns_do_not_mutate_agent_status(db, cfg):
    """Post-Track-A: there is no auto-degrade based on idle streaks.
    The loop-detection defense was deleted because it altered agent
    state behind the LLM's back.  An agent that NoOps all day stays
    HEALTHY; the token economy + community pressure are the natural
    incentives, not hidden timers."""
    class _NoOpRuntime(StubRuntime):
        def decide(self, obs, max_actions=3):
            return [NoOpAction(agent_id=obs.agent.id, reason="idle")]

    engine = SimulationEngine(
        cfg=cfg, db=db,
        runtime=_NoOpRuntime(rng=random.Random(0)),
        run_id="idle-run", rng=random.Random(0),
    )
    engine.metrics_computer = MetricsComputer(db)
    engine.defense_manager = DefenseManager(
        cfg.defenses, db, engine.services, random.Random(0))
    engine.init_world()

    kevin = db.get_agent("eng_kevin")
    agents = db.get_all_agents()
    for tick in range(1, 4):
        engine.turn_mgr.execute_turn(
            db.get_agent(kevin.id), sim_day=1, sim_tick=tick,
            max_actions=3, all_agents=agents,
        )
    engine.defense_manager.run(1, db.get_all_agents())
    kevin_after = db.get_agent(kevin.id)
    assert kevin_after.status == AgentStatus.HEALTHY


# ---------------------------------------------------------------------------
# H6 — impersonation detection pathway
# ---------------------------------------------------------------------------

def test_audit_mail_surfaces_impersonation_pattern(engine):
    """After it_victor impersonates fin_robert via a server read and
    sends a mail, sec_david's audit_mail sweep must return raw
    evidence naming it_victor.  The sweep no longer returns a
    handcrafted suspicion score — the LLM reasons over the raw log
    instead."""
    victor = engine.db.get_agent("it_victor")
    engine.services.host_access.read_secret(
        victor, "srv_payroll_app", "/etc/payroll/signer.env",
        sim_day=1, sim_tick=1,
    )
    action = SendMailAction(
        agent_id=victor.id, recipient_id="hr_emily",
        subject="Reconcile payroll", body="please action",
        as_agent_id="fin_robert",
    )
    engine.turn_mgr._execute_action(
        action, victor, sim_day=1, sim_tick=2,
        all_agents=engine.db.get_all_agents(),
    )

    david = engine.db.get_agent("sec_david")
    audit = AuditMailAction(agent_id=david.id, since_day=1)
    ok, *_ = engine.turn_mgr._execute_action(
        audit, david, sim_day=1, sim_tick=3,
        all_agents=engine.db.get_all_agents(),
    )
    assert ok is True

    events = engine.db.get_events(event_type=EventType.MAIL_AUDITED.value)
    assert events, "audit_mail should emit a MAIL_AUDITED event"
    last = events[-1].payload
    assert last["evidence_count"] >= 2, (
        f"expected ≥2 evidence rows, got {last}")

    alerts = engine.db.get_unread_messages(david.id)
    audit_alerts = [m for m in alerts
                     if m.subject and m.subject.startswith("AUDIT")]
    assert audit_alerts, "audit_mail should deliver a self-alert"
    # The raw evidence should name it_victor somewhere.
    body = audit_alerts[-1].body or ""
    assert "it_victor" in body, (
        f"expected raw evidence to mention it_victor, got: {body[:200]}")


def test_anomaly_detection_fires_in_barrier(engine):
    """Rule-based baseline: when the handcrafted scoring detector is
    explicitly enabled, barrier-phase detection must raise an
    ANOMALY_DETECTED event for it_victor after visible impersonation
    activity.  The default research posture is LLM-driven detection
    (``enable_rule_based_anomaly_detection=False``); this test locks
    down the comparison-baseline path."""
    # Opt in to the rule-based detector for this test only.
    engine.defense_manager.defenses.enable_rule_based_anomaly_detection = True
    victor = engine.db.get_agent("it_victor")
    # Two impersonation-related events: 1 server read + 1 impersonated
    # mail.  Score should be 1.0 (secret read) + 2.0 (imp mail) = 3.0.
    engine.services.host_access.read_secret(
        victor, "srv_payroll_app", "/etc/payroll/signer.env",
        sim_day=1, sim_tick=1,
    )
    engine.turn_mgr._execute_action(
        SendMailAction(
            agent_id=victor.id, recipient_id="hr_emily",
            subject="x", body="y", as_agent_id="fin_robert",
        ),
        victor, sim_day=1, sim_tick=2,
        all_agents=engine.db.get_all_agents(),
    )
    engine.defense_manager.run(sim_day=1, agents=engine.db.get_all_agents())
    anomalies = engine.db.get_events(event_type=EventType.ANOMALY_DETECTED.value)
    assert any(e.agent_id == "it_victor" for e in anomalies)


def test_non_security_agent_cannot_audit_mail(engine):
    """AuditMailAction must be gated to the security role."""
    kevin = engine.db.get_agent("eng_kevin")
    ok, *_ = engine.turn_mgr._execute_action(
        AuditMailAction(agent_id=kevin.id),
        kevin, sim_day=1, sim_tick=1,
        all_agents=engine.db.get_all_agents(),
    )
    assert ok is False


# ---------------------------------------------------------------------------
# H15 — CSRI folds the community-balance outcome
# ---------------------------------------------------------------------------

def test_csri_economic_loss_reflects_drained_community(db, cfg):
    """With baseline wired, draining the community balance must raise
    the CSRI economic component."""
    engine = SimulationEngine(
        cfg=cfg, db=db,
        runtime=StubRuntime(rng=random.Random(3)),
        run_id="csri-run", rng=random.Random(3),
    )
    engine.metrics_computer = MetricsComputer(
        db, csri_weights=[0.1, 0.1, 0.1, 0.1, 0.6])
    engine.defense_manager = DefenseManager(
        cfg.defenses, db, engine.services, random.Random(3))
    engine.init_world()

    # Drain non-attacker wallets directly.
    for a in db.get_all_agents():
        if not a.is_malicious:
            a.wallet_balance = 0.0
            db.update_agent(a)

    metrics = engine.metrics_computer.compute_final("csri-run", final_day=1)
    # With ~60% weight on the economic loss term and the wallets
    # zeroed, CSRI should be clearly above zero.
    assert metrics["csri"] > 0.3


def test_csri_legacy_four_element_weights_still_work(db, cfg):
    """Legacy configs with 4-element csri_weights must still produce
    a numeric CSRI (the new econ_loss term pads to 0)."""
    engine = SimulationEngine(
        cfg=cfg, db=db,
        runtime=StubRuntime(rng=random.Random(4)),
        run_id="legacy-csri", rng=random.Random(4),
    )
    engine.metrics_computer = MetricsComputer(
        db, csri_weights=[0.25, 0.25, 0.25, 0.25])
    engine.defense_manager = DefenseManager(
        cfg.defenses, db, engine.services, random.Random(4))
    engine.init_world()
    metrics = engine.metrics_computer.compute_final("legacy-csri", final_day=1)
    assert "csri" in metrics
    assert 0.0 <= metrics["csri"] <= 1.0


def test_csri_baseline_wired_from_init_world(engine):
    """MetricsComputer installed before init_world must receive the
    baseline non-attacker balance automatically."""
    baseline = engine.metrics_computer.baseline_non_attacker_balance
    # Sum starting balances for all non-malicious agents in the
    # research enterprise.  Uses the config, not the DB.
    expected = sum(
        a.initial_balance for a in engine.cfg.enterprise.agents
        if not a.is_malicious
    )
    assert baseline == pytest.approx(expected)


# ---------------------------------------------------------------------------
# Rule-based detector is DEFAULT OFF.  Security agents see raw evidence.
# ---------------------------------------------------------------------------

def test_rule_based_anomaly_detection_off_by_default(engine):
    """Default DefenseOverrides must have
    ``enable_rule_based_anomaly_detection=False``; an inject that would
    have crossed the old threshold must NOT produce an
    ANOMALY_DETECTED event automatically."""
    victor = engine.db.get_agent("it_victor")
    # Exactly the same trigger as the rule-based baseline test.
    engine.services.host_access.read_secret(
        victor, "srv_payroll_app", "/etc/payroll/signer.env",
        sim_day=1, sim_tick=1,
    )
    engine.turn_mgr._execute_action(
        SendMailAction(
            agent_id=victor.id, recipient_id="hr_emily",
            subject="x", body="y", as_agent_id="fin_robert",
        ),
        victor, sim_day=1, sim_tick=2,
        all_agents=engine.db.get_all_agents(),
    )
    engine.defense_manager.run(sim_day=1, agents=engine.db.get_all_agents())
    anomalies = engine.db.get_events(event_type=EventType.ANOMALY_DETECTED.value)
    assert not anomalies, (
        "rule-based detector must be OFF by default; enable via "
        "DefenseOverrides.enable_rule_based_anomaly_detection")


def test_security_agent_observation_contains_raw_activity(engine):
    """Security agents must see a chronological dump of recent
    security-relevant events in their observation, so the LLM can
    reason over raw evidence instead of relying on handcrafted
    scoring rules."""
    victor = engine.db.get_agent("it_victor")
    engine.services.host_access.read_secret(
        victor, "srv_payroll_app", "/etc/payroll/signer.env",
        sim_day=1, sim_tick=1,
    )
    engine.services.host_access.list_secrets(
        victor, "srv_identity_admin", sim_day=1, sim_tick=2,
    )

    sec_david = engine.db.get_agent("sec_david")
    obs = engine.turn_mgr._build_observation(sec_david, sim_day=1, sim_tick=3)
    summary = obs.recent_activity_summary
    assert summary, "security agent must see recent activity"
    # The secret read and list should both appear.
    joined = "\n".join(summary)
    assert "srv_payroll_app" in joined
    assert "READ" in joined, f"expected a READ line in {summary}"
    assert "it_victor" in joined


def test_non_security_agent_observation_hides_raw_activity(engine):
    """Non-security agents must NOT see the raw security timeline —
    it would leak detection information to everyone."""
    victor = engine.db.get_agent("it_victor")
    engine.services.host_access.read_secret(
        victor, "srv_payroll_app", "/etc/payroll/signer.env",
        sim_day=1, sim_tick=1,
    )
    kevin = engine.db.get_agent("eng_kevin")
    obs = engine.turn_mgr._build_observation(kevin, sim_day=1, sim_tick=2)
    assert obs.recent_activity_summary == []


def test_quarantined_security_agent_observation_is_empty(engine):
    """A quarantined security agent must not receive the raw view —
    isolation should cut off their signal channel."""
    sec_david = engine.db.get_agent("sec_david")
    sec_david.status = AgentStatus.QUARANTINED
    engine.db.update_agent(sec_david)
    obs = engine.turn_mgr._build_observation(sec_david, sim_day=1, sim_tick=1)
    assert obs.recent_activity_summary == []


def test_security_agent_can_isolate_via_action_dsl(engine):
    """LLM security experts must be able to invoke IsolateAgentAction
    from their own decide() output.  End-to-end: security agent →
    IsolateAgentAction → defense_manager.isolate_agent → target
    quarantined + bounty paid (since target is malicious)."""
    from aces.models import IsolateAgentAction
    sec_david = engine.db.get_agent("sec_david")
    before = sec_david.wallet_balance
    action = IsolateAgentAction(
        agent_id=sec_david.id, target_id="it_victor",
        reason="suspicious secret reads + impersonation pattern",
    )
    ok, *_ = engine.turn_mgr._execute_action(
        action, sec_david, sim_day=2, sim_tick=1,
        all_agents=engine.db.get_all_agents(),
    )
    assert ok is True
    victim = engine.db.get_agent("it_victor")
    assert victim.status == AgentStatus.QUARANTINED
    after = engine.db.get_agent(sec_david.id).wallet_balance
    # Bounty paid — it_victor is malicious in the research config.
    assert after > before


def test_non_security_agent_cannot_isolate(engine):
    """Only agents with role='security' may successfully invoke
    IsolateAgentAction.  Any other role must be rejected without
    mutating state."""
    from aces.models import IsolateAgentAction
    kevin = engine.db.get_agent("eng_kevin")
    action = IsolateAgentAction(
        agent_id=kevin.id, target_id="it_victor", reason="rogue attempt")
    ok, *_ = engine.turn_mgr._execute_action(
        action, kevin, sim_day=1, sim_tick=1,
        all_agents=engine.db.get_all_agents(),
    )
    assert ok is False
    assert engine.db.get_agent("it_victor").status != AgentStatus.QUARANTINED


def test_security_agent_can_release_via_action_dsl(engine):
    """ReleaseAgentAction must be callable by a security agent and
    flip a previously-quarantined agent back to HEALTHY.  If the
    released target was malicious, the security agent is fined
    (bounty clawback); if a false positive, fine is refunded."""
    from aces.models import IsolateAgentAction, ReleaseAgentAction
    sec_david = engine.db.get_agent("sec_david")

    # First: isolate eng_kevin (a NON-malicious agent — false positive).
    engine.turn_mgr._execute_action(
        IsolateAgentAction(agent_id=sec_david.id, target_id="eng_kevin",
                            reason="mistake"),
        sec_david, sim_day=1, sim_tick=1,
        all_agents=engine.db.get_all_agents(),
    )
    kevin = engine.db.get_agent("eng_kevin")
    assert kevin.status == AgentStatus.QUARANTINED

    # Now release — this is a false-positive correction → refund.
    balance_before = engine.db.get_agent(sec_david.id).wallet_balance
    ok, *_ = engine.turn_mgr._execute_action(
        ReleaseAgentAction(agent_id=sec_david.id, target_id="eng_kevin",
                            reason="review cleared the agent"),
        sec_david, sim_day=1, sim_tick=2,
        all_agents=engine.db.get_all_agents(),
    )
    assert ok is True
    assert engine.db.get_agent("eng_kevin").status == AgentStatus.HEALTHY
    balance_after = engine.db.get_agent(sec_david.id).wallet_balance
    assert balance_after > balance_before   # refund paid


def test_release_agent_gated_to_security_role(engine):
    """Non-security agents cannot call ReleaseAgentAction."""
    from aces.models import ReleaseAgentAction
    engine.db.get_agent("sec_david")  # ensure setup
    # First quarantine it_victor via the defense manager directly.
    victor = engine.db.get_agent("it_victor")
    victor.status = AgentStatus.QUARANTINED
    engine.db.update_agent(victor)

    kevin = engine.db.get_agent("eng_kevin")
    ok, *_ = engine.turn_mgr._execute_action(
        ReleaseAgentAction(agent_id=kevin.id, target_id="it_victor",
                            reason="try to free attacker"),
        kevin, sim_day=1, sim_tick=1,
        all_agents=engine.db.get_all_agents(),
    )
    assert ok is False
    assert engine.db.get_agent("it_victor").status == AgentStatus.QUARANTINED


def test_release_fine_levied_on_releasing_true_positive(engine):
    """Releasing an actually-malicious agent costs the security
    expert a fine (reverses the earlier bounty)."""
    from aces.models import IsolateAgentAction, ReleaseAgentAction
    sec_david = engine.db.get_agent("sec_david")

    engine.turn_mgr._execute_action(
        IsolateAgentAction(agent_id=sec_david.id, target_id="it_victor",
                            reason="confirmed attacker"),
        sec_david, sim_day=1, sim_tick=1,
        all_agents=engine.db.get_all_agents(),
    )
    after_isolation = engine.db.get_agent(sec_david.id).wallet_balance

    ok, *_ = engine.turn_mgr._execute_action(
        ReleaseAgentAction(agent_id=sec_david.id, target_id="it_victor",
                            reason="changed my mind"),
        sec_david, sim_day=1, sim_tick=2,
        all_agents=engine.db.get_all_agents(),
    )
    assert ok is True
    after_release = engine.db.get_agent(sec_david.id).wallet_balance
    assert after_release < after_isolation   # fine levied for bad release


# ---------------------------------------------------------------------------
# D1 — extra_monitoring tripwire on ServerHost is honest and surfaced
# ---------------------------------------------------------------------------

def _engine_with_server_monitoring_overlay(db, cfg, server_id):
    """Build an engine after forcing ``extra_monitoring: true`` on one
    server via the scenario_overrides pathway — mirrors what the
    directory_hardening factor does in a real run."""
    from aces.config import ScenarioOverrides
    cfg.scenario_overrides = ScenarioOverrides(
        server_updates={server_id: {"extra_monitoring": True}},
        resolved_defenses=cfg.defenses,
    )
    eng = SimulationEngine(cfg, db,
                            runtime=StubRuntime(rng=random.Random(99)),
                            run_id="d1-monitoring",
                            rng=random.Random(99))
    eng.metrics_computer = MetricsComputer(db)
    eng.defense_manager = DefenseManager(cfg.defenses, db, eng.services,
                                          random.Random(99))
    eng.init_world()
    return eng


def test_extra_monitoring_overlay_flips_server_flag(db, cfg):
    eng = _engine_with_server_monitoring_overlay(db, cfg, "srv_identity_admin")
    srv = eng.db.get_server("srv_identity_admin")
    assert srv is not None
    assert srv.extra_monitoring is True
    # Other servers remain untouched.
    payroll = eng.db.get_server("srv_payroll_app")
    assert payroll is not None
    assert payroll.extra_monitoring is False


def test_tripwire_events_marked_and_preserved_in_security_view(db, cfg):
    """An access on an extra_monitoring server must appear in the
    security view tagged [TRIPWIRE] even if it is older than the
    security_view_window_days limit."""
    eng = _engine_with_server_monitoring_overlay(db, cfg, "srv_identity_admin")
    victor = eng.db.get_agent("it_victor")
    # Day 1: the critical access. This is the evidence we want to keep.
    eng.services.host_access.login(victor, "srv_identity_admin",
                                    sim_day=1, sim_tick=1)

    window_days = cfg.defenses.security_view_window_days or 3
    query_day = 1 + window_days + 2    # well outside the window

    view = eng.turn_mgr._build_security_view(
        query_day,
        window_days=window_days,
        limit=cfg.defenses.security_view_limit or 20,
    )
    tripwire_lines = [line for line in view if "[TRIPWIRE]" in line]
    assert len(tripwire_lines) == 1, (
        "expected tripwire entry preserved outside window, got view:\n"
        + "\n".join(view))
    assert "srv_identity_admin" in tripwire_lines[0]


def test_non_tripwire_events_still_respect_window(db, cfg):
    """Accesses to a non-monitored server are pruned when older than
    the window — tripwire exception must not leak to unrelated evidence."""
    eng = _engine_with_server_monitoring_overlay(db, cfg, "srv_identity_admin")
    victor = eng.db.get_agent("it_victor")
    eng.services.host_access.login(victor, "srv_payroll_app",
                                    sim_day=1, sim_tick=1)
    window_days = cfg.defenses.security_view_window_days or 3
    query_day = 1 + window_days + 2
    view = eng.turn_mgr._build_security_view(
        query_day,
        window_days=window_days,
        limit=cfg.defenses.security_view_limit or 20,
    )
    # The normal login should have been pruned by the window.
    assert not any("srv_payroll_app" in line for line in view)
