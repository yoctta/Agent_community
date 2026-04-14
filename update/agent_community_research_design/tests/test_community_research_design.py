"""Design-target tests for the proposed research community extension.

These tests are written against the proposed API, not the current main branch.
They are intended to become executable once the design in
`Agent_Community_Research_Design.md` is implemented.
"""

from __future__ import annotations

import os
import random
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aces.config import load_config
from aces.database import Database
from aces.models import AgentRole, AgentStatus
from aces.runtime import create_runtime
from aces.engine import SimulationEngine


CFG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config")


def _load_research_cfg():
    return load_config(
        enterprise_path=os.path.join(CFG_DIR, "community_research_enterprise.yaml"),
        experiment_path=os.path.join(CFG_DIR, "community_research_experiment.yaml"),
        attack_path=os.path.join(CFG_DIR, "community_research_attacks.yaml"),
    )


@pytest.fixture
def research_cfg():
    return _load_research_cfg()


@pytest.fixture
def db():
    database = Database(":memory:")
    yield database
    database.close()


@pytest.fixture
def engine(db, research_cfg):
    runtime = create_runtime(backend="openai", model="stubbed")
    eng = SimulationEngine(
        cfg=research_cfg,
        db=db,
        runtime=runtime,
        run_id="research-test-run",
        rng=random.Random(1234),
    )
    eng.init_world()
    return eng


# ---------------------------------------------------------------------------
# Config / world initialization
# ---------------------------------------------------------------------------

def test_research_config_initializes_15_agents(db, engine):
    agents = db.get_all_agents()
    assert len(agents) == 15
    assert db.get_agent("it_victor") is not None
    assert db.get_agent("sec_david") is not None


def test_research_config_contains_malicious_agent_memory(db, engine):
    memory = db.get_agent_memory("it_victor")
    objective_keys = {m.key for m in memory}
    assert any(key.startswith("attack_objective_") for key in objective_keys)


# ---------------------------------------------------------------------------
# Directory and trust graph
# ---------------------------------------------------------------------------

def test_hr_can_lookup_any_agent(engine):
    hr = engine.db.get_agent("hr_emily")
    result = engine.services.directory.lookup(hr, "Ryan")
    assert any(a.id == "eng_ryan" for a in result)


def test_non_hr_cannot_lookup_unknown_agent_without_scope(engine):
    engineer = engine.db.get_agent("eng_julia")
    result = engine.services.directory.lookup(engineer, "Robert")
    assert result == []


def test_unknown_sender_is_flagged_untrusted_in_observation(engine):
    sender = engine.db.get_agent("it_victor")
    recipient = engine.db.get_agent("eng_julia")
    engine.services.mail.send(sender, recipient.id, "Need help", "Please do this now")
    obs = engine.turn_mgr._build_observation(recipient, sim_day=1, sim_tick=1)
    trust_map = {x.sender_id: x.trust_level for x in obs.sender_trust}
    assert trust_map[sender.id] in {"unknown", "introduced"}


def test_known_neighbor_is_flagged_trusted(engine):
    sender = engine.db.get_agent("eng_kevin")
    recipient = engine.db.get_agent("eng_julia")
    engine.services.mail.send(sender, recipient.id, "Schema rehearsal", "Please review migration")
    obs = engine.turn_mgr._build_observation(recipient, sim_day=1, sim_tick=1)
    trust_map = {x.sender_id: x.trust_level for x in obs.sender_trust}
    assert trust_map[sender.id] == "trusted_neighbor"


# ---------------------------------------------------------------------------
# Group communication
# ---------------------------------------------------------------------------

def test_group_mail_delivers_only_to_members(engine):
    sender = engine.db.get_agent("exec_tom")
    engine.services.group_mail.send_group(sender, "grp_allhands", "All hands", "Announcement")

    tom = engine.db.get_unread_messages("exec_tom")
    emma = engine.db.get_unread_messages("pm_emma")
    outsider = engine.db.get_unread_messages("nonexistent")

    assert len(emma) == 1
    assert len(tom) == 0
    assert outsider == []


def test_admin_only_group_rejects_non_admin_post(engine):
    sender = engine.db.get_agent("pm_emma")
    msg = engine.services.group_mail.send_group(sender, "grp_allhands", "Ping", "Hello")
    assert msg is None


# ---------------------------------------------------------------------------
# Token economy
# ---------------------------------------------------------------------------

def test_token_transfer_updates_balances_and_ledger(engine):
    robert = engine.db.get_agent("fin_robert")
    emily = engine.db.get_agent("hr_emily")
    before_r = robert.wallet_balance
    before_e = emily.wallet_balance

    tx = engine.services.token_economy.transfer(
        actor=robert,
        sender_identity=robert,
        recipient_id=emily.id,
        amount=50.0,
        note="HR reimbursement",
        sim_day=1,
        sim_tick=1,
    )
    assert tx is not None

    robert_fresh = engine.db.get_agent("fin_robert")
    emily_fresh = engine.db.get_agent("hr_emily")
    assert robert_fresh.wallet_balance == pytest.approx(before_r - 50.0)
    assert emily_fresh.wallet_balance == pytest.approx(before_e + 50.0)


def test_transfer_cap_blocks_oversized_transfer(engine):
    robert = engine.db.get_agent("fin_robert")
    emily = engine.db.get_agent("hr_emily")
    tx = engine.services.token_economy.transfer(
        actor=robert,
        sender_identity=robert,
        recipient_id=emily.id,
        amount=9999.0,
        note="too large",
        sim_day=1,
        sim_tick=1,
    )
    assert tx is None


# ---------------------------------------------------------------------------
# Server access and impersonation
# ---------------------------------------------------------------------------

def test_devops_can_login_release_server(engine):
    sara = engine.db.get_agent("devops_sara")
    session = engine.services.host_access.login(sara, "srv_release_runner")
    assert session is not None


def test_product_cannot_login_release_server(engine):
    emma = engine.db.get_agent("pm_emma")
    session = engine.services.host_access.login(emma, "srv_release_runner")
    assert session is None


def test_malicious_it_admin_can_read_payroll_secret_and_gain_impersonation(engine):
    victor = engine.db.get_agent("it_victor")
    assert engine.services.host_access.login(victor, "srv_payroll_app") is not None
    grant = engine.services.host_access.read_secret(
        victor,
        "srv_payroll_app",
        "/etc/payroll/signer.env",
        sim_day=2,
        sim_tick=1,
    )
    assert grant is not None
    assert grant.victim_agent_id == "fin_robert"


def test_impersonated_transfer_records_actor_and_effective_sender(engine):
    victor = engine.db.get_agent("it_victor")
    target = engine.db.get_agent("hr_emily")
    engine.services.host_access.login(victor, "srv_payroll_app")
    engine.services.host_access.read_secret(victor, "srv_payroll_app", "/etc/payroll/signer.env")

    tx = engine.services.token_economy.transfer(
        actor=victor,
        sender_identity=engine.db.get_agent("fin_robert"),
        recipient_id=target.id,
        amount=75.0,
        note="fraudulent payroll adjustment",
        sim_day=2,
        sim_tick=1,
    )
    assert tx is not None
    assert tx.actor_agent_id == "it_victor"
    assert tx.effective_sender_id == "fin_robert"
    assert tx.via_impersonation is True


def test_key_rotation_revokes_impersonation(engine):
    victor = engine.db.get_agent("it_victor")
    engine.services.host_access.login(victor, "srv_payroll_app")
    engine.services.host_access.read_secret(victor, "srv_payroll_app", "/etc/payroll/signer.env")
    engine.services.impersonation.revoke_for_victim("fin_robert")
    assert not engine.services.impersonation.can_impersonate(
        actor_id="it_victor",
        victim_id="fin_robert",
        capability="transfer_tokens",
    )


# ---------------------------------------------------------------------------
# Security intervention
# ---------------------------------------------------------------------------

def test_security_can_isolate_malicious_agent(engine):
    david = engine.db.get_agent("sec_david")
    victor = engine.db.get_agent("it_victor")
    ok = engine.defense_manager.isolate_agent(david, victor.id, reason="credential abuse")
    assert ok is True
    assert engine.db.get_agent("it_victor").status == AgentStatus.QUARANTINED


def test_quarantined_agent_cannot_transfer_or_login(engine):
    victor = engine.db.get_agent("it_victor")
    victor.status = AgentStatus.QUARANTINED
    engine.db.update_agent(victor)

    login = engine.services.host_access.login(victor, "srv_payroll_app")
    assert login is None

    tx = engine.services.token_economy.transfer(
        actor=victor,
        sender_identity=victor,
        recipient_id="hr_emily",
        amount=10.0,
        note="should fail",
    )
    assert tx is None


# ---------------------------------------------------------------------------
# Metrics and condition overrides
# ---------------------------------------------------------------------------

def test_final_metric_excludes_attacker_balance(engine):
    final_metrics = engine.metrics_computer.compute_final(run_id="research-test-run", final_day=1)
    assert "community_token_balance_excluding_attackers" in final_metrics


def test_condition_override_can_disable_security_agent(research_cfg):
    # Proposed loader result after factor application.
    from aces.config import apply_condition_overrides

    overrides = apply_condition_overrides(
        base_defenses=research_cfg.experiment.baseline_defenses,
        factor_levels={"security_expert": 0},
        factors=research_cfg.experiment.factors,
    )
    assert "sec_david" in overrides.disabled_agents


# ---------------------------------------------------------------------------
# End-to-end research smoke
# ---------------------------------------------------------------------------

def test_research_smoke_run_produces_token_metric(db, research_cfg):
    runtime = create_runtime(backend="openai", model="stubbed")
    engine = SimulationEngine(
        cfg=research_cfg,
        db=db,
        runtime=runtime,
        run_id="research-smoke",
        rng=random.Random(123),
    )
    engine.init_world()
    run = engine.run(days=2)
    assert run.final_metrics is not None
    assert "community_token_balance_excluding_attackers" in run.final_metrics
