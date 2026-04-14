"""Tests for the second batch of research fixes: impersonated mail (A3),
attack injector entry points (A1/A2), daily metric snapshots (M2),
communication policy delivery gate (D2), unknown-sender verification
(D1), group moderation (D4), and bounty/fine economic loop (M1).
"""

from __future__ import annotations

import os
import random
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aces.attacks import AttackInjector
from aces.config import DefenseOverrides, load_config
from aces.database import Database
from aces.defenses import DefenseManager
from aces.engine import SimulationEngine
from aces.metrics import MetricsComputer
from aces.models import (
    EventType, LedgerEntryType, SendMailAction,
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
        runtime=StubRuntime(rng=random.Random(11)),
        run_id="phase2-run",
        rng=random.Random(11),
    )
    eng.metrics_computer = MetricsComputer(db, csri_weights=cfg.experiment.csri_weights)
    eng.defense_manager = DefenseManager(cfg.defenses, db, eng.services, random.Random(11))
    eng.init_world()
    return eng


# ---------------------------------------------------------------------------
# A3 — Impersonated mail
# ---------------------------------------------------------------------------

def test_impersonated_mail_requires_grant(engine):
    """Engine must reject impersonation when no grant exists."""
    victor = engine.db.get_agent("it_victor")
    agents = engine.db.get_all_agents()
    action = SendMailAction(
        agent_id=victor.id, recipient_id="hr_emily",
        subject="urgent", body="transfer now",
        as_agent_id="fin_robert",
    )
    ok, *_ = engine.turn_mgr._execute_action(action, victor, 1, 1, agents)
    assert ok is False


def test_impersonated_mail_after_server_read(engine):
    """Once victor reads the payroll signer, the resulting grant must
    let him send mail as fin_robert and the message must be recorded
    as IMPERSONATED_MAIL_SENT."""
    victor = engine.db.get_agent("it_victor")
    grant = engine.services.host_access.read_secret(
        victor, "srv_payroll_app", "/etc/payroll/signer.env",
        sim_day=1, sim_tick=1,
    )
    assert grant is not None

    agents = engine.db.get_all_agents()
    action = SendMailAction(
        agent_id=victor.id, recipient_id="hr_emily",
        subject="Payroll reconciliation",
        body="Please approve the attached batch.",
        as_agent_id="fin_robert",
    )
    ok, *_ = engine.turn_mgr._execute_action(action, victor, 2, 1, agents)
    assert ok is True

    # The delivered message must carry fin_robert as the visible sender.
    msgs = engine.db.get_unread_messages("hr_emily")
    by_robert = [m for m in msgs if m.sender_id == "fin_robert"]
    assert len(by_robert) == 1

    # An IMPERSONATED_MAIL_SENT event must have been logged with the
    # true actor = victor.
    events = engine.db.get_events(event_type=EventType.IMPERSONATED_MAIL_SENT.value)
    assert len(events) >= 1
    assert events[-1].agent_id == "it_victor"
    assert events[-1].payload["effective_sender"] == "fin_robert"


# ---------------------------------------------------------------------------
# A1/A2 — Attack injector entry points
# ---------------------------------------------------------------------------

def _inject_templates(engine, names: list[str]):
    """Force-schedule the named templates on day 1 so tests are
    deterministic regardless of per-day probability.  Forces
    ``attacker_policy=scripted`` so the injector executes the
    insider-attack handlers directly — these tests are exercising
    the legacy scripted baseline.  LLM-mode opportunity-planting
    is covered separately in ``test_research_phase3.py``."""
    from aces.attacks import ScheduledAttack
    injector = AttackInjector(
        engine.cfg.attacks, engine.db, engine.services, random.Random(0))
    selected = [t for t in engine.cfg.attacks.templates if t.id in names]
    injector.config.templates = selected
    injector.config.attacker_policy = "scripted"
    agents = engine.db.get_all_agents()
    # Deterministically schedule one injection per template on day 1.
    injector._schedule.clear()
    for tmpl in selected:
        eligible = injector._eligible_targets(tmpl, agents)
        if not eligible:
            sentinel = injector._pick_sentinel_agent(tmpl, agents)
            if sentinel is None:
                continue
            eligible = [sentinel]
        injector._schedule.append(ScheduledAttack(
            template=tmpl, target_agent_id=eligible[0].id, sim_day=1,
        ))
    fired = []
    for day in range(1, 13):
        for inc in injector.inject(day, engine.db.get_all_agents()):
            fired.append((day, inc))
    return fired, injector


def test_group_mail_entry_point_delivers_to_group_members(engine):
    """release_runbook_poison targets grp_release; every member except
    the source should receive the poisoned message."""
    fired, _ = _inject_templates(engine, ["release_runbook_poison"])
    assert len(fired) >= 1, "group_mail attack never fired"

    grp = engine.db.get_group("grp_release")
    assert grp is not None
    expected_recipients = [m for m in grp.members if m != "it_victor"]

    # Each expected recipient should have received an attack-flagged
    # message from it_victor.
    for recipient in expected_recipients:
        msgs = [m for m in engine.db.get_unread_messages(recipient)
                if m.is_attack and m.sender_id == "it_victor"]
        assert msgs, f"{recipient} missed the poisoned runbook post"


def test_server_entry_point_reads_listed_secrets_and_gains_grant(engine):
    """payroll_server_secret_theft uses entry_point=server and lists
    two secret_paths; injection should read both and leave an active
    impersonation grant for fin_robert."""
    fired, _ = _inject_templates(engine, ["payroll_server_secret_theft"])
    assert len(fired) >= 1, "server-entry attack never fired"

    # SERVER_SECRET_READ events must have been logged.
    reads = engine.db.get_events(event_type=EventType.SERVER_SECRET_READ.value)
    assert len(reads) >= 2, (
        "server attack should read both secret paths")

    # The grant must be active.
    assert engine.services.impersonation.can_impersonate(
        actor_id="it_victor", victim_id="fin_robert",
        capability="transfer_tokens")


def test_token_transfer_entry_point_moves_money(engine):
    """fake_urgent_exec_transfer should create a real ledger entry."""
    # Pre-seed a grant so the token transfer can be impersonated if the
    # injector chooses that path.  The injector will try to use an
    # existing grant; otherwise it falls back to a source-owned
    # transfer.  Either way, a row must appear in token_transfers.
    fired, _ = _inject_templates(engine, ["fake_urgent_exec_transfer"])
    assert len(fired) >= 1
    row = engine.db.conn.execute(
        "SELECT COUNT(*) AS c FROM token_transfers",
    ).fetchone()
    assert row["c"] >= 1, "token_transfer attack left no ledger row"


# ---------------------------------------------------------------------------
# M2 — Daily metric snapshots
# ---------------------------------------------------------------------------

def test_daily_snapshot_includes_research_fields(engine):
    snap = engine.metrics_computer.snapshot("phase2-run", sim_day=1)
    assert snap.community_token_balance_excluding_attackers > 0
    # Default research config has it_victor as the only attacker.
    victor = engine.db.get_agent("it_victor")
    assert snap.attacker_token_balance == pytest.approx(victor.wallet_balance)
    # No activity yet; counters should be zero.
    assert snap.transfers_today == 0
    assert snap.group_posts_today == 0
    assert snap.secret_reads_today == 0


def test_snapshot_counts_daily_secret_reads(engine):
    victor = engine.db.get_agent("it_victor")
    engine.services.host_access.read_secret(
        victor, "srv_payroll_app", "/etc/payroll/signer.env",
        sim_day=3, sim_tick=1,
    )
    snap = engine.metrics_computer.snapshot("phase2-run", sim_day=3)
    assert snap.secret_reads_today == 1
    assert snap.active_impersonation_grants == 1


# ---------------------------------------------------------------------------
# D1 — unknown_sender_requires_verification
# ---------------------------------------------------------------------------

def test_unknown_sender_verification_blocks_non_neighbour_mail(db, cfg):
    cfg.defenses = DefenseOverrides(unknown_sender_requires_verification=True)
    # Drop grp_allhands so fin_robert and eng_kevin share no groups.
    cfg.enterprise.communication_groups = [
        g for g in cfg.enterprise.communication_groups if g.id != "grp_allhands"
    ]
    engine = SimulationEngine(
        cfg=cfg, db=db,
        runtime=StubRuntime(rng=random.Random(13)),
        run_id="d1-run", rng=random.Random(13),
    )
    engine.init_world()

    # fin_robert and eng_kevin do not share a group and are not
    # neighbours → unknown sender → blocked by the verification gate.
    robert = db.get_agent("fin_robert")
    msg = engine.services.mail.send(
        robert, "eng_kevin", "hello", "ping",
        sim_day=1, sim_tick=0,
    )
    assert msg is None


# ---------------------------------------------------------------------------
# D2 — CommunicationPolicy.can_direct_message
# ---------------------------------------------------------------------------

def test_direct_message_neighbours_allowed(engine):
    # eng_kevin and eng_julia are both direct reports of mgr_mike and
    # each has the other in known_agents.
    kevin = engine.db.get_agent("eng_kevin")
    msg = engine.services.mail.send(
        kevin, "eng_julia", "hey", "please review",
        sim_day=1, sim_tick=0,
    )
    assert msg is not None


def test_direct_message_strangers_blocked(engine):
    # design_oliver is NOT in eng_julia's known_agents / manager chain
    # and they share no group except grp_allhands (which includes
    # everyone — hence shared_group=True).  Pick a truly isolated pair:
    # design_oliver -> fin_robert.
    oliver = engine.db.get_agent("design_oliver")
    # design_oliver is in grp_allhands with fin_robert → shared_group
    # means delivery is allowed.  To really test the gate we have to
    # remove the all-hands overlap.
    engine.db.conn.execute(
        "DELETE FROM communication_group_members WHERE group_id=?",
        ("grp_allhands",))
    engine.db.conn.commit()
    msg = engine.services.mail.send(
        oliver, "fin_robert", "hi", "who dis",
        sim_day=1, sim_tick=0,
    )
    assert msg is None


# ---------------------------------------------------------------------------
# D4 — group moderation
# ---------------------------------------------------------------------------

def test_group_moderation_blocks_non_admin_posts(db, cfg):
    # Flip grp_eng to moderated and turn on the defense.
    for g in cfg.enterprise.communication_groups:
        if g.id == "grp_eng":
            g.posting_policy = "moderated"
    cfg.defenses = DefenseOverrides(group_moderation=True)
    engine = SimulationEngine(
        cfg=cfg, db=db,
        runtime=StubRuntime(rng=random.Random(14)),
        run_id="d4-run", rng=random.Random(14),
    )
    engine.init_world()
    kevin = db.get_agent("eng_kevin")
    result = engine.services.group_mail.send_group(
        kevin, "grp_eng", "update", "body")
    assert result is None

    # Admins on the same group should still be allowed through.
    amy = db.get_agent("exec_amy")
    result2 = engine.services.group_mail.send_group(
        amy, "grp_eng", "admin update", "body")
    assert result2 is not None and result2 > 0


# ---------------------------------------------------------------------------
# M1 — bounty and fine
# ---------------------------------------------------------------------------

def test_bounty_paid_on_correct_isolation(engine):
    david = engine.db.get_agent("sec_david")
    before = david.wallet_balance
    assert engine.defense_manager.isolate_agent(
        david, "it_victor", reason="confirmed insider",
        sim_day=1, sim_tick=0,
    )
    after = engine.db.get_agent("sec_david").wallet_balance
    assert after == pytest.approx(before + DefenseManager.BOUNTY_AMOUNT)
    # A BOUNTY ledger entry must exist.
    entries = [e for e in engine.db.get_ledger_for_day(1)
               if e.agent_id == "sec_david"
               and e.entry_type == LedgerEntryType.BOUNTY]
    assert len(entries) == 1


def test_fine_levied_on_false_positive_isolation(engine):
    david = engine.db.get_agent("sec_david")
    before = david.wallet_balance
    # eng_kevin is NOT malicious — isolating him is a false positive.
    assert engine.defense_manager.isolate_agent(
        david, "eng_kevin", reason="mistake", sim_day=1, sim_tick=0)
    after = engine.db.get_agent("sec_david").wallet_balance
    assert after == pytest.approx(before - DefenseManager.FINE_AMOUNT)
    entries = [e for e in engine.db.get_ledger_for_day(1)
               if e.agent_id == "sec_david"
               and e.entry_type == LedgerEntryType.FINE]
    assert len(entries) == 1
