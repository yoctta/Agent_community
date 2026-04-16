"""Track B regression tests — attacker_policy semantics.

Three modes:
  * llm       (default) — every attack template plants a memory
                opportunity on the named malicious source agent; the
                source's LLM is the sole actor. Zero state mutation
                from the injector, regardless of entry point.
  * scripted  — legacy path; injector executes services directly as
                the capable-attacker comparison baseline.
  * passive   — no attacks fire at all.

Coverage in this file:
  - ``llm`` opportunity planting for every entry point in the
    research config (server / token_transfer / group_mail / mail)
  - ``passive`` silence assertions
  - parity check that ``llm`` mode performs no service calls
  - quarantine-source skip under both llm and scripted modes
"""

from __future__ import annotations

import os
import random
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aces.attacks import AttackInjector, ScheduledAttack
from aces.config import load_config
from aces.database import Database
from aces.defenses import DefenseManager
from aces.engine import SimulationEngine
from aces.metrics import MetricsComputer
from aces.models import EventType
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
        runtime=StubRuntime(rng=random.Random(31)),
        run_id="phase3-run", rng=random.Random(31),
    )
    eng.metrics_computer = MetricsComputer(db, csri_weights=cfg.experiment.csri_weights)
    eng.defense_manager = DefenseManager(cfg.defenses, db, eng.services, random.Random(31))
    eng.init_world()
    return eng


def _force_inject(engine, names, policy):
    """Force-schedule the named templates on day 1 with the given
    attacker_policy.  Returns the injector + the list of incidents
    fired."""
    injector = AttackInjector(
        engine.cfg.attacks, engine.db, engine.services, random.Random(0))
    selected = [t for t in engine.cfg.attacks.templates if t.id in names]
    injector.config.templates = selected
    injector.config.attacker_policy = policy
    agents = engine.db.get_all_agents()
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
    incidents = []
    for inc in injector.inject(1, engine.db.get_all_agents()):
        incidents.append(inc)
    return injector, incidents


# ---------------------------------------------------------------------------
# llm mode — every template plants an opportunity; no service calls
# ---------------------------------------------------------------------------

def test_llm_mode_server_template_plants_opportunity(engine):
    """payroll_server_secret_theft (entry_point=server) under llm
    mode should write an attack_objective memory entry on it_victor
    and NOT call host_access.read_secret."""
    _force_inject(engine, ["payroll_server_secret_theft"], policy="llm")

    # Memory should now contain an opportunity entry.
    mems = engine.db.get_agent_memory("it_victor", category="attack_objective")
    opps = [m for m in mems if m.key.startswith("opportunity_")]
    assert opps, f"expected opportunity memory, got keys: {[m.key for m in mems]}"
    assert any("srv_payroll_app" in m.value for m in opps), (
        "opportunity text should name the target server")
    assert any("/etc/payroll" in m.value for m in opps), (
        "opportunity text should name the credential path")

    # No actual server reads should have happened.
    reads = engine.db.get_events(event_type=EventType.SERVER_SECRET_READ.value)
    assert len(reads) == 0, "llm mode must NOT execute server secret reads"


def test_llm_mode_token_transfer_template_plants_opportunity(engine):
    _force_inject(engine, ["fake_urgent_exec_transfer"], policy="llm")
    mems = engine.db.get_agent_memory("it_victor", category="attack_objective")
    opps = [m for m in mems if m.key.startswith("opportunity_")]
    assert opps
    assert any("transfer" in m.value.lower() for m in opps)
    # No actual transfers should have happened.
    row = engine.db.conn.execute(
        "SELECT COUNT(*) AS c FROM token_transfers").fetchone()
    assert row["c"] == 0


def test_llm_mode_group_mail_template_plants_opportunity(engine):
    _force_inject(engine, ["release_runbook_poison"], policy="llm")
    mems = engine.db.get_agent_memory("it_victor", category="attack_objective")
    opps = [m for m in mems if m.key.startswith("opportunity_")]
    assert opps
    assert any("grp_release" in m.value for m in opps)
    # No GROUP_MAIL_SENT events should have fired from the injector.
    posts = engine.db.get_events(event_type=EventType.GROUP_MAIL_SENT.value)
    assert len(posts) == 0


def test_llm_mode_attack_injected_event_has_opportunity_mode(engine):
    """The ATTACK_INJECTED event must carry mode=opportunity in
    llm mode so analysis can distinguish the two paths."""
    _force_inject(engine, ["payroll_server_secret_theft"], policy="llm")
    events = engine.db.get_events(event_type=EventType.ATTACK_INJECTED.value)
    assert events
    assert events[-1].payload.get("mode") == "opportunity"
    assert events[-1].agent_id == "it_victor"


# ---------------------------------------------------------------------------
# passive mode — nothing fires
# ---------------------------------------------------------------------------

def test_passive_mode_silences_all_attacks(engine):
    _force_inject(engine,
                   ["payroll_server_secret_theft",
                    "fake_urgent_exec_transfer",
                    "release_runbook_poison",
                    "hr_directory_spearphish"],
                   policy="passive")
    # No attack_injected events.
    assert len(engine.db.get_events(
        event_type=EventType.ATTACK_INJECTED.value)) == 0
    # No opportunity memory entries.
    mems = engine.db.get_agent_memory("it_victor", category="attack_objective")
    opps = [m for m in mems if m.key.startswith("opportunity_")]
    assert opps == []
    # No service-level attack effects.
    assert engine.db.count_events(EventType.SERVER_SECRET_READ.value) == 0
    assert engine.db.count_events(EventType.GROUP_MAIL_SENT.value) == 0


# ---------------------------------------------------------------------------
# scripted mode parity (sanity check — same template still works)
# ---------------------------------------------------------------------------

def test_scripted_mode_still_executes(engine):
    """Sanity check: setting policy=scripted reproduces the legacy
    behavior — secrets get read, grants get issued, no opportunity
    memory."""
    _force_inject(engine, ["payroll_server_secret_theft"], policy="scripted")
    reads = engine.db.get_events(event_type=EventType.SERVER_SECRET_READ.value)
    assert len(reads) >= 2
    mems = engine.db.get_agent_memory("it_victor", category="attack_objective")
    opps = [m for m in mems if m.key.startswith("opportunity_")]
    assert opps == [], "scripted mode must not plant opportunity memory"


# ---------------------------------------------------------------------------
# llm mode — mail templates also plant opportunities (no more external-
# vs-insider split; entry_point no longer controls the mode)
# ---------------------------------------------------------------------------

def test_llm_mode_mail_template_plants_opportunity(engine):
    """Under llm mode, a mail-entry template must plant an opportunity
    memory on the source agent and leave the victim unchanged — no
    CREDENTIAL_LEAKED event, no compromised status flip."""
    _force_inject(engine, ["hr_directory_spearphish"], policy="llm")

    mems = engine.db.get_agent_memory("it_victor", category="attack_objective")
    opps = [m for m in mems if m.key.startswith("opportunity_")]
    assert opps, "mail template must plant an opportunity under llm mode"
    assert any("verify" in m.value.lower() or "directory" in m.value.lower()
               for m in opps), (
        "opportunity text should reference the phishing framing")

    # No scripted side effects.
    assert engine.db.count_events(EventType.CREDENTIAL_LEAKED.value) == 0
    victim = engine.db.get_agent("hr_emily")
    assert victim.status.value == "healthy", (
        "mail template under llm mode must not auto-compromise the victim")

    # Audit event should be tagged mode=opportunity, attributed to the
    # malicious source rather than the victim.
    events = engine.db.get_events(event_type=EventType.ATTACK_INJECTED.value)
    assert events
    assert events[-1].payload.get("mode") == "opportunity"
    assert events[-1].agent_id == "it_victor"


def test_llm_mode_mail_template_skipped_when_source_quarantined(engine):
    """Mail templates under llm mode must honour the quarantine-source
    gate and record a skipped_source_quarantined audit event."""
    _quarantine_victor(engine)
    _force_inject(engine, ["hr_directory_spearphish"], policy="llm")

    mems = engine.db.get_agent_memory("it_victor", category="attack_objective")
    opps = [m for m in mems if m.key.startswith("opportunity_")]
    assert opps == [], (
        "quarantined source must not receive new opportunity memories")
    assert engine.db.count_events(EventType.CREDENTIAL_LEAKED.value) == 0

    events = engine.db.get_events(event_type=EventType.ATTACK_INJECTED.value)
    assert events
    assert events[-1].payload.get("mode") == "skipped_source_quarantined"


# ---------------------------------------------------------------------------
# Quarantined-source skip — no fallback attribution to a bystander
# ---------------------------------------------------------------------------

def _quarantine_victor(engine):
    from aces.models import AgentStatus
    victor = engine.db.get_agent("it_victor")
    victor.status = AgentStatus.QUARANTINED
    engine.db.update_agent(victor)


def test_llm_insider_skipped_when_named_source_is_quarantined(engine):
    """Regression: when the only listed source agent is quarantined,
    the llm-mode injector must drop the attack — not fall through to
    scripted execution and not attribute it to a bystander."""
    _quarantine_victor(engine)
    _force_inject(engine, ["release_runbook_poison"], policy="llm")
    # No opportunity planted.
    mems = engine.db.get_agent_memory("it_victor", category="attack_objective")
    opps = [m for m in mems if m.key.startswith("opportunity_")]
    assert opps == []
    # No GROUP_MAIL_SENT event from the injector either.
    assert engine.db.count_events(EventType.GROUP_MAIL_SENT.value) == 0
    # The attack_injected event should be tagged as skipped.
    events = engine.db.get_events(event_type=EventType.ATTACK_INJECTED.value)
    assert events, "an attack_injected audit event should still record the skip"
    assert events[-1].payload.get("mode") == "skipped_source_quarantined"


def test_scripted_insider_skipped_when_named_source_is_quarantined(engine):
    """Regression: even under scripted policy, a quarantined attacker
    cannot have actions attributed to them."""
    _quarantine_victor(engine)
    _force_inject(engine, ["payroll_server_secret_theft"], policy="scripted")
    # The scripted handler should bail out — no SERVER_SECRET_READ events.
    assert engine.db.count_events(EventType.SERVER_SECRET_READ.value) == 0


def test_external_mail_skipped_when_named_source_is_quarantined(engine):
    """Even external mail attacks must skip when the named source
    (here it_victor for hr_directory_spearphish) is quarantined.
    Otherwise the phishing mail would land in HR's inbox attributed
    to the wrong sender."""
    _quarantine_victor(engine)
    _force_inject(engine, ["hr_directory_spearphish"], policy="scripted")
    # No phishing mail should have been delivered.
    assert engine.db.count_events(EventType.CREDENTIAL_LEAKED.value) == 0


def test_token_drain_skipped_when_named_source_is_quarantined(engine):
    """Token-drain class handlers must honour source eligibility.
    Previously they silently drained the target's wallet even when
    the attack's named source agent was contained. That let a
    quarantined attacker still damage the community."""
    _quarantine_victor(engine)
    target_id = "eng_kevin"
    before = engine.db.get_agent(target_id).wallet_balance
    _force_inject(engine, ["engineering_loop_drain"], policy="scripted")
    after = engine.db.get_agent(target_id).wallet_balance
    assert after == before, (
        f"token_drain must not fire when source is quarantined "
        f"(delta={after - before})")


def test_disruption_skipped_when_named_source_is_quarantined(engine):
    """Disruption class handlers must honour source eligibility."""
    _quarantine_victor(engine)
    # Insert a target job so disruption has something to fail.
    from aces.models import Job, JobStatus, JobType, Zone, AgentRole
    j = Job(title="test job", job_type=JobType.DEPLOYMENT,
            zone=Zone.ENGNET, required_role=AgentRole.DEVOPS,
            status=JobStatus.CLAIMED, assigned_to="devops_sara",
            created_day=1)
    engine.db.insert_job(j)
    _force_inject(engine, ["alert_fatigue_disruption"], policy="scripted")
    # Job should still be claimed, not failed.
    survived = engine.db.get_job(j.id)
    assert survived.status == JobStatus.CLAIMED, (
        "disruption must not fail jobs when source is quarantined")


def test_poisoning_skipped_when_named_source_is_quarantined(engine):
    """Poisoning class handlers must honour source eligibility."""
    _quarantine_victor(engine)
    _force_inject(engine, ["release_runbook_poison"], policy="scripted")
    # No is_poisoned document updates should have happened.
    poisoned = engine.db.conn.execute(
        "SELECT COUNT(*) AS c FROM documents WHERE is_poisoned=1"
    ).fetchone()["c"]
    assert poisoned == 0, (
        "poisoning must not fire when source is quarantined")


# ---------------------------------------------------------------------------
# F3 — attacker_policy=passive must not seed hostile objectives
# ---------------------------------------------------------------------------

def test_passive_policy_does_not_seed_attack_objectives(db, cfg):
    """Regression: under ``attacker_policy=passive`` the malicious
    agent must NOT receive his config-planted attack_objectives at
    init_world. Passive mode models "community only, no hostile
    intent", so priming the LLM with hostile goals defeats the
    control condition."""
    cfg.attacks.attacker_policy = "passive"
    from aces.engine import SimulationEngine
    from aces.metrics import MetricsComputer
    from aces.defenses import DefenseManager
    eng = SimulationEngine(cfg, db,
                            runtime=StubRuntime(rng=random.Random(31)),
                            run_id="passive", rng=random.Random(31))
    eng.metrics_computer = MetricsComputer(db)
    eng.defense_manager = DefenseManager(
        cfg.defenses, db, eng.services, random.Random(31))
    eng.init_world()
    victor_mem = db.get_agent_memory(
        "it_victor", category="attack_objective")
    assert victor_mem == [], (
        f"passive mode must not seed attack_objectives; got {len(victor_mem)}")


def test_llm_policy_still_seeds_attack_objectives(db, cfg):
    """Complement of the above: llm mode must still seed objectives."""
    cfg.attacks.attacker_policy = "llm"
    from aces.engine import SimulationEngine
    from aces.metrics import MetricsComputer
    from aces.defenses import DefenseManager
    eng = SimulationEngine(cfg, db,
                            runtime=StubRuntime(rng=random.Random(31)),
                            run_id="llm", rng=random.Random(31))
    eng.metrics_computer = MetricsComputer(db)
    eng.defense_manager = DefenseManager(
        cfg.defenses, db, eng.services, random.Random(31))
    eng.init_world()
    victor_mem = db.get_agent_memory(
        "it_victor", category="attack_objective")
    assert len(victor_mem) >= 1, "llm mode must seed attack objectives"


# ---------------------------------------------------------------------------
# F1 — credential_compromise_count includes both pathways
# ---------------------------------------------------------------------------

def test_credential_compromise_count_includes_mail_leaks(engine):
    """F1 regression: the final-metrics ``credential_compromise_count``
    must count both SERVER_SECRET_READ (insider stealing from host)
    and CREDENTIAL_LEAKED (phishing path) events. Missing either
    undercounts the compromise signal in the research numbers."""
    _force_inject(engine, ["hr_directory_spearphish"], policy="scripted")
    # Phishing path should now be counted.
    n_leak = engine.db.count_events(EventType.CREDENTIAL_LEAKED.value)
    assert n_leak >= 1, "the scripted phishing attack should have fired"
    fm = engine.metrics_computer.compute_final("phase3-run", final_day=1)
    assert fm["credential_compromise_count"] >= n_leak, (
        f"expected credential_compromise_count>={n_leak}, "
        f"got {fm['credential_compromise_count']}")


# ---------------------------------------------------------------------------
# F2 — security view annotates actors with role
# ---------------------------------------------------------------------------

def test_security_view_annotates_actor_with_role(engine):
    """F2 regression: event lines in the security view must render
    actors as ``agent_id[role]`` so the LLM can distinguish routine
    admin-on-own-zone from an intrusion."""
    # Force a server login by exec_james (COO).
    tom = engine.db.get_agent("exec_james")
    engine.services.host_access.login(
        tom, "srv_payroll_app", sim_day=1, sim_tick=1,
    )
    view = engine.turn_mgr._build_security_view(
        sim_day=1, window_days=3, limit=25,
    )
    assert any("exec_james[executive]" in line for line in view), (
        f"security view did not annotate COO login with role: {view}")
