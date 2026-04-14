"""Smoke tests: verify the full pipeline runs end-to-end.

Tests use StubRuntime (a minimal deterministic agent) so they run
without an LLM API key.  Production code uses LLMAgentRuntime or
OpenClawRuntime — both backed by real LLMs.
"""

from __future__ import annotations

import os
import random
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.stub_runtime import StubRuntime

from aces.config import (
    DefenseOverrides, FactorDef,
    load_config, apply_condition_overrides,
)
from aces.database import Database
from aces.models import (
    AgentRole, AgentState, AgentStatus, Event, EventType, Job,
    JobStatus, JobType, Zone,
)
from aces.network import AccessControl, ZoneTopology
from aces.experiment import (
    Condition, generate_full_factorial, generate_fractional_factorial,
    run_single,
)


class TestDatabase(unittest.TestCase):
    def setUp(self):
        self.db = Database(":memory:")

    def tearDown(self):
        self.db.close()

    def test_agent_crud(self):
        a = AgentState(id="a1", name="Test", role=AgentRole.ENGINEER,
                       zone=Zone.ENGNET, wallet_balance=100.0)
        self.db.insert_agent(a)
        got = self.db.get_agent("a1")
        self.assertIsNotNone(got)
        self.assertEqual(got.name, "Test")
        self.assertEqual(got.role, AgentRole.ENGINEER)
        got.wallet_balance = 200.0
        self.db.update_agent(got)
        got2 = self.db.get_agent("a1")
        self.assertAlmostEqual(got2.wallet_balance, 200.0)

    def test_job_claim(self):
        a = AgentState(id="a1", name="T", role=AgentRole.ENGINEER, zone=Zone.ENGNET)
        self.db.insert_agent(a)
        j = Job(id="j1", title="Test Job", job_type=JobType.DEBUGGING,
                zone=Zone.ENGNET, status=JobStatus.PENDING)
        self.db.insert_job(j)
        ok = self.db.claim_job("j1", "a1")
        self.assertTrue(ok)
        # Can't claim again.
        ok2 = self.db.claim_job("j1", "a1")
        self.assertFalse(ok2)

    def test_event_log(self):
        e = Event(event_type=EventType.DAY_START, sim_day=1, sim_tick=0,
                  payload={"day": 1})
        self.db.append_event(e)
        events = self.db.get_events(sim_day=1)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, EventType.DAY_START)


class TestNetwork(unittest.TestCase):
    def test_flat_allows_all(self):
        topo = ZoneTopology(segmentation="flat")
        self.assertTrue(topo.can_reach("engnet", "finnet").allowed)

    def test_strong_blocks_cross_zone(self):
        topo = ZoneTopology(segmentation="strong")
        self.assertFalse(topo.can_reach("engnet", "finnet").allowed)

    def test_strong_allows_via_corpnet(self):
        topo = ZoneTopology(segmentation="strong")
        self.assertTrue(topo.can_reach("engnet", "corpnet").allowed)
        self.assertTrue(topo.can_reach("corpnet", "finnet").allowed)

    def test_quarantined_blocked(self):
        topo = ZoneTopology(segmentation="flat")
        agent = AgentState(id="a1", name="T", role=AgentRole.ENGINEER,
                           zone=Zone.ENGNET, status=AgentStatus.QUARANTINED)
        self.assertFalse(topo.can_reach("engnet", "corpnet", agent).allowed)


class TestFactorial(unittest.TestCase):
    def test_full_factorial_2_factors(self):
        factors = [
            FactorDef(name="A", level0_label="a0", level1_label="a1"),
            FactorDef(name="B", level0_label="b0", level1_label="b1"),
        ]
        conds = generate_full_factorial(factors)
        self.assertEqual(len(conds), 4)

    def test_full_factorial_5_factors(self):
        factors = [FactorDef(name=f"F{i}") for i in range(5)]
        conds = generate_full_factorial(factors)
        self.assertEqual(len(conds), 32)

    def test_fractional_5_factors_res3(self):
        factors = [FactorDef(name=f"F{i}") for i in range(5)]
        conds = generate_fractional_factorial(factors, resolution=3)
        self.assertEqual(len(conds), 8)

    def test_condition_overrides(self):
        base = DefenseOverrides(segmentation="flat")
        factors = [FactorDef(
            name="seg",
            level1_overrides={"segmentation": "strong"},
        )]
        result = apply_condition_overrides(base, {"seg": 1}, factors)
        self.assertEqual(result.segmentation, "strong")


class TestSingleRun(unittest.TestCase):
    def test_baseline_run(self):
        """Run a minimal 3-day simulation with stub runtime."""
        cfg_dir = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "config")
        cfg = load_config(
            enterprise_path=os.path.join(cfg_dir, "enterprise.yaml"),
            experiment_path=os.path.join(cfg_dir, "experiment.yaml"),
            attack_path=os.path.join(cfg_dir, "attacks.yaml"),
        )
        cfg.experiment.days_per_run = 3

        stub = StubRuntime(rng=random.Random(42))
        with tempfile.TemporaryDirectory() as tmpdir:
            cond = Condition(name="test_baseline", factor_levels={})
            result = run_single(cfg, cond, seed=42, output_dir=tmpdir,
                                runtime_override=stub)

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["final_day"], 3)
        self.assertIn("metrics", result)
        m = result["metrics"]
        self.assertIn("jcr", m)
        self.assertIn("pwcl", m)
        self.assertIn("blast_radius", m)
        self.assertIn("csri", m)
        print(f"\n  Baseline 3-day run: JCR={m['jcr']:.3f} PWCL={m['pwcl']:.2f} "
              f"BR={m['blast_radius']:.3f} CSRI={m['csri']:.3f}")


class TestBugFixes(unittest.TestCase):
    """Regression tests for bugs found during audit."""

    def _make_cfg(self):
        cfg_dir = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "config")
        return load_config(
            enterprise_path=os.path.join(cfg_dir, "enterprise.yaml"),
            experiment_path=os.path.join(cfg_dir, "experiment.yaml"),
            attack_path=os.path.join(cfg_dir, "attacks.yaml"),
        )

    def test_payroll_persisted(self):
        """Verify salary credits actually reach agent wallet balances."""
        cfg = self._make_cfg()
        cfg.experiment.days_per_run = 2
        cfg.attacks.enabled_classes = []

        stub = StubRuntime(rng=random.Random(99))
        with tempfile.TemporaryDirectory() as tmpdir:
            cond = Condition(name="payroll_test", factor_levels={})
            result = run_single(cfg, cond, seed=99, output_dir=tmpdir,
                                runtime_override=stub)

            # Re-open the DB and check balances grew.
            from aces.database import Database
            db = Database(result["db_path"])
            for agent in db.get_all_agents():
                adef = next(a for a in cfg.enterprise.agents if a.id == agent.id)
                # After 2 days of salary, balance should exceed initial.
                self.assertGreater(
                    agent.wallet_balance,
                    adef.initial_balance,
                    f"agent {agent.id} balance {agent.wallet_balance} "
                    f"<= initial {adef.initial_balance} after 2 days payroll",
                )
            db.close()

    def test_quarantine_released_only_by_explicit_action(self):
        """Three-state model: quarantine persists until a security
        agent invokes ``release_agent`` — there is no auto-recovery
        timer.  This locks down the post-Track-A state machine where
        the defense manager never rehabilitates agents on its own."""
        from aces.database import Database
        from aces.config import DefenseOverrides
        from aces.defenses import DefenseManager
        from aces.services import ServiceRegistry
        import random

        db = Database(":memory:")
        victim = AgentState(id="a1", name="T", role=AgentRole.ENGINEER,
                             zone=Zone.ENGNET,
                             status=AgentStatus.QUARANTINED)
        sec = AgentState(id="sec1", name="S", role=AgentRole.SECURITY,
                          zone=Zone.SECNET)
        db.insert_agent(victim)
        db.insert_agent(sec)

        defenses = DefenseOverrides()
        cfg = self._make_cfg()
        acl = AccessControl.from_config(cfg.enterprise, defenses)
        svc = ServiceRegistry.build(db, acl, defenses)
        dm = DefenseManager(defenses, db, svc, random.Random(42))

        # Barrier runs many days — no state change without an explicit
        # action.
        for day in range(1, 30):
            dm.run(day, db.get_all_agents())
        self.assertEqual(
            db.get_agent("a1").status, AgentStatus.QUARANTINED,
            "quarantine must persist without an explicit release_agent call",
        )

        # Now an explicit release should flip the status back.
        ok = dm.release_agent(sec, "a1", reason="review cleared",
                                sim_day=30, sim_tick=0)
        self.assertTrue(ok)
        self.assertEqual(db.get_agent("a1").status, AgentStatus.HEALTHY)
        db.close()

    def test_attacks_before_turns(self):
        """Attacks inject before agent turns so agents see attack mail."""
        cfg = self._make_cfg()
        cfg.experiment.days_per_run = 5
        cfg.attacks.templates = [cfg.attacks.templates[0]]  # phishing only
        cfg.attacks.templates[0].earliest_day = 1
        cfg.attacks.templates[0].latest_day = 1
        cfg.attacks.templates[0].probability = 1.0

        stub = StubRuntime(rng=random.Random(42))
        with tempfile.TemporaryDirectory() as tmpdir:
            cond = Condition(name="timing_test", factor_levels={})
            result = run_single(cfg, cond, seed=42, output_dir=tmpdir,
                                runtime_override=stub)

            from aces.database import Database
            from aces.models import EventType
            db = Database(result["db_path"])
            # Attack should be injected on day 1.
            attacks = db.get_events(sim_day=1, event_type=EventType.ATTACK_INJECTED.value)
            self.assertGreater(len(attacks), 0, "no attack injected on day 1")
            # Agent turns should also happen on day 1 (after the attack).
            turns = db.get_events(sim_day=1, event_type=EventType.AGENT_TURN_START.value)
            self.assertGreater(len(turns), 0, "no agent turns on day 1")
            db.close()

    def test_cross_zone_job_visibility(self):
        """Managers in corpnet should see jobs in zones they can reach."""
        from aces.database import Database
        from aces.config import DefenseOverrides
        from aces.engine import TurnManager
        from aces.services import ServiceRegistry

        db = Database(":memory:")
        mgr = AgentState(id="mgr", name="Mgr", role=AgentRole.MANAGER,
                         zone=Zone.CORPNET)
        db.insert_agent(mgr)
        # Job in engnet.
        eng_job = Job(id="j_eng", title="EngNet Job", job_type=JobType.CODE_REVIEW,
                      zone=Zone.ENGNET, status=JobStatus.PENDING, created_day=1)
        db.insert_job(eng_job)

        cfg = self._make_cfg()
        defenses = DefenseOverrides(segmentation="flat")
        acl = AccessControl.from_config(cfg.enterprise, defenses)
        svc = ServiceRegistry.build(db, acl, defenses)
        rt = StubRuntime(rng=random.Random(42))
        tm = TurnManager(db, svc, rt, acl, defenses, random.Random(42))

        obs = tm._build_observation(mgr, sim_day=1, sim_tick=1)
        job_ids = [j.id for j in obs.available_jobs]
        self.assertIn("j_eng", job_ids,
                      "manager in corpnet cannot see engnet jobs under flat topology")
        db.close()


if __name__ == "__main__":
    unittest.main()
