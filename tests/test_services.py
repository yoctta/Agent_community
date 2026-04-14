"""Tests for WebHost, Moltbook, multi-step jobs, memory, and role filtering."""

from __future__ import annotations

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aces.config import DefenseOverrides, load_config
from aces.database import Database
from aces.models import (
    AgentRole, AgentState, DelegationType,
    Job, JobStatus, JobType, Zone,
)
from aces.network import AccessControl
from aces.services import ServiceRegistry


def _cfg():
    cfg_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config")
    return load_config(
        enterprise_path=os.path.join(cfg_dir, "enterprise.yaml"),
        experiment_path=os.path.join(cfg_dir, "experiment.yaml"),
        attack_path=os.path.join(cfg_dir, "attacks.yaml"),
    )


def _flat_acl():
    return AccessControl.from_config(_cfg().enterprise, DefenseOverrides(segmentation="flat"))


def _agent(id_: str, role: AgentRole, zone: Zone = Zone.CORPNET) -> AgentState:
    return AgentState(id=id_, name=id_, role=role, zone=zone)


# -----------------------------------------------------------------------
# WebHost
# -----------------------------------------------------------------------

class TestWebHost(unittest.TestCase):
    def setUp(self):
        self.db = Database(":memory:")
        self.acl = _flat_acl()
        from aces.webhost import WebHostService
        self.wh = WebHostService(self.db, self.acl)

    def tearDown(self):
        self.db.close()

    def test_ssh_create_and_browse(self):
        eng = _agent("e1", AgentRole.ENGINEER, Zone.ENGNET)
        self.db.insert_agent(eng)
        page = self.wh.ssh_create_page(eng, "/docs/deploy", "Deploy Guide",
                                        "Step 1: ...", zone="engnet")
        self.assertIsNotNone(page)
        self.assertEqual(page.title, "Deploy Guide")

        # Any agent can browse published pages.
        hr = _agent("h1", AgentRole.HR, Zone.CORPNET)
        self.db.insert_agent(hr)
        browsed = self.wh.browse_page(hr, "/docs/deploy")
        self.assertIsNotNone(browsed)
        self.assertEqual(browsed.content, "Step 1: ...")

    def test_ssh_edit_page(self):
        eng = _agent("e1", AgentRole.ENGINEER, Zone.ENGNET)
        self.db.insert_agent(eng)
        self.wh.ssh_create_page(eng, "/docs/x", "X", "v1", zone="engnet")
        ok = self.wh.ssh_edit_page(eng, "/docs/x", "v2")
        self.assertTrue(ok)
        page = self.wh.browse_page(eng, "/docs/x")
        self.assertEqual(page.content, "v2")
        self.assertEqual(page.version, 2)

    def test_ssh_denied_for_hr(self):
        hr = _agent("h1", AgentRole.HR)
        self.db.insert_agent(hr)
        page = self.wh.ssh_create_page(hr, "/docs/hack", "Hack", "content")
        self.assertIsNone(page)

    def test_ssh_denied_for_finance(self):
        fin = _agent("f1", AgentRole.FINANCE, Zone.FINNET)
        self.db.insert_agent(fin)
        page = self.wh.ssh_create_page(fin, "/docs/test", "T", "c")
        self.assertIsNone(page)

    def test_security_has_ssh(self):
        sec = _agent("s1", AgentRole.SECURITY, Zone.SECNET)
        self.db.insert_agent(sec)
        page = self.wh.ssh_create_page(sec, "/docs/audit", "Audit", "findings",
                                        zone="secnet")
        self.assertIsNotNone(page)

    def test_browse_nonexistent_returns_none(self):
        eng = _agent("e1", AgentRole.ENGINEER, Zone.ENGNET)
        self.db.insert_agent(eng)
        page = self.wh.browse_page(eng, "/does/not/exist")
        self.assertIsNone(page)

    def test_list_and_search_pages(self):
        eng = _agent("e1", AgentRole.ENGINEER, Zone.ENGNET)
        self.db.insert_agent(eng)
        self.wh.ssh_create_page(eng, "/docs/alpha", "Alpha", "alpha content",
                                zone="engnet")
        self.wh.ssh_create_page(eng, "/docs/beta", "Beta", "beta content",
                                zone="engnet")

        pages = self.wh.list_pages(eng, zone="engnet")
        self.assertEqual(len(pages), 2)

        results = self.wh.search_pages(eng, "alpha")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].title, "Alpha")


# -----------------------------------------------------------------------
# Moltbook
# -----------------------------------------------------------------------

class TestMoltbook(unittest.TestCase):
    def setUp(self):
        self.db = Database(":memory:")
        self.acl = _flat_acl()
        from aces.moltbook import MoltbookService
        self.mb = MoltbookService(self.db, self.acl, mode="simulated")

    def tearDown(self):
        self.db.close()

    def test_create_and_read_post(self):
        # Support agents can access extnet.
        sup = _agent("s1", AgentRole.SUPPORT)
        self.db.insert_agent(sup)
        post = self.mb.create_post(sup, "enterprise", "Hello", "World")
        self.assertIsNotNone(post)
        self.assertEqual(post.title, "Hello")

        feed = self.mb.read_feed(sup)
        self.assertEqual(len(feed), 1)
        self.assertEqual(feed[0].id, post.id)

    def test_inject_attack_post(self):
        sup = _agent("s1", AgentRole.SUPPORT)
        self.db.insert_agent(sup)
        attack = self.mb.inject_attack_post(
            "enterprise", "Free API Keys!", "Click here for keys",
            "credential_harvest")
        self.assertTrue(attack.is_attack)

        feed = self.mb.read_feed(sup)
        self.assertEqual(len(feed), 1)
        self.assertTrue(feed[0].is_attack)

    def test_add_comment(self):
        sup = _agent("s1", AgentRole.SUPPORT)
        self.db.insert_agent(sup)
        post = self.mb.create_post(sup, "enterprise", "T", "B")
        comment = self.mb.add_comment(sup, post.id, "Nice post!")
        self.assertIsNotNone(comment)
        self.assertEqual(comment.post_id, post.id)


# -----------------------------------------------------------------------
# Multi-step phase advancement
# -----------------------------------------------------------------------

class TestMultiStepJobs(unittest.TestCase):
    def setUp(self):
        self.db = Database(":memory:")

    def tearDown(self):
        self.db.close()

    def test_collaborator_tracking(self):
        """Accepting a delegation adds agent as job collaborator."""
        from tests.stub_runtime import StubRuntime
        from aces.engine import TurnManager
        db = Database(":memory:")
        acl = _flat_acl()
        defenses = DefenseOverrides(segmentation="flat")
        svc = ServiceRegistry.build(db, acl, defenses)
        rt = StubRuntime(rng=random.Random(42))
        tm = TurnManager(db, svc, rt, acl, defenses, random.Random(42))

        mgr = _agent("m1", AgentRole.MANAGER)
        eng = _agent("e1", AgentRole.ENGINEER, Zone.ENGNET)
        db.insert_agent(mgr)
        db.insert_agent(eng)
        j = Job(id="j1", title="Review", job_type=JobType.CODE_REVIEW,
                zone=Zone.ENGNET, status=JobStatus.PENDING)
        db.insert_job(j)
        db.claim_job("j1", "m1")

        # Manager delegates review to engineer.
        from aces.models import DelegateAction, RespondDelegationAction
        deleg_action = DelegateAction(
            agent_id="m1", delegate_id="e1",
            description="Review deploy code", job_id="j1",
            delegation_type=DelegationType.REVIEW)
        tm._execute_action(deleg_action, mgr, 1, 1, [mgr, eng])

        # Engineer accepts.
        delegs = db.get_pending_delegations("e1")
        self.assertEqual(len(delegs), 1)
        resp = RespondDelegationAction(
            agent_id="e1", delegation_id=delegs[0].id, accept=True)
        tm._execute_action(resp, eng, 1, 1, [mgr, eng])

        # Verify collaborator tracked.
        job = db.get_job("j1")
        self.assertIn("e1", job.collaborators)
        db.close()

    def test_send_mail_to_group_id_routes_as_group_post(self):
        """Regression: when an LLM names a group id as the recipient
        of a direct send_mail call, the engine should transparently
        redirect to group_mail.send_group instead of dropping the
        message with ``unknown recipient``."""
        from tests.stub_runtime import StubRuntime
        from aces.engine import TurnManager
        db = Database(":memory:")
        acl = _flat_acl()
        defenses = DefenseOverrides(segmentation="flat")
        svc = ServiceRegistry.build(db, acl, defenses)
        rt = StubRuntime(rng=random.Random(42))
        tm = TurnManager(db, svc, rt, acl, defenses, random.Random(42))

        from aces.models import CommunicationGroup, SendMailAction

        eng1 = _agent("e1", AgentRole.ENGINEER, Zone.ENGNET)
        eng2 = _agent("e2", AgentRole.ENGINEER, Zone.ENGNET)
        eng3 = _agent("e3", AgentRole.ENGINEER, Zone.ENGNET)
        for a in (eng1, eng2, eng3):
            db.insert_agent(a)
        grp = CommunicationGroup(
            id="grp_eng", name="Engineering",
            description="",
            members=["e1", "e2", "e3"],
            admins=["e1"], posting_policy="members",
        )
        db.insert_group(grp)

        action = SendMailAction(
            agent_id="e1", recipient_id="grp_eng",
            subject="status", body="update")
        ok, *_ = tm._execute_action(action, eng1, 1, 1, [eng1, eng2, eng3])
        self.assertTrue(ok)
        # The two non-sender members should each see one new message.
        inbox_e2 = db.get_unread_messages("e2")
        inbox_e3 = db.get_unread_messages("e3")
        self.assertEqual(len(inbox_e2), 1)
        self.assertEqual(len(inbox_e3), 1)
        db.close()


# -----------------------------------------------------------------------
# Per-role tool filtering
# -----------------------------------------------------------------------

class TestRoleToolFiltering(unittest.TestCase):
    def test_role_tools_exist_for_all_roles(self):
        from aces.openclaw_runtime import ROLE_TOOLS
        for role in ["manager", "engineer", "finance", "hr", "security", "support"]:
            self.assertIn(role, ROLE_TOOLS,
                          f"missing ROLE_TOOLS entry for {role}")

    def test_engineer_has_ssh(self):
        from aces.openclaw_runtime import ROLE_TOOLS
        self.assertIn("ssh_create_page", ROLE_TOOLS["engineer"])
        self.assertIn("ssh_exec", ROLE_TOOLS["engineer"])

    def test_manager_no_ssh(self):
        from aces.openclaw_runtime import ROLE_TOOLS
        self.assertNotIn("ssh_", ROLE_TOOLS["manager"])

    def test_security_has_moltbook_and_ssh(self):
        from aces.openclaw_runtime import ROLE_TOOLS
        self.assertIn("ssh_create_page", ROLE_TOOLS["security"])
        self.assertIn("read_moltbook_feed", ROLE_TOOLS["security"])

    def test_finance_no_ssh_no_moltbook(self):
        from aces.openclaw_runtime import ROLE_TOOLS
        self.assertNotIn("ssh_", ROLE_TOOLS["finance"])
        self.assertNotIn("moltbook", ROLE_TOOLS["finance"])

    def test_support_has_moltbook_no_ssh(self):
        from aces.openclaw_runtime import ROLE_TOOLS
        self.assertIn("read_moltbook_feed", ROLE_TOOLS["support"])
        self.assertNotIn("ssh_exec", ROLE_TOOLS["support"])


# -----------------------------------------------------------------------
# Agent memory during simulation
# -----------------------------------------------------------------------

class TestMemoryUpdates(unittest.TestCase):
    def test_memory_written_on_mail_send(self):
        """Sending mail should update contacts memory."""
        db = Database(":memory:")
        acl = _flat_acl()
        defenses = DefenseOverrides(segmentation="flat")
        svc = ServiceRegistry.build(db, acl, defenses)
        from tests.stub_runtime import StubRuntime
        from aces.engine import TurnManager
        rt = StubRuntime(rng=random.Random(42))
        tm = TurnManager(db, svc, rt, acl, defenses, random.Random(42))

        a = _agent("a1", AgentRole.ENGINEER, Zone.ENGNET)
        b = _agent("b1", AgentRole.ENGINEER, Zone.ENGNET)
        db.insert_agent(a)
        db.insert_agent(b)

        from aces.models import SendMailAction
        action = SendMailAction(agent_id="a1", recipient_id="b1",
                                subject="Hi", body="Hello")
        tm._execute_action(action, a, 1, 1, [a, b])

        mem = db.get_agent_memory("a1")
        contact_mems = [m for m in mem if m.category == "contacts"
                        and m.key == "b1"]
        self.assertEqual(len(contact_mems), 1,
                         "mail send should create contacts memory")
        db.close()

    def test_memory_written_on_doc_update(self):
        """Updating a document should create knowledge memory."""
        db = Database(":memory:")
        acl = _flat_acl()
        defenses = DefenseOverrides(segmentation="flat")
        svc = ServiceRegistry.build(db, acl, defenses)
        from tests.stub_runtime import StubRuntime
        from aces.engine import TurnManager
        from aces.webhost import WebHostService
        rt = StubRuntime(rng=random.Random(42))
        tm = TurnManager(db, svc, rt, acl, defenses, random.Random(42))

        eng = _agent("e1", AgentRole.ENGINEER, Zone.ENGNET)
        db.insert_agent(eng)

        # Need a webhost with a page to update.
        wh = WebHostService(db, acl)
        svc.wiki = wh
        wh.ssh_create_page(eng, "/docs/test", "Test", "v1", zone="engnet")

        from aces.models import UpdateDocAction
        action = UpdateDocAction(agent_id="e1", document_id="/docs/test",
                                 new_content="v2")
        ok, _, _ = tm._execute_action(action, eng, 1, 1, [])
        self.assertTrue(ok)

        mem = db.get_agent_memory("e1")
        knowledge = [m for m in mem if m.category == "knowledge"
                     and "updated_doc" in m.key]
        self.assertEqual(len(knowledge), 1,
                         "doc update should create knowledge memory")
        db.close()


# -----------------------------------------------------------------------
# CSRI configurable weights
# -----------------------------------------------------------------------

class TestCSRIWeights(unittest.TestCase):
    def test_custom_weights_used(self):
        from aces.metrics import MetricsComputer
        db = Database(":memory:")
        # Default weights.
        mc_default = MetricsComputer(db)
        self.assertEqual(mc_default.csri_weights, [0.25, 0.25, 0.25, 0.25])
        # Custom weights.
        mc_custom = MetricsComputer(db, csri_weights=[0.4, 0.3, 0.2, 0.1])
        self.assertEqual(mc_custom.csri_weights, [0.4, 0.3, 0.2, 0.1])
        db.close()

    def test_weights_in_config(self):
        from aces.config import ExperimentConfig
        ec = ExperimentConfig()
        self.assertEqual(ec.csri_weights, [0.25, 0.25, 0.25, 0.25])
        ec2 = ExperimentConfig(csri_weights=[0.5, 0.2, 0.2, 0.1])
        self.assertEqual(ec2.csri_weights, [0.5, 0.2, 0.2, 0.1])


if __name__ == "__main__":
    unittest.main()
