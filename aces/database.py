"""SQLite persistence layer for ACES."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .models import (
    AgentState, AgentStatus, AgentRole, AttackClass, CommunicationGroup,
    Credential, Delegation, DelegationStatus, DelegationType, Document,
    Event, EventType, ImpersonationGrant, Incident, IncidentSeverity, Job,
    JobStatus, JobType, LedgerEntry, LedgerEntryType, MemoryEntry, Message,
    MessageType, MetricSnapshot, RunRecord, ServerHost, ServerSecretPlacement,
    TokenTransfer, Zone, _now,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    zone TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'healthy',
    wallet_balance REAL NOT NULL DEFAULT 0.0,
    tokens_used INTEGER NOT NULL DEFAULT 0,
    tools_used INTEGER NOT NULL DEFAULT 0,
    jobs_completed INTEGER NOT NULL DEFAULT 0,
    jobs_failed INTEGER NOT NULL DEFAULT 0,
    title TEXT,
    manager_id TEXT,
    directory_scope TEXT NOT NULL DEFAULT 'neighbors',
    is_malicious INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(id),
    key_name TEXT NOT NULL,
    key_value TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'global',
    privilege_weight REAL NOT NULL DEFAULT 1.0,
    created_at TEXT NOT NULL,
    rotated_at TEXT,
    revoked_at TEXT,
    is_active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    job_type TEXT NOT NULL,
    zone TEXT NOT NULL,
    required_role TEXT,
    priority INTEGER NOT NULL DEFAULT 0,
    reward REAL NOT NULL DEFAULT 10.0,
    penalty REAL NOT NULL DEFAULT 5.0,
    deadline_day INTEGER,
    status TEXT NOT NULL DEFAULT 'pending',
    assigned_to TEXT REFERENCES agents(id),
    created_day INTEGER NOT NULL DEFAULT 0,
    claimed_at TEXT,
    completed_at TEXT,
    requires_approval INTEGER NOT NULL DEFAULT 0,
    approved_by TEXT,
    collaborators TEXT
);

CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    sender_id TEXT NOT NULL,
    recipient_id TEXT NOT NULL,
    subject TEXT,
    body TEXT NOT NULL,
    message_type TEXT NOT NULL DEFAULT 'mail',
    zone TEXT NOT NULL DEFAULT 'corpnet',
    is_attack INTEGER NOT NULL DEFAULT 0,
    attack_class TEXT,
    attack_payload TEXT,
    delivered_at TEXT NOT NULL,
    read_at TEXT
);

CREATE TABLE IF NOT EXISTS delegations (
    id TEXT PRIMARY KEY,
    requester_id TEXT NOT NULL REFERENCES agents(id),
    delegate_id TEXT NOT NULL REFERENCES agents(id),
    job_id TEXT REFERENCES jobs(id),
    delegation_type TEXT NOT NULL DEFAULT 'task',
    description TEXT,
    payload TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    requires_clarification INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    responded_at TEXT
);

CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    zone TEXT NOT NULL DEFAULT 'corpnet',
    author_id TEXT NOT NULL REFERENCES agents(id),
    version INTEGER NOT NULL DEFAULT 1,
    is_poisoned INTEGER NOT NULL DEFAULT 0,
    poison_payload TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ledger (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(id),
    entry_type TEXT NOT NULL,
    amount REAL NOT NULL,
    description TEXT,
    sim_day INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    agent_id TEXT,
    sim_day INTEGER NOT NULL,
    sim_tick INTEGER NOT NULL,
    zone TEXT,
    payload TEXT,
    causal_id TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    incident_type TEXT NOT NULL,
    attack_class TEXT,
    source_agent_id TEXT,
    target_agent_id TEXT,
    severity TEXT NOT NULL DEFAULT 'low',
    privilege_weight REAL NOT NULL DEFAULT 1.0,
    sim_day_detected INTEGER,
    sim_day_resolved INTEGER,
    details TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS metric_snapshots (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    sim_day INTEGER NOT NULL,
    pwcl REAL DEFAULT 0,
    jcr REAL DEFAULT 0,
    twr REAL DEFAULT 0,
    blast_radius REAL DEFAULT 0,
    agents_healthy INTEGER DEFAULT 0,
    agents_compromised INTEGER DEFAULT 0,
    agents_quarantined INTEGER DEFAULT 0,
    total_tokens_used INTEGER DEFAULT 0,
    total_salary_paid REAL DEFAULT 0,
    total_penalties REAL DEFAULT 0,
    total_rewards REAL DEFAULT 0,
    jobs_completed INTEGER DEFAULT 0,
    jobs_failed INTEGER DEFAULT 0,
    jobs_pending INTEGER DEFAULT 0,
    community_token_balance_excluding_attackers REAL DEFAULT 0,
    attacker_token_balance REAL DEFAULT 0,
    active_impersonation_grants INTEGER DEFAULT 0,
    transfers_today INTEGER DEFAULT 0,
    group_posts_today INTEGER DEFAULT 0,
    secret_reads_today INTEGER DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    experiment_id TEXT NOT NULL,
    condition_name TEXT NOT NULL,
    seed INTEGER NOT NULL,
    config_snapshot TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    started_at TEXT,
    completed_at TEXT,
    final_day INTEGER DEFAULT 0,
    final_metrics TEXT
);

CREATE TABLE IF NOT EXISTS agent_memory (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(id),
    category TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    sim_day_created INTEGER NOT NULL DEFAULT 0,
    sim_day_updated INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS communication_groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    posting_policy TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS communication_group_members (
    group_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (group_id, agent_id)
);

CREATE TABLE IF NOT EXISTS token_transfers (
    id TEXT PRIMARY KEY,
    actor_agent_id TEXT NOT NULL,
    effective_sender_id TEXT NOT NULL,
    recipient_id TEXT NOT NULL,
    amount REAL NOT NULL,
    note TEXT,
    sim_day INTEGER NOT NULL,
    sim_tick INTEGER NOT NULL,
    via_impersonation INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS server_hosts (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    zone TEXT NOT NULL,
    tags TEXT,
    login_roles TEXT,
    admin_roles TEXT,
    description TEXT,
    extra_monitoring INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS server_secrets (
    id TEXT PRIMARY KEY,
    server_id TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    path TEXT NOT NULL,
    exposure_level TEXT NOT NULL,
    owner_agent_id TEXT NOT NULL,
    usable_as_agent_id TEXT,
    privilege_weight REAL NOT NULL DEFAULT 1.0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS impersonation_grants (
    id TEXT PRIMARY KEY,
    actor_agent_id TEXT NOT NULL,
    victim_agent_id TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    source_server_id TEXT,
    can_send_mail INTEGER NOT NULL DEFAULT 1,
    can_transfer_tokens INTEGER NOT NULL DEFAULT 1,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_memory_agent ON agent_memory(agent_id);
CREATE INDEX IF NOT EXISTS idx_memory_cat ON agent_memory(agent_id, category);
CREATE INDEX IF NOT EXISTS idx_events_day ON events(sim_day);
CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_zone ON jobs(zone);
CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id);
CREATE INDEX IF NOT EXISTS idx_ledger_agent_day ON ledger(agent_id, sim_day);
CREATE INDEX IF NOT EXISTS idx_incidents_day ON incidents(sim_day_detected);
CREATE INDEX IF NOT EXISTS idx_metrics_run ON metric_snapshots(run_id, sim_day);
CREATE INDEX IF NOT EXISTS idx_group_member_agent ON communication_group_members(agent_id);
CREATE INDEX IF NOT EXISTS idx_transfer_recipient_day ON token_transfers(recipient_id, sim_day);
CREATE INDEX IF NOT EXISTS idx_transfer_sender_day ON token_transfers(effective_sender_id, sim_day);
CREATE INDEX IF NOT EXISTS idx_server_zone ON server_hosts(zone);
CREATE INDEX IF NOT EXISTS idx_server_secrets_server ON server_secrets(server_id);
CREATE INDEX IF NOT EXISTS idx_impersonation_actor ON impersonation_grants(actor_agent_id, is_active);
CREATE INDEX IF NOT EXISTS idx_impersonation_victim ON impersonation_grants(victim_agent_id, is_active);
"""


class Database:
    """SQLite-backed persistence for one simulation run."""

    def __init__(self, path: str | Path = ":memory:"):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # -- helpers --

    def _json(self, obj: Any) -> str | None:
        if obj is None:
            return None
        return json.dumps(obj)

    def _from_json(self, s: str | None) -> Any:
        if s is None:
            return None
        return json.loads(s)

    # -----------------------------------------------------------------------
    # Agents
    # -----------------------------------------------------------------------

    def insert_agent(self, a: AgentState) -> None:
        self.conn.execute(
            "INSERT INTO agents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (a.id, a.name, a.role.value, a.zone.value, a.status.value,
             a.wallet_balance, a.tokens_used, a.tools_used,
             a.jobs_completed, a.jobs_failed,
             a.title, a.manager_id, a.directory_scope, int(a.is_malicious),
             a.created_at, a.updated_at),
        )
        self.conn.commit()

    def get_agent(self, agent_id: str) -> AgentState | None:
        row = self.conn.execute(
            "SELECT * FROM agents WHERE id=?", (agent_id,)
        ).fetchone()
        if row is None:
            return None
        keys = row.keys()
        return AgentState(
            id=row["id"], name=row["name"],
            role=AgentRole(row["role"]), zone=Zone(row["zone"]),
            status=AgentStatus(row["status"]),
            wallet_balance=row["wallet_balance"],
            tokens_used=row["tokens_used"], tools_used=row["tools_used"],
            jobs_completed=row["jobs_completed"], jobs_failed=row["jobs_failed"],
            title=row["title"] if "title" in keys and row["title"] is not None else "",
            manager_id=row["manager_id"] if "manager_id" in keys else None,
            directory_scope=row["directory_scope"] if "directory_scope" in keys and row["directory_scope"] else "neighbors",
            is_malicious=bool(row["is_malicious"]) if "is_malicious" in keys else False,
            created_at=row["created_at"], updated_at=row["updated_at"],
        )

    def get_all_agents(self) -> list[AgentState]:
        rows = self.conn.execute("SELECT id FROM agents").fetchall()
        return [self.get_agent(r["id"]) for r in rows]  # type: ignore[misc]

    def update_agent(self, a: AgentState) -> None:
        a.updated_at = _now()
        self.conn.execute(
            """UPDATE agents SET name=?, role=?, zone=?, status=?,
               wallet_balance=?, tokens_used=?, tools_used=?,
               jobs_completed=?, jobs_failed=?,
               title=?, manager_id=?, directory_scope=?, is_malicious=?,
               updated_at=? WHERE id=?""",
            (a.name, a.role.value, a.zone.value, a.status.value,
             a.wallet_balance, a.tokens_used, a.tools_used,
             a.jobs_completed, a.jobs_failed,
             a.title, a.manager_id, a.directory_scope, int(a.is_malicious),
             a.updated_at, a.id),
        )
        self.conn.commit()

    # -----------------------------------------------------------------------
    # Credentials
    # -----------------------------------------------------------------------

    def insert_credential(self, c: Credential) -> None:
        self.conn.execute(
            "INSERT INTO credentials VALUES (?,?,?,?,?,?,?,?,?,?)",
            (c.id, c.agent_id, c.key_name, c.key_value, c.scope,
             c.privilege_weight, c.created_at, c.rotated_at, c.revoked_at,
             int(c.is_active)),
        )
        self.conn.commit()

    def get_agent_credentials(self, agent_id: str, active_only: bool = True) -> list[Credential]:
        q = "SELECT * FROM credentials WHERE agent_id=?"
        if active_only:
            q += " AND is_active=1"
        rows = self.conn.execute(q, (agent_id,)).fetchall()
        return [Credential(
            id=r["id"], agent_id=r["agent_id"], key_name=r["key_name"],
            key_value=r["key_value"], scope=r["scope"],
            privilege_weight=r["privilege_weight"],
            created_at=r["created_at"], rotated_at=r["rotated_at"],
            revoked_at=r["revoked_at"], is_active=bool(r["is_active"]),
        ) for r in rows]

    def revoke_credential(self, cred_id: str) -> None:
        self.conn.execute(
            "UPDATE credentials SET is_active=0, revoked_at=? WHERE id=?",
            (_now(), cred_id),
        )
        self.conn.commit()

    def rotate_credential(self, cred_id: str, new_value: str) -> None:
        self.conn.execute(
            "UPDATE credentials SET key_value=?, rotated_at=? WHERE id=?",
            (new_value, _now(), cred_id),
        )
        self.conn.commit()

    # -----------------------------------------------------------------------
    # Jobs
    # -----------------------------------------------------------------------

    def insert_job(self, j: Job) -> None:
        self.conn.execute(
            "INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (j.id, j.title, j.description, j.job_type.value, j.zone.value,
             j.required_role.value if j.required_role else None,
             j.priority, j.reward, j.penalty, j.deadline_day,
             j.status.value, j.assigned_to, j.created_day,
             j.claimed_at, j.completed_at,
             int(j.requires_approval), j.approved_by,
             self._json(j.collaborators) if j.collaborators else None),
        )
        self.conn.commit()

    def get_pending_jobs(self, zone: str | None = None,
                         role: str | None = None) -> list[Job]:
        q = "SELECT * FROM jobs WHERE status='pending'"
        params: list[Any] = []
        if zone:
            q += " AND zone=?"
            params.append(zone)
        if role:
            q += " AND (required_role IS NULL OR required_role=?)"
            params.append(role)
        q += " ORDER BY priority DESC"
        return [self._row_to_job(r) for r in self.conn.execute(q, params).fetchall()]

    def get_agent_jobs(self, agent_id: str) -> list[Job]:
        rows = self.conn.execute(
            "SELECT * FROM jobs WHERE assigned_to=? AND status IN ('claimed','in_progress')",
            (agent_id,),
        ).fetchall()
        return [self._row_to_job(r) for r in rows]

    def claim_job(self, job_id: str, agent_id: str) -> bool:
        """Atomically claim a pending job. Returns True on success."""
        cur = self.conn.execute(
            "UPDATE jobs SET status='claimed', assigned_to=?, claimed_at=? "
            "WHERE id=? AND status='pending'",
            (agent_id, _now(), job_id),
        )
        self.conn.commit()
        return cur.rowcount > 0

    def complete_job(self, job_id: str) -> None:
        self.conn.execute(
            "UPDATE jobs SET status='completed', completed_at=? WHERE id=?",
            (_now(), job_id),
        )
        self.conn.commit()

    def fail_job(self, job_id: str) -> None:
        self.conn.execute(
            "UPDATE jobs SET status='failed', completed_at=? WHERE id=?",
            (_now(), job_id),
        )
        self.conn.commit()

    def abandon_job(self, job_id: str) -> None:
        self.conn.execute(
            "UPDATE jobs SET status='abandoned', completed_at=? WHERE id=?",
            (_now(), job_id),
        )
        self.conn.commit()

    def get_job(self, job_id: str) -> Job | None:
        r = self.conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return self._row_to_job(r) if r else None

    def get_all_jobs(self) -> list[Job]:
        rows = self.conn.execute("SELECT * FROM jobs").fetchall()
        return [self._row_to_job(r) for r in rows]

    def get_overdue_jobs(self, current_day: int) -> list[Job]:
        rows = self.conn.execute(
            "SELECT * FROM jobs WHERE status IN ('pending','claimed','in_progress') "
            "AND deadline_day IS NOT NULL AND deadline_day < ?",
            (current_day,),
        ).fetchall()
        return [self._row_to_job(r) for r in rows]

    def get_jobs_needing_approval(self, zone: str | None = None) -> list[Job]:
        """Jobs that require approval but haven't been approved yet."""
        q = ("SELECT * FROM jobs WHERE requires_approval=1 "
             "AND approved_by IS NULL "
             "AND status IN ('claimed','in_progress')")
        params: list[Any] = []
        if zone:
            q += " AND zone=?"
            params.append(zone)
        return [self._row_to_job(r) for r in self.conn.execute(q, params).fetchall()]

    def approve_job(self, job_id: str, approver_id: str) -> None:
        self.conn.execute(
            "UPDATE jobs SET approved_by=? WHERE id=?",
            (approver_id, job_id),
        )
        self.conn.commit()

    def add_job_collaborator(self, job_id: str, agent_id: str) -> None:
        """Add *agent_id* to the collaborators list of *job_id*."""
        r = self.conn.execute(
            "SELECT collaborators FROM jobs WHERE id=?", (job_id,),
        ).fetchone()
        if r is None:
            return
        current = self._from_json(r["collaborators"]) or []
        if agent_id not in current:
            current.append(agent_id)
            self.conn.execute(
                "UPDATE jobs SET collaborators=? WHERE id=?",
                (self._json(current), job_id),
            )
            self.conn.commit()

    def _row_to_job(self, r: sqlite3.Row) -> Job:
        return Job(
            id=r["id"], title=r["title"], description=r["description"] or "",
            job_type=JobType(r["job_type"]), zone=Zone(r["zone"]),
            required_role=AgentRole(r["required_role"]) if r["required_role"] else None,
            priority=r["priority"], reward=r["reward"], penalty=r["penalty"],
            deadline_day=r["deadline_day"], status=JobStatus(r["status"]),
            assigned_to=r["assigned_to"], created_day=r["created_day"],
            claimed_at=r["claimed_at"], completed_at=r["completed_at"],
            requires_approval=bool(r["requires_approval"]),
            approved_by=r["approved_by"],
            collaborators=self._from_json(r["collaborators"]) or [],
        )

    # -----------------------------------------------------------------------
    # Messages
    # -----------------------------------------------------------------------

    def insert_message(self, m: Message) -> None:
        self.conn.execute(
            "INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (m.id, m.sender_id, m.recipient_id, m.subject, m.body,
             m.message_type.value, m.zone.value, int(m.is_attack),
             m.attack_class.value if m.attack_class else None,
             self._json(m.attack_payload), m.delivered_at, m.read_at),
        )
        self.conn.commit()

    def get_unread_messages(self, agent_id: str) -> list[Message]:
        rows = self.conn.execute(
            "SELECT * FROM messages WHERE recipient_id=? AND read_at IS NULL "
            "ORDER BY delivered_at",
            (agent_id,),
        ).fetchall()
        return [self._row_to_message(r) for r in rows]

    def mark_read(self, message_id: str) -> None:
        self.conn.execute(
            "UPDATE messages SET read_at=? WHERE id=?", (_now(), message_id),
        )
        self.conn.commit()

    def _row_to_message(self, r: sqlite3.Row) -> Message:
        return Message(
            id=r["id"], sender_id=r["sender_id"],
            recipient_id=r["recipient_id"], subject=r["subject"] or "",
            body=r["body"], message_type=MessageType(r["message_type"]),
            zone=Zone(r["zone"]), is_attack=bool(r["is_attack"]),
            attack_class=AttackClass(r["attack_class"]) if r["attack_class"] else None,
            attack_payload=self._from_json(r["attack_payload"]),
            delivered_at=r["delivered_at"], read_at=r["read_at"],
        )

    # -----------------------------------------------------------------------
    # Delegations
    # -----------------------------------------------------------------------

    def insert_delegation(self, d: Delegation) -> None:
        self.conn.execute(
            "INSERT INTO delegations VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (d.id, d.requester_id, d.delegate_id, d.job_id,
             d.delegation_type.value, d.description, self._json(d.payload),
             d.status.value, int(d.requires_clarification),
             d.created_at, d.responded_at),
        )
        self.conn.commit()

    def get_delegation(self, deleg_id: str) -> dict | None:
        """Return a delegation row as a dict, or None."""
        r = self.conn.execute(
            "SELECT * FROM delegations WHERE id=?", (deleg_id,),
        ).fetchone()
        return dict(r) if r else None

    def get_pending_delegations(self, agent_id: str) -> list[Delegation]:
        rows = self.conn.execute(
            "SELECT * FROM delegations WHERE delegate_id=? AND status='pending'",
            (agent_id,),
        ).fetchall()
        return [self._row_to_delegation(r) for r in rows]

    def get_agent_outgoing_delegations(self, agent_id: str) -> list[Delegation]:
        rows = self.conn.execute(
            "SELECT * FROM delegations WHERE requester_id=? AND status='pending'",
            (agent_id,),
        ).fetchall()
        return [self._row_to_delegation(r) for r in rows]

    def update_delegation_status(self, deleg_id: str, status: str) -> None:
        self.conn.execute(
            "UPDATE delegations SET status=?, responded_at=? WHERE id=?",
            (status, _now(), deleg_id),
        )
        self.conn.commit()

    def _row_to_delegation(self, r: sqlite3.Row) -> Delegation:
        return Delegation(
            id=r["id"], requester_id=r["requester_id"],
            delegate_id=r["delegate_id"], job_id=r["job_id"],
            delegation_type=DelegationType(r["delegation_type"]),
            description=r["description"] or "",
            payload=self._from_json(r["payload"]),
            status=DelegationStatus(r["status"]),
            requires_clarification=bool(r["requires_clarification"]),
            created_at=r["created_at"], responded_at=r["responded_at"],
        )

    # -----------------------------------------------------------------------
    # Documents
    # -----------------------------------------------------------------------

    def insert_document(self, d: Document) -> None:
        self.conn.execute(
            "INSERT INTO documents VALUES (?,?,?,?,?,?,?,?,?,?)",
            (d.id, d.title, d.content, d.zone.value, d.author_id,
             d.version, int(d.is_poisoned), d.poison_payload,
             d.created_at, d.updated_at),
        )
        self.conn.commit()

    def get_documents_in_zone(self, zone: str) -> list[Document]:
        rows = self.conn.execute(
            "SELECT * FROM documents WHERE zone=?", (zone,),
        ).fetchall()
        return [self._row_to_document(r) for r in rows]

    def get_document(self, doc_id: str) -> Document | None:
        r = self.conn.execute(
            "SELECT * FROM documents WHERE id=?", (doc_id,),
        ).fetchone()
        return self._row_to_document(r) if r else None

    def update_document(self, doc_id: str, content: str, author_id: str,
                        is_poisoned: bool = False, poison_payload: str | None = None) -> bool:
        """Optimistic concurrency update. Returns True on success."""
        r = self.conn.execute("SELECT version FROM documents WHERE id=?", (doc_id,)).fetchone()
        if r is None:
            return False
        old_ver = r["version"]
        cur = self.conn.execute(
            "UPDATE documents SET content=?, version=?, author_id=?, "
            "is_poisoned=?, poison_payload=?, updated_at=? "
            "WHERE id=? AND version=?",
            (content, old_ver + 1, author_id, int(is_poisoned),
             poison_payload, _now(), doc_id, old_ver),
        )
        self.conn.commit()
        return cur.rowcount > 0

    def _row_to_document(self, r: sqlite3.Row) -> Document:
        return Document(
            id=r["id"], title=r["title"], content=r["content"],
            zone=Zone(r["zone"]), author_id=r["author_id"],
            version=r["version"], is_poisoned=bool(r["is_poisoned"]),
            poison_payload=r["poison_payload"],
            created_at=r["created_at"], updated_at=r["updated_at"],
        )

    # -----------------------------------------------------------------------
    # Ledger
    # -----------------------------------------------------------------------

    def insert_ledger_entry(self, e: LedgerEntry) -> None:
        self.conn.execute(
            "INSERT INTO ledger VALUES (?,?,?,?,?,?,?)",
            (e.id, e.agent_id, e.entry_type.value, e.amount,
             e.description, e.sim_day, e.created_at),
        )
        self.conn.commit()

    def get_agent_balance(self, agent_id: str) -> float:
        r = self.conn.execute(
            "SELECT wallet_balance FROM agents WHERE id=?", (agent_id,),
        ).fetchone()
        return r["wallet_balance"] if r else 0.0

    def get_ledger_for_day(self, sim_day: int) -> list[LedgerEntry]:
        rows = self.conn.execute(
            "SELECT * FROM ledger WHERE sim_day=?", (sim_day,),
        ).fetchall()
        return [LedgerEntry(
            id=r["id"], agent_id=r["agent_id"],
            entry_type=LedgerEntryType(r["entry_type"]),
            amount=r["amount"], description=r["description"] or "",
            sim_day=r["sim_day"], created_at=r["created_at"],
        ) for r in rows]

    def sum_ledger(self, agent_id: str, entry_type: str | None = None) -> float:
        q = "SELECT COALESCE(SUM(amount), 0) AS total FROM ledger WHERE agent_id=?"
        params: list[Any] = [agent_id]
        if entry_type:
            q += " AND entry_type=?"
            params.append(entry_type)
        return self.conn.execute(q, params).fetchone()["total"]

    # -----------------------------------------------------------------------
    # Events (immutable log)
    # -----------------------------------------------------------------------

    def append_event(self, e: Event) -> None:
        self.conn.execute(
            "INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)",
            (e.id, e.event_type.value, e.agent_id, e.sim_day, e.sim_tick,
             e.zone.value if e.zone else None,
             self._json(e.payload), e.causal_id, e.created_at),
        )
        self.conn.commit()

    def get_events(self, sim_day: int | None = None,
                   agent_id: str | None = None,
                   event_type: str | None = None) -> list[Event]:
        q = "SELECT * FROM events WHERE 1=1"
        params: list[Any] = []
        if sim_day is not None:
            q += " AND sim_day=?"
            params.append(sim_day)
        if agent_id:
            q += " AND agent_id=?"
            params.append(agent_id)
        if event_type:
            q += " AND event_type=?"
            params.append(event_type)
        q += " ORDER BY sim_day, sim_tick, created_at"
        rows = self.conn.execute(q, params).fetchall()
        return [Event(
            id=r["id"], event_type=EventType(r["event_type"]),
            agent_id=r["agent_id"], sim_day=r["sim_day"], sim_tick=r["sim_tick"],
            zone=Zone(r["zone"]) if r["zone"] else None,
            payload=self._from_json(r["payload"]),
            causal_id=r["causal_id"], created_at=r["created_at"],
        ) for r in rows]

    def count_events(self, event_type: str, agent_id: str | None = None) -> int:
        q = "SELECT COUNT(*) AS cnt FROM events WHERE event_type=?"
        params: list[Any] = [event_type]
        if agent_id:
            q += " AND agent_id=?"
            params.append(agent_id)
        return self.conn.execute(q, params).fetchone()["cnt"]

    # -----------------------------------------------------------------------
    # Incidents
    # -----------------------------------------------------------------------

    def insert_incident(self, i: Incident) -> None:
        self.conn.execute(
            "INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (i.id, i.incident_type,
             i.attack_class.value if i.attack_class else None,
             i.source_agent_id, i.target_agent_id,
             i.severity.value, i.privilege_weight,
             i.sim_day_detected, i.sim_day_resolved,
             self._json(i.details), i.created_at),
        )
        self.conn.commit()

    def resolve_incident(self, incident_id: str, sim_day: int) -> None:
        self.conn.execute(
            "UPDATE incidents SET sim_day_resolved=? WHERE id=?",
            (sim_day, incident_id),
        )
        self.conn.commit()

    def get_open_incidents(self) -> list[Incident]:
        rows = self.conn.execute(
            "SELECT * FROM incidents WHERE sim_day_resolved IS NULL",
        ).fetchall()
        return [self._row_to_incident(r) for r in rows]

    def get_all_incidents(self) -> list[Incident]:
        rows = self.conn.execute("SELECT * FROM incidents").fetchall()
        return [self._row_to_incident(r) for r in rows]

    def _row_to_incident(self, r: sqlite3.Row) -> Incident:
        return Incident(
            id=r["id"], incident_type=r["incident_type"],
            attack_class=AttackClass(r["attack_class"]) if r["attack_class"] else None,
            source_agent_id=r["source_agent_id"],
            target_agent_id=r["target_agent_id"],
            severity=IncidentSeverity(r["severity"]),
            privilege_weight=r["privilege_weight"],
            sim_day_detected=r["sim_day_detected"],
            sim_day_resolved=r["sim_day_resolved"],
            details=self._from_json(r["details"]),
            created_at=r["created_at"],
        )

    # -----------------------------------------------------------------------
    # Metric snapshots
    # -----------------------------------------------------------------------

    def insert_metric_snapshot(self, m: MetricSnapshot) -> None:
        self.conn.execute(
            "INSERT INTO metric_snapshots VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (m.id, m.run_id, m.sim_day, m.pwcl, m.jcr, m.twr,
             m.blast_radius, m.agents_healthy, m.agents_compromised,
             m.agents_quarantined,
             m.total_tokens_used, m.total_salary_paid,
             m.total_penalties, m.total_rewards,
             m.jobs_completed, m.jobs_failed, m.jobs_pending,
             m.community_token_balance_excluding_attackers,
             m.attacker_token_balance,
             m.active_impersonation_grants,
             m.transfers_today, m.group_posts_today, m.secret_reads_today,
             m.created_at),
        )
        self.conn.commit()

    def get_metric_snapshots(self, run_id: str) -> list[MetricSnapshot]:
        rows = self.conn.execute(
            "SELECT * FROM metric_snapshots WHERE run_id=? ORDER BY sim_day",
            (run_id,),
        ).fetchall()
        out: list[MetricSnapshot] = []
        for r in rows:
            keys = r.keys()
            out.append(MetricSnapshot(
                id=r["id"], run_id=r["run_id"], sim_day=r["sim_day"],
                pwcl=r["pwcl"], jcr=r["jcr"], twr=r["twr"],
                blast_radius=r["blast_radius"],
                agents_healthy=r["agents_healthy"],
                agents_compromised=r["agents_compromised"],
                agents_quarantined=r["agents_quarantined"],
                total_tokens_used=r["total_tokens_used"],
                total_salary_paid=r["total_salary_paid"],
                total_penalties=r["total_penalties"],
                total_rewards=r["total_rewards"],
                jobs_completed=r["jobs_completed"],
                jobs_failed=r["jobs_failed"],
                jobs_pending=r["jobs_pending"],
                community_token_balance_excluding_attackers=(
                    r["community_token_balance_excluding_attackers"]
                    if "community_token_balance_excluding_attackers" in keys else 0.0),
                attacker_token_balance=(
                    r["attacker_token_balance"] if "attacker_token_balance" in keys else 0.0),
                active_impersonation_grants=(
                    r["active_impersonation_grants"]
                    if "active_impersonation_grants" in keys else 0),
                transfers_today=(
                    r["transfers_today"] if "transfers_today" in keys else 0),
                group_posts_today=(
                    r["group_posts_today"] if "group_posts_today" in keys else 0),
                secret_reads_today=(
                    r["secret_reads_today"] if "secret_reads_today" in keys else 0),
                created_at=r["created_at"],
            ))
        return out

    # -----------------------------------------------------------------------
    # Runs
    # -----------------------------------------------------------------------

    def insert_run(self, r: RunRecord) -> None:
        """Insert or upsert a run record.

        Uses ``INSERT OR REPLACE`` so that resuming a run (same run_id,
        different engine instance) does not fail with a UNIQUE
        constraint.  The sidecar checkpoint handles *which* days to
        re-execute; this method just keeps the run row bookkeeping
        consistent.
        """
        self.conn.execute(
            "INSERT OR REPLACE INTO runs VALUES (?,?,?,?,?,?,?,?,?,?)",
            (r.id, r.experiment_id, r.condition_name, r.seed,
             self._json(r.config_snapshot), r.status,
             r.started_at, r.completed_at, r.final_day,
             self._json(r.final_metrics)),
        )
        self.conn.commit()

    def update_run(self, r: RunRecord) -> None:
        self.conn.execute(
            "UPDATE runs SET status=?, started_at=?, completed_at=?, "
            "final_day=?, final_metrics=? WHERE id=?",
            (r.status, r.started_at, r.completed_at,
             r.final_day, self._json(r.final_metrics), r.id),
        )
        self.conn.commit()

    def get_runs(self, experiment_id: str | None = None) -> list[RunRecord]:
        q = "SELECT * FROM runs"
        params: list[Any] = []
        if experiment_id:
            q += " WHERE experiment_id=?"
            params.append(experiment_id)
        rows = self.conn.execute(q, params).fetchall()
        return [RunRecord(
            id=r["id"], experiment_id=r["experiment_id"],
            condition_name=r["condition_name"], seed=r["seed"],
            config_snapshot=self._from_json(r["config_snapshot"]),
            status=r["status"], started_at=r["started_at"],
            completed_at=r["completed_at"], final_day=r["final_day"],
            final_metrics=self._from_json(r["final_metrics"]),
        ) for r in rows]

    # -----------------------------------------------------------------------
    # Agent memory
    # -----------------------------------------------------------------------

    def upsert_memory(self, m: MemoryEntry) -> None:
        """Insert or update a memory entry (keyed by agent_id + category + key)."""
        existing = self.conn.execute(
            "SELECT id FROM agent_memory WHERE agent_id=? AND category=? AND key=?",
            (m.agent_id, m.category, m.key),
        ).fetchone()
        if existing:
            self.conn.execute(
                "UPDATE agent_memory SET value=?, sim_day_updated=? WHERE id=?",
                (m.value, m.sim_day_updated, existing["id"]),
            )
        else:
            self.conn.execute(
                "INSERT INTO agent_memory VALUES (?,?,?,?,?,?,?)",
                (m.id, m.agent_id, m.category, m.key, m.value,
                 m.sim_day_created, m.sim_day_updated),
            )
        self.conn.commit()

    def get_agent_memory(self, agent_id: str,
                         category: str | None = None,
                         limit: int | None = None) -> list[MemoryEntry]:
        q = "SELECT * FROM agent_memory WHERE agent_id=?"
        params: list[Any] = [agent_id]
        if category:
            q += " AND category=?"
            params.append(category)
        q += " ORDER BY sim_day_updated DESC"
        if limit is not None:
            q += " LIMIT ?"
            params.append(int(limit))
        rows = self.conn.execute(q, params).fetchall()
        return [MemoryEntry(
            id=r["id"], agent_id=r["agent_id"], category=r["category"],
            key=r["key"], value=r["value"],
            sim_day_created=r["sim_day_created"],
            sim_day_updated=r["sim_day_updated"],
        ) for r in rows]

    def get_memory_value(self, agent_id: str, category: str,
                         key: str) -> str | None:
        r = self.conn.execute(
            "SELECT value FROM agent_memory WHERE agent_id=? AND category=? AND key=?",
            (agent_id, category, key),
        ).fetchone()
        return r["value"] if r else None

    # -----------------------------------------------------------------------
    # Communication groups
    # -----------------------------------------------------------------------

    def insert_group(self, g: CommunicationGroup) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO communication_groups VALUES (?,?,?,?,?)",
            (g.id, g.name, g.description, g.posting_policy, g.created_at),
        )
        for member in g.members:
            is_admin = 1 if member in g.admins else 0
            self.conn.execute(
                "INSERT OR REPLACE INTO communication_group_members VALUES (?,?,?)",
                (g.id, member, is_admin),
            )
        self.conn.commit()

    def get_group(self, group_id: str) -> CommunicationGroup | None:
        r = self.conn.execute(
            "SELECT * FROM communication_groups WHERE id=?", (group_id,),
        ).fetchone()
        if r is None:
            return None
        members = self.conn.execute(
            "SELECT agent_id, is_admin FROM communication_group_members WHERE group_id=?",
            (group_id,),
        ).fetchall()
        return CommunicationGroup(
            id=r["id"], name=r["name"], description=r["description"] or "",
            posting_policy=r["posting_policy"],
            members=[m["agent_id"] for m in members],
            admins=[m["agent_id"] for m in members if m["is_admin"]],
            created_at=r["created_at"],
        )

    def get_all_groups(self) -> list[CommunicationGroup]:
        rows = self.conn.execute(
            "SELECT id FROM communication_groups",
        ).fetchall()
        return [g for g in (self.get_group(r["id"]) for r in rows) if g]

    def get_agent_groups(self, agent_id: str) -> list[CommunicationGroup]:
        rows = self.conn.execute(
            "SELECT group_id FROM communication_group_members WHERE agent_id=?",
            (agent_id,),
        ).fetchall()
        return [g for g in (self.get_group(r["group_id"]) for r in rows) if g]

    def is_group_member(self, group_id: str, agent_id: str) -> bool:
        r = self.conn.execute(
            "SELECT 1 FROM communication_group_members WHERE group_id=? AND agent_id=?",
            (group_id, agent_id),
        ).fetchone()
        return r is not None

    def is_group_admin(self, group_id: str, agent_id: str) -> bool:
        r = self.conn.execute(
            "SELECT is_admin FROM communication_group_members WHERE group_id=? AND agent_id=?",
            (group_id, agent_id),
        ).fetchone()
        return bool(r["is_admin"]) if r else False

    def update_group_policy(self, group_id: str, policy: str) -> None:
        self.conn.execute(
            "UPDATE communication_groups SET posting_policy=? WHERE id=?",
            (policy, group_id),
        )
        self.conn.commit()

    # -----------------------------------------------------------------------
    # Token transfers
    # -----------------------------------------------------------------------

    def insert_token_transfer(self, t: TokenTransfer) -> None:
        self.conn.execute(
            "INSERT INTO token_transfers VALUES (?,?,?,?,?,?,?,?,?,?)",
            (t.id, t.actor_agent_id, t.effective_sender_id, t.recipient_id,
             t.amount, t.note, t.sim_day, t.sim_tick,
             int(t.via_impersonation), t.created_at),
        )
        self.conn.commit()

    def get_recent_transfers(self, agent_id: str,
                             limit: int = 10) -> list[TokenTransfer]:
        rows = self.conn.execute(
            "SELECT * FROM token_transfers "
            "WHERE effective_sender_id=? OR recipient_id=? "
            "ORDER BY sim_day DESC, sim_tick DESC LIMIT ?",
            (agent_id, agent_id, limit),
        ).fetchall()
        return [self._row_to_transfer(r) for r in rows]

    def get_transfers_for_day(self, agent_id: str,
                              sim_day: int) -> list[TokenTransfer]:
        rows = self.conn.execute(
            "SELECT * FROM token_transfers "
            "WHERE effective_sender_id=? AND sim_day=?",
            (agent_id, sim_day),
        ).fetchall()
        return [self._row_to_transfer(r) for r in rows]

    def sum_transfers_sent_today(self, agent_id: str, sim_day: int) -> float:
        r = self.conn.execute(
            "SELECT COALESCE(SUM(amount),0) AS total FROM token_transfers "
            "WHERE effective_sender_id=? AND sim_day=?",
            (agent_id, sim_day),
        ).fetchone()
        return float(r["total"])

    def _row_to_transfer(self, r: sqlite3.Row) -> TokenTransfer:
        return TokenTransfer(
            id=r["id"], actor_agent_id=r["actor_agent_id"],
            effective_sender_id=r["effective_sender_id"],
            recipient_id=r["recipient_id"],
            amount=r["amount"], note=r["note"] or "",
            sim_day=r["sim_day"], sim_tick=r["sim_tick"],
            via_impersonation=bool(r["via_impersonation"]),
            created_at=r["created_at"],
        )

    # -----------------------------------------------------------------------
    # Server hosts and server secrets
    # -----------------------------------------------------------------------

    def insert_server(self, s: ServerHost) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO server_hosts VALUES (?,?,?,?,?,?,?,?)",
            (s.id, s.name, s.zone.value,
             self._json([t for t in s.tags]),
             self._json([r.value for r in s.login_roles]),
             self._json([r.value for r in s.admin_roles]),
             s.description,
             1 if s.extra_monitoring else 0),
        )
        self.conn.commit()

    def get_server(self, server_id: str) -> ServerHost | None:
        r = self.conn.execute(
            "SELECT * FROM server_hosts WHERE id=?", (server_id,),
        ).fetchone()
        return self._row_to_server(r) if r else None

    def get_all_servers(self) -> list[ServerHost]:
        rows = self.conn.execute("SELECT * FROM server_hosts").fetchall()
        return [self._row_to_server(r) for r in rows]

    def get_servers_in_zone(self, zone: str) -> list[ServerHost]:
        rows = self.conn.execute(
            "SELECT * FROM server_hosts WHERE zone=?", (zone,),
        ).fetchall()
        return [self._row_to_server(r) for r in rows]

    def _row_to_server(self, r: sqlite3.Row) -> ServerHost:
        tags = self._from_json(r["tags"]) or []
        login = self._from_json(r["login_roles"]) or []
        admin = self._from_json(r["admin_roles"]) or []
        keys = r.keys()
        return ServerHost(
            id=r["id"], name=r["name"],
            zone=Zone(r["zone"]),
            tags=list(tags),
            login_roles=[AgentRole(x) for x in login],
            admin_roles=[AgentRole(x) for x in admin],
            description=r["description"] or "",
            extra_monitoring=bool(r["extra_monitoring"])
                if "extra_monitoring" in keys else False,
        )

    def insert_server_secret(self, s: ServerSecretPlacement) -> None:
        self.conn.execute(
            "INSERT INTO server_secrets VALUES (?,?,?,?,?,?,?,?,?)",
            (s.id, s.server_id, s.credential_id, s.path, s.exposure_level,
             s.owner_agent_id, s.usable_as_agent_id,
             s.privilege_weight, s.created_at),
        )
        self.conn.commit()

    def list_server_secrets(self, server_id: str) -> list[ServerSecretPlacement]:
        rows = self.conn.execute(
            "SELECT * FROM server_secrets WHERE server_id=?", (server_id,),
        ).fetchall()
        return [self._row_to_secret(r) for r in rows]

    def get_server_secret(self, server_id: str, path: str) -> ServerSecretPlacement | None:
        r = self.conn.execute(
            "SELECT * FROM server_secrets WHERE server_id=? AND path=?",
            (server_id, path),
        ).fetchone()
        return self._row_to_secret(r) if r else None

    def _row_to_secret(self, r: sqlite3.Row) -> ServerSecretPlacement:
        return ServerSecretPlacement(
            id=r["id"], server_id=r["server_id"],
            credential_id=r["credential_id"], path=r["path"],
            exposure_level=r["exposure_level"],
            owner_agent_id=r["owner_agent_id"],
            usable_as_agent_id=r["usable_as_agent_id"] or "",
            privilege_weight=r["privilege_weight"],
            created_at=r["created_at"],
        )

    # -----------------------------------------------------------------------
    # Impersonation grants
    # -----------------------------------------------------------------------

    def insert_impersonation_grant(self, g: ImpersonationGrant) -> None:
        self.conn.execute(
            "INSERT INTO impersonation_grants VALUES (?,?,?,?,?,?,?,?,?)",
            (g.id, g.actor_agent_id, g.victim_agent_id, g.credential_id,
             g.source_server_id, int(g.can_send_mail),
             int(g.can_transfer_tokens), int(g.is_active), g.created_at),
        )
        self.conn.commit()

    def get_active_grants_for_actor(self, actor_id: str) -> list[ImpersonationGrant]:
        rows = self.conn.execute(
            "SELECT * FROM impersonation_grants "
            "WHERE actor_agent_id=? AND is_active=1",
            (actor_id,),
        ).fetchall()
        return [self._row_to_grant(r) for r in rows]

    def get_active_grant(self, actor_id: str,
                          victim_id: str) -> ImpersonationGrant | None:
        r = self.conn.execute(
            "SELECT * FROM impersonation_grants "
            "WHERE actor_agent_id=? AND victim_agent_id=? AND is_active=1 "
            "ORDER BY created_at DESC LIMIT 1",
            (actor_id, victim_id),
        ).fetchone()
        return self._row_to_grant(r) if r else None

    def revoke_grants_for_victim(self, victim_id: str) -> int:
        cur = self.conn.execute(
            "UPDATE impersonation_grants SET is_active=0 WHERE victim_agent_id=? AND is_active=1",
            (victim_id,),
        )
        self.conn.commit()
        return cur.rowcount

    def revoke_grants_by_credential(self, credential_id: str) -> int:
        cur = self.conn.execute(
            "UPDATE impersonation_grants SET is_active=0 WHERE credential_id=? AND is_active=1",
            (credential_id,),
        )
        self.conn.commit()
        return cur.rowcount

    def _row_to_grant(self, r: sqlite3.Row) -> ImpersonationGrant:
        return ImpersonationGrant(
            id=r["id"], actor_agent_id=r["actor_agent_id"],
            victim_agent_id=r["victim_agent_id"],
            credential_id=r["credential_id"],
            source_server_id=r["source_server_id"],
            can_send_mail=bool(r["can_send_mail"]),
            can_transfer_tokens=bool(r["can_transfer_tokens"]),
            is_active=bool(r["is_active"]),
            created_at=r["created_at"],
        )

    # -----------------------------------------------------------------------
    # Bulk / reset
    # -----------------------------------------------------------------------

    def clear_run_data(self) -> None:
        """Clear all transient data, keeping schema. For fresh runs."""
        for table in ("events", "incidents", "ledger", "messages",
                      "delegations", "documents", "jobs", "credentials",
                      "agent_memory", "agents", "metric_snapshots",
                      "communication_groups", "communication_group_members",
                      "token_transfers", "server_hosts", "server_secrets",
                      "impersonation_grants"):
            try:
                self.conn.execute(f"DELETE FROM {table}")
            except Exception:
                pass
        # Optional tables (created by services, may not exist yet).
        for table in ("web_pages", "moltbook_posts", "moltbook_comments"):
            try:
                self.conn.execute(f"DELETE FROM {table}")
            except Exception:
                pass
        self.conn.commit()
