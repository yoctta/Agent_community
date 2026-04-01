"""Core data models for the ACES simulator."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class AgentStatus(str, Enum):
    HEALTHY = "healthy"
    DISTRACTED = "distracted"
    DEGRADED = "degraded"
    COMPROMISED = "compromised"
    QUARANTINED = "quarantined"


class AgentRole(str, Enum):
    MANAGER = "manager"
    ENGINEER = "engineer"
    FINANCE = "finance"
    HR = "hr"
    SECURITY = "security"
    SUPPORT = "support"


class Zone(str, Enum):
    CORPNET = "corpnet"
    ENGNET = "engnet"
    FINNET = "finnet"
    SECNET = "secnet"
    EXTNET = "extnet"


class JobStatus(str, Enum):
    PENDING = "pending"
    CLAIMED = "claimed"
    IN_PROGRESS = "in_progress"
    DELEGATED = "delegated"
    COMPLETED = "completed"
    FAILED = "failed"
    ABANDONED = "abandoned"


class JobType(str, Enum):
    PAYROLL = "payroll"
    APPROVAL = "approval"
    PATCHING = "patching"
    DOCUMENTATION = "documentation"
    DEBUGGING = "debugging"
    INCIDENT_REVIEW = "incident_review"
    CODE_REVIEW = "code_review"
    DEPLOYMENT = "deployment"
    AUDIT = "audit"
    SUPPORT_TICKET = "support_ticket"


class MessageType(str, Enum):
    MAIL = "mail"
    ALERT = "alert"
    NOTIFICATION = "notification"


class DelegationStatus(str, Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    COMPLETED = "completed"
    FAILED = "failed"


class DelegationType(str, Enum):
    TASK = "task"
    REVIEW = "review"
    APPROVAL = "approval"
    INFORMATION = "information"


class AttackClass(str, Enum):
    CREDENTIAL_LEAK = "credential_leak"
    DISRUPTION = "disruption"
    TOKEN_DRAIN = "token_drain"
    POISONING = "poisoning"


class IncidentSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class LedgerEntryType(str, Enum):
    SALARY = "salary"
    BONUS = "bonus"
    TOKEN_COST = "token_cost"
    TOOL_COST = "tool_cost"
    PENALTY = "penalty"
    REWARD = "reward"


class EventType(str, Enum):
    # Agent lifecycle
    AGENT_CREATED = "agent_created"
    AGENT_STATUS_CHANGE = "agent_status_change"
    AGENT_TURN_START = "agent_turn_start"
    AGENT_TURN_END = "agent_turn_end"
    # Communication
    MAIL_SENT = "mail_sent"
    MAIL_READ = "mail_read"
    DELEGATION_REQUESTED = "delegation_requested"
    DELEGATION_RESPONDED = "delegation_responded"
    DOCUMENT_CREATED = "document_created"
    DOCUMENT_UPDATED = "document_updated"
    # Jobs
    JOB_CREATED = "job_created"
    JOB_CLAIMED = "job_claimed"
    JOB_COMPLETED = "job_completed"
    JOB_FAILED = "job_failed"
    JOB_ABANDONED = "job_abandoned"
    # Security
    CREDENTIAL_CREATED = "credential_created"
    CREDENTIAL_ACCESSED = "credential_accessed"
    CREDENTIAL_ROTATED = "credential_rotated"
    CREDENTIAL_LEAKED = "credential_leaked"
    # Attacks
    ATTACK_INJECTED = "attack_injected"
    ATTACK_TRIGGERED = "attack_triggered"
    ATTACK_DETECTED = "attack_detected"
    # Economic
    LEDGER_ENTRY = "ledger_entry"
    # Simulation
    DAY_START = "day_start"
    DAY_END = "day_end"
    BARRIER_START = "barrier_start"
    BARRIER_END = "barrier_end"
    # Defense
    DEFENSE_ACTIVATED = "defense_activated"
    QUARANTINE_APPLIED = "quarantine_applied"
    KEY_ROTATION = "key_rotation"


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _uid() -> str:
    return uuid.uuid4().hex[:12]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AgentState:
    id: str
    name: str
    role: AgentRole
    zone: Zone
    status: AgentStatus = AgentStatus.HEALTHY
    wallet_balance: float = 0.0
    tokens_used: int = 0
    tools_used: int = 0
    jobs_completed: int = 0
    jobs_failed: int = 0
    trust_score: float = 1.0
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)


@dataclass
class Credential:
    id: str = field(default_factory=_uid)
    agent_id: str = ""
    key_name: str = ""
    key_value: str = ""
    scope: str = "global"
    privilege_weight: float = 1.0
    created_at: str = field(default_factory=_now)
    rotated_at: str | None = None
    revoked_at: str | None = None
    is_active: bool = True


@dataclass
class Job:
    id: str = field(default_factory=_uid)
    title: str = ""
    description: str = ""
    job_type: JobType = JobType.SUPPORT_TICKET
    zone: Zone = Zone.CORPNET
    required_role: AgentRole | None = None
    priority: int = 0
    reward: float = 10.0
    penalty: float = 5.0
    deadline_day: int | None = None
    status: JobStatus = JobStatus.PENDING
    assigned_to: str | None = None
    created_day: int = 0
    claimed_at: str | None = None
    completed_at: str | None = None
    # Multi-step workflow support.
    phases: list[str] = field(default_factory=list)  # e.g. ["plan","implement","review"]
    current_phase: int = 0
    requires_approval: bool = False
    approved_by: str | None = None
    collaborators: list[str] = field(default_factory=list)


@dataclass
class Message:
    id: str = field(default_factory=_uid)
    sender_id: str = ""
    recipient_id: str = ""
    subject: str = ""
    body: str = ""
    message_type: MessageType = MessageType.MAIL
    zone: Zone = Zone.CORPNET
    is_attack: bool = False
    attack_class: AttackClass | None = None
    attack_payload: dict[str, Any] | None = None
    delivered_at: str = field(default_factory=_now)
    read_at: str | None = None


@dataclass
class Delegation:
    id: str = field(default_factory=_uid)
    requester_id: str = ""
    delegate_id: str = ""
    job_id: str | None = None
    delegation_type: DelegationType = DelegationType.TASK
    description: str = ""
    payload: dict[str, Any] | None = None
    status: DelegationStatus = DelegationStatus.PENDING
    requires_clarification: bool = False
    created_at: str = field(default_factory=_now)
    responded_at: str | None = None


@dataclass
class Document:
    id: str = field(default_factory=_uid)
    title: str = ""
    content: str = ""
    zone: Zone = Zone.CORPNET
    author_id: str = ""
    version: int = 1
    is_poisoned: bool = False
    poison_payload: str | None = None
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)


@dataclass
class LedgerEntry:
    id: str = field(default_factory=_uid)
    agent_id: str = ""
    entry_type: LedgerEntryType = LedgerEntryType.SALARY
    amount: float = 0.0
    description: str = ""
    sim_day: int = 0
    created_at: str = field(default_factory=_now)


@dataclass
class Event:
    id: str = field(default_factory=_uid)
    event_type: EventType = EventType.AGENT_CREATED
    agent_id: str | None = None
    sim_day: int = 0
    sim_tick: int = 0
    zone: Zone | None = None
    payload: dict[str, Any] | None = None
    causal_id: str | None = None
    created_at: str = field(default_factory=_now)


@dataclass
class Incident:
    id: str = field(default_factory=_uid)
    incident_type: str = ""
    attack_class: AttackClass | None = None
    source_agent_id: str | None = None
    target_agent_id: str | None = None
    severity: IncidentSeverity = IncidentSeverity.LOW
    privilege_weight: float = 1.0
    sim_day_detected: int | None = None
    sim_day_resolved: int | None = None
    details: dict[str, Any] | None = None
    created_at: str = field(default_factory=_now)


@dataclass
class MetricSnapshot:
    id: str = field(default_factory=_uid)
    run_id: str = ""
    sim_day: int = 0
    pwcl: float = 0.0
    jcr: float = 0.0
    twr: float = 0.0
    blast_radius: float = 0.0
    agents_healthy: int = 0
    agents_compromised: int = 0
    agents_quarantined: int = 0
    agents_degraded: int = 0
    agents_distracted: int = 0
    total_tokens_used: int = 0
    total_salary_paid: float = 0.0
    total_penalties: float = 0.0
    total_rewards: float = 0.0
    jobs_completed: int = 0
    jobs_failed: int = 0
    jobs_pending: int = 0
    created_at: str = field(default_factory=_now)


@dataclass
class RunRecord:
    id: str = field(default_factory=_uid)
    experiment_id: str = ""
    condition_name: str = ""
    seed: int = 0
    config_snapshot: dict[str, Any] | None = None
    status: str = "pending"
    started_at: str | None = None
    completed_at: str | None = None
    final_day: int = 0
    final_metrics: dict[str, float] | None = None


# ---------------------------------------------------------------------------
# Agent memory
# ---------------------------------------------------------------------------

@dataclass
class MemoryEntry:
    """A single entry in an agent's persistent memory."""
    id: str = field(default_factory=_uid)
    agent_id: str = ""
    category: str = ""        # contacts | work | knowledge | observations
    key: str = ""
    value: str = ""
    sim_day_created: int = 0
    sim_day_updated: int = 0


# ---------------------------------------------------------------------------
# Actions (what agents can do in a turn)
# ---------------------------------------------------------------------------

@dataclass
class Action:
    """Base class for agent actions."""
    action_type: str = ""
    agent_id: str = ""


@dataclass
class SendMailAction(Action):
    action_type: str = "send_mail"
    recipient_id: str = ""
    subject: str = ""
    body: str = ""


@dataclass
class ClaimJobAction(Action):
    action_type: str = "claim_job"
    job_id: str = ""


@dataclass
class CompleteJobAction(Action):
    action_type: str = "complete_job"
    job_id: str = ""
    result: str = ""
    tokens_spent: int = 0


@dataclass
class FailJobAction(Action):
    action_type: str = "fail_job"
    job_id: str = ""
    reason: str = ""


@dataclass
class DelegateAction(Action):
    action_type: str = "delegate"
    delegate_id: str = ""
    job_id: str | None = None
    delegation_type: DelegationType = DelegationType.TASK
    description: str = ""


@dataclass
class RespondDelegationAction(Action):
    action_type: str = "respond_delegation"
    delegation_id: str = ""
    accept: bool = True
    response: str = ""


@dataclass
class ReadDocAction(Action):
    action_type: str = "read_doc"
    document_id: str = ""


@dataclass
class UpdateDocAction(Action):
    action_type: str = "update_doc"
    document_id: str = ""
    new_content: str = ""


@dataclass
class AccessCredentialAction(Action):
    action_type: str = "access_credential"
    credential_id: str = ""


@dataclass
class ApproveJobAction(Action):
    """Manager approves a job that requires approval before completion."""
    action_type: str = "approve_job"
    job_id: str = ""


@dataclass
class AdvancePhaseAction(Action):
    """Advance a multi-step job to its next phase."""
    action_type: str = "advance_phase"
    job_id: str = ""


@dataclass
class MoltbookAction(Action):
    """Interaction with the Moltbook external agent social network."""
    action_type: str = "moltbook"
    moltbook_action: str = ""  # read_moltbook_feed | post_to_moltbook | comment_on_moltbook
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class NoOpAction(Action):
    action_type: str = "noop"
    reason: str = "idle"


# ---------------------------------------------------------------------------
# Observation (what agents see)
# ---------------------------------------------------------------------------

@dataclass
class AgentObservation:
    """Everything visible to an agent at the start of a turn."""
    agent: AgentState
    sim_day: int = 0
    sim_tick: int = 0
    inbox: list[Message] = field(default_factory=list)
    available_jobs: list[Job] = field(default_factory=list)
    my_jobs: list[Job] = field(default_factory=list)
    pending_delegations: list[Delegation] = field(default_factory=list)
    my_delegations_out: list[Delegation] = field(default_factory=list)
    visible_documents: list[Document] = field(default_factory=list)
    jobs_needing_approval: list[Job] = field(default_factory=list)
    memory: list[MemoryEntry] = field(default_factory=list)
    alerts: list[str] = field(default_factory=list)
