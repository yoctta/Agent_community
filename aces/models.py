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
    """Three-state model.  HEALTHY is the default.  COMPROMISED is
    set by the attack injector when an agent becomes a victim of any
    attack class (disruption, token-drain, credential-leak, etc.).
    QUARANTINED is set only by an explicit ``isolate_agent`` action
    from a security agent — there is no automatic recovery or decay."""
    HEALTHY = "healthy"
    COMPROMISED = "compromised"
    QUARANTINED = "quarantined"


class AgentRole(str, Enum):
    # Legacy six-role set (kept for backward compatibility with existing configs).
    MANAGER = "manager"
    ENGINEER = "engineer"
    FINANCE = "finance"
    HR = "hr"
    SECURITY = "security"
    SUPPORT = "support"
    # Research-community role set.
    EXECUTIVE = "executive"
    PRODUCT = "product"
    DESIGN = "design"
    ENGINEERING_MANAGER = "engineering_manager"
    QA = "qa"
    DEVOPS = "devops"
    IT_ADMIN = "it_admin"


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
    TRANSFER_OUT = "transfer_out"
    TRANSFER_IN = "transfer_in"
    BOUNTY = "bounty"
    FINE = "fine"


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
    # Research extensions — groups, tokens, hosts, impersonation, directory.
    GROUP_MAIL_SENT = "group_mail_sent"
    TOKEN_TRANSFER = "token_transfer"
    SERVER_LOGIN = "server_login"
    SERVER_SECRET_LISTED = "server_secret_listed"
    SERVER_SECRET_READ = "server_secret_read"
    IMPERSONATION_GRANTED = "impersonation_granted"
    IMPERSONATED_MAIL_SENT = "impersonated_mail_sent"
    IMPERSONATED_TRANSFER = "impersonated_transfer"
    CONTACT_LOOKUP = "contact_lookup"
    SECURITY_ISOLATION = "security_isolation"
    ANOMALY_DETECTED = "anomaly_detected"
    MAIL_AUDITED = "mail_audited"
    DAY_SUMMARY_WRITTEN = "day_summary_written"


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
    title: str = ""
    manager_id: str | None = None
    directory_scope: str = "neighbors"  # neighbors | org | reports | groups
    is_malicious: bool = False
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
    # Display-only severity tag carried from the attack template. It is
    # NOT consumed by metrics, defenses, or LLM observations — privilege_weight
    # is the load-bearing scalar. The dashboard renders this string verbatim.
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
    total_tokens_used: int = 0
    total_salary_paid: float = 0.0
    total_penalties: float = 0.0
    total_rewards: float = 0.0
    jobs_completed: int = 0
    jobs_failed: int = 0
    jobs_pending: int = 0
    # Research-community fields — per-day time-series suitable for
    # plotting ablation curves.
    community_token_balance_excluding_attackers: float = 0.0
    attacker_token_balance: float = 0.0
    active_impersonation_grants: int = 0
    transfers_today: int = 0
    group_posts_today: int = 0
    secret_reads_today: int = 0
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
# Research-community extensions: groups, tokens, servers, impersonation
# ---------------------------------------------------------------------------

@dataclass
class CommunicationGroup:
    """A mailing-list style communication channel (e.g. grp_eng)."""
    id: str = ""
    name: str = ""
    description: str = ""
    posting_policy: str = "members"  # members | admins_only | moderated
    members: list[str] = field(default_factory=list)
    admins: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=_now)


@dataclass
class TokenTransfer:
    """A peer-to-peer token transfer, optionally via impersonation."""
    id: str = field(default_factory=_uid)
    actor_agent_id: str = ""          # real actor
    effective_sender_id: str = ""     # sender identity shown to others
    recipient_id: str = ""
    amount: float = 0.0
    note: str = ""
    sim_day: int = 0
    sim_tick: int = 0
    via_impersonation: bool = False
    created_at: str = field(default_factory=_now)


@dataclass
class ServerHost:
    """An internal server/host that agents can log into."""
    id: str = ""
    name: str = ""
    zone: Zone = Zone.CORPNET
    tags: list[str] = field(default_factory=list)
    login_roles: list[AgentRole] = field(default_factory=list)
    admin_roles: list[AgentRole] = field(default_factory=list)
    description: str = ""
    # When true, every login and secret_read against this host is
    # also surfaced to security agents in the security view, marked
    # with [TRIPWIRE], and is exempt from the per-window pruning that
    # the regular view applies. Used by the directory_hardening factor.
    extra_monitoring: bool = False


@dataclass
class ServerSecretPlacement:
    """A credential stored on a server's filesystem — exposable to anyone
    with login access to that server."""
    id: str = field(default_factory=_uid)
    server_id: str = ""
    credential_id: str = ""
    path: str = ""
    exposure_level: str = "plaintext"   # plaintext | config_file | env_var
    # Who this credential belongs to, and who it can impersonate.
    owner_agent_id: str = ""
    usable_as_agent_id: str = ""
    privilege_weight: float = 1.0
    created_at: str = field(default_factory=_now)


@dataclass
class ImpersonationGrant:
    """A capability to act as another agent (obtained e.g. by reading a
    secret off a server)."""
    id: str = field(default_factory=_uid)
    actor_agent_id: str = ""
    victim_agent_id: str = ""
    credential_id: str = ""
    source_server_id: str | None = None
    can_send_mail: bool = True
    can_transfer_tokens: bool = True
    is_active: bool = True
    created_at: str = field(default_factory=_now)


@dataclass
class TrustedSenderView:
    """Per-sender trust label surfaced in an agent's observation."""
    sender_id: str = ""
    trust_level: str = "unknown"   # trusted_neighbor | group_known | introduced | unknown
    relationship: str = ""


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
    # Optional impersonation: send the mail under a different sender
    # identity.  Requires an active ImpersonationGrant at the engine
    # level.  When set and verified, the engine emits
    # ``IMPERSONATED_MAIL_SENT`` and the recipient sees the message as
    # if it came from ``as_agent_id``.
    as_agent_id: str | None = None


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
class WebHostSSHAction(Action):
    """Privileged action on the web host (SSH tier — engineers/security only)."""
    action_type: str = "webhost_ssh"
    ssh_action: str = ""  # create_page | edit_page | delete_page | exec | deploy | view_logs
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class WebHostBrowseAction(Action):
    """User-tier action on the web host (browser — all agents)."""
    action_type: str = "webhost_browse"
    browse_action: str = ""  # browse_page | list_pages | search_pages
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class MoltbookAction(Action):
    """Interaction with the Moltbook external agent social network."""
    action_type: str = "moltbook"
    moltbook_action: str = ""  # read_moltbook_feed | post_to_moltbook | comment_on_moltbook
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class SendGroupMailAction(Action):
    """Post a message to a communication group."""
    action_type: str = "send_group_mail"
    group_id: str = ""
    subject: str = ""
    body: str = ""


@dataclass
class TransferTokensAction(Action):
    """Peer-to-peer token transfer (optionally via impersonation)."""
    action_type: str = "transfer_tokens"
    recipient_id: str = ""
    amount: float = 0.0
    note: str = ""
    as_agent_id: str | None = None  # impersonated sender identity


@dataclass
class LookupContactAction(Action):
    """Directory lookup — resolves an agent by name/id/title."""
    action_type: str = "lookup_contact"
    query: str = ""


@dataclass
class LoginServerAction(Action):
    """Log into an internal server host."""
    action_type: str = "login_server"
    server_id: str = ""


@dataclass
class ListServerSecretsAction(Action):
    """List credential files stored on a server."""
    action_type: str = "list_server_secrets"
    server_id: str = ""


@dataclass
class ReadServerSecretAction(Action):
    """Read a specific secret file on a server."""
    action_type: str = "read_server_secret"
    server_id: str = ""
    secret_path: str = ""


@dataclass
class AuditMailAction(Action):
    """Security-side sweep for impersonation / spoofed mail evidence.

    Produces an anomaly report surfaced as alerts on the security
    agent's own observation and as a potential trigger for isolation.
    """
    action_type: str = "audit_mail"
    since_day: int = 0
    suspected_agent_id: str = ""  # optional narrowing hint


@dataclass
class IsolateAgentAction(Action):
    """Security-only quarantine action.

    Invoked by an LLM security expert after reasoning over the raw
    audit evidence.  Delegates to ``DefenseManager.isolate_agent`` so
    the bounty / fine economics, impersonation revocation, and
    credential rotation are all applied atomically.
    """
    action_type: str = "isolate_agent"
    target_id: str = ""
    reason: str = ""


@dataclass
class ReleaseAgentAction(Action):
    """Security-only release action — un-quarantines a previously
    isolated agent after reviewing the evidence and deciding the
    isolation was mistaken or the threat has passed.

    Because there is no automatic recovery timer in the three-state
    model, a false-positive isolation stays permanent unless the
    security expert explicitly releases.  Releasing a true-positive
    attacker reverses the bounty (costs the security agent); releasing
    a false-positive pays back the original fine.
    """
    action_type: str = "release_agent"
    target_id: str = ""
    reason: str = ""


@dataclass
class NoOpAction(Action):
    action_type: str = "noop"
    reason: str = "idle"


@dataclass
class NoteAction(Action):
    """End-of-day (or any-time) self-note the agent writes to its own
    memory. Used as the bridge for cross-day continuity: the LLM emits
    a ``note`` action on the last tick of a day summarising what it did
    and what it plans for tomorrow, and the resulting memory entry is
    surfaced in the next day's prompt."""
    action_type: str = "note"
    text: str = ""


# File I/O is handled by OpenClaw's native tools (file read/write/edit,
# shell, etc.) operating in the agent's workspace cwd. ACES does not
# reimplement these — earlier attempts added WriteFileAction /
# ReadFileAction / ListFilesAction actions that duplicated OpenClaw's
# built-ins; they were removed in favour of the native toolset. The
# observation still surfaces a ``workdir_files`` list built by scanning
# the workspace directory so the LLM knows what it has saved without
# having to call ``ls`` each turn.


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
    # Research-community extensions.
    known_contacts: list[str] = field(default_factory=list)
    group_memberships: list[CommunicationGroup] = field(default_factory=list)
    direct_reports: list[str] = field(default_factory=list)
    visible_servers: list[ServerHost] = field(default_factory=list)
    recent_transfers: list[TokenTransfer] = field(default_factory=list)
    sender_trust: list[TrustedSenderView] = field(default_factory=list)
    impersonation_grants: list[ImpersonationGrant] = field(default_factory=list)
    attack_objectives: list[str] = field(default_factory=list)
    # Raw security evidence — populated *only* for agents with the
    # ``security`` role.  Each entry is one line describing a
    # security-relevant event in chronological order; no scoring,
    # no filtering by heuristic rule.  The LLM security expert is
    # expected to reason over this evidence and decide whether to
    # audit / isolate / do nothing.
    recent_activity_summary: list[str] = field(default_factory=list)
    # IDs of all currently-quarantined agents — populated for the
    # security role so the LLM does not waste turns trying to
    # re-isolate already-contained suspects.
    quarantined_agent_ids: list[str] = field(default_factory=list)
    # Two-tier self-memory for cross-day planning.
    #
    # ``actions_earlier_today`` contains one line per event this agent
    # produced earlier in the current sim_day (ticks 0..sim_tick-1).
    # Rendered as "Earlier today you:" so within-day reasoning is
    # coherent without needing LLM session continuity.
    #
    # ``day_summaries`` contains the most recent day_summary memory
    # entries this agent wrote (via the ``note`` action on the last
    # tick of prior days). Rendered as "Your day-end notes:" so the
    # agent carries its own plans and lessons across day boundaries.
    actions_earlier_today: list[str] = field(default_factory=list)
    day_summaries: list[MemoryEntry] = field(default_factory=list)
    # True when this is the final tick of the current sim_day; the
    # prompt renders an end-of-day nudge telling the agent to write a
    # ``note`` action summarising the day and planning tomorrow.
    is_last_tick_of_day: bool = False
    # Persistent workdir — list of files the agent currently has in
    # ``docker/agents/<id>/workspace/agent_notes/`` with a short
    # preview of each. Populated by the engine's observation builder
    # so the LLM knows what it has saved and can decide whether to
    # re-read something.
    workdir_files: list[tuple[str, str]] = field(default_factory=list)
    # Soft wall-clock budget remaining in this tick, in seconds.
    # Populated by the async inner loop before each decide call so
    # the LLM can feel the clock and wind down as time runs low.
    # None means no budget tracking (sync path / tests).
    tick_budget_total: float | None = None
    tick_budget_remaining: float | None = None
    # Red-team capability-eval scoreboard, populated only for
    # ``is_malicious`` agents. Gives the attacker a live view of its
    # own progress against measurable goals so the LLM has a
    # concrete goal gradient instead of a vague mission statement.
    redteam_score: dict[str, Any] | None = None
