"""Enterprise services: mail, delegation, wiki, vault, IAM."""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass, field
from typing import Any

from .config import DefenseOverrides
from .database import Database
from .models import (
    AgentState, AttackClass, Credential, Delegation, DelegationStatus,
    DelegationType, Document, Event, EventType, LedgerEntry, LedgerEntryType,
    Message, MessageType, Zone, _now, _uid,
)
from .network import AccessControl, AccessDecision

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Mail service
# ---------------------------------------------------------------------------

class MailService:
    """Asynchronous enterprise mail routed through the simulator."""

    def __init__(self, db: Database, acl: AccessControl):
        self.db = db
        self.acl = acl

    def send(self, sender: AgentState, recipient_id: str,
             subject: str, body: str, *,
             zone: Zone = Zone.CORPNET,
             sim_day: int = 0, sim_tick: int = 0,
             is_attack: bool = False,
             attack_class: AttackClass | None = None,
             attack_payload: dict[str, Any] | None = None) -> Message | None:
        """Send a mail message. Returns None if blocked by ACL."""
        recipient = self.db.get_agent(recipient_id)
        if recipient is None:
            log.warning("mail: unknown recipient %s", recipient_id)
            return None
        check = self.acl.check_zone_access(sender, recipient.zone.value)
        if not check.allowed:
            log.info("mail blocked: %s → %s (%s)", sender.id, recipient_id, check.reason)
            return None
        msg = Message(
            sender_id=sender.id, recipient_id=recipient_id,
            subject=subject, body=body, zone=zone,
            is_attack=is_attack, attack_class=attack_class,
            attack_payload=attack_payload,
        )
        self.db.insert_message(msg)
        self.db.append_event(Event(
            event_type=EventType.MAIL_SENT, agent_id=sender.id,
            sim_day=sim_day, sim_tick=sim_tick, zone=zone,
            payload={"message_id": msg.id, "recipient": recipient_id,
                     "is_attack": is_attack},
        ))
        return msg

    def read_inbox(self, agent: AgentState, sim_day: int = 0,
                   sim_tick: int = 0) -> list[Message]:
        """Read and mark all unread messages for *agent*."""
        msgs = self.db.get_unread_messages(agent.id)
        for m in msgs:
            self.db.mark_read(m.id)
            self.db.append_event(Event(
                event_type=EventType.MAIL_READ, agent_id=agent.id,
                sim_day=sim_day, sim_tick=sim_tick, zone=m.zone,
                payload={"message_id": m.id, "is_attack": m.is_attack},
            ))
        return msgs


# ---------------------------------------------------------------------------
# Delegation service
# ---------------------------------------------------------------------------

class DelegationService:
    """Typed delegation requests and responses."""

    def __init__(self, db: Database, acl: AccessControl,
                 defenses: DefenseOverrides):
        self.db = db
        self.acl = acl
        self.require_typed = defenses.communication_discipline == "typed"
        self.clarification_gate = defenses.clarification_gate

    def request(self, requester: AgentState, delegate_id: str,
                delegation_type: DelegationType, description: str, *,
                job_id: str | None = None,
                payload: dict[str, Any] | None = None,
                sim_day: int = 0, sim_tick: int = 0) -> Delegation | None:
        delegate = self.db.get_agent(delegate_id)
        if delegate is None:
            return None
        check = self.acl.check_zone_access(requester, delegate.zone.value)
        if not check.allowed:
            log.info("delegation blocked: %s → %s (%s)",
                     requester.id, delegate_id, check.reason)
            return None
        needs_clarification = False
        if self.clarification_gate:
            # If the description is too short or the type is generic,
            # flag for clarification rather than auto-accepting.
            if len(description) < 20 or delegation_type == DelegationType.TASK:
                needs_clarification = True
        deleg = Delegation(
            requester_id=requester.id, delegate_id=delegate_id,
            job_id=job_id, delegation_type=delegation_type,
            description=description, payload=payload,
            requires_clarification=needs_clarification,
        )
        self.db.insert_delegation(deleg)
        self.db.append_event(Event(
            event_type=EventType.DELEGATION_REQUESTED,
            agent_id=requester.id, sim_day=sim_day, sim_tick=sim_tick,
            payload={"delegation_id": deleg.id, "delegate": delegate_id,
                     "type": delegation_type.value,
                     "needs_clarification": needs_clarification},
        ))
        return deleg

    def respond(self, delegate: AgentState, delegation_id: str,
                accept: bool, *, sim_day: int = 0, sim_tick: int = 0) -> None:
        status = DelegationStatus.ACCEPTED if accept else DelegationStatus.REJECTED
        self.db.update_delegation_status(delegation_id, status.value)
        self.db.append_event(Event(
            event_type=EventType.DELEGATION_RESPONDED,
            agent_id=delegate.id, sim_day=sim_day, sim_tick=sim_tick,
            payload={"delegation_id": delegation_id, "accepted": accept},
        ))


# ---------------------------------------------------------------------------
# Wiki / Document service
# ---------------------------------------------------------------------------

class WikiService:
    """Shared document creation and editing with optimistic concurrency."""

    def __init__(self, db: Database, acl: AccessControl):
        self.db = db
        self.acl = acl

    def create(self, author: AgentState, title: str, content: str,
               zone: Zone, *, sim_day: int = 0, sim_tick: int = 0) -> Document:
        doc = Document(
            title=title, content=content, zone=zone,
            author_id=author.id,
        )
        self.db.insert_document(doc)
        self.db.append_event(Event(
            event_type=EventType.DOCUMENT_CREATED,
            agent_id=author.id, sim_day=sim_day, sim_tick=sim_tick,
            zone=zone, payload={"document_id": doc.id, "title": title},
        ))
        return doc

    def read(self, agent: AgentState, doc_id: str) -> Document | None:
        doc = self.db.get_document(doc_id)
        if doc is None:
            return None
        check = self.acl.check_zone_access(agent, doc.zone.value)
        if not check.allowed:
            log.info("doc read blocked: agent=%s doc_zone=%s (%s)",
                     agent.id, doc.zone.value, check.reason)
            return None
        return doc

    def update(self, agent: AgentState, doc_id: str, new_content: str, *,
               sim_day: int = 0, sim_tick: int = 0,
               is_poisoned: bool = False,
               poison_payload: str | None = None) -> bool:
        doc = self.db.get_document(doc_id)
        if doc is None:
            return False
        check = self.acl.check_zone_access(agent, doc.zone.value)
        if not check.allowed:
            return False
        ok = self.db.update_document(
            doc_id, new_content, agent.id,
            is_poisoned=is_poisoned, poison_payload=poison_payload,
        )
        if ok:
            self.db.append_event(Event(
                event_type=EventType.DOCUMENT_UPDATED,
                agent_id=agent.id, sim_day=sim_day, sim_tick=sim_tick,
                zone=doc.zone,
                payload={"document_id": doc_id, "is_poisoned": is_poisoned},
            ))
        return ok

    def list_documents(self, agent: AgentState, zone: Zone) -> list[Document]:
        check = self.acl.check_zone_access(agent, zone.value)
        if not check.allowed:
            return []
        return self.db.get_documents_in_zone(zone.value)


# ---------------------------------------------------------------------------
# Vault service (credential management)
# ---------------------------------------------------------------------------

class VaultService:
    """Secret / credential storage, retrieval, and rotation."""

    def __init__(self, db: Database, acl: AccessControl,
                 defenses: DefenseOverrides):
        self.db = db
        self.acl = acl
        self.scoped = defenses.credential_scope == "scoped"
        self.rotation_enabled = defenses.credential_rotation
        self.rotation_interval = defenses.rotation_interval_days

    def issue(self, agent: AgentState, key_name: str, *,
              scope: str = "global",
              privilege_weight: float = 1.0,
              sim_day: int = 0, sim_tick: int = 0) -> Credential:
        """Issue a new credential to *agent*."""
        actual_scope = scope
        if self.scoped and scope == "global":
            actual_scope = agent.zone.value  # restrict to home zone
        cred = Credential(
            agent_id=agent.id, key_name=key_name,
            key_value=secrets.token_hex(16),
            scope=actual_scope, privilege_weight=privilege_weight,
        )
        self.db.insert_credential(cred)
        self.db.append_event(Event(
            event_type=EventType.CREDENTIAL_CREATED,
            agent_id=agent.id, sim_day=sim_day, sim_tick=sim_tick,
            payload={"credential_id": cred.id, "scope": actual_scope,
                     "key_name": key_name},
        ))
        return cred

    def access(self, agent: AgentState, cred_id: str, target_zone: str, *,
               sim_day: int = 0, sim_tick: int = 0) -> str | None:
        """Retrieve a credential value if access is allowed."""
        creds = self.db.get_agent_credentials(agent.id)
        cred = next((c for c in creds if c.id == cred_id), None)
        if cred is None:
            return None
        scope_ok = self.acl.check_credential_scope(agent, cred.scope, target_zone)
        if not scope_ok.allowed:
            log.info("credential access denied: agent=%s cred=%s zone=%s (%s)",
                     agent.id, cred_id, target_zone, scope_ok.reason)
            return None
        self.db.append_event(Event(
            event_type=EventType.CREDENTIAL_ACCESSED,
            agent_id=agent.id, sim_day=sim_day, sim_tick=sim_tick,
            payload={"credential_id": cred_id, "target_zone": target_zone},
        ))
        return cred.key_value

    def rotate(self, agent_id: str, sim_day: int = 0, sim_tick: int = 0) -> int:
        """Rotate all active credentials for *agent_id*. Returns count."""
        creds = self.db.get_agent_credentials(agent_id)
        rotated = 0
        for c in creds:
            new_val = secrets.token_hex(16)
            self.db.rotate_credential(c.id, new_val)
            rotated += 1
            self.db.append_event(Event(
                event_type=EventType.CREDENTIAL_ROTATED,
                agent_id=agent_id, sim_day=sim_day, sim_tick=sim_tick,
                payload={"credential_id": c.id},
            ))
        return rotated

    def revoke(self, cred_id: str, sim_day: int = 0, sim_tick: int = 0) -> None:
        self.db.revoke_credential(cred_id)

    def check_rotation_due(self, agent_id: str, current_day: int) -> bool:
        """Check if agent's credentials are due for rotation."""
        if not self.rotation_enabled:
            return False
        creds = self.db.get_agent_credentials(agent_id)
        for c in creds:
            # Simplified: check if credential was created/rotated more than
            # rotation_interval days ago (using sim_day tracking via events).
            if c.rotated_at is None:
                # Never rotated — check if old enough.
                return True  # conservative: rotate if never rotated
        return False


# ---------------------------------------------------------------------------
# IAM service
# ---------------------------------------------------------------------------

class IAMService:
    """Identity and access management — role and permission checks."""

    # Default role → allowed services mapping.
    ROLE_SERVICES: dict[str, set[str]] = {
        "manager": {"mail", "delegation", "wiki", "vault", "jobs", "iam"},
        "engineer": {"mail", "delegation", "wiki", "vault", "jobs", "repo", "ci"},
        "finance": {"mail", "delegation", "wiki", "vault", "payroll", "budget"},
        "hr": {"mail", "delegation", "wiki", "vault", "personnel"},
        "security": {"mail", "delegation", "wiki", "vault", "iam", "monitoring", "jobs", "moltbook"},
        "support": {"mail", "delegation", "wiki", "jobs", "ticketing", "moltbook"},
    }

    def __init__(self, acl: AccessControl):
        self.acl = acl

    def can_use_service(self, agent: AgentState, service: str) -> bool:
        allowed = self.ROLE_SERVICES.get(agent.role.value, set())
        return service in allowed

    def can_access_zone(self, agent: AgentState, zone: str) -> AccessDecision:
        return self.acl.check_zone_access(agent, zone)


# ---------------------------------------------------------------------------
# Service registry
# ---------------------------------------------------------------------------

@dataclass
class ServiceRegistry:
    """Central registry holding all enterprise services."""
    mail: MailService | None = None
    delegation: DelegationService | None = None
    wiki: WikiService | None = None
    vault: VaultService | None = None
    iam: IAMService | None = None
    moltbook: Any = None  # MoltbookService (imported lazily to avoid circular deps)

    @classmethod
    def build(cls, db: Database, acl: AccessControl,
              defenses: DefenseOverrides) -> "ServiceRegistry":
        return cls(
            mail=MailService(db, acl),
            delegation=DelegationService(db, acl, defenses),
            wiki=WikiService(db, acl),
            vault=VaultService(db, acl, defenses),
            iam=IAMService(acl),
        )
