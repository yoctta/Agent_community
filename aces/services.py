"""Enterprise services: mail, delegation, wiki, vault, IAM,
directory, group mail, token economy, host access, impersonation."""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from typing import Any

from .config import DefenseOverrides, TokenPolicyDef
from .database import Database
from .models import (
    AgentState, AgentStatus, AttackClass, CommunicationGroup,
    Credential, Delegation, DelegationStatus, DelegationType, Document,
    Event, EventType, ImpersonationGrant, LedgerEntry, LedgerEntryType,
    Message, ServerHost, ServerSecretPlacement, TokenTransfer,
    Zone,
)
from .network import AccessControl, AccessDecision, CommunicationPolicy, SocialTrustGraph

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Mail service
# ---------------------------------------------------------------------------

class MailService:
    """Asynchronous enterprise mail routed through the simulator."""

    def __init__(self, db: Database, acl: AccessControl,
                 comms_policy: "CommunicationPolicy | None" = None,
                 defenses: DefenseOverrides | None = None):
        self.db = db
        self.acl = acl
        self.comms_policy = comms_policy
        self.defenses = defenses or DefenseOverrides()

    def send(self, sender: AgentState, recipient_id: str,
             subject: str, body: str, *,
             zone: Zone = Zone.CORPNET,
             sim_day: int = 0, sim_tick: int = 0,
             is_attack: bool = False,
             attack_class: AttackClass | None = None,
             attack_payload: dict[str, Any] | None = None,
             actor: AgentState | None = None,
             trust_override: str | None = None) -> Message | None:
        """Send a mail message. Returns None if blocked.

        When *actor* is supplied and differs from *sender*, this is an
        impersonated send: ``sender`` is the effective identity the
        recipient sees, and ``actor`` is the real agent doing the work.
        The caller (engine) is responsible for verifying the
        impersonation grant before invoking this.

        ``trust_override`` lets callers (e.g. attack injector) force a
        specific trust label so verification-gate defenses can treat
        spoofed mail as unknown even if the sender is a neighbour.
        """
        recipient = self.db.get_agent(recipient_id)
        if recipient is None:
            log.warning("mail: unknown recipient %s", recipient_id)
            return None
        check = self.acl.check_zone_access(sender, recipient.zone.value)
        if not check.allowed:
            log.info("mail blocked: %s → %s (%s)", sender.id, recipient_id, check.reason)
            return None

        # Compute trust level first so defenses can reason about it
        # regardless of whether this is an attack send.  The policy
        # delivery gate (D2) is skipped for attacks — their whole
        # premise is reaching untrusted agents — but D1 still applies.
        shared_group = False
        trust_level = "unknown"
        if self.comms_policy is not None:
            shared_group = self._shares_group(sender.id, recipient.id)
            trust_level = self.comms_policy.sender_trust_level(
                recipient, sender.id, shared_group=shared_group)
        if trust_override is not None:
            trust_level = trust_override
        if self.comms_policy is not None and not is_attack:
            if not self.comms_policy.can_direct_message(
                    sender, recipient, shared_group=shared_group):
                log.info("mail blocked by comms policy: %s → %s (level=%s)",
                         sender.id, recipient_id, trust_level)
                return None

        # Defense D1 — unknown_sender_requires_verification.  When the
        # defense is active and the sender is unknown to the recipient,
        # refuse delivery.  A future enhancement could queue the mail
        # for explicit approval; a hard block is simpler and sufficient
        # for the factorial study.
        if (self.defenses.unknown_sender_requires_verification
                and trust_level == "unknown"):
            log.info("mail blocked by verification gate: %s → %s",
                     sender.id, recipient_id)
            return None

        via_imp = actor is not None and actor.id != sender.id
        msg = Message(
            sender_id=sender.id, recipient_id=recipient_id,
            subject=subject, body=body, zone=zone,
            is_attack=is_attack, attack_class=attack_class,
            attack_payload=attack_payload,
        )
        self.db.insert_message(msg)
        self.db.append_event(Event(
            event_type=(EventType.IMPERSONATED_MAIL_SENT if via_imp
                         else EventType.MAIL_SENT),
            agent_id=(actor.id if actor is not None else sender.id),
            sim_day=sim_day, sim_tick=sim_tick, zone=zone,
            payload={"message_id": msg.id, "recipient": recipient_id,
                     "is_attack": is_attack,
                     "effective_sender": sender.id,
                     "via_impersonation": via_imp,
                     "trust_level": trust_level},
        ))
        return msg

    def _shares_group(self, a_id: str, b_id: str) -> bool:
        groups = self.db.get_agent_groups(a_id)
        for g in groups:
            if b_id in g.members:
                return True
        return False

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
# Directory service — HR / org-wide contact lookup
# ---------------------------------------------------------------------------

class DirectoryService:
    """Resolves agents by id, name, title, or role.

    Enforces per-agent ``directory_scope`` via ``CommunicationPolicy``.
    HR, security, and executives typically have ``directory_scope: org``
    so they can resolve any agent; engineers only see their neighbors.
    """

    def __init__(self, db: Database, policy: CommunicationPolicy):
        self.db = db
        self.policy = policy

    def lookup(self, agent: AgentState, query: str) -> list[AgentState]:
        q = (query or "").strip().lower()
        if not q:
            return []
        results: list[AgentState] = []
        for candidate in self.db.get_all_agents():
            if candidate.id == agent.id:
                continue
            hay = " ".join([
                candidate.id, candidate.name or "",
                candidate.title or "", candidate.role.value,
            ]).lower()
            if q not in hay:
                continue
            if not self.policy.can_lookup_contact(agent, candidate.id):
                continue
            results.append(candidate)
        if results:
            self.db.append_event(Event(
                event_type=EventType.CONTACT_LOOKUP,
                agent_id=agent.id,
                payload={"query": query,
                         "matches": [c.id for c in results[:10]]},
            ))
        return results

    def can_lookup(self, agent: AgentState, target_id: str) -> bool:
        return self.policy.can_lookup_contact(agent, target_id)

    def share_contact(self, from_agent: AgentState, target_id: str,
                       with_agent_id: str) -> bool:
        """Introduce *target_id* to *with_agent_id* via the social graph.

        Records the introducer so the receiver can see *who* vouched
        for the new contact — a weak but real trust signal.
        """
        label = f"introduced_by:{from_agent.id}"
        self.policy.trust.add_introduction(with_agent_id, target_id, label)
        return True


# ---------------------------------------------------------------------------
# Group mail service
# ---------------------------------------------------------------------------

class GroupMailService:
    """Fan-out mail to the members of a communication group."""

    def __init__(self, db: Database, acl: AccessControl,
                 defenses: DefenseOverrides | None = None):
        self.db = db
        self.acl = acl
        self.defenses = defenses or DefenseOverrides()

    def list_groups(self, agent: AgentState) -> list[CommunicationGroup]:
        return self.db.get_agent_groups(agent.id)

    def send_group(self, sender: AgentState, group_id: str,
                    subject: str, body: str, *,
                    sim_day: int = 0, sim_tick: int = 0) -> int | None:
        """Fan out a group post.

        Returns the number of recipients delivered to on success (>=0),
        or ``None`` if the post was blocked (unknown group, posting
        policy violation, or quarantined sender).  ``0`` is a legitimate
        success — e.g. a solo-member group that only contains the sender.
        """
        if sender.status == AgentStatus.QUARANTINED:
            return None
        group = self.db.get_group(group_id)
        if group is None:
            return None
        # Check posting policy.
        if group.posting_policy == "admins_only":
            if sender.id not in group.admins:
                log.info("group mail blocked: %s not admin of %s",
                         sender.id, group_id)
                return None
        elif group.posting_policy == "members":
            if sender.id not in group.members:
                log.info("group mail blocked: %s not member of %s",
                         sender.id, group_id)
                return None
        elif group.posting_policy == "moderated":
            if sender.id not in group.members:
                return None
            # D4: when the group_moderation defense is active, moderated
            # groups fall back to admin-only delivery — non-admin posts
            # are silently dropped (equivalent to "queued for approval
            # and never approved" for this simulation).
            if (self.defenses.group_moderation
                    and sender.id not in group.admins):
                log.info("moderated group %s: blocked non-admin post from %s",
                         group_id, sender.id)
                return None

        # Fan out: one message per recipient, each recorded as a group post.
        delivered = 0
        for recipient_id in group.members:
            if recipient_id == sender.id:
                continue
            msg = Message(
                sender_id=sender.id, recipient_id=recipient_id,
                subject=f"[{group.name}] {subject}", body=body,
                zone=sender.zone,
            )
            self.db.insert_message(msg)
            delivered += 1
        self.db.append_event(Event(
            event_type=EventType.GROUP_MAIL_SENT, agent_id=sender.id,
            sim_day=sim_day, sim_tick=sim_tick, zone=sender.zone,
            payload={"group_id": group_id, "subject": subject,
                     "recipients": delivered},
        ))
        return delivered


# ---------------------------------------------------------------------------
# Token economy service — peer transfers, caps, bounty/fine
# ---------------------------------------------------------------------------

class TokenEconomyService:
    """Moves value between agent wallets and records a ledger entry."""

    def __init__(self, db: Database, policy: TokenPolicyDef,
                 defenses: DefenseOverrides):
        self.db = db
        self.policy = policy
        self.defenses = defenses

    def transfer(self, actor: AgentState, sender_identity: AgentState,
                 recipient_id: str, amount: float, note: str = "", *,
                 sim_day: int = 0, sim_tick: int = 0,
                 via_impersonation: bool = False) -> TokenTransfer | None:
        if not self.policy.allow_peer_transfers:
            return None
        if amount <= 0:
            return None
        if self.policy.require_note and not note:
            return None
        # Quarantined actors cannot move money.
        if actor.status == AgentStatus.QUARANTINED:
            return None
        # Auto-detect impersonation: if the actor is acting as someone
        # else, mark the transfer so downstream metrics can attribute it.
        if actor.id != sender_identity.id:
            via_impersonation = True
        recipient = self.db.get_agent(recipient_id)
        if recipient is None or recipient.id == sender_identity.id:
            return None
        # Refuse to transfer on behalf of a quarantined victim — even
        # if the caller already has an impersonation grant, the
        # target's isolation must halt further abuse.
        sender_fresh = self.db.get_agent(sender_identity.id)
        if sender_fresh is None:
            return None
        if sender_fresh.status == AgentStatus.QUARANTINED:
            return None
        # Overdraft protection: refuse to push the effective sender's
        # balance negative.  Without this a single impersonated
        # transfer could drain the victim arbitrarily deep and skew
        # the community-balance outcome metric.
        if sender_fresh.wallet_balance < amount:
            log.info("transfer blocked: %s insufficient funds (%.2f < %.2f)",
                     sender_identity.id, sender_fresh.wallet_balance, amount)
            return None

        # Enforce daily cap against the *effective sender* identity.
        # DefenseOverrides.transfer_cap_per_day (>0) tightens the
        # policy cap; we never loosen it.
        sent_today = self.db.sum_transfers_sent_today(sender_identity.id, sim_day)
        cap = self.policy.daily_transfer_cap
        if self.defenses.transfer_cap_per_day > 0:
            cap = min(cap, self.defenses.transfer_cap_per_day)
        if sent_today + amount > cap:
            log.info("transfer blocked: %s would exceed cap (sent=%.2f new=%.2f cap=%.2f)",
                     sender_identity.id, sent_today, amount, cap)
            return None

        recipient_fresh = self.db.get_agent(recipient_id)
        if recipient_fresh is None:
            return None
        sender_fresh.wallet_balance -= amount
        recipient_fresh.wallet_balance += amount
        self.db.update_agent(sender_fresh)
        self.db.update_agent(recipient_fresh)

        tx = TokenTransfer(
            actor_agent_id=actor.id,
            effective_sender_id=sender_identity.id,
            recipient_id=recipient_id,
            amount=amount, note=note,
            sim_day=sim_day, sim_tick=sim_tick,
            via_impersonation=via_impersonation,
        )
        self.db.insert_token_transfer(tx)
        self.db.insert_ledger_entry(LedgerEntry(
            agent_id=sender_identity.id,
            entry_type=LedgerEntryType.TRANSFER_OUT,
            amount=-amount,
            description=f"transfer to {recipient_id}: {note}",
            sim_day=sim_day,
        ))
        self.db.insert_ledger_entry(LedgerEntry(
            agent_id=recipient_id,
            entry_type=LedgerEntryType.TRANSFER_IN,
            amount=amount,
            description=f"transfer from {sender_identity.id}: {note}",
            sim_day=sim_day,
        ))
        self.db.append_event(Event(
            event_type=(EventType.IMPERSONATED_TRANSFER
                         if via_impersonation else EventType.TOKEN_TRANSFER),
            agent_id=actor.id, sim_day=sim_day, sim_tick=sim_tick,
            payload={"transfer_id": tx.id, "amount": amount,
                     "effective_sender": sender_identity.id,
                     "recipient": recipient_id,
                     "via_impersonation": via_impersonation},
        ))
        return tx

    def recent_transfers(self, agent_id: str,
                          limit: int = 10) -> list[TokenTransfer]:
        return self.db.get_recent_transfers(agent_id, limit)

    def community_balance_excluding(self, agent_ids: list[str]) -> float:
        total = 0.0
        for a in self.db.get_all_agents():
            if a.id in agent_ids:
                continue
            total += a.wallet_balance
        return total


# ---------------------------------------------------------------------------
# Host access service — login, list secrets, read secrets
# ---------------------------------------------------------------------------

class HostAccessService:
    """Gates server login and secret reads, issues impersonation grants
    when a secret with ``usable_as_agent_id`` is read."""

    def __init__(self, db: Database, acl: AccessControl,
                 impersonation: "ImpersonationService"):
        self.db = db
        self.acl = acl
        self.impersonation = impersonation

    def list_servers(self, agent: AgentState) -> list[ServerHost]:
        out: list[ServerHost] = []
        for srv in self.db.get_all_servers():
            # Reachable in the network AND allowed by role.
            if not self.acl.check_zone_access(agent, srv.zone.value).allowed:
                continue
            if srv.login_roles and agent.role not in srv.login_roles:
                continue
            out.append(srv)
        return out

    def _authorize(self, agent: AgentState, server_id: str) -> ServerHost | None:
        """Silent access check.  Returns the server if the agent is
        permitted to log in, otherwise None.  Does NOT emit an event —
        callers log their own operation-specific event."""
        if agent.status == AgentStatus.QUARANTINED:
            return None
        srv = self.db.get_server(server_id)
        if srv is None:
            return None
        if not self.acl.check_zone_access(agent, srv.zone.value).allowed:
            return None
        if srv.login_roles and agent.role not in srv.login_roles:
            return None
        return srv

    def login(self, agent: AgentState, server_id: str, *,
              sim_day: int = 0, sim_tick: int = 0) -> ServerHost | None:
        """Public login action — emits a SERVER_LOGIN event."""
        srv = self._authorize(agent, server_id)
        if srv is None:
            return None
        self.db.append_event(Event(
            event_type=EventType.SERVER_LOGIN,
            agent_id=agent.id, sim_day=sim_day, sim_tick=sim_tick,
            zone=srv.zone,
            payload={"server_id": server_id,
                     "tripwire": bool(srv.extra_monitoring)},
        ))
        return srv

    def list_secrets(self, agent: AgentState, server_id: str, *,
                      sim_day: int = 0, sim_tick: int = 0) -> list[ServerSecretPlacement]:
        srv = self._authorize(agent, server_id)
        if srv is None:
            return []
        secrets_ = self.db.list_server_secrets(server_id)
        self.db.append_event(Event(
            event_type=EventType.SERVER_SECRET_LISTED,
            agent_id=agent.id, sim_day=sim_day, sim_tick=sim_tick,
            zone=srv.zone,
            payload={"server_id": server_id,
                     "count": len(secrets_),
                     "tripwire": bool(srv.extra_monitoring)},
        ))
        return secrets_

    def read_secret(self, agent: AgentState, server_id: str, secret_path: str, *,
                     sim_day: int = 0, sim_tick: int = 0) -> ImpersonationGrant | None:
        srv = self._authorize(agent, server_id)
        if srv is None:
            return None
        secret = self.db.get_server_secret(server_id, secret_path)
        if secret is None:
            return None
        self.db.append_event(Event(
            event_type=EventType.SERVER_SECRET_READ,
            agent_id=agent.id, sim_day=sim_day, sim_tick=sim_tick,
            zone=srv.zone,
            payload={"server_id": server_id, "path": secret_path,
                     "owner": secret.owner_agent_id,
                     "privilege_weight": secret.privilege_weight,
                     "tripwire": bool(srv.extra_monitoring)},
        ))
        # If this secret is usable to impersonate someone, issue a grant.
        victim_id = secret.usable_as_agent_id or secret.owner_agent_id
        if not victim_id:
            return None
        return self.impersonation.grant_from_credential(
            actor=agent, victim_id=victim_id,
            credential_id=secret.credential_id,
            server_id=server_id,
            sim_day=sim_day, sim_tick=sim_tick,
        )


# ---------------------------------------------------------------------------
# Impersonation service — grant / check / revoke
# ---------------------------------------------------------------------------

class ImpersonationService:
    def __init__(self, db: Database):
        self.db = db

    def grant_from_credential(self, actor: AgentState, victim_id: str,
                                credential_id: str,
                                server_id: str | None = None, *,
                                sim_day: int = 0, sim_tick: int = 0) -> ImpersonationGrant:
        grant = ImpersonationGrant(
            actor_agent_id=actor.id,
            victim_agent_id=victim_id,
            credential_id=credential_id,
            source_server_id=server_id,
        )
        self.db.insert_impersonation_grant(grant)
        self.db.append_event(Event(
            event_type=EventType.IMPERSONATION_GRANTED,
            agent_id=actor.id, sim_day=sim_day, sim_tick=sim_tick,
            payload={"grant_id": grant.id, "victim": victim_id,
                     "credential_id": credential_id,
                     "source_server_id": server_id},
        ))
        return grant

    def can_impersonate(self, actor_id: str, victim_id: str,
                         capability: str = "send_mail") -> bool:
        grant = self.db.get_active_grant(actor_id, victim_id)
        if grant is None:
            return False
        if capability == "send_mail":
            return grant.can_send_mail
        if capability == "transfer_tokens":
            return grant.can_transfer_tokens
        return True

    def revoke_for_victim(self, victim_id: str) -> int:
        return self.db.revoke_grants_for_victim(victim_id)

    def revoke_by_credential(self, credential_id: str) -> int:
        return self.db.revoke_grants_by_credential(credential_id)


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
    webhost: Any = None   # WebHostService
    # Research-community services.
    directory: DirectoryService | None = None
    group_mail: GroupMailService | None = None
    token_economy: TokenEconomyService | None = None
    host_access: HostAccessService | None = None
    impersonation: ImpersonationService | None = None

    @classmethod
    def build(cls, db: Database, acl: AccessControl,
              defenses: DefenseOverrides,
              *,
              social: SocialTrustGraph | None = None,
              token_policy: TokenPolicyDef | None = None) -> "ServiceRegistry":
        imp = ImpersonationService(db)
        policy = CommunicationPolicy(trust=social or SocialTrustGraph())
        return cls(
            mail=MailService(db, acl, comms_policy=policy, defenses=defenses),
            delegation=DelegationService(db, acl, defenses),
            wiki=WikiService(db, acl),
            vault=VaultService(db, acl, defenses),
            iam=IAMService(acl),
            directory=DirectoryService(db, policy),
            group_mail=GroupMailService(db, acl, defenses=defenses),
            token_economy=TokenEconomyService(db,
                                              token_policy or TokenPolicyDef(),
                                              defenses),
            host_access=HostAccessService(db, acl, imp),
            impersonation=imp,
        )
