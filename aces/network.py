"""Network zone topology, social trust graph, and access control."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from .config import DefenseOverrides, EnterpriseConfig, ZoneLink
from .models import AgentState, AgentStatus, Zone

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Default topology rules
# ---------------------------------------------------------------------------

# Flat topology: every zone can reach every other zone.
FLAT_LINKS: list[tuple[str, str]] = [
    (z1.value, z2.value)
    for z1 in Zone for z2 in Zone
]

# Weak segmentation: internal zones are fully connected; ExtNet can reach
# CorpNet only. No direct external→FinNet/SecNet.
WEAK_DENY: set[tuple[str, str]] = {
    ("extnet", "finnet"),
    ("extnet", "secnet"),
    ("extnet", "engnet"),
}

# Strong segmentation: each zone can reach CorpNet (hub), and CorpNet can
# reach every zone. Cross-zone traffic requires traversing CorpNet plus an
# explicit bridge or role-based rule.
STRONG_DIRECT: set[tuple[str, str]] = {
    ("corpnet", z.value) for z in Zone
} | {
    (z.value, "corpnet") for z in Zone
}


@dataclass
class AccessDecision:
    allowed: bool
    reason: str = ""


@dataclass
class ZoneTopology:
    """Determines reachability between zones given segmentation level."""

    segmentation: str = "flat"  # flat | weak | strong
    # Explicit links loaded from config (override defaults).
    explicit_links: list[ZoneLink] = field(default_factory=list)
    # Role-based bridge overrides: (from, to) → set of allowed roles.
    bridge_roles: dict[tuple[str, str], set[str]] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def from_config(cls, enterprise: EnterpriseConfig,
                    defenses: DefenseOverrides) -> "ZoneTopology":
        topo = cls(segmentation=defenses.segmentation)
        topo.explicit_links = list(enterprise.zone_links)
        for link in enterprise.zone_links:
            if link.allowed_roles:
                key = (link.from_zone, link.to_zone)
                topo.bridge_roles[key] = set(link.allowed_roles)
        return topo

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def can_reach(self, from_zone: str, to_zone: str,
                  agent: AgentState | None = None) -> AccessDecision:
        """Check if traffic from *from_zone* to *to_zone* is allowed."""
        if from_zone == to_zone:
            return AccessDecision(True)

        # Quarantined agents cannot reach anything outside their own zone.
        if agent and agent.status == AgentStatus.QUARANTINED:
            return AccessDecision(False, "agent is quarantined")

        # Check explicit links first (they take precedence).
        for link in self.explicit_links:
            if link.from_zone == from_zone and link.to_zone == to_zone:
                if link.allowed_roles and agent:
                    if agent.role.value not in link.allowed_roles:
                        return AccessDecision(
                            False,
                            f"role {agent.role.value} not in bridge allowlist",
                        )
                return AccessDecision(True)

        # Fall back to segmentation-level defaults.
        if self.segmentation == "flat":
            return AccessDecision(True)

        if self.segmentation == "weak":
            if (from_zone, to_zone) in WEAK_DENY:
                return AccessDecision(False, "denied by weak segmentation")
            return AccessDecision(True)

        if self.segmentation == "strong":
            if (from_zone, to_zone) in STRONG_DIRECT:
                return AccessDecision(True)
            # Check role-based bridge override.
            key = (from_zone, to_zone)
            if key in self.bridge_roles:
                if agent and agent.role.value in self.bridge_roles[key]:
                    return AccessDecision(True)
                return AccessDecision(False, "bridge requires specific role")
            return AccessDecision(False, "denied by strong segmentation")

        # Unknown segmentation level → deny.
        return AccessDecision(False, f"unknown segmentation: {self.segmentation}")

    def reachable_zones(self, from_zone: str,
                        agent: AgentState | None = None) -> list[str]:
        """Return all zones reachable from *from_zone*."""
        return [
            z.value for z in Zone
            if self.can_reach(from_zone, z.value, agent).allowed
        ]


# ---------------------------------------------------------------------------
# Access control layer (wraps topology + credential scope checks)
# ---------------------------------------------------------------------------

@dataclass
class AccessControl:
    """Enforces zone access and credential-scope policies."""

    topology: ZoneTopology
    credential_scope: str = "broad"  # broad | scoped

    @classmethod
    def from_config(cls, enterprise: EnterpriseConfig,
                    defenses: DefenseOverrides) -> "AccessControl":
        return cls(
            topology=ZoneTopology.from_config(enterprise, defenses),
            credential_scope=defenses.credential_scope,
        )

    def check_zone_access(self, agent: AgentState,
                          target_zone: str) -> AccessDecision:
        return self.topology.can_reach(agent.zone.value, target_zone, agent)

    def check_credential_scope(self, agent: AgentState,
                               cred_scope: str,
                               target_zone: str) -> AccessDecision:
        """Check whether a credential's scope allows use in *target_zone*."""
        if self.credential_scope == "broad":
            return AccessDecision(True)
        # Scoped credentials: scope must match target zone or be "global".
        if cred_scope in ("global", target_zone):
            return AccessDecision(True)
        return AccessDecision(
            False,
            f"credential scope '{cred_scope}' does not cover zone '{target_zone}'",
        )

    def check_service_access(self, agent: AgentState,
                             service_zone: str,
                             service_name: str) -> AccessDecision:
        """Check if agent can use a service hosted in *service_zone*."""
        zone_ok = self.check_zone_access(agent, service_zone)
        if not zone_ok.allowed:
            return zone_ok
        return AccessDecision(True)


# ---------------------------------------------------------------------------
# Social trust graph (Layer B — who knows whom socially)
# ---------------------------------------------------------------------------

@dataclass
class SocialTrustGraph:
    """Second-layer graph describing who trusts whom socially.

    Populated at world init from ``AgentDef.known_agents`` and
    ``AgentDef.manager_id``.  Used by ``CommunicationPolicy`` to classify
    senders as ``trusted_neighbor``, ``group_known``, ``introduced``, or
    ``unknown``.  This is intentionally separate from the zone topology —
    an agent may be able to *reach* another zone without socially
    trusting anyone in it.
    """

    # agent_id -> set of (other_agent_id, relationship_label)
    _neighbors: dict[str, dict[str, str]] = field(default_factory=dict)

    @classmethod
    def from_config(cls, enterprise: EnterpriseConfig) -> "SocialTrustGraph":
        """Build the social graph.

        Explicit ``known_agents`` labels win: they're authoritative
        descriptions of the working relationship.  The ``manager_id``
        bidirectional pass only *adds* edges that don't already exist,
        so e.g. `sec_david.manager_id == exec_tom` + explicit
        `exec_tom.known_agents[sec_david] = "cross-team"` preserves
        the cross-team annotation on the CEO side.
        """
        g = cls()
        # Pass 1: explicit known_agents edges.
        for a in enterprise.agents:
            g._neighbors.setdefault(a.id, {})
            for ka in a.known_agents:
                g._neighbors[a.id][ka.id] = ka.relationship
        # Pass 2: manager/report edges — only fill gaps, never overwrite.
        for a in enterprise.agents:
            if not a.manager_id:
                continue
            g._neighbors.setdefault(a.id, {}).setdefault(
                a.manager_id, "manager")
            g._neighbors.setdefault(a.manager_id, {}).setdefault(
                a.id, "report")
        return g

    def is_trusted_neighbor(self, a_id: str, b_id: str) -> bool:
        return b_id in self._neighbors.get(a_id, {})

    def relationship(self, a_id: str, b_id: str) -> str:
        return self._neighbors.get(a_id, {}).get(b_id, "")

    def neighbors(self, agent_id: str) -> list[str]:
        return list(self._neighbors.get(agent_id, {}).keys())

    def direct_reports(self, agent_id: str) -> list[str]:
        return [
            other for other, rel in self._neighbors.get(agent_id, {}).items()
            if rel == "report"
        ]

    def add_introduction(self, a_id: str, b_id: str,
                          label: str = "introduced") -> None:
        self._neighbors.setdefault(a_id, {})[b_id] = label
        self._neighbors.setdefault(b_id, {})[a_id] = label


# ---------------------------------------------------------------------------
# Communication policy (Layer B helper)
# ---------------------------------------------------------------------------

@dataclass
class CommunicationPolicy:
    """Governs who can look up whom, send directly, and post to groups.

    This is intentionally decoupled from ``AccessControl`` — directory
    lookup and sender-trust labelling are social concerns, not zone-level
    firewall concerns.  The engine wires a ``CommunicationPolicy`` for
    the ``DirectoryService`` and for observation assembly.
    """
    trust: SocialTrustGraph

    def can_lookup_contact(self, agent: AgentState, target_id: str) -> bool:
        """True if *agent* can resolve *target_id* via the directory.

        ``directory_scope`` is authoritative — role is never used as a
        bypass.  Configure an agent's scope explicitly:

        - ``"org"``      — can resolve any agent (HR lead, security, CEO)
        - ``"reports"``  — can resolve direct reports only
        - ``"groups"``   — can resolve any co-member of a group
        - ``"neighbors"``— can resolve already-known colleagues only
        """
        scope = agent.directory_scope or "neighbors"
        if scope == "org":
            return True
        if scope == "reports":
            return target_id in self.trust.direct_reports(agent.id)
        if scope == "groups":
            # Any agent we share a group with (resolved by caller
            # since CommunicationPolicy does not own group state).
            return self.trust.is_trusted_neighbor(agent.id, target_id)
        # Default: neighbor-only lookup.
        return self.trust.is_trusted_neighbor(agent.id, target_id)

    def sender_trust_level(self, recipient: AgentState, sender_id: str,
                            shared_group: bool = False) -> str:
        if self.trust.is_trusted_neighbor(recipient.id, sender_id):
            rel = self.trust.relationship(recipient.id, sender_id)
            # "introduced" or "introduced_by:X" are weaker than a
            # direct working relationship; surface them as introduced.
            if rel == "introduced" or rel.startswith("introduced_by:"):
                return "introduced"
            return "trusted_neighbor"
        if shared_group:
            return "group_known"
        return "unknown"

    def can_direct_message(self, sender: AgentState, recipient: AgentState,
                            shared_group: bool = False) -> bool:
        """True if *sender* is allowed to deliver direct mail to *recipient*.

        The delivery gate is intentionally looser than the trust label:
        - if no trust graph is configured (empty world), allow — this
          keeps legacy configs that never declared ``known_agents``
          working in permissive mode
        - trusted neighbours (both directions) pass
        - co-members of any group pass
        - senders that the recipient can resolve via their directory
          scope pass (the recipient already considers them look-up-able)
        - agents in either side's direct-report chain pass
        - senders with ``directory_scope`` of ``"org"`` (HR, security,
          executives with org scope) can always reach any agent
        - everyone else is blocked — this is what makes social trust
          load-bearing instead of advisory.
        """
        if sender.id == recipient.id:
            return True
        # Permissive default when the configured trust graph is empty.
        # Research scenarios populate known_agents + manager_id, so
        # the graph is non-empty and this branch is skipped there.
        if not self.trust._neighbors:
            return True
        if self.trust.is_trusted_neighbor(sender.id, recipient.id):
            return True
        if self.trust.is_trusted_neighbor(recipient.id, sender.id):
            return True
        if shared_group:
            return True
        if sender.directory_scope == "org":
            return True
        # Recipients with org scope can receive anything — they are
        # inherently a support/escalation channel.
        if recipient.directory_scope == "org":
            return True
        # Managers can reach their own reports.
        if sender.id in self.trust.direct_reports(recipient.id):
            return True
        if recipient.id in self.trust.direct_reports(sender.id):
            return True
        return False
