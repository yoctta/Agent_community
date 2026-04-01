"""Network zone topology and access control enforcement."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from .config import DefenseOverrides, EnterpriseConfig, ZoneDef, ZoneLink
from .models import AgentRole, AgentState, AgentStatus, Zone

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
