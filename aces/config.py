"""Configuration loading and validation for ACES."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import AgentRole, AttackClass, Zone


# ---------------------------------------------------------------------------
# Configuration data classes
# ---------------------------------------------------------------------------

@dataclass
class KnownAgentDef:
    """A relationship entry in an agent's known-agents list."""
    id: str
    relationship: str = "peer"  # peer | manager | report | cross-team | external
    notes: str = ""


@dataclass
class MemoryPreload:
    """A memory entry to seed into an agent at world init."""
    category: str  # contacts | work | knowledge | observations
    key: str
    value: str


@dataclass
class AgentDef:
    """Definition of a single agent in the enterprise."""
    id: str
    name: str
    role: str  # maps to AgentRole
    zone: str  # maps to Zone (home zone)
    salary: float = 100.0
    initial_balance: float = 500.0
    allowed_zones: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    # Rich configuration.
    specialization: str = ""           # e.g. "backend infrastructure"
    expertise: list[str] = field(default_factory=list)  # ["Python", "CI/CD"]
    seniority: str = "mid"             # junior | mid | senior | lead
    # Relationships.
    known_agents: list[KnownAgentDef] = field(default_factory=list)
    # Domain knowledge this agent starts with.
    world_knowledge: list[str] = field(default_factory=list)
    # Memory entries populated at init.
    initial_memory: list[MemoryPreload] = field(default_factory=list)
    # Resources and access.
    services: list[str] = field(default_factory=list)   # repo, ci, monitoring, ...
    access_level: str = "standard"     # restricted | standard | elevated | admin
    # Personality.
    communication_style: str = "professional"  # concise | professional | verbose | casual
    initiative: str = "moderate"       # low | moderate | high
    caution_level: str = "moderate"    # low | moderate | high
    # Research-community extensions.
    title: str = ""                    # display title (CEO, CTO, ...)
    manager_id: str | None = None      # reporting relationship
    directory_scope: str = "neighbors" # neighbors | org | reports | groups
    is_malicious: bool = False         # this agent has attacker objectives
    attack_objectives: list[str] = field(default_factory=list)
    trusted_groups: list[str] = field(default_factory=list)


@dataclass
class CommunicationGroupDef:
    """A mailing-list group shared by several agents."""
    id: str
    name: str = ""
    description: str = ""
    posting_policy: str = "members"  # members | admins_only | moderated
    members: list[str] = field(default_factory=list)
    admins: list[str] = field(default_factory=list)


@dataclass
class TokenPolicyDef:
    """Governs peer-to-peer token transfers."""
    allow_peer_transfers: bool = True
    daily_transfer_cap: float = 600.0
    flagged_transfer_threshold: float = 250.0
    require_note: bool = True


@dataclass
class ServerDef:
    """An internal host an agent can log into."""
    id: str
    name: str = ""
    zone: str = "corpnet"
    tags: list[str] = field(default_factory=list)
    login_roles: list[str] = field(default_factory=list)
    admin_roles: list[str] = field(default_factory=list)
    description: str = ""
    extra_monitoring: bool = False


@dataclass
class SecretStorageDef:
    server_id: str
    path: str = ""
    exposure_level: str = "plaintext"


@dataclass
class SecretPlacementDef:
    """A credential placed on one or more servers."""
    owner_agent_id: str
    key_name: str
    privilege_weight: float = 1.0
    usable_as_agent_id: str | None = None
    stored_on: list[SecretStorageDef] = field(default_factory=list)


@dataclass
class ScenarioOverrides:
    """Structured overlay a condition can apply to the base enterprise.

    Backwards compatible with the older API that returned a
    :class:`DefenseOverrides` directly — attribute access falls through
    to ``resolved_defenses`` so legacy callers doing
    ``result.segmentation`` still work.  ``resolved_defenses`` is a
    declared optional field rather than a dynamic attribute so
    ``copy.deepcopy`` and equality behave predictably.
    """
    defenses: dict[str, Any] = field(default_factory=dict)
    enabled_agents: list[str] = field(default_factory=list)
    disabled_agents: list[str] = field(default_factory=list)
    agent_updates: dict[str, dict[str, Any]] = field(default_factory=dict)
    attack_updates: dict[str, dict[str, Any]] = field(default_factory=dict)
    server_updates: dict[str, dict[str, Any]] = field(default_factory=dict)
    group_updates: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Top-level knobs on AttackConfig itself (attacker_policy,
    # attack_density, etc.). Distinct from ``attack_updates`` which
    # patches individual attack templates by id.
    attacks: dict[str, Any] = field(default_factory=dict)
    resolved_defenses: "DefenseOverrides | None" = None
    # Unknown keys collected from the raw factor overrides — surfaced
    # via warnings so misconfigurations are visible instead of silently
    # ignored.
    unknown_defense_fields: list[str] = field(default_factory=list)
    unknown_agent_updates: list[tuple[str, str]] = field(default_factory=list)

    def __getattr__(self, name: str) -> Any:
        # Fall through to ``resolved_defenses`` so ``result.segmentation``
        # keeps working for legacy callers.  Only reached when the
        # attribute is not found via normal lookup.
        rd = self.__dict__.get("resolved_defenses")
        if rd is not None and hasattr(rd, name):
            return getattr(rd, name)
        raise AttributeError(name)


@dataclass
class ZoneDef:
    """Definition of a network zone."""
    name: str
    description: str = ""
    services: list[str] = field(default_factory=list)
    trust_level: str = "internal"  # internal | restricted | untrusted


@dataclass
class ZoneLink:
    """A directed connectivity rule between zones."""
    from_zone: str
    to_zone: str
    requires_bridge: bool = False
    allowed_roles: list[str] = field(default_factory=list)  # empty = all


@dataclass
class JobTemplateDef:
    """Template for generating routine jobs."""
    job_type: str
    title_pattern: str = ""
    zone: str = "corpnet"
    required_role: str | None = None
    priority: int = 0
    reward: float = 10.0
    penalty: float = 5.0
    deadline_days: int = 3
    frequency: float = 1.0  # expected count per sim-day
    requires_approval: bool = False


@dataclass
class AttackTemplateDef:
    """Template for an attack that can be injected."""
    id: str
    attack_class: str  # maps to AttackClass
    name: str = ""
    description: str = ""
    entry_point: str = "mail"  # mail | ticket | wiki | external | delegation |
                               # group_mail | server | token_transfer | impersonation
    target_roles: list[str] = field(default_factory=list)
    target_zones: list[str] = field(default_factory=list)
    target_groups: list[str] = field(default_factory=list)
    target_servers: list[str] = field(default_factory=list)
    source_agent_ids: list[str] = field(default_factory=list)
    severity: str = "medium"
    privilege_weight: float = 1.0
    payload: dict[str, Any] = field(default_factory=dict)
    earliest_day: int = 1
    latest_day: int = 30
    probability: float = 1.0  # probability of injection per eligible window


@dataclass
class FactorDef:
    """A binary experimental factor."""
    name: str
    description: str = ""
    level0_label: str = "off"
    level1_label: str = "on"
    level0_overrides: dict[str, Any] = field(default_factory=dict)
    level1_overrides: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Top-level configs
# ---------------------------------------------------------------------------

@dataclass
class EnterpriseConfig:
    """Full enterprise definition."""
    name: str = "default_enterprise"
    agents: list[AgentDef] = field(default_factory=list)
    zones: list[ZoneDef] = field(default_factory=list)
    zone_links: list[ZoneLink] = field(default_factory=list)
    job_templates: list[JobTemplateDef] = field(default_factory=list)
    # Research extensions — groups, token policy, servers, secrets.
    communication_groups: list[CommunicationGroupDef] = field(default_factory=list)
    token_policy: TokenPolicyDef = field(default_factory=TokenPolicyDef)
    servers: list[ServerDef] = field(default_factory=list)
    secret_placements: list[SecretPlacementDef] = field(default_factory=list)
    # Economic defaults
    salary_per_day: float = 100.0
    token_cost_per_1k: float = 0.50
    tool_cost_per_call: float = 0.10
    ticks_per_day: int = 6
    max_actions_per_tick: int = 3


@dataclass
class AttackConfig:
    """Attack suite definition.

    ``attacker_policy`` controls how the injector treats *insider*
    attack templates — those whose ``source_agent_ids`` names an
    in-simulation malicious agent (typically ``it_victor``):

    - ``"llm"`` (default): the injector plants an *opportunity* in the
      attacker's ``attack_objective`` memory describing the target
      (server, path, victim) and lets the attacker's LLM decide
      whether/when to act.  This is the autonomous-attacker mode the
      research is centered on.

    - ``"scripted"``: the legacy path — the injector calls services
      directly on the attacker's behalf (e.g. ``host_access.read_secret``,
      ``token_economy.transfer``).  Useful as a comparison baseline
      that holds the attacker's actions constant across conditions
      so the research can measure defense effects in isolation.

    - ``"passive"``: no attacks at all.  The malicious agent still
      exists but receives no objectives and the injector does
      nothing.  Used as a community-only control.

    External attacks (mail/ticket/wiki/external entry points)
    represent outside adversaries and are always scripted in both
    ``llm`` and ``scripted`` modes.  Only ``passive`` silences them.
    """
    templates: list[AttackTemplateDef] = field(default_factory=list)
    attack_density: float = 1.0  # multiplier on injection probability
    enabled_classes: list[str] = field(default_factory=lambda: [
        "credential_leak", "disruption", "token_drain", "poisoning",
    ])
    attacker_policy: str = "llm"  # llm | scripted | passive


@dataclass
class DefenseOverrides:
    """Overrides applied when a defense factor is active."""
    segmentation: str = "flat"  # flat | weak | strong
    credential_scope: str = "broad"  # broad | scoped
    credential_rotation: bool = False
    rotation_interval_days: int = 5
    communication_discipline: str = "free"  # free | typed
    clarification_gate: bool = False
    # Peer-to-peer transfer cap (distinct from LLM spend_cap — LLM
    # tokens and money movement are different constraints).  Defaults
    # to 0, meaning "not configured"; the token-economy service falls
    # back to TokenPolicyDef.daily_transfer_cap in that case.
    transfer_cap_per_day: float = 0.0
    unknown_sender_requires_verification: bool = False
    group_moderation: bool = False
    # ------------------------------------------------------------
    # Rule-based anomaly detector — **default OFF**.
    # ------------------------------------------------------------
    # The rule-based scoring model below is intentionally disabled
    # by default.  The research question is "can an LLM security
    # expert detect an LLM attacker", so baking detection rules into
    # the simulator bypasses the LLM's judgment.  Set this flag to
    # ``True`` only when you want a handcrafted baseline to compare
    # against the LLM-driven detection pathway.  When off, the
    # security agent still has access to raw evidence via (a) the
    # ``recent_activity_summary`` field in their observation and
    # (b) the ``AuditMailAction`` tool which dumps recent events.
    enable_rule_based_anomaly_detection: bool = False
    anomaly_threshold: float = 3.0
    anomaly_weight_impersonated_mail: float = 2.0
    anomaly_weight_impersonated_transfer: float = 2.0
    anomaly_weight_secret_read: float = 1.0
    anomaly_window_days: int = 2
    # How many days of raw events to include in the security agent's
    # ``recent_activity_summary`` observation slice.  This is LLM-
    # driven — no scoring, no pre-filtering, just a chronological
    # dump for the model to reason over.
    security_view_window_days: int = 3
    security_view_limit: int = 30
    bounty_amount: float = 75.0
    fine_amount: float = 30.0
    # Post-compromise credential rotation.  When True, the defense
    # manager rotates credentials for any COMPROMISED or QUARANTINED
    # agent at the end-of-day barrier, which also invalidates any
    # active impersonation grants backed by those credentials.  Kept
    # as a defense knob because it's a deterministic operational
    # action, not a rule-based reasoning shortcut.
    recovery_key_rotation: bool = False


@dataclass
class ExperimentConfig:
    """Experiment design definition."""
    name: str = "default_experiment"
    description: str = ""
    factors: list[FactorDef] = field(default_factory=list)
    design: str = "full_factorial"  # full_factorial | fractional
    fractional_resolution: int = 3
    seeds: list[int] = field(default_factory=lambda: [42])
    days_per_run: int = 30
    early_stop_insolvency: bool = True
    insolvency_threshold: float = -1000.0
    early_stop_full_compromise: bool = True
    # CSRI component weights: [confidentiality, availability, economic, spread].
    csri_weights: list[float] = field(default_factory=lambda: [0.25, 0.25, 0.25, 0.25])
    # Baseline defense settings
    baseline_defenses: DefenseOverrides = field(default_factory=DefenseOverrides)


@dataclass
class ACESConfig:
    """Root configuration combining all parts."""
    enterprise: EnterpriseConfig = field(default_factory=EnterpriseConfig)
    attacks: AttackConfig = field(default_factory=AttackConfig)
    experiment: ExperimentConfig = field(default_factory=ExperimentConfig)
    defenses: DefenseOverrides = field(default_factory=DefenseOverrides)
    db_path: str = "aces_data.db"
    log_level: str = "INFO"
    llm_backend: str = "openai"  # openclaw | anthropic | openai | openrouter | together | ollama | ...
    llm_model: str = ""
    llm_api_key: str = ""
    llm_base_url: str = ""     # auto-detected for known providers; override for custom endpoints
    # Reasoning-model budget control ("minimal" | "low" | "medium" |
    # "high").  Forwarded as a flat ``reasoning_effort`` field on
    # every chat/completions request.  ``low`` on gpt-5-family and
    # codex-spark models cuts completion tokens ~10-30x on short
    # structured tasks like agent action selection.
    llm_reasoning_effort: str | None = None
    # Concurrency cap for the async engine — the LLM runtime gates
    # in-flight requests with a semaphore of this size.  Pick a value
    # compatible with your provider's RPM ceiling.
    llm_concurrency: int = 16
    llm_request_timeout: float = 60.0
    llm_max_tokens: int = 512
    llm_temperature: float = 0.2
    # Arbitrary provider-specific fields merged verbatim into every
    # request body.  Useful for one-off knobs the simulator doesn't
    # model explicitly.
    llm_extra_params: dict[str, Any] = field(default_factory=dict)
    # When true, SimulationEngine.run_async is used instead of the
    # serial run().  The runtime must have a working decide_async
    # implementation (LLMAgentRuntime does by default; StubRuntime
    # falls back via asyncio.to_thread).
    use_async_engine: bool = False
    openclaw_base_url: str = "http://localhost:18789"
    moltbook_url: str = "http://moltbook:3000/api/v1"  # self-hosted default; override for public
    moltbook_api_key: str = ""
    moltbook_submolt: str = "enterprise"
    output_dir: str = "results"
    # The ScenarioOverrides that produced this config's final defense
    # state. Non-default when the config was built by
    # ``apply_condition_overrides``; carries server/group/agent/attack
    # overlays that the engine must consult at ``init_world`` time.
    scenario_overrides: "ScenarioOverrides | None" = None


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def _build_agent_def(d: dict) -> AgentDef:
    known = [
        KnownAgentDef(
            id=k["id"],
            relationship=k.get("relationship", "peer"),
            notes=k.get("notes", ""),
        )
        for k in d.get("known_agents", [])
    ]
    mem = [
        MemoryPreload(
            category=m["category"], key=m["key"], value=m["value"],
        )
        for m in d.get("initial_memory", [])
    ]
    return AgentDef(
        id=d["id"],
        name=d.get("name", d["id"]),
        role=d["role"],
        zone=d["zone"],
        salary=d.get("salary", 100.0),
        initial_balance=d.get("initial_balance", 500.0),
        allowed_zones=d.get("allowed_zones", []),
        tools=d.get("tools", []),
        specialization=d.get("specialization", ""),
        expertise=d.get("expertise", []),
        seniority=d.get("seniority", "mid"),
        known_agents=known,
        world_knowledge=d.get("world_knowledge", []),
        initial_memory=mem,
        services=d.get("services", []),
        access_level=d.get("access_level", "standard"),
        communication_style=d.get("communication_style", "professional"),
        initiative=d.get("initiative", "moderate"),
        caution_level=d.get("caution_level", "moderate"),
        title=d.get("title", ""),
        manager_id=d.get("manager_id"),
        directory_scope=d.get("directory_scope", "neighbors"),
        is_malicious=d.get("is_malicious", False),
        attack_objectives=d.get("attack_objectives", []),
        trusted_groups=d.get("trusted_groups", []),
    )


def _build_zone_def(d: dict) -> ZoneDef:
    return ZoneDef(
        name=d["name"],
        description=d.get("description", ""),
        services=d.get("services", []),
        trust_level=d.get("trust_level", "internal"),
    )


def _build_zone_link(d: dict) -> ZoneLink:
    return ZoneLink(
        from_zone=d["from_zone"],
        to_zone=d["to_zone"],
        requires_bridge=d.get("requires_bridge", False),
        allowed_roles=d.get("allowed_roles", []),
    )


def _build_job_template(d: dict) -> JobTemplateDef:
    return JobTemplateDef(
        job_type=d["job_type"],
        title_pattern=d.get("title_pattern", ""),
        zone=d.get("zone", "corpnet"),
        required_role=d.get("required_role"),
        priority=d.get("priority", 0),
        reward=d.get("reward", 10.0),
        penalty=d.get("penalty", 5.0),
        deadline_days=d.get("deadline_days", 3),
        frequency=d.get("frequency", 1.0),
        requires_approval=d.get("requires_approval", False),
    )


def _build_attack_template(d: dict) -> AttackTemplateDef:
    return AttackTemplateDef(
        id=d["id"],
        attack_class=d["attack_class"],
        name=d.get("name", d["id"]),
        description=d.get("description", ""),
        entry_point=d.get("entry_point", "mail"),
        target_roles=d.get("target_roles", []),
        target_zones=d.get("target_zones", []),
        target_groups=d.get("target_groups", []),
        target_servers=d.get("target_servers", []),
        source_agent_ids=d.get("source_agent_ids", []),
        severity=d.get("severity", "medium"),
        privilege_weight=d.get("privilege_weight", 1.0),
        payload=d.get("payload", {}),
        earliest_day=d.get("earliest_day", 1),
        latest_day=d.get("latest_day", 30),
        probability=d.get("probability", 1.0),
    )


def _build_group(d: dict) -> CommunicationGroupDef:
    return CommunicationGroupDef(
        id=d["id"],
        name=d.get("name", d["id"]),
        description=d.get("description", ""),
        posting_policy=d.get("posting_policy", "members"),
        members=list(d.get("members", [])),
        admins=list(d.get("admins", [])),
    )


def _build_token_policy(d: dict) -> TokenPolicyDef:
    return TokenPolicyDef(
        allow_peer_transfers=d.get("allow_peer_transfers", True),
        daily_transfer_cap=d.get("daily_transfer_cap", 600.0),
        flagged_transfer_threshold=d.get("flagged_transfer_threshold", 250.0),
        require_note=d.get("require_note", True),
    )


def _build_server(d: dict) -> ServerDef:
    return ServerDef(
        id=d["id"],
        name=d.get("name", d["id"]),
        zone=d.get("zone", "corpnet"),
        tags=list(d.get("tags", [])),
        login_roles=list(d.get("login_roles", [])),
        admin_roles=list(d.get("admin_roles", [])),
        description=d.get("description", ""),
        extra_monitoring=bool(d.get("extra_monitoring", False)),
    )


def _build_secret_placement(d: dict) -> SecretPlacementDef:
    stored = []
    for s in d.get("stored_on", []):
        stored.append(SecretStorageDef(
            server_id=s["server_id"],
            path=s.get("path", ""),
            exposure_level=s.get("exposure_level", "plaintext"),
        ))
    return SecretPlacementDef(
        owner_agent_id=d["owner_agent_id"],
        key_name=d["key_name"],
        privilege_weight=d.get("privilege_weight", 1.0),
        usable_as_agent_id=d.get("usable_as_agent_id"),
        stored_on=stored,
    )


def _build_factor(d: dict) -> FactorDef:
    return FactorDef(
        name=d["name"],
        description=d.get("description", ""),
        level0_label=d.get("level0_label", "off"),
        level1_label=d.get("level1_label", "on"),
        level0_overrides=d.get("level0_overrides", {}),
        level1_overrides=d.get("level1_overrides", {}),
    )


def _build_defense_overrides(d: dict) -> DefenseOverrides:
    ov = DefenseOverrides()
    for k, v in d.items():
        if hasattr(ov, k):
            setattr(ov, k, v)
    return ov


def load_yaml(path: str | Path) -> dict:
    with open(path) as f:
        return yaml.safe_load(f) or {}


def load_enterprise_config(data: dict) -> EnterpriseConfig:
    ec = EnterpriseConfig(name=data.get("name", "default_enterprise"))
    ec.agents = [_build_agent_def(a) for a in data.get("agents", [])]
    ec.zones = [_build_zone_def(z) for z in data.get("zones", [])]
    ec.zone_links = [_build_zone_link(l) for l in data.get("zone_links", [])]
    ec.job_templates = [_build_job_template(j) for j in data.get("job_templates", [])]
    ec.communication_groups = [_build_group(g)
                                for g in data.get("communication_groups", [])]
    if "token_policy" in data:
        ec.token_policy = _build_token_policy(data["token_policy"])
    ec.servers = [_build_server(s) for s in data.get("servers", [])]
    ec.secret_placements = [_build_secret_placement(p)
                             for p in data.get("secret_placements", [])]
    for key in ("salary_per_day", "token_cost_per_1k", "tool_cost_per_call",
                "ticks_per_day", "max_actions_per_tick"):
        if key in data:
            setattr(ec, key, data[key])
    return ec


def load_attack_config(data: dict) -> AttackConfig:
    ac = AttackConfig()
    ac.templates = [_build_attack_template(t) for t in data.get("templates", [])]
    ac.attack_density = data.get("attack_density", 1.0)
    ac.enabled_classes = data.get("enabled_classes", ac.enabled_classes)
    policy = data.get("attacker_policy", "llm")
    if policy not in ("llm", "scripted", "passive"):
        raise ValueError(
            f"attacker_policy must be llm|scripted|passive, got {policy!r}")
    ac.attacker_policy = policy
    return ac


def load_experiment_config(data: dict) -> ExperimentConfig:
    xc = ExperimentConfig(
        name=data.get("name", "default_experiment"),
        description=data.get("description", ""),
    )
    xc.factors = [_build_factor(f) for f in data.get("factors", [])]
    xc.design = data.get("design", "full_factorial")
    xc.fractional_resolution = data.get("fractional_resolution", 3)
    xc.seeds = data.get("seeds", [42])
    xc.days_per_run = data.get("days_per_run", 30)
    xc.early_stop_insolvency = data.get("early_stop_insolvency", True)
    xc.insolvency_threshold = data.get("insolvency_threshold", -1000.0)
    xc.early_stop_full_compromise = data.get("early_stop_full_compromise", True)
    if "baseline_defenses" in data:
        xc.baseline_defenses = _build_defense_overrides(data["baseline_defenses"])
    return xc


def load_config(
    enterprise_path: str | Path | None = None,
    experiment_path: str | Path | None = None,
    attack_path: str | Path | None = None,
    overrides: dict[str, Any] | None = None,
) -> ACESConfig:
    """Load and merge configuration from YAML files."""
    cfg = ACESConfig()

    if enterprise_path:
        cfg.enterprise = load_enterprise_config(load_yaml(enterprise_path))
    if attack_path:
        cfg.attacks = load_attack_config(load_yaml(attack_path))
    if experiment_path:
        cfg.experiment = load_experiment_config(load_yaml(experiment_path))

    # Start with baseline defenses from experiment config
    cfg.defenses = copy.deepcopy(cfg.experiment.baseline_defenses)

    if overrides:
        for k, v in overrides.items():
            if hasattr(cfg, k):
                setattr(cfg, k, v)

    return cfg


def apply_condition_overrides(
    base_defenses: DefenseOverrides,
    factor_levels: dict[str, int],
    factors: list[FactorDef],
) -> ScenarioOverrides:
    """Apply factor-level overrides to produce a condition-specific overlay.

    Returns a ``ScenarioOverrides`` containing both the resulting defense
    configuration (``defenses`` — a dict, so it can be applied to a
    ``DefenseOverrides`` instance or inspected as structured data) and
    agent/server/group overlays used by the engine to materialize a
    condition-specific world.

    The overrides in each factor level can be:

    - a flat dict of ``DefenseOverrides`` field names (legacy form), or
    - a structured dict with the keys ``defenses``, ``enabled_agents``,
      ``disabled_agents``, ``agent_updates``, ``attack_updates``,
      ``server_updates``, ``group_updates``.

    Both forms are supported for backward compatibility.
    """
    defenses = copy.deepcopy(base_defenses)
    overlay = ScenarioOverrides()

    for factor in factors:
        level = factor_levels.get(factor.name, 0)
        raw = factor.level1_overrides if level == 1 else factor.level0_overrides

        # Detect structured form vs legacy flat form.
        structured_keys = {
            "defenses", "enabled_agents", "disabled_agents",
            "agent_updates", "attack_updates", "server_updates",
            "group_updates", "attacks",
        }
        if any(k in structured_keys for k in raw):
            # Structured form.
            for k, v in raw.get("defenses", {}).items():
                if hasattr(defenses, k):
                    setattr(defenses, k, v)
                else:
                    overlay.unknown_defense_fields.append(k)
            overlay.enabled_agents.extend(raw.get("enabled_agents", []))
            overlay.disabled_agents.extend(raw.get("disabled_agents", []))
            for aid, patch in raw.get("agent_updates", {}).items():
                overlay.agent_updates.setdefault(aid, {}).update(patch)
            for aid, patch in raw.get("attack_updates", {}).items():
                overlay.attack_updates.setdefault(aid, {}).update(patch)
            for sid, patch in raw.get("server_updates", {}).items():
                overlay.server_updates.setdefault(sid, {}).update(patch)
            for gid, patch in raw.get("group_updates", {}).items():
                overlay.group_updates.setdefault(gid, {}).update(patch)
            overlay.attacks.update(raw.get("attacks", {}))
        else:
            # Legacy flat form — treated entirely as defense fields.
            for k, v in raw.items():
                if hasattr(defenses, k):
                    setattr(defenses, k, v)
                else:
                    overlay.unknown_defense_fields.append(k)

    # Resolve the concrete defenses and a serializable snapshot.
    overlay.resolved_defenses = defenses
    overlay.defenses = {
        f: getattr(defenses, f)
        for f in [
            "segmentation", "credential_scope", "credential_rotation",
            "rotation_interval_days", "communication_discipline",
            "clarification_gate", "transfer_cap_per_day",
            "unknown_sender_requires_verification", "group_moderation",
            "enable_rule_based_anomaly_detection",
            "anomaly_threshold", "anomaly_weight_impersonated_mail",
            "anomaly_weight_impersonated_transfer",
            "anomaly_weight_secret_read", "anomaly_window_days",
            "security_view_window_days", "security_view_limit",
            "bounty_amount", "fine_amount", "recovery_key_rotation",
        ]
    }
    return overlay
