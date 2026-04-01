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
    phases: list[str] = field(default_factory=list)
    requires_approval: bool = False


@dataclass
class AttackTemplateDef:
    """Template for an attack that can be injected."""
    id: str
    attack_class: str  # maps to AttackClass
    name: str = ""
    description: str = ""
    entry_point: str = "mail"  # mail | ticket | wiki | external | delegation
    target_roles: list[str] = field(default_factory=list)
    target_zones: list[str] = field(default_factory=list)
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
    # Economic defaults
    salary_per_day: float = 100.0
    token_cost_per_1k: float = 0.50
    tool_cost_per_call: float = 0.10
    ticks_per_day: int = 6
    max_actions_per_tick: int = 3


@dataclass
class AttackConfig:
    """Attack suite definition."""
    templates: list[AttackTemplateDef] = field(default_factory=list)
    attack_density: float = 1.0  # multiplier on injection probability
    enabled_classes: list[str] = field(default_factory=lambda: [
        "credential_leak", "disruption", "token_drain", "poisoning",
    ])


@dataclass
class DefenseOverrides:
    """Overrides applied when a defense factor is active."""
    segmentation: str = "flat"  # flat | weak | strong
    credential_scope: str = "broad"  # broad | scoped
    credential_rotation: bool = False
    rotation_interval_days: int = 5
    communication_discipline: str = "free"  # free | typed
    clarification_gate: bool = False
    spend_cap_enabled: bool = False
    spend_cap_per_day: float = 500.0
    spend_cap_action: str = "downgrade"  # downgrade | block
    recovery_quarantine: bool = False
    recovery_trust_decay: bool = False
    trust_decay_rate: float = 0.1
    recovery_key_rotation: bool = False
    loop_detection: bool = True
    loop_max_repeats: int = 5


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
    openclaw_base_url: str = "http://localhost:18789"
    moltbook_url: str = "http://moltbook:3000/api/v1"  # self-hosted default; override for public
    moltbook_api_key: str = ""
    moltbook_submolt: str = "enterprise"
    output_dir: str = "results"


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
        phases=d.get("phases", []),
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
        severity=d.get("severity", "medium"),
        privilege_weight=d.get("privilege_weight", 1.0),
        payload=d.get("payload", {}),
        earliest_day=d.get("earliest_day", 1),
        latest_day=d.get("latest_day", 30),
        probability=d.get("probability", 1.0),
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
) -> DefenseOverrides:
    """Apply factor-level overrides to produce a condition-specific defense config."""
    result = copy.deepcopy(base_defenses)
    for factor in factors:
        level = factor_levels.get(factor.name, 0)
        overrides = factor.level1_overrides if level == 1 else factor.level0_overrides
        for k, v in overrides.items():
            if hasattr(result, k):
                setattr(result, k, v)
    return result
