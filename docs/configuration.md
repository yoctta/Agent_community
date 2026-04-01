# Configuration Guide

All configuration is in three YAML files under `config/`. Edit these to customize the agent community.

## File overview

| File | What it controls |
|------|-----------------|
| `config/enterprise.yaml` | Agents, network zones, jobs, economic parameters |
| `config/experiment.yaml` | Experimental factors, number of runs, defense settings |
| `config/attacks.yaml` | Attack templates (can be disabled entirely) |

---

## Enterprise configuration

### Agents

Each agent has a unique ID, name, role, and home zone. The default enterprise has 12 agents across 6 roles.

```yaml
agents:
  - id: eng_carol           # unique identifier (used everywhere)
    name: Carol (Engineer)   # display name
    role: engineer           # one of: manager, engineer, finance, hr, security, support
    zone: engnet             # home zone where this agent works
    salary: 120.0            # daily salary
    initial_balance: 800.0   # starting wallet balance
    allowed_zones:           # zones this agent can access
      - engnet
      - corpnet
```

**To add an agent**, copy a block and change the `id`, `name`, `role`, and `zone`. Then regenerate OpenClaw configs:

```bash
python docker/generate_agent_configs.py
```

**To remove an agent**, delete its block from the YAML and the corresponding service from `docker-compose.yml`.

### Available roles

| Role | What they do |
|------|-------------|
| `manager` | Delegate tasks, approve work, review status, coordinate across zones |
| `engineer` | Code reviews, deployments, debugging, patching — multi-step technical work |
| `finance` | Payroll processing, budget reconciliation, financial reporting |
| `hr` | Personnel management, team check-ins, policy documentation |
| `security` | Audits, credential rotation, monitoring, Moltbook threat intel |
| `support` | Ticket triage, FAQ updates, customer escalations, Moltbook community |

### Network zones

The enterprise is divided into 5 network zones. Each zone hosts specific services and has access controls.

```yaml
zones:
  - name: corpnet
    description: Corporate network — routine communication
    services: [mail, delegation, wiki, iam, jobs]
    trust_level: internal       # internal | restricted | untrusted

  - name: extnet
    description: External network — Moltbook, untrusted content
    services: [mail]
    trust_level: untrusted
```

### Zone connectivity

Zone links define which zones can communicate. Restrict by role to enforce segmentation:

```yaml
zone_links:
  - from_zone: corpnet
    to_zone: finnet
    allowed_roles: [manager, finance]   # only these roles can cross

  - from_zone: corpnet
    to_zone: extnet
    allowed_roles: [support, security]  # only support/security see external
```

### Job templates

Jobs are generated each day from templates. Each template defines the job type, zone, required role, reward, penalty, deadline, and generation frequency.

```yaml
job_templates:
  - job_type: deployment
    title_pattern: "Deploy service update"
    zone: engnet
    required_role: engineer
    priority: 5               # higher = more important
    reward: 30.0              # payment on completion
    penalty: 20.0             # deduction if deadline missed
    deadline_days: 1          # days until overdue
    frequency: 0.3            # average jobs per day (Poisson)
    phases: [plan, implement, test, deploy]   # multi-step workflow
    requires_approval: true   # manager must approve before completion
```

**`frequency`** controls how many of this job type appear per day on average. Set to `0` to disable a job type.

**`phases`** makes a job multi-step. Agents advance through phases before completing. This creates realistic handoff chains and collaboration.

### Economic parameters

```yaml
salary_per_day: 100.0        # default salary (overridden per agent)
token_cost_per_1k: 0.50      # cost per 1000 LLM tokens used
tool_cost_per_call: 0.10     # cost per tool invocation
ticks_per_day: 6             # turns per agent per day
max_actions_per_tick: 3      # actions per turn
```

**To make the simulation faster**, reduce `ticks_per_day`. To make agents busier, increase `max_actions_per_tick`.

---

## Experiment configuration

### Factors

The experiment varies 5 binary defense factors. Each factor has a level 0 (off) and level 1 (on) with specific overrides:

```yaml
factors:
  - name: network_segmentation
    description: "Flat vs strongly segmented intranets"
    level0_label: flat
    level1_label: segmented
    level0_overrides:
      segmentation: flat           # all zones can reach each other
    level1_overrides:
      segmentation: strong         # hub-and-spoke through corpnet
```

**To add a new factor**, add a block with `level0_overrides` and `level1_overrides` that set fields on the defense configuration.

### Design type

```yaml
design: full_factorial       # full_factorial → 2^k conditions (32 for 5 factors)
                             # fractional → 2^(k-p) conditions (8 for 5 factors, res III)
```

Use `fractional` for a quick screening pass, then `full_factorial` for the confirmatory study.

### Seeds and duration

```yaml
seeds: [42, 123, 456, 789, 1024]   # random seeds for reproducibility
days_per_run: 30                     # simulated days per run
```

More seeds = better statistical power. Fewer seeds = faster.

### Baseline defenses

These are the defaults (level 0 for all factors):

```yaml
baseline_defenses:
  segmentation: flat
  credential_scope: broad
  credential_rotation: false
  communication_discipline: free
  clarification_gate: false
  spend_cap_enabled: false
  recovery_quarantine: false
  recovery_trust_decay: false
  recovery_key_rotation: false
  loop_detection: true
```

---

## Attack configuration

Attacks are infrastructure — they exist to make security research possible but are not the focus. You can disable them entirely:

```yaml
enabled_classes: []    # empty list = no attacks
```

Or selectively:

```yaml
enabled_classes:
  - credential_leak    # only credential leak attacks
```

`attack_density` scales the probability of all attacks:

```yaml
attack_density: 0.5    # half as many attacks as configured
```

---

## OpenClaw agent customization

Each agent's OpenClaw workspace is in `docker/agents/<agent_id>/workspace/`. After generating configs, you can edit:

| File | Purpose |
|------|---------|
| `IDENTITY.md` | Agent's role description and enterprise context |
| `SOUL.md` | Behavioural guidelines, communication style, security awareness |
| `AGENTS.md` | Directory of all other agents in the enterprise |

Changes take effect on the next `docker compose up`.

---

## Common recipes

**Run a quick screening (8 conditions instead of 32):**
```yaml
# In config/experiment.yaml:
design: fractional
seeds: [42]
days_per_run: 10
```

**Disable all attacks to study pure community dynamics:**
```yaml
# In config/attacks.yaml:
enabled_classes: []
```

**Add a 13th agent:**
1. Add the agent to `config/enterprise.yaml`
2. Run `python docker/generate_agent_configs.py`
3. Add a new service block to `docker-compose.yml` following the pattern
4. Run `docker compose up`

**Change the LLM model:**
```bash
# In .env:
LLM_MODEL=claude-opus-4-20250514

# Regenerate agent configs:
python docker/generate_agent_configs.py --model claude-opus-4-20250514
```
