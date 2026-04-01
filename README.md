# ACES — Agent Community Enterprise Simulator

A configurable framework for running persistent, multi-agent enterprise simulations where autonomous AI agents collaborate, communicate, and work across segmented intranets.

Each agent is a fully autonomous [OpenClaw](https://github.com/openclaw/openclaw) instance with its own role, workspace, credentials, wallet, and LLM connection. Agents interact through mediated enterprise services — mail, typed delegation, shared wiki, credential vault — and engage with the broader agent community via [Moltbook](https://moltbook.com) (external agent social network). The simulation produces rich, replayable event traces suitable for studying community dynamics, coordination patterns, and security properties.

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                    YAML Configuration                      │
│   enterprise.yaml     experiment.yaml     attacks.yaml     │
└────────────┬───────────────┬───────────────┬───────────────┘
             │               │               │
             ▼               ▼               ▼
┌────────────────────────────────────────────────────────────┐
│              Simulation Engine (Python)                     │
│                                                            │
│   Day loop: generate jobs → inject events → agent turns    │
│   Tick loop: shuffle order → observe → decide → execute    │
│   Barrier: payroll → penalties → defenses → metrics        │
└──────┬────────────┬────────────┬────────────┬──────────────┘
       │            │            │            │
       ▼            ▼            ▼            ▼
  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌──────────┐
  │OpenClaw │ │OpenClaw │ │OpenClaw │ │OpenClaw  │
  │ Alice   │ │  Carol  │ │  Jack   │ │  Leo     │
  │(Manager)│ │(Engineer│ │(Security│ │(Support) │
  │ :18701  │ │ :18703  │ │ :18710  │ │ :18712   │
  └─────────┘ └─────────┘ └─────────┘ └──────────┘
       ×12 agents, each in its own gateway
```

**12 agents** across 6 roles (manager, engineer, finance, HR, security, support) operate in **5 network zones** (CorpNet, EngNet, FinNet, SecNet, ExtNet) with configurable segmentation, credential policies, and communication discipline.

## Quickstart

### Option A: Mock agents (no LLM, no Docker — instant)

```bash
pip install pyyaml
python run_experiment.py single --backend mock --seed 42
```

### Option B: Docker Compose with OpenClaw agents

```bash
# 1. Configure
cp .env.example .env              # add your LLM_API_KEY

# 2. Generate per-agent OpenClaw workspaces
python docker/generate_agent_configs.py

# 3. Run
docker compose up
```

This starts 12 OpenClaw gateways (one per agent) and the ACES simulator. Each agent reasons with its own LLM connection and calls enterprise tools autonomously.

### Option C: Full experiment (32 conditions x 5 seeds)

```bash
docker compose run simulator run
```

## What happens during a simulation

Each simulated day (30 days per run by default):

1. **Jobs generated** — payroll batches, code reviews, deployments, support tickets, security audits (Poisson-sampled from templates)
2. **Agent turns** — 6 ticks per day, each agent gets up to 3 actions per tick:
   - Read mail and respond contextually
   - Claim and work on jobs (multi-step: plan → implement → test → deploy)
   - Delegate tasks to role-appropriate colleagues
   - Request and provide peer reviews
   - Update wiki with findings
   - Read and post on Moltbook
3. **Barrier phase** — salaries paid, overdue jobs penalized, defenses evaluated, metrics snapshotted

A typical 30-day run produces ~8,600 events: 1,100 organic mails, 500 delegations, 120 wiki edits, 60 Moltbook posts, and 260 jobs across the enterprise.

## Configuration

All configuration lives in three YAML files under `config/`. See [docs/configuration.md](docs/configuration.md) for the full reference.

| File | Controls |
|------|----------|
| `config/enterprise.yaml` | Agents (roles, zones, salaries), network topology, job templates, economic parameters |
| `config/experiment.yaml` | Experimental factors, factorial design, seeds, defense baselines |
| `config/attacks.yaml` | Attack templates and density (can be disabled entirely) |

### Adding an agent

Add a block to `config/enterprise.yaml`:

```yaml
agents:
  - id: eng_mallory
    name: Mallory (Engineer)
    role: engineer
    zone: engnet
    salary: 120.0
    initial_balance: 800.0
    allowed_zones: [engnet, corpnet]
```

Then regenerate OpenClaw configs: `python docker/generate_agent_configs.py`

### Tuning the simulation

```yaml
# Faster runs (fewer ticks, shorter duration)
ticks_per_day: 3
max_actions_per_tick: 2

# In experiment.yaml
days_per_run: 10
seeds: [42]
design: fractional          # 8 conditions instead of 32
```

### Disabling attacks

```yaml
# In attacks.yaml
enabled_classes: []
```

## Project structure

```
aces/                        # Core Python package
  models.py                  # Data model: Agent, Job, Message, Credential, Event, Action, ...
  config.py                  # YAML config loading and validation
  database.py                # SQLite persistence (per-run)
  network.py                 # Zone topology and access control (flat/weak/strong)
  services.py                # Enterprise services: mail, delegation, wiki, vault, IAM
  moltbook.py                # Moltbook integration (ExtNet social network)
  runtime.py                 # Agent runtime: mock (rule-based) + LLM adapter
  openclaw_runtime.py         # OpenClaw gateway integration (tool-calling)
  engine.py                  # Simulation engine: day/tick loop, turns, barrier
  attacks.py                 # Attack injection framework
  defenses.py                # Defense mechanisms: spend caps, trust decay, quarantine
  metrics.py                 # Outcome measures: PWCL, JCR, TWR, blast radius, CSRI
  experiment.py              # Factorial design, condition generation, multi-run orchestration
  cli.py                     # Command-line interface

config/                      # YAML configuration
  enterprise.yaml            # 12 agents, 5 zones, 10 job templates
  experiment.yaml            # 5 binary factors, factorial design
  attacks.yaml               # 10 attack templates across 4 classes

docker/                      # Docker infrastructure
  generate_agent_configs.py  # Creates per-agent OpenClaw workspaces from enterprise.yaml

docs/
  quickstart.md              # Getting started guide
  configuration.md           # Full configuration reference

docker-compose.yml           # 13 services: 12 OpenClaw agents + simulator
Dockerfile                   # Simulator container image
```

## Agent runtime backends

| Backend | Flag | What it does |
|---------|------|--------------|
| `mock` | `--backend mock` | Deterministic rule-based agents with role-specific behavioral profiles. No LLM, no network. For testing and baseline experiments. |
| `openclaw` | `--backend openclaw` | Each agent is a full OpenClaw instance. The simulator sends observations and tool definitions via the OpenAI-compatible HTTP API; agents reason autonomously and call enterprise tools. |
| `openai` / `anthropic` | `--backend openai` | Direct LLM API calls without OpenClaw. Lighter weight, single-process. |

## Experimental factors

The framework supports factorial experiments over 5 binary defense factors:

| Factor | Level 0 (off) | Level 1 (on) |
|--------|---------------|--------------|
| Network segmentation | Flat (all zones connected) | Strong (hub-and-spoke, role-gated bridges) |
| Credential policy | Broad, no rotation | Scoped to home zone, rotated every 5 days |
| Communication discipline | Free-form delegation | Typed delegation + clarification gate |
| Budget control | No spend cap | Hard cap at $300/day with downgrade |
| Recovery controls | Passive logging | Quarantine + trust decay + key rotation |

Full factorial: 2^5 = 32 conditions. Fractional (resolution III): 8 conditions.

## Outcome measures

| Metric | Definition |
|--------|-----------|
| PWCL | Privilege-Weighted Confidentiality Loss — credential dwell time x privilege weight |
| JCR | Job Completion Rate — reward-weighted completed / total jobs |
| TWR | Token Waste Ratio — attack-induced tokens / total tokens |
| Blast Radius | Peak fraction of agents not healthy |
| TTD / TTR | Time to Detection / Time to Recovery |
| CSRI | Community Security Risk Index — composite of above |

## CLI reference

```bash
python run_experiment.py single --backend mock --seed 42     # one run
python run_experiment.py run                                  # full experiment
python run_experiment.py conditions                           # list all conditions
python run_experiment.py analyze -o results                   # tabulate results
```

## License

MIT
