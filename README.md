# ACES — Agent Community Enterprise Simulator

A configurable framework for running persistent, multi-agent enterprise simulations where autonomous AI agents collaborate, communicate, and work across segmented intranets.

Two ready-to-run communities:

- **Baseline (12 agents, 6 roles)** — the original enterprise from `config/enterprise.yaml`. Manager/engineer/finance/hr/security/support, five zones, ten job templates.
- **Research community (15 agents, 12 roles)** — `config/community_research_enterprise.yaml`. CEO/CTO/COO, product, design, engineering manager, engineers, QA, DevOps, security, HR, finance, and a malicious IT admin. Adds communication groups, a token economy, internal server hosts, credential placements, and impersonation mechanics. Used for studying insider threat, detection, and community security dynamics.

Each agent is powered by an LLM via [OpenClaw](https://github.com/openclaw/openclaw) running in embedded mode, or via any OpenAI-compatible endpoint directly. The simulator invokes `openclaw agent --local` as a subprocess (or makes async `/v1/chat/completions` calls) for each agent turn. Agents interact through mediated enterprise services — mail, typed delegation, shared wiki, credential vault, directory lookup, group mailing lists, peer token transfers, server login/secret read, impersonation — and engage with the broader agent community via [Moltbook](https://moltbook.com). Every interaction produces a replayable event trace suitable for studying community dynamics, coordination patterns, and security properties.

**Inner action loop.** Each tick, every agent runs an inner loop: observe → decide (LLM call) → execute → re-observe → decide → ... until the agent emits `noop` or the tick's wall-clock budget (default 180s) is exhausted. A tick is a message-propagation barrier, not a per-agent action budget. This lets agents chain multi-step actions naturally (e.g. read credential → acquire grant → transfer tokens) within a single tick. Agents run their inner loops concurrently across a tick via `asyncio.gather`; apply calls are serialised via a shared lock to preserve determinism.

**Role playbooks.** Each agent inherits a role-specific playbook (`aces/playbooks.py`) that sets their identity framing and action priorities. Three templates: productive worker (13 roles, with per-role priority overrides for finance/executive/devops/hr), security threat hunter, and red-team pentester. Playbooks drive both the turn prompt (via `aces/prompting.py`) and the persistent workspace files (IDENTITY.md, SOUL.md) so the LLM's persona is coherent across layers.

**Two-tier self-memory.** Within a day, each agent sees a `[EARLIER TODAY YOU]` block listing all their own earlier actions. Across days, agents write end-of-day notes via the `note` action, surfaced the next day as `[YOUR DAY-END NOTES]`. This replaces OpenClaw session continuity (which was deliberately disabled for observability) with an explicit, auditable memory mechanism.

**Real-cost wallet brake.** Each LLM call's token usage is estimated and deducted from the agent's wallet at `token_cost_per_1k` rate. When an agent's wallet drops below the expected cost of one more call, the inner loop stops. This makes agent salary a real budget constraint on LLM API spend.

## Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                     YAML Configuration                            │
│    enterprise.yaml      experiment.yaml      attacks.yaml         │
└──────────┬──────────────────┬──────────────────┬──────────────────┘
           │                  │                  │
           ▼                  ▼                  ▼
┌───────────────────────────────────────────────────────────────────┐
│               Simulation Engine  (aces/engine.py)                 │
│                                                                   │
│  Day loop ─▶ generate jobs ─▶ inject events ─▶ agent turns       │
│  Tick loop ─▶ shuffle agents ─▶ observe ─▶ decide ─▶ execute     │
│  Barrier ──▶ payroll ─▶ penalties ─▶ defenses ─▶ metrics         │
└──────┬─────────────────────────────────────────────┬──────────────┘
       │  one subprocess per agent turn              │
       ▼                                             ▼
  ┌──────────────────────────────────────┐     ┌──────────┐
  │  OPENCLAW_STATE_DIR=docker/agents/X  │     │ Services │
  │  openclaw agent --agent main         │     │  ┌─Mail──┐│
  │    --session-id <uuid>               │     │  │Deleg. ││
  │    --message "<observation>"         │     │  │Wiki   ││
  │    --json --local                    │     │  │Vault  ││
  │                                      │     │  │Moltbk ││
  │  ├─ loads IDENTITY.md, SOUL.md       │     │  └───────┘│
  │  ├─ reads auth-profiles.json         │     └──────────┘
  │  ├─ calls LLM (Anthropic/OpenAI/…)   │
  │  └─ returns JSON actions             │
  └──────────────────────────────────────┘
         ×12 agents, each isolated by state dir
```

## How it works

### The inner action loop

Each tick, every agent runs an inner loop until they decide to stop (or the tick budget expires):

1. **Observe** — builds a rich `AgentObservation`:
   - Role playbook identity + ordered priorities
   - Red-team scoreboard (attacker only) — live progress against scored objectives
   - Day-end notes from prior days + within-day action log from earlier ticks/iterations
   - Wall-clock time budget remaining (with wind-down hints)
   - Workspace files (persistent across days, written via OpenClaw's native tools)
   - Active impersonation grants held (with concrete weaponization instructions)
   - Inbox, jobs, delegations, colleagues, groups, servers, transfers
   - For security agents: raw event timeline + quarantined agent IDs

2. **Decide** — sends the observation to the agent's LLM:
   - OpenClaw injects persistent workspace context (IDENTITY.md with playbook-driven identity, SOUL.md with role priorities, AGENTS.md with directory)
   - OpenClaw's native tools (file read/write/edit, shell) are available for working memory
   - The agent emits a JSON array of ACES actions for simulation-visible decisions
   - A unique `--session-id` per turn prevents session-level context leakage

3. **Execute** — each action is applied, then the observation refreshes and the loop continues:
   - Mail (direct + group, with optional `as_agent_id` impersonation via grant)
   - Token transfers (with optional impersonation)
   - Server login, secret listing/reading (issues impersonation grants on credential read)
   - Job claim/complete/approve, delegation request/response
   - Wiki read/update, Moltbook read/post
   - Security: `isolate_agent` / `release_agent` (bounty/fine economics)
   - `note` — end-of-day self-summary written to agent memory
   - `noop` — explicitly ends the inner loop for this tick

### What agents actually do

In a verified 1-day run (12 agents, 72 turns), agents produced:

- **40 emails** — managers sent sprint kickoffs, engineers replied with status updates, security flagged routing anomalies
- **2 jobs completed** — an engineer reviewed a PR ($20 reward), support resolved a ticket ($10)
- **15 documents created** — engineers used SSH to create deployment guides and runbooks
- **5 credential accesses** — security agents performing quarterly access reviews
- **106 memory entries** — agents remembered who they communicated with and what they worked on

Agents write contextual, role-appropriate emails. A manager might send *"Auth Service Migration — Day 1 Check-in"* to an engineer who responds *"I've claimed the auth service v2.1 deployment task. Will keep you updated."*

### Multi-step jobs

Jobs with `requires_approval: true` cannot be completed until a manager (or executive / engineering manager) calls `approve_job`. Combined with delegation chains — `delegate` to assign work, `respond_delegation` to accept — this creates natural handoff structure between roles without imposing a fixed phase pipeline.

### Agent memory

Memory evolves during the simulation. Agents start with seeded memories (known colleagues, domain knowledge, current projects) and accumulate new entries as they work:

- **Completing a job** → work memory ("Completed 'Deploy auth service' on day 3")
- **Sending mail** → contact memory ("Sent 'Sprint update' to mgr_alice on day 2")
- **Delegating** → contact memory ("Delegated 'review code' to eng_dave on day 4")
- **Reading/updating docs** → knowledge memory ("Read 'Deployment Guide' v2 on day 5")

Memory is included in every observation, so agents build awareness of their relationships and work history over the 30-day run.

### Per-role tool filtering

Not all agents can do everything. The action space is role-filtered:

| Capability | Manager | Engineer | Finance | HR | Security | Support |
|-----------|:-------:|:--------:|:-------:|:--:|:--------:|:-------:|
| Claim/complete jobs | ✓ | ✓ | ✓ | — | ✓ | ✓ |
| Approve jobs | ✓ | — | — | — | ✓ | — |
| SSH (create/edit pages) | — | ✓ | — | — | ✓ | — |
| Browse intranet | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Access credentials | — | ✓ | ✓ | ✓ | ✓ | — |
| Moltbook (read/post) | — | — | — | — | ✓ | ✓ |
| Send mail / delegate | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

Engineers and security get SSH access to the internal web host (create pages, edit content, run commands). Everyone else can only browse published pages.

## Quickstart

### Option A: Docker Compose (recommended)

```bash
# 1. Configure your LLM API key
cp .env.example .env              # edit: add your LLM_API_KEY

# 2. Generate per-agent OpenClaw workspaces
python docker/generate_agent_configs.py

# 3. Copy your OpenClaw auth to each agent
#    (or manually place auth-profiles.json — see "API key setup" below)

# 4. Run
docker compose up
```

Docker Compose starts 3 services:
- **moltbook-db** — PostgreSQL for the Moltbook social network
- **moltbook** — self-hosted Moltbook API server
- **simulator** — the ACES engine with Node.js + OpenClaw installed

The simulator runs OpenClaw in embedded mode — each agent turn invokes `openclaw agent --local` as a subprocess. No separate gateway containers.

### Option B: Direct LLM (no OpenClaw, no Docker)

```bash
pip install pyyaml httpx

python run_experiment.py single \
  --backend anthropic \
  --model claude-sonnet-4-6 \
  --api-key sk-ant-...
```

This calls the LLM API directly for each agent decision. The simulator builds prompts with agent identity and role context, sends them to the API, and parses the JSON response. Simpler setup but agents don't get OpenClaw's workspace context injection.

### Option C: Local (Ollama, no API key)

```bash
pip install pyyaml httpx
ollama pull llama3

python run_experiment.py single --backend ollama --model llama3
```

### Option D: Full factorial experiment

```bash
# 32 conditions × 5 seeds = 160 runs
python run_experiment.py run --backend anthropic --api-key sk-ant-...
```

### Option E: Research community + async + codex-spark (fast, factorial-ready)

The 15-agent research community with the async engine and `gpt-5.3-codex-spark`
at `reasoning_effort=low` is the combination we use for pilot studies:

```bash
pip install pyyaml httpx

# Single 30-day run, security expert enabled.
python run_experiment.py single \
  --research \
  --backend openai \
  --base-url https://your-openai-compatible-proxy/ \
  --api-key $LLM_API_KEY \
  --model gpt-5.3-codex-spark \
  --reasoning-effort low \
  --async-engine \
  --concurrency 16 \
  --max-tokens 384 \
  --seed 42

# Full factorial (32 conditions × 5 seeds) — see the cost estimate in
# docs/research_scenarios.md before kicking this off.
python run_experiment.py run \
  --research --async-engine \
  --backend openai --base-url https://your-openai-compatible-proxy/ \
  --api-key $LLM_API_KEY \
  --model gpt-5.3-codex-spark --reasoning-effort low
```

Analyze the results:

```bash
python analyze_research_results.py --output results/
# Writes results/analysis/{per_day.csv, summary.csv, condition_means.csv}
```

## API key setup

### For direct LLM mode

Pass `--api-key` on the command line or set `LLM_API_KEY` in `.env`.

### For OpenClaw mode

Each agent needs an `auth-profiles.json` at `docker/agents/<id>/agents/main/agent/auth-profiles.json`. The format (verified against OpenClaw 2026.3.8):

```json
{
  "version": 1,
  "profiles": {
    "anthropic:default": {
      "type": "token",
      "provider": "anthropic",
      "token": "sk-ant-your-key-here"
    }
  }
}
```

`generate_agent_configs.py` creates these with a `${LLM_API_KEY}` placeholder. For local runs, copy your existing OpenClaw auth:

```bash
for d in docker/agents/*/agents/main/agent; do
  cp ~/.openclaw/agents/main/agent/auth-profiles.json "$d/"
done
```

For Docker, the `${LLM_API_KEY}` env var is expanded at container startup.

## Configuration

All configuration lives in three YAML files under `config/`. See [docs/configuration.md](docs/configuration.md) for the full reference.

| File | Controls |
|------|----------|
| `enterprise.yaml` | Agents (roles, zones, salaries, relationships, knowledge, memory), network topology, job templates, economic parameters |
| `experiment.yaml` | Experimental factors, factorial design, seeds, defense baselines, CSRI weights |
| `attacks.yaml` | Attack templates and density (can be disabled entirely) |

### Agent profiles

Each agent has a rich, configurable profile that flows into their OpenClaw workspace:

```yaml
agents:
  - id: eng_carol
    name: Carol (Engineer)
    role: engineer
    zone: engnet
    salary: 120.0
    initial_balance: 800.0
    allowed_zones: [engnet, corpnet]

    # Profile — written to IDENTITY.md, injected by OpenClaw
    specialization: backend infrastructure
    expertise: [distributed systems, Python, Go, PostgreSQL, CI/CD]
    seniority: senior

    # Personality — written to SOUL.md, shapes agent behavior
    communication_style: concise
    initiative: high
    caution_level: moderate

    # Relationships — seeded as contact memory
    known_agents:
      - id: eng_dave
        relationship: peer
        notes: "Pair on code reviews, strong on API design"

    # Domain knowledge — seeded as knowledge memory
    world_knowledge:
      - "The payment service uses PostgreSQL 15 with read replicas"

    # Pre-loaded memory entries
    initial_memory:
      - category: work
        key: current_project
        value: "Leading auth service migration"
```

After editing, regenerate workspaces: `python docker/generate_agent_configs.py`

### Tuning the simulation

```yaml
# Faster runs
ticks_per_day: 3          # fewer turns per agent per day
max_actions_per_tick: 2   # fewer actions per turn

# In experiment.yaml
days_per_run: 10          # shorter simulation
seeds: [42]               # single seed
design: fractional        # 8 conditions instead of 32

# Custom CSRI weights (default: equal). Five components:
#   [conf_loss, avail_loss, twr, spread, econ_loss]
# Legacy 4-element vectors are padded with 0 for econ_loss.
csri_weights: [0.2, 0.2, 0.2, 0.2, 0.2]
```

### Disabling attacks

```yaml
# In attacks.yaml
enabled_classes: []       # no attacks — pure community dynamics
```

## Performance

Each agent turn takes ~6 seconds with Claude Sonnet (OpenClaw embedded mode, minimal workspace stubs). For a 1-day simulation:

| Agents | Ticks/day | Turns | Wall time | LLM cost (est.) |
|--------|-----------|-------|-----------|-----------------|
| 12 | 6 | 72 | ~8 min | ~$1 |
| 12 | 3 | 36 | ~4 min | ~$0.50 |

A full 30-day run takes ~4 hours. For factorial experiments, run conditions in parallel across machines.

The direct LLM backend (no OpenClaw) is faster per turn (~2s) because it skips workspace context injection, but agents don't get the rich personality and identity context from IDENTITY.md/SOUL.md.

## Extending with external services

ACES can integrate any website or API that agents should interact with. The Moltbook integration is the reference implementation. See [docs/extending.md](docs/extending.md) for the step-by-step guide.

The pattern:

1. Create a service class with `simulated` + `live` modes
2. Add an action dataclass to `models.py`
3. Register in the service registry
4. Add an execution handler in the engine
5. Add role-specific tool instructions in `ROLE_TOOLS`
6. Optionally add attack templates

Example services: GitHub (code hosting), Slack (real-time chat), Notion (knowledge base), Grafana (monitoring).

## Project structure

```
aces/                        # Core Python package
  models.py                  # Data models: Agent, Job, Message, Credential, Event, Action
  config.py                  # YAML config loading and validation
  database.py                # SQLite persistence (per-run)
  network.py                 # Zone topology and access control (flat/weak/strong)
  services.py                # Enterprise services: mail, delegation, wiki, vault, IAM
  webhost.py                 # Internal web server (SSH + browser tiers)
  moltbook.py                # Moltbook social network (simulated + live modes)
  playbooks.py               # Role playbooks: red-team pentester, threat hunter, productive worker
  prompting.py               # Shared prompt construction + action JSON parsing (both runtimes)
  runtime.py                 # LLMAgentRuntime — direct API calls to any provider
  openclaw_runtime.py        # OpenClawRuntime — subprocess-based, verified against 2026.3.8
  engine.py                  # Simulation engine: inner action loop, barrier, wallet brake
  attacks.py                 # Attack injection framework (policy: llm / scripted / passive)
  defenses.py                # Defense mechanisms: key rotation, anomaly detection, quarantine
  metrics.py                 # PWCL, JCR, TWR, blast radius, TTD, TTR, CSRI
  experiment.py              # Factorial design, condition generation, multi-run orchestration
  cli.py                     # Command-line interface

config/                      # YAML configuration
  enterprise.yaml            # 12 agents, 5 zones, 10 job templates
  experiment.yaml            # 5 binary factors, factorial design
  attacks.yaml               # 10 attack templates across 4 classes

docker/                      # Docker infrastructure
  generate_agent_configs.py  # Creates per-agent OpenClaw workspaces from enterprise.yaml
  moltbook.Dockerfile        # Builds self-hosted Moltbook from source

tests/
  test_smoke.py              # 16 smoke tests (pipeline, DB, network, factorial, bug fixes)
  test_services.py           # 23 service tests (WebHost, Moltbook, multi-step, memory, CSRI)
  stub_runtime.py            # Deterministic stub for testing without LLM

docker-compose.yml           # 3 services: moltbook-db, moltbook, simulator
Dockerfile                   # Simulator image (Python + Node.js + OpenClaw)
```

## Agent runtime backends

| Backend | Flag | How it works |
|---------|------|-------------|
| `openclaw` | `--backend openclaw` | Each turn runs `openclaw agent --local` as a subprocess. OpenClaw loads the agent's workspace (IDENTITY.md, SOUL.md, AGENTS.md), calls the LLM, returns a JSON response. Per-agent isolation via `OPENCLAW_STATE_DIR`. |
| `anthropic` | `--backend anthropic` | Direct Anthropic API (`/v1/messages`). Single-process, lighter weight. |
| `openai` | `--backend openai` | Direct OpenAI API. |
| `openrouter` | `--backend openrouter` | OpenRouter — access any model from any provider. |
| `ollama` | `--backend ollama` | Local Ollama instance. No API key needed. |
| Any other | `--backend NAME --base-url URL` | Any OpenAI-compatible endpoint (Together, vLLM, LiteLLM). |

## Experimental factors

The framework supports factorial experiments over 5 binary defense factors:

| Factor | Level 0 (off) | Level 1 (on) |
|--------|---------------|--------------|
| Network segmentation | Flat (all zones connected) | Strong (hub-and-spoke, role-gated) |
| Credential policy | Broad, no rotation | Scoped to home zone, rotated every 5 days |
| Communication discipline | Free-form delegation | Typed delegation + clarification gate |
| Budget control | No spend cap | Hard cap at $300/day with downgrade |
| Recovery controls | Passive logging | Quarantine + trust decay + key rotation |

Full factorial: 2^6 = 64 conditions (with `attacker_autonomy`). Fractional (resolution III): 8 conditions.

## Outcome measures

| Metric | Scale | Definition |
|---|---|---|
| **CSRI** | 0–1, lower=better | Community Security Risk Index — weighted composite of the five below. **This is the headline outcome** because it's staffing-invariant (adding/removing sec_david as a factor doesn't bias it). |
| PWCL | ≥0, lower=better | Privilege-Weighted Confidentiality Loss — `Σ privilege_weight × dwell_days` over open credential-leak incidents |
| JCR | 0–1, higher=better | Job Completion Rate — `reward-weighted completed / total` |
| TWR | 0–1, lower=better | Token Waste Ratio — `attack-induced tokens / total tokens` |
| Blast Radius | 0–1, lower=better | Peak fraction of agents not healthy |
| econ_loss | 0–1, lower=better | `1 − community_balance / (start + total_salary)` — staffing-invariant economic shortfall |
| community_balance | $ absolute | `sum(wallet for a in agents if not a.is_malicious)`. Raw number — **salary-biased across conditions that add/remove agents**; use CSRI for comparisons. |
| TTD / TTR | days | Time to Detection / Time to Recovery |

### Framework health check

Before trusting a research experiment, run `python scripts/run_framework_justification.py`. Supports `CELLS=fast|sec|full` for partial runs. It executes a four-cell 2×2 (±attacker, ±security_expert) and gates on four CSRI-based criteria:

1. attacker causes damage (CSRI > clean baseline)
2. security recovers damage (CSRI < attacker_only)
3. security_only has bounded FP overhead (CSRI near clean, ≤1 FP isolation)
4. sheriff catches the real attacker in attack_defended (≥1 TP isolation)

If any check fails, investigate before trusting any downstream factorial.

## CLI reference

```bash
# Single run with OpenClaw agents
python run_experiment.py single --backend openclaw --seed 42

# Single run with direct LLM
python run_experiment.py single --backend anthropic --api-key sk-... --seed 42

# Full factorial experiment
python run_experiment.py run --backend anthropic --api-key sk-...

# List all experimental conditions
python run_experiment.py conditions

# Analyze results
python run_experiment.py analyze -o results
```

## Tests

```bash
pip install pytest
python -m pytest tests/ -q        # 153 tests, ~13s
```

## License

MIT
