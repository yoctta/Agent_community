# Quickstart

ACES runs a simulated enterprise where 12 AI agents work, communicate, and collaborate across segmented intranets.

## Three ways to run

| Mode | LLM needed? | Docker needed? | Best for |
|------|:-----------:|:--------------:|----------|
| Mock agents | No | No | Testing, development, quick experiments |
| Direct LLM | Yes | No | Lightweight runs without OpenClaw |
| OpenClaw agents | Yes | Yes | Full autonomous agent simulation |

---

## Mode 1: Mock agents (no LLM, no cost)

Agents use deterministic rule-based behavior. No API key needed.

```bash
pip install pyyaml
python run_experiment.py single --backend mock --seed 42
```

This runs a full 30-day simulation in ~1 second.

---

## Mode 2: Direct LLM API

The simulator calls Anthropic or OpenAI directly for each agent decision. No Docker, no OpenClaw.

```bash
pip install pyyaml httpx

# With Anthropic (Claude):
python run_experiment.py single \
  --backend anthropic \
  --model claude-sonnet-4-20250514 \
  --api-key sk-ant-api03-your-key-here

# With OpenAI:
python run_experiment.py single \
  --backend openai \
  --model gpt-4o \
  --api-key sk-your-openai-key
```

How it works: the simulator formats each agent's observation (inbox, jobs, delegations) as a prompt, sends it to the LLM API with the agent's role-filtered tool definitions, and parses the response into actions.

**Cost estimate:** ~12 agents x 6 ticks/day x 30 days = ~2,160 LLM calls per run. At ~500 tokens per call, that's roughly $1-5 per run depending on the model.

---

## Mode 3: OpenClaw agents (full Docker stack)

Each agent runs as an autonomous OpenClaw instance in its own Docker container with its own LLM connection.

### Step 1: Configure your API key

```bash
cp .env.example .env
```

Edit `.env`:

```bash
# For Anthropic:
LLM_API_KEY=sk-ant-api03-your-anthropic-key
LLM_PROVIDER=anthropic
LLM_MODEL=claude-sonnet-4-20250514

# OR for OpenAI:
LLM_API_KEY=sk-your-openai-key
LLM_PROVIDER=openai
LLM_MODEL=gpt-4o
```

### Step 2: Generate agent workspaces

This creates a per-agent OpenClaw workspace directory with identity, personality, and gateway config:

```bash
python docker/generate_agent_configs.py
```

The generator reads `LLM_PROVIDER` and `LLM_MODEL` and writes them into each agent's `config.yaml`. To switch models later:

```bash
python docker/generate_agent_configs.py --provider openai --model gpt-4o
```

### Step 3: Start the simulation

```bash
docker compose up
```

This starts 13 containers:
- 12 OpenClaw gateways (ports 18701-18712), each running one agent
- 1 ACES simulator that orchestrates the day/tick cycle

### How the API key flows

```
.env (LLM_API_KEY=sk-ant-...)
  │
  ├─▶ docker-compose.yml (env_file: .env)
  │     │
  │     ├─▶ mgr-alice container (OpenClaw gateway)
  │     │     └─▶ config.yaml: apiKey: "${LLM_API_KEY}"
  │     │           └─▶ OpenClaw reads the env var at startup
  │     │                 └─▶ Gateway calls Anthropic/OpenAI API
  │     │
  │     ├─▶ eng-carol container (same flow)
  │     ├─▶ ... (12 containers total)
  │     │
  │     └─▶ simulator container
  │           └─▶ Sends observations to each agent's gateway
  │                 via HTTP (localhost:18701-18712)
  │                 └─▶ Gateway forwards to LLM, returns actions
```

Each OpenClaw gateway:
1. Reads `LLM_API_KEY` from its environment
2. Loads its `config.yaml` which specifies the provider (anthropic/openai) and model
3. Exposes an OpenAI-compatible HTTP API on its port
4. When the simulator sends an observation, the gateway formats it with the agent's workspace context (IDENTITY.md, SOUL.md, AGENTS.md) and calls the LLM
5. The LLM response (tool calls) flows back to the simulator

### Choosing a model

| Model | Provider | Cost | Quality |
|-------|----------|------|---------|
| `claude-sonnet-4-20250514` | anthropic | $$ | Good balance of cost and reasoning |
| `claude-opus-4-20250514` | anthropic | $$$$ | Best reasoning, highest cost |
| `claude-haiku-4-5-20251001` | anthropic | $ | Fast, cheapest, simpler behavior |
| `gpt-4o` | openai | $$ | Strong general purpose |
| `gpt-4o-mini` | openai | $ | Budget option |

For full experiments (160 runs), start with a cheaper model. For single-run validation, use a stronger model.

---

## View results

```bash
# Summary table of all conditions
python run_experiment.py analyze -o results

# Raw data in per-run SQLite databases
ls results/run_*.db

# Inspect a specific run
python -c "
from aces.database import Database
db = Database('results/run_XXXX.db')
print(f'Events: {len(db.get_events())}')
print(f'Jobs: {len(db.get_all_jobs())}')
for a in db.get_all_agents():
    print(f'  {a.name}: balance=\${a.wallet_balance:.2f} status={a.status.value}')
db.close()
"
```

## What happens during a simulation

Each simulated day:
1. New jobs generated (payroll, code reviews, deployments, support tickets)
2. Each agent gets 6 turns per day, up to 3 actions per turn
3. Agents read mail, claim jobs, delegate tasks, update wiki, build intranet pages, post on Moltbook
4. At end of day: salaries paid, overdue jobs penalized, defenses evaluated, metrics snapshotted

A typical 30-day run produces ~8,600 events: 1,100 organic mails, 500 delegations, 120 wiki edits, 60 Moltbook posts, 7+ intranet pages, and 260 jobs.
