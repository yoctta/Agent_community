# Quickstart

ACES runs a simulated enterprise where 12 AI agents work, communicate, and collaborate across segmented intranets. Each agent is powered by an LLM (via [OpenClaw](https://github.com/openclaw/openclaw) or direct API calls).

## Two ways to run

| Mode | Docker needed? | Best for |
|------|:--------------:|----------|
| Direct LLM | No | Quick runs without OpenClaw setup |
| OpenClaw agents | Optional | Full autonomous agents with rich identity/personality |

Both require an LLM API key (Anthropic, OpenAI, OpenRouter, or any OpenAI-compatible provider). Ollama works locally without a key.

---

## Mode 1: Direct LLM API

The simulator calls the LLM directly for each agent decision. No Docker, no OpenClaw.

```bash
pip install pyyaml httpx

# Anthropic (Claude):
python run_experiment.py single \
  --backend anthropic \
  --model claude-sonnet-4-6 \
  --api-key sk-ant-your-key-here

# OpenAI:
python run_experiment.py single \
  --backend openai --model gpt-4o --api-key sk-...

# OpenRouter (any model):
python run_experiment.py single \
  --backend openrouter --model anthropic/claude-sonnet-4-6 --api-key sk-or-...

# Ollama (local, no key):
python run_experiment.py single --backend ollama --model llama3
```

How it works: the simulator formats each agent's observation (inbox, jobs, delegations, memory) as a prompt with role-filtered action definitions, sends it to the LLM, and parses the JSON response into actions.

---

## Mode 2: OpenClaw agents (embedded mode)

Each agent turn runs `openclaw agent --local` as a subprocess. OpenClaw loads the agent's workspace files (IDENTITY.md with role/expertise, SOUL.md with personality, AGENTS.md with the enterprise directory), calls the LLM, and returns a response. This gives agents richer context than direct API calls.

### Prerequisites

```bash
pip install pyyaml httpx
npm install -g openclaw     # or: npx openclaw
```

### Step 1: Generate agent workspaces

```bash
python docker/generate_agent_configs.py
```

This creates per-agent state directories under `docker/agents/`:
```
docker/agents/eng_carol/
  openclaw.json                           # agent config (model, workspace path)
  agents/main/agent/auth-profiles.json    # LLM API key
  workspace/
    IDENTITY.md    # role, expertise, domain knowledge
    SOUL.md        # personality, communication style, guidelines
    AGENTS.md      # enterprise directory + personal relationships
```

### Step 2: Set up API keys

Copy your existing OpenClaw auth to each agent:

```bash
for d in docker/agents/*/agents/main/agent; do
  cp ~/.openclaw/agents/main/agent/auth-profiles.json "$d/"
done
```

Or create auth-profiles.json manually:

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

### Step 3: Run

```bash
python run_experiment.py single --backend openclaw --seed 42
```

### With Docker Compose

Docker Compose adds self-hosted Moltbook (agent social network):

```bash
cp .env.example .env              # add your LLM_API_KEY
python docker/generate_agent_configs.py
docker compose up
```

This starts 3 containers:
- **moltbook-db** — PostgreSQL for Moltbook
- **moltbook** — self-hosted Moltbook API (built from source)
- **simulator** — ACES engine with Node.js + OpenClaw installed

No separate agent containers — the simulator runs all 12 agents via embedded OpenClaw subprocesses, isolated by `OPENCLAW_STATE_DIR`.

### How the API key flows (OpenClaw mode)

```
auth-profiles.json (per agent)
  │
  └─▶ OPENCLAW_STATE_DIR=docker/agents/<id>
        └─▶ openclaw agent --agent main --session-id <uuid>
              --message "<observation>" --json --local
              │
              ├─ reads: <state_dir>/agents/main/agent/auth-profiles.json
              ├─ loads: <state_dir>/workspace/{IDENTITY,SOUL,AGENTS}.md
              ├─ calls LLM (Anthropic/OpenAI/configured provider)
              └─ returns JSON: { "payloads": [{ "text": "[actions]" }] }
```

### Choosing a model

| Model | Provider flag | Cost | Notes |
|-------|----------|------|-------|
| `claude-sonnet-4-6` | anthropic | $$ | Good balance — recommended |
| `claude-opus-4-6` | anthropic | $$$$ | Best reasoning |
| `claude-haiku-4-5` | anthropic | $ | Fast, cheapest |
| `gpt-4o` | openai | $$ | Strong general purpose |
| `llama3` | ollama | Free | Local, no API key |

---

## View results

```bash
# Summary table
python run_experiment.py analyze -o results

# Inspect a specific run
python3 -c "
from aces.database import Database
db = Database('results/run_XXXX.db')
for a in db.get_all_agents():
    print(f'{a.name}: balance=\${a.wallet_balance:.2f} jobs={a.jobs_completed} status={a.status.value}')
events = db.get_events()
print(f'Total events: {len(events)}')
db.close()
"
```

## Performance

Each agent turn takes ~6 seconds with Claude Sonnet via OpenClaw (~2s with direct API).

| Config | Turns/day | Wall time/day |
|--------|-----------|---------------|
| 12 agents, 6 ticks | 72 | ~8 min (OpenClaw) / ~2.5 min (direct) |
| 12 agents, 3 ticks | 36 | ~4 min (OpenClaw) / ~1.5 min (direct) |

A default 30-day run: ~4 hours (OpenClaw) or ~1.5 hours (direct LLM).
