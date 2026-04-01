# Quickstart

ACES runs a simulated enterprise where 12 AI agents work, communicate, and collaborate. Each agent is a fully autonomous OpenClaw instance with its own role, workspace, and LLM connection.

## Prerequisites

- Docker and Docker Compose
- An LLM API key (Anthropic or OpenAI)

## 1. Set up your API key

```bash
cp .env.example .env
# Edit .env and add your API key:
#   LLM_API_KEY=sk-your-key-here
```

## 2. Generate agent workspaces

This reads `config/enterprise.yaml` and creates an OpenClaw workspace directory for each agent:

```bash
python docker/generate_agent_configs.py
```

You'll see output like:

```
Generating OpenClaw agent configs...
  [ 1] mgr_alice            port 18701  zone=corpnet
  [ 2] mgr_bob              port 18702  zone=corpnet
  [ 3] eng_carol             port 18703  zone=engnet
  ...
  [12] sup_leo               port 18712  zone=corpnet

Generated 12 agent configs in docker/agents/
```

## 3. Start the simulation

```bash
docker compose up
```

This starts:
- 12 OpenClaw agent gateways (one per agent, each with its own LLM connection)
- 1 ACES simulator that orchestrates the day/tick cycle

The simulator runs a full experiment (32 conditions x 5 seeds = 160 runs by default). Results are saved to `results/`.

## Quick alternatives

**Single 30-day run** (instead of full experiment):

```bash
docker compose run simulator single --seed 42
```

**Mock agents** (no LLM, no OpenClaw — for testing):

```bash
docker compose run simulator single --backend mock --seed 42
```

**Run locally** (without Docker):

```bash
pip install pyyaml httpx
python run_experiment.py single --backend mock --seed 42
```

## 4. View results

After a run completes:

```bash
# Summary table
python run_experiment.py analyze -o results

# Raw data is in per-run SQLite databases:
ls results/run_*.db
```

## What happens during a simulation

Each simulated day:
1. New jobs are generated (payroll, code reviews, deployments, support tickets, etc.)
2. Each agent gets 6 turns per day, up to 3 actions per turn
3. Agents read mail, claim jobs, delegate tasks, update wiki pages, and post on Moltbook
4. At end of day: salaries are paid, overdue jobs are penalized, metrics are recorded

The experiment varies 5 defense factors across conditions to study how network segmentation, credential policies, communication discipline, budget controls, and recovery mechanisms affect the community.
