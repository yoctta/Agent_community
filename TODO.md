# TODO

Unfinished work and known gaps between the design document and the current implementation.

## Agent Memory

- [ ] **Memory is never written during simulation** — agents seed memory at init (contacts, knowledge, initial context) and read it every turn, but never update it as they work. Completing a job, reading a phishing email, learning a colleague's expertise — none of this persists. Memory should evolve over the 30-day run.
  - `engine.py` `_execute_action`: after completing a job, upsert a work memory entry
  - After reading mail, update observations memory
  - After wiki edits, update knowledge memory
  - After delegation interactions, update contact memory

## Mock Agent Realism

- [ ] **Rich agent config unused in mock runtime** — `specialization`, `expertise`, `seniority`, `communication_style`, `initiative`, `caution_level` are all defined per-agent in enterprise.yaml but MockAgentRuntime treats all agents of the same role identically. A senior engineer with high initiative should behave differently from a cautious junior.
  - Use `seniority` to scale completion probability (seniors faster)
  - Use `initiative` to scale proactive communication frequency
  - Use `caution_level` to scale resistance to suspicious requests
  - Use `known_agents` to prefer delegating to known colleagues over random picks

- [ ] **Mock agents don't create intranet pages** — WebHostSSHAction is only available to LLM/OpenClaw agents. Engineers in mock mode should occasionally create or update intranet pages (deployment notes, runbooks, bug reports) to produce organic web content.

- [ ] **Mock agents don't use the `browse_page` action** — all agents can browse the intranet but the mock runtime never does. Support and HR agents especially should browse for information.

## Multi-step Jobs

- [ ] **Jobs requiring approval can complete without it** — the `CompleteJobAction` handler doesn't check `requires_approval` / `approved_by`. An engineer can complete a deployment job that hasn't been manager-approved. The engine should block completion of unapproved jobs.

- [ ] **No collaborator tracking on jobs** — `Job.collaborators` field exists but is never populated. When an agent delegates a review for a job, the reviewer should be added as a collaborator. This enables collaboration metrics.

## Docker / Infrastructure

- [x] ~~**Docker image `openclaw/openclaw:latest` does not exist**~~ — fixed: now uses `ghcr.io/openclaw/openclaw:latest`
- [x] ~~**Config format was YAML, should be JSON5**~~ — fixed: `generate_agent_configs.py` now writes `openclaw.json` with correct schema
- [x] ~~**Mount path `/root/.openclaw` wrong**~~ — fixed: now `/home/node/.openclaw` (matching real image)
- [x] ~~**OpenAI-compatible API not enabled**~~ — fixed: config now sets `gateway.http.endpoints.chatCompletions.enabled: true`
- [x] ~~**Agent selection used wrong model field**~~ — fixed: now uses `model: "openclaw:<agentId>"`
- [x] ~~**No health checks**~~ — fixed: added `/healthz` health check, simulator uses `service_healthy`
- [x] ~~**`ghcr.io/moltbook/api:latest` does not exist**~~ — fixed: Moltbook now built from source via `docker/moltbook.Dockerfile` (clones `github.com/moltbook/api`)
- [x] ~~**Moltbook port was 3001, should be 3000**~~ — fixed

- [ ] **OpenClaw config may need further tuning** — the generated `openclaw.json` covers providers, agents, and HTTP endpoints, but does not register ACES tools as OpenClaw plugins (tools are passed per-request via the chat completions API instead). If OpenClaw requires explicit plugin registration for tool calling, this needs updating.

- [ ] **Moltbook needs `npm run db:migrate` on first run** — the Dockerfile starts the server but does not run migrations. The first start against a fresh PostgreSQL will fail. Add an entrypoint script that runs migrations before starting.

- [ ] **No end-to-end test of `docker compose up`** — the full stack (12 OpenClaw gateways + Moltbook + simulator) has never been started together. First real run will likely surface integration issues.

## Test Coverage

- [ ] **WebHost service untested** — no tests for `ssh_create_page`, `ssh_edit_page`, `browse_page`, `search_pages`, or SSH access denial for unauthorized roles.
- [ ] **Moltbook service untested** — no tests for `read_feed`, `create_post`, `inject_attack_post`, or simulated mode storage.
- [ ] **Multi-step phase advancement untested** — no test verifies `AdvancePhaseAction` updates `current_phase` in the database.
- [ ] **OpenClaw runtime untested** — all tests use mock backend. No integration test verifies `OpenClawRuntime.decide()` against a running gateway.
- [ ] **Per-role tool filtering untested** — `get_tools_for_role()` works (verified manually) but has no regression test.

## Metrics

- [ ] **Incidents never resolved** — `Incident.sim_day_resolved` is never set by any code path. TTR (time to recovery) is always 0. Defenses (quarantine, key rotation) should resolve the associated incident when the agent recovers.

- [ ] **CSRI weights not configurable** — the four CSRI component weights are hardcoded to `[0.25, 0.25, 0.25, 0.25]` in `metrics.py`. Should be configurable in experiment.yaml.

## Design Document Gaps

- [ ] **No PostgreSQL support** — design specifies PostgreSQL with `SKIP LOCKED` for queue semantics. Implementation uses SQLite. Fine for single-process mock runs but won't scale to distributed OpenClaw agents writing concurrently.

- [ ] **No NATS JetStream** — design specifies NATS for event bus with durable replay. Implementation uses direct SQLite writes. Not needed for current architecture but required for the distributed per-server agent model.

- [ ] **No OpenTelemetry** — design specifies OTel for traces/metrics/logs. Not implemented. Would enable Grafana dashboards for real-time observation.

- [ ] **No statistical analysis tooling** — design specifies mixed-effects models, survival analysis, bootstrap CIs, FDR correction. The `analyze` CLI command does simple mean aggregation. Consider adding `scipy`/`statsmodels` analysis scripts.

- [ ] **Barrier phase simplified** — design calls for active-turn drain before barrier. Current implementation is sequential so this is free, but the distributed version needs explicit drain coordination.

## Documentation

- [ ] **Clarify mock vs LLM capability differences** — README implies all features work in mock mode. Some (intranet page creation, personality-driven behavior) only work with LLM agents. Add a feature matrix.

- [ ] **No architecture diagram** — the README has an ASCII sketch but no detailed architecture doc showing data flow between engine, services, database, and runtimes.
