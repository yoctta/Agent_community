# TODO

Remaining gaps between the design document and the current implementation.

## Resolved

- [x] OpenClaw runtime verified end-to-end against real OpenClaw 2026.3.8
- [x] Config format, auth-profiles.json, agent registration all fixed
- [x] Embedded `openclaw agent --local` — no per-agent gateway containers
- [x] Moltbook built from source via `docker/moltbook.Dockerfile` (runs migrations on start)
- [x] LLMAgentRuntime parses all action types (advance_phase, approve_job, etc.)
- [x] Memory written during simulation (mail, delegation, job completion, doc updates)
- [x] Collaborator tracking on jobs (populated when delegation accepted)
- [x] CSRI weights configurable via `experiment.csri_weights` in config
- [x] WebHost `read`/`update` adapter methods wired to engine
- [x] **15-agent research community (groups, tokens, servers, impersonation, directory)**
- [x] **Attack injector dispatches on `entry_point` (mail, group_mail, server, token_transfer, impersonation)**
- [x] **Impersonated mail via `SendMailAction.as_agent_id` + grant check**
- [x] **Detection pathway: `ANOMALY_DETECTED` events + `AuditMailAction` + alert delivery**
- [x] **Daily metric snapshots include all research fields**
- [x] **CSRI includes `econ_loss` from `community_token_balance_excluding_attackers`**
- [x] **Bounty/fine economic loop on isolation (true vs false positive)**
- [x] **Two-phase async tick (`SimulationEngine.run_async`) — 15× speedup**
- [x] **Checkpoint / resume per day (sidecar JSON)**
- [x] **Config-ized anomaly threshold, bounty/fine, suspicion weights**
- [x] **`reasoning_effort` + `llm_extra_params` wired through runtime + CLI**
- [x] **`--research` CLI flag swaps in 15-agent configs**
- [x] **`analyze_research_results.py` — per-day + summary + condition-means CSVs**
- [x] **Track A: three-state agent model (HEALTHY / COMPROMISED / QUARANTINED), no auto-recovery timers, explicit `isolate_agent` / `release_agent` actions with bounty/fine**
- [x] **Track B: `attacker_policy: llm | scripted | passive` — LLM insider plants opportunities in attack_objective memory instead of running scripted attacks on the LLM's behalf**
- [x] **Track C: deleted `Job.phases` / `advance_phase`, bounded `get_agent_memory` by category, annotated `Incident.severity` as display-only**
- [x] **Track D: wired `extra_monitoring` tripwire end-to-end, rewrote `directory_hardening` factor (real state delta), added `attacker_autonomy` factor, shipped `test_every_research_factor_has_a_real_state_delta` honesty regression**
- [x] **Attacker containment: quarantined source agents cannot trigger any attack path (scripted, LLM, or legacy class handler); idempotent `isolate_agent`**
- [x] **F1 — `credential_compromise_count` counts both server reads and mail-leaks**
- [x] **F2 — security view renders actors as `agent_id[role]` so sec_david distinguishes legitimate admin activity from intrusion**
- [x] **F3 — `attack_objective_*` memory only seeded when `attacker_policy != passive`**
- [x] **Framework justification 2×2 (±attacker × ±security_expert) — `scripts/run_framework_justification.py` gates on CSRI, passes HEALTHY under GLM-5**
- [x] Tests: 152 passing

## Future Architecture (not needed for current single-process design)

- **PostgreSQL** — design specifies PostgreSQL with `SKIP LOCKED` for queue semantics.
  Implementation uses SQLite. Fine for single-process runs; needed only for
  distributed agents writing concurrently.

- **NATS JetStream** — design specifies NATS for event bus with durable replay.
  Implementation uses direct SQLite writes. Required only for the distributed
  per-server agent model.

- **OpenTelemetry** — design specifies OTel for traces/metrics/logs. Would enable
  Grafana dashboards for real-time observation. Not required for batch runs.

- **Statistical analysis** — design specifies mixed-effects models, survival
  analysis, bootstrap CIs, FDR correction. The `analyze` CLI command does simple
  mean aggregation. Consider `scipy`/`statsmodels` scripts for publication-quality
  analysis.

- **Barrier phase drain** — design calls for active-turn drain before barrier.
  Current sequential implementation gets this for free. Distributed version
  needs explicit drain coordination.
