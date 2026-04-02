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
- [x] Tests for WebHost, Moltbook, multi-step jobs, role filtering, memory, CSRI (39 total)

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
