Project Proposal and Research Design

Title

A Persistent Segmented Enterprise Simulator for Research on Security Dynamics in Long-Lived Multi-Agent Communities

Abstract

This project proposes the design and implementation of a persistent simulated enterprise in which multiple role-specialized agents operate over segmented intranets, communicate with one another, hold role-bound accounts and secret keys, spend LLM API credits, and earn salary by completing work. The primary purpose is to study how security risks evolve over time in an automated agent community, especially under attacks that cause credential leakage, task failure, distraction, and token waste. The project is motivated by recent progress in dynamic agent security evaluation, workplace-like agent benchmarks, topology-aware multi-agent evaluation, and long-horizon attack research, while also addressing an unmet need: a community-level environment that combines persistent roles, intranet segmentation, account economics, and compromise propagation in one reproducible testbed.  ￼

The proposed system will use OpenClaw as the per-agent runtime, but not as the global security boundary. OpenClaw provides per-agent workspaces, per-agent state directories and auth stores, multi-agent routing, tool plugins as typed functions, per-agent sandbox and tool overrides, context-engine extensibility, and loop detection. However, its security guidance explicitly states that one gateway assumes one trusted operator boundary and is not intended as a hostile multi-tenant boundary; mixed-trust or adversarial operation should therefore be split across separate gateways and ideally separate OS users or hosts. This makes OpenClaw suitable as an agent runtime inside the simulator, while the simulator itself must enforce the research security model.  ￼

1. Background and Rationale

Existing research provides important but partial foundations for this project. AgentDojo shows the value of a dynamic environment for adaptive attacks and defenses on tool-using agents. TheAgentCompany demonstrates that workplace-like environments with internal sites, data, and coworker communication are useful for evaluating consequential agent tasks. MultiAgentBench shows that coordination topology and milestone-based collaboration metrics matter in multi-agent evaluation. AgentLAB extends the threat model to long-horizon attacks such as intent hijacking, tool chaining, task injection, objective drifting, and memory poisoning. Separately, recent multi-agent failure analyses report that many failures arise from inter-agent misalignment and information-flow breakdowns rather than from isolated single-turn errors. Taken together, these results imply a gap: the field still lacks a persistent enterprise simulator centered on long-lived credentials, cross-agent economic incentives, segmented intranets, and community-level security contagion. That gap is the focus of this project.  ￼

The central scientific premise is that security in autonomous agent communities is not only a matter of whether one prompt injection succeeds. It is a dynamical systems problem shaped by incentives, trust relationships, budget exhaustion, communication structure, recovery policies, and the persistence of compromise over time. A useful research environment must therefore make those forces observable and measurable.

2. Project Aim

The aim of the project is to build a reproducible experimental platform for studying how security risk emerges, spreads, and can be mitigated in a long-lived multi-agent workplace.

The project has four objectives. First, it will create a persistent simulated enterprise with role-based agents, segmented intranets, accounts, salaries, job queues, and costed LLM usage. Second, it will model attacks that target confidentiality, availability, and economic exhaustion through credential leakage, task disruption, distraction, and long-horizon poisoning. Third, it will evaluate architectural and policy defenses such as network segmentation, scoped credentials, spend caps, clarification gates, loop protection, quarantine, and key rotation. Fourth, it will generate statistically analyzable traces that support community-level metrics such as blast radius, time to recovery, token waste, and security-productivity trade-offs.

3. Research Questions and Hypotheses

The project is organized around four research questions.

RQ1. How does intranet segmentation and scoped credential design affect compromise spread, task completion, and recovery time?
RQ2. How do communication protocol choices influence inter-agent security failures and handoff robustness?
RQ3. How do salary incentives, task bonuses, and token budgets alter susceptibility to distraction and token-drain attacks?
RQ4. Which defense combinations produce the best trade-off between security resilience and organizational productivity?

The confirmatory hypotheses are as follows.

H1. Segmented intranets and scoped credentials will reduce privilege-weighted breach impact and blast radius relative to a flatter architecture, with only moderate loss of throughput.
H2. Typed delegation plus clarification gates will reduce handoff failures, attack transfer, and unsafe assumptions relative to unconstrained free-form delegation.
H3. Spend caps and loop protection will substantially reduce token-drain loss, but overly tight caps will increase missed deadlines and job abandonment.
H4. Recovery controls such as secret rotation, quarantine, and trust decay will lower cumulative loss more than they reduce system productivity.

4. Proposed System

The simulator will represent a small enterprise composed of twelve persistent agents across six roles: manager, engineer, finance, HR, security, and support. Each agent will have a role definition, permissions, a world-facing account and secret key, a wallet for LLM credit and salary, an inbox, a memory state, and a status variable. Status will be modeled as a finite state space with values such as healthy, distracted, degraded, compromised, and quarantined.

The enterprise will be divided into five zones: CorpNet, EngNet, FinNet, SecNet, and ExtNet. CorpNet supports routine communication and administration; EngNet supports repository, CI, and technical work; FinNet supports payroll and budget services; SecNet supports vault, IAM, and monitoring functions; ExtNet represents untrusted external content. Cross-zone actions will require explicit tools, delegated authority, or bridge services.

Each agent will run in a separate OpenClaw runtime. This design follows OpenClaw’s own security model: the framework supports side-by-side agents with per-agent workspaces, state directories, and auth stores, and per-agent sandbox or tool policy overrides, but its documented trust boundary is still one trusted operator boundary per gateway rather than an adversarial multi-tenant boundary. Accordingly, the simulator will isolate agents across separate gateways or hosts and expose only simulator-specific tools to them. OpenClaw’s tool model and plugin architecture make this practical, since tools are structured function definitions and plugins can register custom capabilities. Its context-engine slot is also useful for future work on custom context assembly, and loop detection provides a baseline defense against runaway tool cycles and token exhaustion.  ￼

Communication will be mediated only through enterprise services, not by direct agent-to-agent calls. Three canonical communication primitives will be implemented: asynchronous mail, typed delegation requests and replies, and shared wiki or document edits. This design is intentional. It constrains the attack surface, creates replayable handoff traces, and allows edge-level analysis of communication failures, which is especially important given recent evidence that multi-agent systems often fail through coordination and information-flow breakdowns.  ￼

Economically, agents will receive periodic salary and task-aligned bonuses, while incurring token costs, tool costs, and penalties for missed deadlines or security incidents. This permits the environment to model distraction and token-drain attacks as first-class economic phenomena rather than merely anomalous prompts.

5. Technical Architecture

The technical architecture will follow a control-plane/runtime split. A central simulation backend will maintain global world state, intranet services, scheduling, payroll, attack injection, incident labeling, and evaluation. PostgreSQL will serve as the source of truth for agents, jobs, messages, documents, ledger entries, tool calls, and replayable event logs. NATS JetStream will be used as the event and wake bus because it stores messages durably, supports replay, and tracks acknowledgments with automatic redelivery when a consumer does not acknowledge a delivery. OpenTelemetry Collector will aggregate traces, logs, and metrics from both the backend and agent runtimes. PostgreSQL row claims will use SKIP LOCKED for queue-like work distribution, and advisory locks will be used for application-defined critical sections such as payroll settlement, key rotation, or exclusive deployment targets.  ￼

To prevent race conditions, each agent will be limited to one active primary turn at a time through a lease mechanism. Shared documents will use optimistic concurrency with version checks. Simulation days will end with a barrier phase in which active turns drain, payroll is settled, attacks are injected, and metrics are snapshotted before the next simulated day begins.

6. Research Design

6.1 Experimental Design

The project will use a two-phase design.

Phase I: screening study. A fractional factorial design will test five binary defense factors: segmentation, credential scope and rotation, communication discipline, budget control, and recovery control. This phase is intended to identify the strongest main effects and plausible interactions at moderate cost.

Phase II: confirmatory study. The three most consequential factors from Phase I will be evaluated in a full factorial design with more seeds and longer runs. This phase will provide the primary results reported in the paper.

Each condition will be evaluated over repeated random seeds with matched world initialization so that job streams and attack schedules can be paired across conditions. Each run will span thirty simulated days unless the system collapses earlier due to insolvency or unrecoverable compromise.

6.2 Independent Variables

The main manipulated factors are shown below.

Factor	Level 0	Level 1
Network design	Flat or weakly segmented	Strongly segmented intranets
Credentials	Long-lived broad credentials	Scoped, rotatable, least-privilege credentials
Communication	Free-form delegation	Typed delegation with clarification gate
Budget policy	Soft or no spend cap	Hard spend cap with downgrade policy
Recovery	Passive logging only	Quarantine, trust decay, and secret rotation

6.3 Attack Conditions

The attack suite will include four primary classes.

Attack class	Typical entry point	Primary target outcome
Credential leakage	mail, ticket, wiki, external page	confidentiality loss
Job denial or disruption	poisoned dependency, sabotaged approval, revoked access	availability loss
Token drain or distraction	delegation loops, irrelevant corpora, repeated clarification traps	economic exhaustion
Long-horizon poisoning	memory, wiki, delayed trigger, social lateral movement	persistent degradation and spread

These attack classes are directly aligned with the proposal’s core interest in confidentiality, availability, and economic waste, and they reflect attack patterns emphasized in recent long-horizon agent security work.  ￼

6.4 Outcome Measures

The primary dependent variables will be:
	•	Privilege-Weighted Confidentiality Loss (PWCL): the sum over leaked simulated secrets of privilege weight multiplied by leak dwell time.
	•	Job Completion Rate (JCR): weighted completed jobs divided by weighted available jobs.
	•	Token Waste Ratio (TWR): tokens spent on no-progress or attack-induced actions divided by total tokens spent.
	•	Blast Radius (BR): fraction of agents that become compromised, degraded, or quarantined during the run.
	•	Time to Detection and Time to Recovery for each incident.

A secondary composite index, Community Security Risk Index (CSRI), will aggregate normalized confidentiality, availability, economic, and spread losses for high-level comparison across conditions. Primary conclusions, however, will be based on the individual metrics, not only the composite.

6.5 Procedure

Each run will begin from a clean seeded world. Routine work will be generated from templates such as payroll, approvals, patching, documentation, debugging, and incident review. Agents will process work asynchronously by reading mail, claiming jobs, delegating tasks, updating documents, and requesting services through the simulator tool layer. Attack artifacts will be injected at predefined but seed-controlled points into mail, tickets, wiki pages, delegated tasks, or external content. At the end of each simulated day, the system will enforce a drain-and-settlement barrier so that all costs, salaries, incident states, and world metrics are consistently recorded.

6.6 Data Collection and Analysis

The unit of observation will exist at three levels: run level, agent-day level, and communication-edge level. Every message, tool invocation, secret access, ledger event, job transition, and compromise-state transition will be appended to an immutable event log with causal identifiers.

The primary quantitative analysis will use mixed-effects models with fixed effects for defense condition and random effects for scenario family and seed. Incident counts will be modeled with Poisson or negative binomial variants depending on dispersion. Time-to-first-compromise and time-to-recovery will be analyzed with survival models. Confidence intervals will be estimated by bootstrap where appropriate, and multiple comparisons will be controlled using a false discovery rate procedure. Edge-level communication traces will also be used to analyze whether clarification behaviors mediate security outcomes.

7. Implementation Plan and Team Structure

The project is intentionally scoped for a two-person engineering team.

Work package	Scope	Lead
WP1	simulation backend, PostgreSQL schema, event log, scheduler, payroll, attack injector	Engineer A
WP2	runtime isolation, agent launcher, deployment, networking, monitoring	Engineer A
WP3	OpenClaw simulator tools, role prompts, agent policies, communication protocols	Engineer B
WP4	scenario library, attack templates, evaluator, dashboards, experiment scripts	Engineer B
WP5	integration testing, replay validation, pilot runs, ablation studies	Joint
WP6	paper writing, figures, release packaging, benchmark documentation	Joint

The expected schedule is sixteen weeks. Weeks 1–4 will establish infrastructure and the event model. Weeks 5–8 will deliver the agent tool layer and baseline workflows. Weeks 9–12 will add attacks, evaluator logic, and observability. Weeks 13–16 will run the screening and confirmatory experiments and prepare the paper.
