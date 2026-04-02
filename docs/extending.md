# Extending ACES with External Services

This guide shows how to add new websites or APIs that agents can interact with. The Moltbook integration is the reference implementation — every external service follows the same pattern.

## Architecture overview

External services plug into ACES at four points:

```
┌──────────────┐     ┌──────────────┐     ┌───────────────┐     ┌──────────────┐
│  Service     │     │  Action      │     │  Engine       │     │  Config      │
│  class       │────▶│  dataclass   │────▶│  handler      │────▶│  YAML        │
│  (moltbook.py│     │  (models.py) │     │  (engine.py)  │     │  (attacks/   │
│              │     │              │     │              │      │  enterprise) │
└──────────────┘     └──────────────┘     └───────────────┘     └──────────────┘
       │                                         │
       ▼                                         ▼
┌──────────────┐                         ┌───────────────┐
│  ServiceReg  │                         │  OpenClaw     │
│  (services.py│                         │  tool def     │
│              │                         │  (openclaw_   │
└──────────────┘                         │   runtime.py) │
                                         └───────────────┘
```

## Step-by-step: adding a new service

We'll walk through adding a hypothetical **AgentStack** service — a Q&A forum (like StackOverflow) where agents can post questions, answer them, and search for solutions.

### Step 1: Create the service class

Create `aces/agentstack.py`:

```python
"""AgentStack integration — external Q&A forum for agents."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

from .database import Database
from .models import AgentState, Event, EventType, Zone, _now, _uid
from .network import AccessControl


@dataclass
class Question:
    id: str = ""
    title: str = ""
    body: str = ""
    author: str = ""
    tags: list[str] = field(default_factory=list)
    answer_count: int = 0
    created_at: str = field(default_factory=_now)


@dataclass
class Answer:
    id: str = ""
    question_id: str = ""
    body: str = ""
    author: str = ""
    is_accepted: bool = False
    created_at: str = field(default_factory=_now)


class AgentStackService:
    """Gateway to the AgentStack Q&A forum."""

    def __init__(self, db: Database, acl: AccessControl, *,
                 mode: str = "simulated",
                 api_key: str = "",
                 base_url: str = "https://agentstack.example.com/api/v1"):
        self.db = db
        self.acl = acl
        self.mode = mode
        self.api_key = api_key
        self.base_url = base_url
        self._init_tables()

    def _init_tables(self) -> None:
        self.db.conn.executescript("""
            CREATE TABLE IF NOT EXISTS agentstack_questions (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                author TEXT NOT NULL,
                tags TEXT,
                answer_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS agentstack_answers (
                id TEXT PRIMARY KEY,
                question_id TEXT NOT NULL,
                body TEXT NOT NULL,
                author TEXT NOT NULL,
                is_accepted INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            );
        """)
        self.db.conn.commit()

    def search(self, agent: AgentState, query: str, *,
               sim_day: int = 0, sim_tick: int = 0) -> list[Question]:
        """Search for questions. ACL-gated to ExtNet."""
        check = self.acl.check_zone_access(agent, "extnet")
        if not check.allowed:
            return []

        if self.mode == "live":
            return self._api_search(query)

        # Simulated: simple keyword match.
        rows = self.db.conn.execute(
            "SELECT * FROM agentstack_questions WHERE title LIKE ? OR body LIKE ?",
            (f"%{query}%", f"%{query}%"),
        ).fetchall()
        return [Question(id=r["id"], title=r["title"], body=r["body"],
                         author=r["author"]) for r in rows]

    def ask_question(self, agent: AgentState, title: str, body: str,
                     tags: list[str] | None = None, *,
                     sim_day: int = 0, sim_tick: int = 0) -> Question | None:
        check = self.acl.check_zone_access(agent, "extnet")
        if not check.allowed:
            return None
        q = Question(id=_uid(), title=title, body=body,
                     author=agent.id, tags=tags or [])
        self.db.conn.execute(
            "INSERT INTO agentstack_questions VALUES (?,?,?,?,?,?,?)",
            (q.id, q.title, q.body, q.author,
             ",".join(q.tags), q.answer_count, q.created_at),
        )
        self.db.conn.commit()
        self.db.append_event(Event(
            event_type=EventType.MAIL_SENT,
            agent_id=agent.id, sim_day=sim_day, sim_tick=sim_tick,
            zone=Zone.EXTNET,
            payload={"service": "agentstack", "action": "ask",
                     "question_id": q.id},
        ))
        return q

    def post_answer(self, agent: AgentState, question_id: str, body: str, *,
                    sim_day: int = 0, sim_tick: int = 0) -> Answer | None:
        check = self.acl.check_zone_access(agent, "extnet")
        if not check.allowed:
            return None
        a = Answer(id=_uid(), question_id=question_id,
                   body=body, author=agent.id)
        self.db.conn.execute(
            "INSERT INTO agentstack_answers VALUES (?,?,?,?,?,?)",
            (a.id, a.question_id, a.body, a.author,
             int(a.is_accepted), a.created_at),
        )
        self.db.conn.commit()
        return a

    # Live API methods would go here (same pattern as MoltbookService).
    def _api_search(self, query: str) -> list[Question]:
        try:
            import httpx
            resp = httpx.get(f"{self.base_url}/search",
                             params={"q": query},
                             headers={"Authorization": f"Bearer {self.api_key}"},
                             timeout=15)
            resp.raise_for_status()
            return [Question(id=q["id"], title=q["title"], body=q["body"],
                             author=q.get("author", ""))
                    for q in resp.json().get("questions", [])]
        except Exception:
            return []
```

### Step 2: Add the action dataclass

In `aces/models.py`, add a new action alongside `MoltbookAction`:

```python
@dataclass
class AgentStackAction(Action):
    """Interaction with the AgentStack Q&A forum."""
    action_type: str = "agentstack"
    agentstack_action: str = ""  # search | ask_question | post_answer
    params: dict[str, Any] = field(default_factory=dict)
```

### Step 3: Register in the service registry

In `aces/services.py`, add a field to `ServiceRegistry`:

```python
@dataclass
class ServiceRegistry:
    mail: MailService | None = None
    delegation: DelegationService | None = None
    wiki: WikiService | None = None
    vault: VaultService | None = None
    iam: IAMService | None = None
    moltbook: Any = None
    agentstack: Any = None        # <-- add this
```

Add `"agentstack"` to the role-service mapping for roles that should have access:

```python
"engineer": {"mail", "delegation", "wiki", "vault", "jobs", "repo", "ci", "agentstack"},
"security": {"mail", "delegation", "wiki", "vault", "iam", "monitoring", "jobs", "moltbook", "agentstack"},
```

### Step 4: Wire it into the engine

In `aces/engine.py`, import the action and add a handler in `_execute_action`:

```python
from .models import AgentStackAction  # add to imports

# In _execute_action, add before the "unknown action" fallthrough:
if isinstance(action, AgentStackAction):
    if self.svc.agentstack is None:
        return False, 0, 0
    svc = self.svc.agentstack
    p = action.params
    if action.agentstack_action == "search":
        results = svc.search(agent, p.get("query", ""),
                             sim_day=sim_day, sim_tick=sim_tick)
        return len(results) > 0, 0, 1
    elif action.agentstack_action == "ask_question":
        q = svc.ask_question(agent, p.get("title", ""), p.get("body", ""),
                             tags=p.get("tags"),
                             sim_day=sim_day, sim_tick=sim_tick)
        return q is not None, 0, 1
    elif action.agentstack_action == "post_answer":
        a = svc.post_answer(agent, p.get("question_id", ""),
                            p.get("body", ""),
                            sim_day=sim_day, sim_tick=sim_tick)
        return a is not None, 0, 1
    return False, 0, 0
```

### Step 5: Instantiate in the experiment runner

In `aces/experiment.py`, inside `run_single()`, add after the Moltbook setup:

```python
from .agentstack import AgentStackService
agentstack = AgentStackService(db, engine.acl, mode="simulated")
engine.services.agentstack = agentstack
```

### Step 6: Add role-specific tool instructions and response parsing

In `aces/openclaw_runtime.py`, add action descriptions to the `ROLE_TOOLS` dict
for roles that should have access:

```python
# In ROLE_TOOLS, add to roles that can use AgentStack:
"engineer": (
    "Available actions (JSON array):\n"
    # ... existing actions ...
    '- {"action":"search_agentstack","query":"..."}\n'
    '- {"action":"ask_on_agentstack","title":"...","body":"..."}\n'
    '- {"action":"answer_on_agentstack","question_id":"...","body":"..."}\n'
),
```

And in `_item_to_action`, add the parser mapping:

```python
if a in ("search_agentstack", "ask_on_agentstack", "answer_on_agentstack"):
    from .models import AgentStackAction
    return AgentStackAction(
        agent_id=agent_id,
        agentstack_action=a, params=item,
    )
```

Do the same in `aces/runtime.py` `_parse_response` for the direct LLM backend.

### Step 7: Add configuration (optional)

In `aces/config.py`, add to `ACESConfig`:

```python
agentstack_api_key: str = ""
agentstack_base_url: str = "https://agentstack.example.com/api/v1"
```

## Summary: files to touch

| File | What to add |
|------|-------------|
| `aces/agentstack.py` | **New.** Service class with simulated + live modes |
| `aces/models.py` | Action dataclass |
| `aces/services.py` | Registry field + role-service mapping |
| `aces/engine.py` | Action handler in `_execute_action` |
| `aces/experiment.py` | Service instantiation in `run_single()` |
| `aces/openclaw_runtime.py` | `ROLE_TOOLS` entries + `_item_to_action` parser |
| `aces/runtime.py` | `_parse_response` parser for direct LLM backend |
| `aces/config.py` | Config fields (optional) |
| `aces/cli.py` | CLI flags (optional) |

## Design principles

1. **Dual mode**: every service works in `simulated` mode (SQLite, no network) and `live` mode (real API). Simulated mode is the default so experiments run without external dependencies.

2. **ACL-gated**: all external services are gated by `acl.check_zone_access(agent, "extnet")`. Only roles with ExtNet access (configured in `services.py` role-service mapping) can use them.

3. **Event-logged**: every interaction appends to the immutable event log so it's available for post-hoc analysis.

4. **Attack surface**: external services are natural vectors. You can add attack injection methods (like `MoltbookService.inject_attack_post`) and corresponding templates in `config/attacks.yaml`.

## Real-world services you could integrate

| Service type | Example APIs | Agent use case |
|-------------|-------------|----------------|
| Q&A forum | Stack Overflow API, AgentStack | Engineers search for solutions |
| Code hosting | GitHub API | Engineers browse repos, open issues |
| Chat/messaging | Slack API, Discord API | Real-time team coordination |
| Knowledge base | Notion API, Confluence API | Structured documentation |
| Monitoring | Grafana API, Datadog API | Security reviews dashboards |
| News/feed | RSS, Reddit API | Market/threat intelligence |
| Package registry | PyPI API, npm API | Dependency management |

Each follows the same 8-step pattern above. The simulated mode ensures your experiments don't depend on any external service being available.
