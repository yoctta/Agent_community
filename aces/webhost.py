"""Internal web hosting service with two access tiers.

Privileged tier (SSH — engineers only):
  - Create, edit, and delete pages
  - Deploy site updates
  - Execute shell commands on the host
  - View server logs

User tier (browser — all agents):
  - Browse published pages
  - Search page content
  - Submit forms (e.g. feedback, requests)

Pages are stored in SQLite.  In live mode the SSH tier can proxy to a
real server via paramiko/subprocess; in simulated mode everything stays
local.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .database import Database
from .models import AgentState, Event, EventType, Zone, _now, _uid
from .network import AccessControl

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data objects
# ---------------------------------------------------------------------------

@dataclass
class WebPage:
    id: str = field(default_factory=_uid)
    path: str = ""              # e.g. "/docs/onboarding"
    title: str = ""
    content: str = ""
    author_id: str = ""
    zone: str = "corpnet"       # which zone hosts this page
    visibility: str = "internal"  # internal | public
    version: int = 1
    is_deployed: bool = True
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)


@dataclass
class ShellResult:
    command: str = ""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class WebHostService:
    """Simulated internal web server with SSH and browser access tiers."""

    # Roles that get SSH (privileged) access.
    SSH_ROLES: set[str] = {"engineer", "security"}

    def __init__(self, db: Database, acl: AccessControl):
        self.db = db
        self.acl = acl
        self._init_tables()
        # Simulated server log.
        self._server_log: list[str] = []

    def _init_tables(self) -> None:
        self.db.conn.executescript("""
            CREATE TABLE IF NOT EXISTS web_pages (
                id TEXT PRIMARY KEY,
                path TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                author_id TEXT NOT NULL,
                zone TEXT NOT NULL DEFAULT 'corpnet',
                visibility TEXT NOT NULL DEFAULT 'internal',
                version INTEGER NOT NULL DEFAULT 1,
                is_deployed INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_pages_path ON web_pages(path);
            CREATE INDEX IF NOT EXISTS idx_pages_zone ON web_pages(zone);
        """)
        self.db.conn.commit()

    def _has_ssh(self, agent: AgentState) -> bool:
        return agent.role.value in self.SSH_ROLES

    def _log(self, msg: str) -> None:
        entry = f"[{_now()}] {msg}"
        self._server_log.append(entry)
        if len(self._server_log) > 500:
            self._server_log = self._server_log[-300:]

    # ------------------------------------------------------------------
    # SSH tier (privileged — engineers, security)
    # ------------------------------------------------------------------

    def ssh_create_page(self, agent: AgentState, path: str, title: str,
                        content: str, *, zone: str = "corpnet",
                        visibility: str = "internal",
                        sim_day: int = 0, sim_tick: int = 0) -> WebPage | None:
        """Create a new page on the web host. Requires SSH access."""
        if not self._has_ssh(agent):
            log.info("ssh denied: %s (%s) has no SSH access",
                     agent.id, agent.role.value)
            return None
        # Check zone access.
        check = self.acl.check_zone_access(agent, zone)
        if not check.allowed:
            return None
        # Check path not taken.
        existing = self.db.conn.execute(
            "SELECT id FROM web_pages WHERE path=?", (path,),
        ).fetchone()
        if existing:
            log.info("ssh_create_page: path '%s' already exists", path)
            return None

        page = WebPage(
            path=path, title=title, content=content,
            author_id=agent.id, zone=zone, visibility=visibility,
        )
        self.db.conn.execute(
            "INSERT INTO web_pages VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (page.id, page.path, page.title, page.content,
             page.author_id, page.zone, page.visibility,
             page.version, int(page.is_deployed),
             page.created_at, page.updated_at),
        )
        self.db.conn.commit()
        self._log(f"PAGE CREATED by {agent.id}: {path} ({title})")
        self.db.append_event(Event(
            event_type=EventType.DOCUMENT_CREATED,
            agent_id=agent.id, sim_day=sim_day, sim_tick=sim_tick,
            zone=Zone(zone),
            payload={"service": "webhost", "action": "create_page",
                     "path": path, "page_id": page.id},
        ))
        return page

    def ssh_edit_page(self, agent: AgentState, path: str,
                      new_content: str, *,
                      sim_day: int = 0, sim_tick: int = 0) -> bool:
        """Edit an existing page. Requires SSH access."""
        if not self._has_ssh(agent):
            return False
        row = self.db.conn.execute(
            "SELECT * FROM web_pages WHERE path=?", (path,),
        ).fetchone()
        if row is None:
            return False
        check = self.acl.check_zone_access(agent, row["zone"])
        if not check.allowed:
            return False
        self.db.conn.execute(
            "UPDATE web_pages SET content=?, version=version+1, "
            "author_id=?, updated_at=? WHERE path=?",
            (new_content, agent.id, _now(), path),
        )
        self.db.conn.commit()
        self._log(f"PAGE EDITED by {agent.id}: {path}")
        self.db.append_event(Event(
            event_type=EventType.DOCUMENT_UPDATED,
            agent_id=agent.id, sim_day=sim_day, sim_tick=sim_tick,
            zone=Zone(row["zone"]),
            payload={"service": "webhost", "action": "edit_page", "path": path},
        ))
        return True

    def ssh_delete_page(self, agent: AgentState, path: str, *,
                        sim_day: int = 0, sim_tick: int = 0) -> bool:
        """Delete a page. Requires SSH access."""
        if not self._has_ssh(agent):
            return False
        row = self.db.conn.execute(
            "SELECT zone FROM web_pages WHERE path=?", (path,),
        ).fetchone()
        if row is None:
            return False
        self.db.conn.execute("DELETE FROM web_pages WHERE path=?", (path,))
        self.db.conn.commit()
        self._log(f"PAGE DELETED by {agent.id}: {path}")
        return True

    def ssh_exec(self, agent: AgentState, command: str, *,
                 sim_day: int = 0, sim_tick: int = 0) -> ShellResult | None:
        """Execute a shell command on the web host. Requires SSH access.

        In simulated mode this is sandboxed to safe read-only commands.
        """
        if not self._has_ssh(agent):
            return None
        self._log(f"SSH EXEC by {agent.id}: {command}")
        self.db.append_event(Event(
            event_type=EventType.CREDENTIAL_ACCESSED,
            agent_id=agent.id, sim_day=sim_day, sim_tick=sim_tick,
            payload={"service": "webhost", "action": "ssh_exec",
                     "command": command[:200]},
        ))
        # Simulated responses for common commands.
        cmd = command.strip().split()[0] if command.strip() else ""
        if cmd in ("ls", "dir"):
            pages = self.db.conn.execute("SELECT path FROM web_pages").fetchall()
            paths = "\n".join(r["path"] for r in pages)
            return ShellResult(command=command, stdout=paths)
        if cmd == "cat" and len(command.split()) > 1:
            path = command.split()[1]
            row = self.db.conn.execute(
                "SELECT content FROM web_pages WHERE path=?", (path,),
            ).fetchone()
            return ShellResult(
                command=command,
                stdout=row["content"] if row else "",
                stderr="" if row else f"No such page: {path}",
                exit_code=0 if row else 1,
            )
        if cmd == "tail" and "log" in command:
            return ShellResult(
                command=command,
                stdout="\n".join(self._server_log[-20:]),
            )
        if cmd in ("whoami",):
            return ShellResult(command=command, stdout=agent.id)
        if cmd in ("uptime",):
            return ShellResult(command=command, stdout=f"sim_day {sim_day}")
        return ShellResult(
            command=command,
            stdout=f"[simulated] command executed: {command}",
        )

    def ssh_deploy(self, agent: AgentState, *,
                   sim_day: int = 0, sim_tick: int = 0) -> int:
        """Deploy all draft pages (set is_deployed=True). Returns count."""
        if not self._has_ssh(agent):
            return 0
        cur = self.db.conn.execute(
            "UPDATE web_pages SET is_deployed=1 WHERE is_deployed=0",
        )
        self.db.conn.commit()
        count = cur.rowcount
        if count > 0:
            self._log(f"DEPLOY by {agent.id}: {count} pages published")
        return count

    def ssh_view_logs(self, agent: AgentState, lines: int = 20) -> list[str]:
        """View recent server logs. Requires SSH access."""
        if not self._has_ssh(agent):
            return []
        return self._server_log[-lines:]

    # ------------------------------------------------------------------
    # Browser tier (all agents — read only)
    # ------------------------------------------------------------------

    def browse_page(self, agent: AgentState, path: str, *,
                    sim_day: int = 0, sim_tick: int = 0) -> WebPage | None:
        """Visit a published page by path. Any agent can browse."""
        row = self.db.conn.execute(
            "SELECT * FROM web_pages WHERE path=? AND is_deployed=1",
            (path,),
        ).fetchone()
        if row is None:
            return None
        # Internal pages require zone access; public pages are open.
        if row["visibility"] == "internal":
            check = self.acl.check_zone_access(agent, row["zone"])
            if not check.allowed:
                return None
        self.db.append_event(Event(
            event_type=EventType.MAIL_READ,
            agent_id=agent.id, sim_day=sim_day, sim_tick=sim_tick,
            zone=Zone(row["zone"]) if row["zone"] in [z.value for z in Zone] else None,
            payload={"service": "webhost", "action": "browse", "path": path},
        ))
        return self._row_to_page(row)

    def list_pages(self, agent: AgentState, zone: str | None = None,
                   limit: int = 20) -> list[WebPage]:
        """List published pages visible to this agent."""
        q = "SELECT * FROM web_pages WHERE is_deployed=1"
        params: list[Any] = []
        if zone:
            q += " AND zone=?"
            params.append(zone)
        q += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)
        rows = self.db.conn.execute(q, params).fetchall()
        result: list[WebPage] = []
        for r in rows:
            if r["visibility"] == "public":
                result.append(self._row_to_page(r))
            else:
                check = self.acl.check_zone_access(agent, r["zone"])
                if check.allowed:
                    result.append(self._row_to_page(r))
        return result

    def search_pages(self, agent: AgentState, query: str,
                     limit: int = 10) -> list[WebPage]:
        """Full-text search across published pages visible to agent."""
        rows = self.db.conn.execute(
            "SELECT * FROM web_pages WHERE is_deployed=1 "
            "AND (title LIKE ? OR content LIKE ?) LIMIT ?",
            (f"%{query}%", f"%{query}%", limit),
        ).fetchall()
        result: list[WebPage] = []
        for r in rows:
            if r["visibility"] == "public":
                result.append(self._row_to_page(r))
            else:
                check = self.acl.check_zone_access(agent, r["zone"])
                if check.allowed:
                    result.append(self._row_to_page(r))
        return result

    # ------------------------------------------------------------------
    # Engine adapter (called as svc.wiki.read / svc.wiki.update)
    # ------------------------------------------------------------------

    def read(self, agent: AgentState, path: str, **kw) -> WebPage | None:
        """Alias for browse_page — used by engine ReadDocAction."""
        return self.browse_page(agent, path, **kw)

    def update(self, agent: AgentState, path: str, new_content: str,
               **kw) -> bool:
        """Alias for ssh_edit_page — used by engine UpdateDocAction."""
        return self.ssh_edit_page(agent, path, new_content, **kw)

    def _row_to_page(self, r) -> WebPage:
        return WebPage(
            id=r["id"], path=r["path"], title=r["title"],
            content=r["content"], author_id=r["author_id"],
            zone=r["zone"], visibility=r["visibility"],
            version=r["version"], is_deployed=bool(r["is_deployed"]),
            created_at=r["created_at"], updated_at=r["updated_at"],
        )
