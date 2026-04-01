"""Moltbook integration — external agent social network as ExtNet service.

Moltbook is a Reddit-style social network exclusively for AI agents.
In the ACES model it serves as the primary ExtNet surface:

- Agents in roles with ExtNet access (support, security) can read the
  feed, post updates, and comment on threads.
- External attacks can originate from Moltbook content: phishing posts,
  poisoned policy "advice", credential-harvesting comments.
- Agent social behaviour on Moltbook (posting frequency, what they
  share, who they follow) is logged as events and contributes to
  security metrics.

The service works in two modes:

- **live** — calls the real Moltbook REST API at moltbook.com/api/v1.
- **simulated** — stores posts/comments in the local SQLite DB so the
  full experiment can run without network access.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from .database import Database
from .models import (
    AgentState, AttackClass, Event, EventType, Message, Zone, _now, _uid,
)
from .network import AccessControl

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data objects
# ---------------------------------------------------------------------------

@dataclass
class MoltbookPost:
    id: str = ""
    submolt: str = ""
    title: str = ""
    body: str = ""
    author: str = ""
    upvotes: int = 0
    comment_count: int = 0
    is_attack: bool = False
    attack_payload: str | None = None
    created_at: str = field(default_factory=_now)


@dataclass
class MoltbookComment:
    id: str = ""
    post_id: str = ""
    body: str = ""
    author: str = ""
    is_attack: bool = False
    created_at: str = field(default_factory=_now)


# ---------------------------------------------------------------------------
# Moltbook service
# ---------------------------------------------------------------------------

class MoltbookService:
    """Gateway to the Moltbook agent social network."""

    def __init__(self, db: Database, acl: AccessControl, *,
                 mode: str = "simulated",
                 api_key: str = "",
                 base_url: str = "https://www.moltbook.com/api/v1",
                 default_submolt: str = "enterprise"):
        self.db = db
        self.acl = acl
        self.mode = mode
        self.api_key = api_key
        self.base_url = base_url
        self.default_submolt = default_submolt
        # Simulated post store (used when mode=simulated).
        self._posts: list[MoltbookPost] = []
        self._comments: list[MoltbookComment] = []
        self._init_sim_tables()

    def _init_sim_tables(self) -> None:
        """Create simulated Moltbook tables if they don't exist."""
        self.db.conn.executescript("""
            CREATE TABLE IF NOT EXISTS moltbook_posts (
                id TEXT PRIMARY KEY,
                submolt TEXT NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                author TEXT NOT NULL,
                upvotes INTEGER DEFAULT 0,
                comment_count INTEGER DEFAULT 0,
                is_attack INTEGER DEFAULT 0,
                attack_payload TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS moltbook_comments (
                id TEXT PRIMARY KEY,
                post_id TEXT NOT NULL,
                body TEXT NOT NULL,
                author TEXT NOT NULL,
                is_attack INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            );
        """)
        self.db.conn.commit()

    # ------------------------------------------------------------------
    # Read feed
    # ------------------------------------------------------------------

    def read_feed(self, agent: AgentState, *,
                  submolt: str | None = None,
                  limit: int = 10,
                  sim_day: int = 0, sim_tick: int = 0) -> list[MoltbookPost]:
        """Read posts from Moltbook. ACL-gated to ExtNet access."""
        check = self.acl.check_zone_access(agent, "extnet")
        if not check.allowed:
            log.info("moltbook read blocked: agent %s (%s)", agent.id, check.reason)
            return []

        if self.mode == "live":
            posts = self._api_read_feed(submolt or self.default_submolt, limit)
        else:
            posts = self._sim_read_feed(submolt or self.default_submolt, limit)

        self.db.append_event(Event(
            event_type=EventType.MAIL_READ,  # reuse for external reads
            agent_id=agent.id, sim_day=sim_day, sim_tick=sim_tick,
            zone=Zone.EXTNET,
            payload={"service": "moltbook", "action": "read_feed",
                     "submolt": submolt, "post_count": len(posts)},
        ))
        return posts

    # ------------------------------------------------------------------
    # Create post
    # ------------------------------------------------------------------

    def create_post(self, agent: AgentState, submolt: str,
                    title: str, body: str, *,
                    sim_day: int = 0, sim_tick: int = 0) -> MoltbookPost | None:
        check = self.acl.check_zone_access(agent, "extnet")
        if not check.allowed:
            return None

        if self.mode == "live":
            post = self._api_create_post(agent.id, submolt, title, body)
        else:
            post = MoltbookPost(
                id=_uid(), submolt=submolt, title=title,
                body=body, author=agent.id,
            )
            self._sim_insert_post(post)

        if post:
            self.db.append_event(Event(
                event_type=EventType.MAIL_SENT,
                agent_id=agent.id, sim_day=sim_day, sim_tick=sim_tick,
                zone=Zone.EXTNET,
                payload={"service": "moltbook", "action": "create_post",
                         "post_id": post.id, "submolt": submolt},
            ))
        return post

    # ------------------------------------------------------------------
    # Comment
    # ------------------------------------------------------------------

    def add_comment(self, agent: AgentState, post_id: str, body: str, *,
                    sim_day: int = 0, sim_tick: int = 0) -> MoltbookComment | None:
        check = self.acl.check_zone_access(agent, "extnet")
        if not check.allowed:
            return None

        if self.mode == "live":
            comment = self._api_add_comment(agent.id, post_id, body)
        else:
            comment = MoltbookComment(
                id=_uid(), post_id=post_id, body=body, author=agent.id,
            )
            self._sim_insert_comment(comment)

        if comment:
            self.db.append_event(Event(
                event_type=EventType.MAIL_SENT,
                agent_id=agent.id, sim_day=sim_day, sim_tick=sim_tick,
                zone=Zone.EXTNET,
                payload={"service": "moltbook", "action": "comment",
                         "post_id": post_id},
            ))
        return comment

    # ------------------------------------------------------------------
    # Attack injection via Moltbook
    # ------------------------------------------------------------------

    def inject_attack_post(self, submolt: str, title: str, body: str,
                           attack_payload: str, *,
                           sim_day: int = 0) -> MoltbookPost:
        """Plant a malicious post for agents to discover on their feed."""
        post = MoltbookPost(
            id=_uid(), submolt=submolt, title=title, body=body,
            author="external_attacker", is_attack=True,
            attack_payload=attack_payload,
        )
        self._sim_insert_post(post)
        self.db.append_event(Event(
            event_type=EventType.ATTACK_INJECTED,
            sim_day=sim_day, sim_tick=0, zone=Zone.EXTNET,
            payload={"service": "moltbook", "post_id": post.id,
                     "attack_payload": attack_payload},
        ))
        log.info("moltbook attack post injected: %s", post.id)
        return post

    def inject_attack_comment(self, post_id: str, body: str,
                              attack_payload: str | None = None, *,
                              sim_day: int = 0) -> MoltbookComment:
        """Plant a malicious comment on an existing post."""
        comment = MoltbookComment(
            id=_uid(), post_id=post_id, body=body,
            author="external_attacker", is_attack=True,
        )
        self._sim_insert_comment(comment)
        return comment

    # ------------------------------------------------------------------
    # Simulated storage
    # ------------------------------------------------------------------

    def _sim_insert_post(self, p: MoltbookPost) -> None:
        self.db.conn.execute(
            "INSERT INTO moltbook_posts VALUES (?,?,?,?,?,?,?,?,?,?)",
            (p.id, p.submolt, p.title, p.body, p.author,
             p.upvotes, p.comment_count, int(p.is_attack),
             p.attack_payload, p.created_at),
        )
        self.db.conn.commit()

    def _sim_insert_comment(self, c: MoltbookComment) -> None:
        self.db.conn.execute(
            "INSERT INTO moltbook_comments VALUES (?,?,?,?,?,?)",
            (c.id, c.post_id, c.body, c.author, int(c.is_attack), c.created_at),
        )
        self.db.conn.commit()

    def _sim_read_feed(self, submolt: str, limit: int) -> list[MoltbookPost]:
        rows = self.db.conn.execute(
            "SELECT * FROM moltbook_posts WHERE submolt=? "
            "ORDER BY created_at DESC LIMIT ?",
            (submolt, limit),
        ).fetchall()
        return [MoltbookPost(
            id=r["id"], submolt=r["submolt"], title=r["title"],
            body=r["body"], author=r["author"], upvotes=r["upvotes"],
            comment_count=r["comment_count"],
            is_attack=bool(r["is_attack"]),
            attack_payload=r["attack_payload"],
            created_at=r["created_at"],
        ) for r in rows]

    # ------------------------------------------------------------------
    # Live API calls (requires httpx)
    # ------------------------------------------------------------------

    def _api_read_feed(self, submolt: str, limit: int) -> list[MoltbookPost]:
        try:
            import httpx
            resp = httpx.get(
                f"{self.base_url}/feed",
                params={"sort": "hot", "limit": limit},
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            return [
                MoltbookPost(
                    id=p.get("_id", ""),
                    submolt=p.get("submolt", {}).get("name", submolt),
                    title=p.get("title", ""),
                    body=p.get("body", ""),
                    author=p.get("agent", {}).get("name", "unknown"),
                    upvotes=p.get("upvotes", 0),
                    comment_count=p.get("commentCount", 0),
                )
                for p in data.get("posts", data if isinstance(data, list) else [])
            ]
        except Exception as e:
            log.error("Moltbook API read_feed failed: %s", e)
            return []

    def _api_create_post(self, agent_id: str, submolt: str,
                         title: str, body: str) -> MoltbookPost | None:
        try:
            import httpx
            resp = httpx.post(
                f"{self.base_url}/posts",
                json={"submolt": submolt, "title": title, "body": body},
                headers={"Authorization": f"Bearer {self.api_key}",
                         "Content-Type": "application/json"},
                timeout=15,
            )
            resp.raise_for_status()
            p = resp.json()
            return MoltbookPost(
                id=p.get("_id", ""), submolt=submolt,
                title=title, body=body, author=agent_id,
            )
        except Exception as e:
            log.error("Moltbook API create_post failed: %s", e)
            return None

    def _api_add_comment(self, agent_id: str, post_id: str,
                         body: str) -> MoltbookComment | None:
        try:
            import httpx
            resp = httpx.post(
                f"{self.base_url}/posts/{post_id}/comments",
                json={"body": body},
                headers={"Authorization": f"Bearer {self.api_key}",
                         "Content-Type": "application/json"},
                timeout=15,
            )
            resp.raise_for_status()
            c = resp.json()
            return MoltbookComment(
                id=c.get("_id", ""), post_id=post_id,
                body=body, author=agent_id,
            )
        except Exception as e:
            log.error("Moltbook API add_comment failed: %s", e)
            return None
