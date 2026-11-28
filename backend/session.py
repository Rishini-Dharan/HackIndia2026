"""
Per-visitor state for the public demo.

Each browser gets a client id (kept in localStorage) and its own Session: its own
workspace, simulated attack, blocklist, detector window and saved cases. Code
reads the active session through S(), which is set per WebSocket message, per
simulator tick and per ingest batch via the `use_session` context manager.
Outside any context S() returns a default session (used by tests, the CLI eval,
and ingest batches when nobody is connected).
"""

import re
import time
import uuid
from collections import deque
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field

from ml_detector import MLAnomalyDetector

DEFAULT_CLIENT_ID = "_default"
CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9-]{8,64}$")
IDLE_SESSION_TTL_SECONDS = 3600


@dataclass
class Session:
    client_id: str
    # investigation workspace (ws_handler)
    current_workspace: dict = field(default_factory=dict)
    last_evidence: list = field(default_factory=list)
    attacker_ip: str = ""
    victim_ip: str = ""
    case_id: str = ""
    # simulation and containment (anomaly_simulator)
    is_attack_active: bool = False
    proactive_triggered: bool = False
    blocked_ips: set = field(default_factory=set)
    mitigation_time: float | None = None
    recent_events: deque = field(default_factory=lambda: deque(maxlen=1000))
    detector: MLAnomalyDetector = field(default_factory=MLAnomalyDetector)
    last_seen: float = field(default_factory=time.time)
    chat_times: deque = field(default_factory=deque)
    detections_by_src: dict = field(default_factory=dict)
    attack_family: str | None = None  # UNSW-NB15 family replayed by the current simulated attack  # src ip -> recent detection times  # recent chat messages, for rate limiting


SESSIONS: dict[str, Session] = {}
_current: ContextVar[Session | None] = ContextVar("qg_session", default=None)


def normalize_client_id(raw: str | None) -> str:
    """Accept a well-formed client id from the browser, otherwise mint one."""
    return raw if raw and CLIENT_ID_RE.match(raw) else uuid.uuid4().hex


def get_or_create(client_id: str) -> Session:
    sess = SESSIONS.get(client_id)
    if sess is None:
        sess = SESSIONS[client_id] = Session(client_id=client_id)
        with use_session(sess):
            import ws_handler
            ws_handler.reset_current_workspace()
    sess.last_seen = time.time()
    return sess


def S() -> Session:
    """The active session, or the default one outside any session context."""
    return _current.get() or get_or_create(DEFAULT_CLIENT_ID)


def current_client_id() -> str:
    return S().client_id


@contextmanager
def use_session(sess: Session):
    token = _current.set(sess)
    try:
        yield sess
    finally:
        _current.reset(token)


CHATS_PER_MINUTE = 10


def allow_chat(sess: "Session", now: float | None = None) -> bool:
    """Per-visitor limit on chat messages that reach the planner."""
    now = time.time() if now is None else now
    while sess.chat_times and now - sess.chat_times[0] > 60:
        sess.chat_times.popleft()
    if len(sess.chat_times) >= CHATS_PER_MINUTE:
        return False
    sess.chat_times.append(now)
    return True


def evict_idle(connected_client_ids: set[str]):
    """Drop sessions nobody has used for an hour (saved cases stay in Qdrant)."""
    cutoff = time.time() - IDLE_SESSION_TTL_SECONDS
    for cid in [c for c, s in SESSIONS.items()
                if c != DEFAULT_CLIENT_ID and c not in connected_client_ids and s.last_seen < cutoff]:
        del SESSIONS[cid]
