"""
Q-Guardian OS — FastAPI WebSocket Backend
Main application entry point.
"""

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv

# Load .env from parent directory (qguardian-os/.env)
_env_path = Path(__file__).resolve().parent.parent / ".env"
if _env_path.exists() and not os.getenv("QG_SKIP_DOTENV"):  # tests set this so they never use real keys
    load_dotenv(_env_path)
    print(f"[CONFIG] Loaded env from {_env_path}")

import hmac
from datetime import datetime, timezone
import time

from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field
from fastapi.middleware.cors import CORSMiddleware

from ws_handler import ConnectionManager, handle_ws_message
import anomaly_simulator as sim
import session
import llm_orchestrator


manager = ConnectionManager()

# Shared secrets. Unset means open access, which is fine on localhost; any public
# deployment must set QG_INGEST_TOKEN (render.yaml generates one).
INGEST_TOKEN = os.getenv("QG_INGEST_TOKEN", "")
WS_TOKEN = os.getenv("QG_WS_TOKEN", "")


def _token_ok(expected: str, given: str | None) -> bool:
    return not expected or (given is not None and hmac.compare_digest(expected.encode(), given.encode()))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    print("[Q-Guardian OS] Backend starting...")
    print(f"[Q-Guardian OS] Planner: {llm_orchestrator.LAST_MODE}")
    task = asyncio.create_task(sim.anomaly_simulator(manager))
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    print("[Q-Guardian OS] Backend shut down.")


app = FastAPI(
    title="Q-Guardian OS",
    version="2.0.0",
    description="Stateful AI Security Operations Center — WebSocket Backend",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173",
        *[o for o in os.getenv("CORS_ORIGINS", "").split(",") if o],
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "Q-Guardian OS",
        "connections": len(manager.active_connections),
        "sessions": len(manager.connected_client_ids()),
        "planner": llm_orchestrator.LAST_MODE,
        "telemetry_source": "java-ingest" if time.time() - sim.LAST_INGEST_AT < sim.INGEST_TAKEOVER_SECONDS else "simulator",
    }


class IngestEvent(BaseModel):
    ts: str | None = None
    src_ip: str = Field(min_length=1, max_length=64)
    dst_ip: str = Field(min_length=1, max_length=64)
    protocol: str = Field(default="TCP", max_length=16)
    port: int = Field(ge=0, le=65535)
    bytes: int = Field(ge=0)
    flags: str | None = None


class IngestBatch(BaseModel):
    events: list[IngestEvent] = Field(max_length=1000)


@app.post("/ingest")
async def ingest(batch: IngestBatch, x_ingest_token: str | None = Header(default=None)):
    """Receives parsed telemetry batches from the Java ingestion service.
    While batches keep arriving, the built-in simulator stays paused."""
    if not _token_ok(INGEST_TOKEN, x_ingest_token):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or missing X-Ingest-Token")
    if batch.events:
        sim.LAST_INGEST_AT = time.time()
    events = []
    for ev in batch.events:
        raw = ev.model_dump()
        if raw["ts"] and raw["ts"].isdigit():  # Java sends epoch seconds; the UI expects ISO 8601
            raw["ts"] = datetime.fromtimestamp(int(raw["ts"]), tz=timezone.utc).isoformat()
        events.append(raw)

    # Real telemetry is the shared network view: every connected visitor's session
    # classifies it with its own detector and blocklist. The default session always
    # does too, so the response reflects detections even with nobody watching.
    threats = 0
    targets = [session.DEFAULT_CLIENT_ID, *sorted(manager.connected_client_ids() - {session.DEFAULT_CLIENT_ID})]
    for client_id in targets:
        with session.use_session(session.get_or_create(client_id)):
            found = 0
            for raw in events:
                result = await sim.process_event(manager, dict(raw))
                found += bool(result.get("is_threat"))
        if client_id == session.DEFAULT_CLIENT_ID:
            threats = found
    return {"accepted": len(batch.events), "threats": threats}


@app.websocket("/ws/chat")
async def ws_chat(websocket: WebSocket):
    if not _token_ok(WS_TOKEN, websocket.query_params.get("token")):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    # The browser keeps a client id in localStorage, so a reload resumes the same
    # private session; anything malformed gets a fresh one.
    client_id = session.normalize_client_id(websocket.query_params.get("client"))
    visitor = session.get_or_create(client_id)
    session_id = await manager.connect(websocket, client_id)
    print(f"[WS] Client connected: {session_id} (session {client_id[:8]})")

    # Send welcome message
    with session.use_session(visitor):
        await manager.send_personal(websocket, {
            "type": "chat",
            "role": "agent",
            "content": "🛡️ Q-Guardian OS online. I'm your AI Security Operations assistant. Ask me to show live traffic, analyze threats, or mitigate attacks.",
        })
        await manager.send_personal(websocket, {"type": "agent_mode", **llm_orchestrator.LAST_MODE})

    try:
        while True:
            data = await websocket.receive_json()
            visitor.last_seen = time.time()
            with session.use_session(visitor):
                await handle_ws_message(manager, websocket, session_id, data)
    except WebSocketDisconnect:
        manager.disconnect(session_id)
        print(f"[WS] Client disconnected: {session_id}")
    except Exception as e:
        print(f"[WS] Error for {session_id}: {e}")
        manager.disconnect(session_id)
