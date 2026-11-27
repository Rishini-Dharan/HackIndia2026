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
if _env_path.exists():
    load_dotenv(_env_path)
    print(f"[CONFIG] Loaded env from {_env_path}")

import time

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from fastapi.middleware.cors import CORSMiddleware

from ws_handler import ConnectionManager, handle_ws_message
import anomaly_simulator as sim
import llm_orchestrator


manager = ConnectionManager()


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
async def ingest(batch: IngestBatch):
    """Receives parsed telemetry batches from the Java ingestion service.
    While batches keep arriving, the built-in simulator stays paused."""
    sim.LAST_INGEST_AT = time.time()
    threats = 0
    for ev in batch.events:
        result = await sim.process_event(manager, ev.model_dump())
        threats += bool(result.get("is_threat"))
    return {"accepted": len(batch.events), "threats": threats}


@app.websocket("/ws/chat")
async def ws_chat(websocket: WebSocket):
    session_id = await manager.connect(websocket)
    print(f"[WS] Client connected: {session_id}")

    # Send welcome message
    await manager.send_personal(websocket, {
        "type": "chat",
        "role": "agent",
        "content": "🛡️ Q-Guardian OS online. I'm your AI Security Operations assistant. Ask me to show live traffic, analyze threats, or mitigate attacks.",
    })
    await manager.send_personal(websocket, {"type": "agent_mode", **llm_orchestrator.LAST_MODE})

    try:
        while True:
            data = await websocket.receive_json()
            await handle_ws_message(manager, websocket, session_id, data)
    except WebSocketDisconnect:
        manager.disconnect(session_id)
        print(f"[WS] Client disconnected: {session_id}")
    except Exception as e:
        print(f"[WS] Error for {session_id}: {e}")
        manager.disconnect(session_id)
