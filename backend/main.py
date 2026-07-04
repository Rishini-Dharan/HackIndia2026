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

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from ws_handler import ConnectionManager, handle_ws_message
from anomaly_simulator import anomaly_simulator


manager = ConnectionManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    provider = os.getenv("LLM_PROVIDER", "mock")
    print(f"[Q-Guardian OS] Backend starting...")
    print(f"[Q-Guardian OS] LLM Provider: {provider}")
    if provider == "groq":
        print(f"[Q-Guardian OS] Groq Model: {os.getenv('GROQ_MODEL', 'llama-3.3-70b-versatile')}")
    task = asyncio.create_task(anomaly_simulator(manager))
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
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"],
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
    }


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
