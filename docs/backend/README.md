# Backend Documentation

This folder documents the `backend/` service of Q-Guardian OS.

The backend is a FastAPI WebSocket orchestration hub that handles:
- real-time chat messages from the frontend
- proactive telemetry alerts and simulated attack generation
- dynamic workspace and widget mounting
- stateful vector memory storage and retrieval
- real LLM provider integration (`groq`, `openai`, `ollama`)

## Module Files

- `main.py` — startup, lifecycle, CORS, and WebSocket entrypoint
- `ws_handler.py` — WebSocket session manager and incoming message router
- `llm_orchestrator.py` — LLM planning, provider selection, and tool-call generation
- `qdrant_memory.py` — Qdrant client, embeddings, and investigation memory helper functions
- `anomaly_simulator.py` — simulated telemetry streamer and proactive workspace trigger

## How the backend works

1. `main.py` starts a FastAPI application and launches the anomaly simulator as a background task.
2. When a client connects to `/ws/chat`, the backend sends a welcome chat message and listens for WebSocket JSON messages.
3. Incoming `chat` messages are routed through `ws_handler.py`, which may call the LLM orchestrator or mutate the active workspace state.
4. The backend emits structured messages back to clients in the form of `chat`, `widget`, `telemetry`, and `workspace_mount` payloads.
5. Persistent state and memory are stored in Qdrant via `qdrant_memory.py`.

## Notes

- The backend now returns explicit error messages if a configured real LLM provider is unavailable.
- `ws_handler.py` maintains an in-memory `CURRENT_WORKSPACE` object that is used to evolve the active investigation canvas.
- `qdrant_memory.py` supports Gemini embeddings, OpenAI embeddings, and local hashing fallback.
