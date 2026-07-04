# 🛡️ Q-Guardian OS — An Adaptive Investigation Operating System

> Q-Guardian does not generate dashboards—it generates adaptive investigation workspaces. Every workspace is composed in real time from live telemetry, investigation memory, and analyst intent. As the investigation evolves, the workspace mirrors the AI's reasoning state, ensuring analysts always see the right tools, evidence, and actions at the right moment.

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────┐
│                   User (Browser)                     │
│                                                      │
│   ┌─────────────────────────────────────────────┐    │
│   │           React Chat Canvas                 │    │
│   │  ┌─────────┐ ┌──────────┐ ┌─────────────┐  │    │
│   │  │ Traffic  │ │ Topology │ │ Mitigation  │  │    │
│   │  │  Chart   │ │   Map    │ │   Console   │  │    │
│   │  └─────────┘ └──────────┘ └─────────────┘  │    │
│   │        ▲ Zustand Store (WebSocket)          │    │
│   └────────┼────────────────────────────────────┘    │
│            │ WebSocket (ws://localhost:8000/ws/chat)  │
└────────────┼─────────────────────────────────────────┘
             │
┌────────────┼─────────────────────────────────────────┐
│   FastAPI  │  WebSocket Backend                      │
│            ▼                                         │
│   ┌────────────────┐    ┌──────────────────────┐     │
│   │  WS Handler    │───▶│  LLM Orchestrator    │     │
│   │ (Router)       │    │  (Mock/OpenAI/Ollama)│     │
│   └────────────────┘    └──────────────────────┘     │
│            │                                         │
│   ┌────────────────┐                                 │
│   │ Anomaly        │  ← Broadcasts telemetry every   │
│   │ Simulator      │    500ms to all connected WS    │
│   └────────────────┘                                 │
└──────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────┐
│   Java Telemetry Ingestion (standalone)              │
│   - BufferedReader + manual charAt/indexOf parsing   │
│   - Simulates high-speed DDoS packet processing     │
└──────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Option A: Docker Compose (recommended)
```bash
cd qguardian-os
docker compose up --build
```
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000/health
- **Backend Docs**: http://localhost:8000/docs

### Option B: Local Development

**1. Start the backend:**
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

**2. Start the frontend:**
```bash
cd frontend
npm install
npm run dev
```
Open http://localhost:5173

### Run the Demo Script
```bash
pip install websockets
python demo-attack.py
```

---

## 🎯 How It Works

1. **User types** a message in the chat canvas (e.g., "Show me live traffic").
2. **WebSocket** sends it to the FastAPI backend.
3. **LLM Orchestrator** processes the intent. Instead of generating markdown, it emits a **structured tool call**:
   ```json
   {"action": "mount", "component": "LiveTrafficChart", "props": {...}}
   ```
4. **WidgetRenderer** on the frontend receives this and **dynamically mounts** the React component inline in the chat — zero page reloads.
5. **Anomaly Simulator** continuously pushes telemetry data over the same WebSocket, keeping mounted charts live.

## 📦 Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 19, Vite, TypeScript, Tailwind CSS v4, Zustand, Recharts |
| Backend | FastAPI, WebSockets, OpenAI/Ollama SDK |
| Ingestion | Java 17 (manual `charAt`/`indexOf` parsing) |
| Infrastructure | Docker, Docker Compose |

## 🔧 LLM Configuration

Set environment variables to switch providers:

| Variable | Default | Options |
|----------|---------|---------|
| `LLM_PROVIDER` | `mock` | `mock`, `openai`, `ollama` |
| `OPENAI_API_KEY` | (empty) | Your API key |
| `OPENAI_MODEL` | `gpt-4o` | Any OpenAI model |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Your Ollama URL |
| `OLLAMA_MODEL` | `llama3` | Any Ollama model |

The **mock** mode works out-of-the-box with keyword-based intent matching that emits the same structured JSON a real LLM would.

## 📜 License

MIT — Built as a showcase for the "Stateful AI Agents with Dynamic UI" paradigm.
