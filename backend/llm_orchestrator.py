"""
Q-Guardian OS — LLM Orchestrator (Intent Router)

Routes user chat messages to either:
  1. A structured tool-call that emits widget mount/unmount JSON, or
  2. A plain text agent response.

Supports four modes:
  - mock   (default) — keyword-based intent matching
  - groq             — Groq cloud API (OpenAI-compatible, fast inference)
  - openai           — OpenAI chat completions with function calling
  - ollama           — Local Ollama API
"""

import os
import json
import random
import httpx

# ── Configuration ────────────────────────────────────────────────
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "mock")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_BASE_URL = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1/chat/completions")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")


# ── Tool Definition (shared across providers) ───────────────────
RENDER_WIDGET_TOOL = {
    "type": "function",
    "function": {
        "name": "render_security_widget",
        "description": "Mount an interactive security widget in the user's chat canvas. Use this for traffic, topology, mitigation, active incidents, OR to render custom layouts/tables/resumes dynamically using DynamicDashboard.",
        "parameters": {
            "type": "object",
            "properties": {
                "component": {
                    "type": "string",
                    "enum": ["LiveTrafficChart", "ThreatTopology", "MitigationAction", "IncidentTriageBoard", "DynamicDashboard"],
                    "description": "The widget component to mount.",
                },
                "title": {
                    "type": "string",
                    "description": "Display title for the widget.",
                },
                "description": {
                    "type": "string",
                    "description": "Brief description of what this widget shows.",
                },
                "props": {
                    "type": "object",
                    "description": "Component-specific props. For DynamicDashboard, structure props as: { 'layoutType': 'table'|'cards'|'form'|'document', 'data': [...] or 'config': {...} }",
                },
            },
            "required": ["component", "title"],
        },
    },
}

SYSTEM_PROMPT = """You are Q-Guardian OS, an AI Security Operations Center assistant.

You have access to a tool called render_security_widget that mounts interactive security widgets directly in the user's chat canvas. You MUST use this tool whenever the user asks for:
- Live traffic monitoring or network data → mount LiveTrafficChart
- Threat analysis, topology, blast radius, or attack mapping → mount ThreatTopology (NetworkTopologyVisualizer)
- Summaries of active threats, triage, or incident boards → mount IncidentTriageBoard
- Mitigation, blocking, isolating IPs, or incident response → mount MitigationAction (MitigationActionPanel)
- Custom dashboards, firewall rules tables, system load metrics, or styled resumes/documents → mount DynamicDashboard (DynamicDashboard)

For DynamicDashboard props, configure it based on layoutType:
1. 'cards' -> data: Array of { label: str, value: str|num, trend?: str, trendColor?: 'green'|'red'|'neutral' }
2. 'table' -> columns: Array of { key: str, label: str }, rows: Array of objects, actions?: Array of { action: str, label: str, style?: 'default'|'danger' }
3. 'form' -> fields: Array of { name: str, label: str, type: 'text'|'number'|'slider'|'toggle', value: any, min?: num, max?: num }
4. 'document' -> blocks: Array of { type: 'title'|'section'|'paragraph'|'keyvalue'|'list', content: any }

You are stateful. You have access to a vector database (Qdrant) which remembers past interactions, blocked IPs, and incidents. Use retrieved memory context to reply intelligently and render UIs that reflect the current state.

When using the tool, do NOT also generate a text description of the data. The widget IS the response.

Be concise, professional, and proactive."""


# ── Mock Mode (keyword-based intent matching) ────────────────────

def _generate_threat_nodes():
    """Generate realistic threat topology data."""
    attacker_ips = [f"45.33.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(random.randint(1, 3))]
    victim_ips = [f"192.168.1.{random.randint(1,50)}" for _ in range(random.randint(2, 5))]
    clean_ips = [f"10.0.0.{random.randint(1,20)}" for _ in range(random.randint(3, 6))]

    nodes = []
    edges = []

    for ip in attacker_ips:
        nodes.append({"id": ip, "type": "attacker", "label": ip, "severity": "critical"})

    for ip in victim_ips:
        nodes.append({"id": ip, "type": "victim", "label": ip, "severity": "high"})
        src = random.choice(attacker_ips)
        edges.append({
            "source": src,
            "target": ip,
            "attackType": random.choice(["DDoS", "SQLi", "XSS", "BruteForce"]),
            "bandwidth": random.randint(100, 10000),
        })

    for ip in clean_ips:
        nodes.append({"id": ip, "type": "clean", "label": ip, "severity": "low"})

    return nodes, edges


async def _mock_route(user_text: str) -> list[dict]:
    """Keyword-based intent matching that simulates LLM tool calling."""
    s = user_text.lower()

    # ── Traffic / monitoring intents ─────────────────────────────
    if any(kw in s for kw in ["traffic", "monitor", "live", "stream", "packets", "bandwidth", "network"]):
        return [
            {
                "type": "chat",
                "role": "agent",
                "content": "📡 Mounting the live traffic monitor. Telemetry data is streaming in real-time.",
            },
            {
                "type": "widget",
                "action": "mount",
                "component": "LiveTrafficChart",
                "id": f"traffic-{random.randint(1000,9999)}",
                "props": {
                    "title": "Live Network Traffic",
                    "description": "Real-time packet throughput across monitored interfaces",
                },
            },
        ]

    # ── Threat / topology intents ────────────────────────────────
    if any(kw in s for kw in ["threat", "topology", "blast", "attack", "map", "graph", "radius", "analyze", "analyse"]):
        nodes, edges = _generate_threat_nodes()
        return [
            {
                "type": "chat",
                "role": "agent",
                "content": f"🔍 Detected {len([n for n in nodes if n['type'] == 'attacker'])} attacker node(s) targeting {len([n for n in nodes if n['type'] == 'victim'])} servers. Mounting the threat topology.",
            },
            {
                "type": "widget",
                "action": "mount",
                "component": "ThreatTopology",
                "id": f"topology-{random.randint(1000,9999)}",
                "props": {
                    "title": "Attack Blast Radius",
                    "description": "Node-link visualization of active threat vectors",
                    "nodes": nodes,
                    "edges": edges,
                },
            },
        ]

    # ── Triage board intents ──────────────────────────────────────
    if any(kw in s for kw in ["triage", "summary", "board", "active threats", "incidents", "list"]):
        return [
            {
                "type": "chat",
                "role": "agent",
                "content": "📋 Fetching the current incident triage board.",
            },
            {
                "type": "widget",
                "action": "mount",
                "component": "IncidentTriageBoard",
                "id": f"triage-{random.randint(1000,9999)}",
                "props": {
                    "title": "Incident Triage Board",
                    "description": "Active anomalies requiring operator attention",
                },
            },
        ]

    # ── Active Firewall Rules (Stateful memory check) ──────────────
    if any(kw in s for kw in ["rule", "firewall", "blocked", "active blocks"]):
        import qdrant_memory
        mems = qdrant_memory.search_memory("isolate", limit=10, category="mitigation_actions")
        rows = []
        for i, m in enumerate(mems):
            # Parse payload info
            rows.append({
                "id": f"FW-{100+i}",
                "ips": ", ".join(m.get("ips", [])) if isinstance(m.get("ips"), list) else str(m.get("ips", "")),
                "strategy": m.get("strategy", "block").upper(),
                "timestamp": "Active Ruleset"
            })
        if not rows:
            rows.append({
                "id": "N/A",
                "ips": "No active IP blocks registered in Qdrant.",
                "strategy": "NONE",
                "timestamp": "N/A"
            })
        return [
            {
                "type": "chat",
                "role": "agent",
                "content": "🔒 Querying active firewall rules in Qdrant vector memory...",
            },
            {
                "type": "widget",
                "action": "mount",
                "component": "DynamicDashboard",
                "id": f"rules-{random.randint(1000,9999)}",
                "props": {
                    "title": "Active Firewall Rules",
                    "description": "Currently enforced IP isolations retrieved from Qdrant",
                    "layoutType": "table",
                    "columns": [
                        {"key": "id", "label": "Rule ID"},
                        {"key": "ips", "label": "Isolated IPs"},
                        {"key": "strategy", "label": "Strategy"},
                        {"key": "timestamp", "label": "Status"}
                    ],
                    "rows": rows
                }
            }
        ]

    # ── Performance & System Processes ─────────────────────────────
    if any(kw in s for kw in ["process", "system", "load", "cpu"]):
        return [
            {
                "type": "chat",
                "role": "agent",
                "content": "🖥️ Querying system load metrics and active process list...",
            },
            {
                "type": "widget",
                "action": "mount",
                "component": "DynamicDashboard",
                "id": f"system-{random.randint(1000,9999)}",
                "props": {
                    "title": "System Performance & Process Board",
                    "description": "Real-time CPU, RAM, and active processes",
                    "layoutType": "table",
                    "columns": [
                        {"key": "pid", "label": "PID"},
                        {"key": "process", "label": "Process Name"},
                        {"key": "cpu", "label": "CPU (%)"},
                        {"key": "memory", "label": "RAM (MB)"},
                        {"key": "status", "label": "Status"}
                    ],
                    "rows": [
                        {"pid": "1042", "process": "java TelemetryIngestion --simulate 500", "cpu": "1.2", "memory": "245", "status": "Running"},
                        {"pid": "1049", "process": "uvicorn main:app --port 8000", "cpu": "0.8", "memory": "112", "status": "Running"},
                        {"pid": "1055", "process": "node /node_modules/.bin/vite", "cpu": "0.1", "memory": "89", "status": "Running"},
                        {"pid": "1080", "process": "qdrant_client --in-memory-db", "cpu": "0.5", "memory": "154", "status": "Running"}
                    ],
                    "actions": [
                        {"action": "kill_process", "label": "Kill Process", "style": "danger"}
                    ]
                }
            }
        ]

    # ── Resume / Operator Profile Creator ──────────────────────────
    if any(kw in s for kw in ["resume", "cv", "profile", "creator"]):
        return [
            {
                "type": "chat",
                "role": "agent",
                "content": "📝 Rendering professional profile and security operator resume creator UI...",
            },
            {
                "type": "widget",
                "action": "mount",
                "component": "DynamicDashboard",
                "id": f"resume-{random.randint(1000,9999)}",
                "props": {
                    "title": "Professional Operator Profile",
                    "description": "Dynamic GenUI resume document preview",
                    "layoutType": "document",
                    "blocks": [
                        {"type": "title", "content": "Alex Mercer - Senior DevSecOps & SOC Architect"},
                        {"type": "section", "content": "Professional Summary"},
                        {"type": "paragraph", "content": "Highly accomplished cybersecurity professional specializing in Stateful AI Ops, real-time telemetry streaming, and reactive dashboard architectures. Proven expertise in building low-latency WebSocket orchestration nodes and integrating vector memory structures for automated threat containment."},
                        {"type": "section", "content": "Technical Proficiencies"},
                        {"type": "keyvalue", "content": {"Languages": "Java, Python, TypeScript, Go", "AI Systems": "OpenAI, Groq Cloud, Qdrant Vector DB, Sentence Embeddings", "Infrastructure": "Kubernetes, Docker, FastAPI, React/Zustand"}},
                        {"type": "section", "content": "Professional Experience"},
                        {"type": "list", "content": [
                            "Lead Security Architect @ Q-Guardian Enterprise: Maintained Conversational SOC operating system, reducing threat mitigation latency to < 1.5 seconds.",
                            "Security Ingestion Engineer @ Defense-AI: Engineered Java-based packet log parse engines parsing millions of concurrent packet strings."
                        ]}
                    ]
                }
            }
        ]

    # ── Mitigation / action intents ───────────────────────────────
    if any(kw in s for kw in ["mitigate", "block", "isolate", "quarantine", "action", "respond"]):
        return [
            {
                "type": "chat",
                "role": "agent",
                "content": "🛡️ Preparing mitigation protocols. Please confirm the action below.",
            },
            {
                "type": "widget",
                "action": "mount",
                "component": "MitigationAction",
                "id": f"mitigation-{random.randint(1000,9999)}",
                "props": {
                    "title": "Mitigation Action Panel",
                    "description": "Isolate compromised endpoints",
                    "threatIps": [
                        f"45.33.{random.randint(1,254)}.{random.randint(1,254)}"
                        for _ in range(random.randint(2, 5))
                    ],
                    "attackType": random.choice(["Volumetric DDoS", "SQL Injection", "Brute Force"]),
                    "severity": random.choice(["high", "critical"]),
                    "blockDurationHours": 24,
                    "scope": "global"
                },
            },
        ]

    # ── Dashboard / overview ─────────────────────────────────────
    if any(kw in s for kw in ["dashboard", "overview", "status", "summary"]):
        return [
            {
                "type": "chat",
                "role": "agent",
                "content": (
                    "📊 **Security Operations Summary**\n\n"
                    f"• **Active Threats:** {random.randint(3, 12)}\n"
                    f"• **Packets Analyzed (24h):** {random.randint(500000, 2000000):,}\n"
                    f"• **Anomalies Detected:** {random.randint(45, 200)}\n"
                    f"• **Mitigations Executed:** {random.randint(5, 30)}\n"
                    f"• **Mean Detection Time:** {random.uniform(0.3, 2.5):.1f}s\n\n"
                    "Ask me to **show live traffic**, **analyze threats**, or **mitigate attacks** to mount interactive widgets."
                ),
            },
        ]

    # ── Help / capabilities ──────────────────────────────────────
    if any(kw in s for kw in ["help", "what can", "capabilities", "how"]):
        return [
            {
                "type": "chat",
                "role": "agent",
                "content": (
                    "🛡️ **Q-Guardian OS Capabilities**\n\n"
                    "I can mount interactive security widgets directly in this chat:\n\n"
                    "• **\"Show live traffic\"** → Real-time packet throughput chart\n"
                    "• **\"Analyze threat topology\"** → Attack blast radius visualization\n"
                    "• **\"Mitigate the attack\"** → Incident response console\n"
                    "• **\"Dashboard summary\"** → Current security posture overview\n\n"
                    "All widgets are reactive and update via WebSocket in real-time."
                ),
            },
        ]

    # ── General conversational fallback ──────────────────────────
    return [
        {
            "type": "chat",
            "role": "agent",
            "content": (
                f"I understand you're asking about: *\"{user_text}\"*\n\n"
                "As your security operations AI, I can:\n"
                "• **Monitor** live network traffic\n"
                "• **Analyze** threat topology and blast radius\n"
                "• **Mitigate** attacks by isolating compromised IPs\n\n"
                "Try asking me to \"show live traffic\" or \"analyze the threats\"."
            ),
        },
    ]


# ── OpenAI Mode ──────────────────────────────────────────────────

async def _openai_compatible_route(user_text: str, *, api_url: str, api_key: str, model: str) -> list[dict]:
    """
    Generic route for any OpenAI-compatible API (OpenAI, Groq, Together, etc.).
    Uses chat completions with tool calling.
    """
    import qdrant_memory
    
    # Retrieve related memories from Qdrant
    memories = qdrant_memory.search_memory(user_text, limit=5)
    context_str = ""
    if memories:
        context_str = "\n".join([f"- {m['text']}" for m in memories])
        
    system_prompt = SYSTEM_PROMPT
    if context_str:
        system_prompt += f"\n\nRetrieved context from Qdrant vector memory:\n{context_str}\n(Reflect this state in your answer and tool calls if relevant.)"

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                api_url,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_text},
                    ],
                    "tools": [RENDER_WIDGET_TOOL],
                    "tool_choice": "auto",
                    "temperature": 0.3,
                },
            )
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as e:
        print(f"[LLM] HTTP Error from provider: {e.response.text}")
        raise e

    choice = data["choices"][0]
    message = choice["message"]
    results = []

    # Check for tool calls
    if message.get("tool_calls"):
        for tc in message["tool_calls"]:
            if tc["function"]["name"] == "render_security_widget":
                args = json.loads(tc["function"]["arguments"])
                widget_msg = {
                    "type": "widget",
                    "action": "mount",
                    "component": args["component"],
                    "id": f"{args['component'].lower()}-{random.randint(1000,9999)}",
                    "props": {
                        "title": args.get("title", args["component"]),
                        "description": args.get("description", ""),
                        **(args.get("props", {})),
                    },
                }

                # For topology, generate node data if not provided
                if args["component"] == "ThreatTopology" and "nodes" not in widget_msg["props"]:
                    nodes, edges = _generate_threat_nodes()
                    widget_msg["props"]["nodes"] = nodes
                    widget_msg["props"]["edges"] = edges

                # For mitigation, generate IPs if not provided
                if args["component"] == "MitigationAction" and "threatIps" not in widget_msg["props"]:
                    widget_msg["props"]["threatIps"] = [
                        f"45.33.{random.randint(1,254)}.{random.randint(1,254)}"
                        for _ in range(random.randint(2, 5))
                    ]

                results.append(widget_msg)

    # Also include text content if present
    if message.get("content"):
        results.insert(0, {
            "type": "chat",
            "role": "agent",
            "content": message["content"],
        })

    if not results:
        results.append({
            "type": "chat",
            "role": "agent",
            "content": "I processed your request but didn't generate a response. Could you rephrase?",
        })

    return results


async def _openai_route(user_text: str) -> list[dict]:
    """Route via OpenAI chat completions."""
    return await _openai_compatible_route(
        user_text,
        api_url="https://api.openai.com/v1/chat/completions",
        api_key=OPENAI_API_KEY,
        model=OPENAI_MODEL,
    )


async def _groq_route(user_text: str) -> list[dict]:
    """Route via Groq cloud API (OpenAI-compatible, ultra-fast inference)."""
    return await _openai_compatible_route(
        user_text,
        api_url=GROQ_BASE_URL,
        api_key=GROQ_API_KEY,
        model=GROQ_MODEL,
    )


# ── Ollama Mode ──────────────────────────────────────────────────

async def _ollama_route(user_text: str) -> list[dict]:
    """Route via local Ollama API. Falls back to mock if Ollama is unavailable."""
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{OLLAMA_BASE_URL}/api/chat",
                json={
                    "model": OLLAMA_MODEL,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_text},
                    ],
                    "stream": False,
                },
            )
            resp.raise_for_status()
            data = resp.json()

        content = data.get("message", {}).get("content", "")
        if content:
            return [{"type": "chat", "role": "agent", "content": content}]
    except Exception as e:
        print(f"[LLM] Ollama unavailable ({e}), falling back to mock mode")

    return await _mock_route(user_text)


# ── Public Router ────────────────────────────────────────────────

async def route_intent(user_text: str) -> list[dict]:
    """
    Main entry point. Routes user text through the configured LLM provider.
    Returns a list of WebSocket messages to send back to the client.
    """
    provider = LLM_PROVIDER.lower()

    if provider == "groq" and GROQ_API_KEY:
        try:
            return await _groq_route(user_text)
        except Exception as e:
            print(f"[LLM] Groq error: {e}, falling back to mock")
            return await _mock_route(user_text)

    if provider == "openai" and OPENAI_API_KEY:
        try:
            return await _openai_route(user_text)
        except Exception as e:
            print(f"[LLM] OpenAI error: {e}, falling back to mock")
            return await _mock_route(user_text)

    if provider == "ollama":
        return await _ollama_route(user_text)

    # Default: mock mode
    return await _mock_route(user_text)
