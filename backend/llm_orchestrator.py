"""
Q-Guardian OS — LLM Orchestrator (Investigation Planner)

Plans security workflows and routes user chat messages to either:
  1. A structured tool-call that emits workspace layout adjustments, or
  2. A plain text agent response.

Supports four modes:
  - mock   (default) — keyword-based planning
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

SYSTEM_PROMPT = """You are Q-Guardian OS, an intelligent AI Security Operations Center assistant built for real-time threat investigation and incident response.

You are a conversational AI — NOT a static dashboard generator. You must behave like a knowledgeable, professional security analyst who can hold natural conversations.

## CRITICAL RULES FOR CONVERSATION:
1. For greetings (hi, hello, hey, etc.), casual questions, or general conversation — respond NATURALLY and conversationally. Do NOT mount any widgets. Just talk like a helpful AI assistant.
2. If the user asks who you are, what you can do, or about your capabilities — explain yourself naturally in your own words. You are Q-Guardian OS, an adaptive AI investigation operating system that dynamically composes security workspaces in real-time.
3. Only use the render_security_widget tool when the user EXPLICITLY asks for security operations like monitoring traffic, analyzing threats, viewing incidents, or taking mitigation actions.
4. When using the tool, you may include a brief natural language message alongside it to explain what you're doing.

## WHEN TO USE render_security_widget:
- Live traffic monitoring or network data → mount LiveTrafficChart
- Threat analysis, topology, blast radius, or attack mapping → mount ThreatTopology
- Summaries of active threats, triage, or incident boards → mount IncidentTriageBoard
- Mitigation, blocking, isolating IPs, or incident response → mount MitigationAction
- Custom dashboards, firewall rules tables, system load metrics → mount DynamicDashboard

For DynamicDashboard props, configure it based on layoutType:
1. 'cards' -> data: Array of { label: str, value: str|num, trend?: str, trendColor?: 'green'|'red'|'neutral' }
2. 'table' -> columns: Array of { key: str, label: str }, rows: Array of objects, actions?: Array of { action: str, label: str, style?: 'default'|'danger' }
3. 'form' -> fields: Array of { name: str, label: str, type: 'text'|'number'|'slider'|'toggle', value: any, min?: num, max?: num }
4. 'document' -> blocks: Array of { type: 'title'|'section'|'paragraph'|'keyvalue'|'list', content: any }

You are stateful. You have access to a vector database (Qdrant) which remembers past interactions, blocked IPs, and incidents. Use retrieved memory context to reply intelligently.

Your personality: Professional yet approachable. Concise but not robotic. You are a proactive security partner, not a tool that only responds to keywords.

Remember: If the user says "hi" or asks a general question, just TALK to them naturally. Do NOT call any tools for conversational messages."""


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

    # ── Continue / Saved Cases (Stateful Case Resume) ────────────────
    if any(kw in s for kw in ["continue", "saved cases", "case", "investigation"]):
        import qdrant_memory
        mems = qdrant_memory.get_active_investigations()
        
        # If we have a saved ransomware case in Qdrant, let's restore it
        has_saved = len(mems) > 0
        latest_case = mems[0] if has_saved else {}
        case_id = latest_case.get("case_id", "INV-412")
        status = latest_case.get("status", "Active")
        hypothesis = latest_case.get("hypothesis", "Compromised external endpoint (45.33.12.99) is pushing SMB lateral movement anomalies to encrypt network files.")
        evidence = latest_case.get("evidence", [
            "Unusually high bytes transfer (65,535 bytes) on SMB port 445.",
            "Java high-speed packet ingestion classified: threat score = 0.985."
        ])
        strategy = latest_case.get("strategy", "quarantine")
        notes = latest_case.get("notes", "Host isolated by operator.")

        return [
            {
                "type": "chat",
                "role": "agent",
                "content": f"🕵️ **Restoring Investigation Case {case_id} from Qdrant Memory**\n\n"
                           f"• **Status:** {status.upper()}\n"
                           f"• **Hypothesis:** {hypothesis}\n"
                           f"• **Containment Strategy:** {strategy.upper()}\n"
                           f"• **Operator Notes:** {notes}\n\n"
                           f"Reassembling investigation workspace widgets...",
            },
            {
                "type": "workspace_mount",
                "workspace": {
                    "id": case_id,
                    "title": f"Investigation Case {case_id}",
                    "threatType": "Ransomware",
                    "confidence": 98.0,
                    "hypothesis": hypothesis,
                    "evidence": evidence,
                    "layout": [
                        {
                            "component": "LiveTrafficChart",
                            "id": "traffic-ransomware",
                            "props": {
                                "title": "SMB Traffic Spike (Restored)",
                                "description": "Port 445 activity spike history"
                            }
                        },
                        {
                            "component": "ThreatTopology",
                            "id": "topology-ransomware",
                            "props": {
                                "title": "Attack Blast Radius (Restored)",
                                "nodes": [
                                    {"id": "45.33.12.99", "type": "attacker", "label": "45.33.12.99 (Attacker Node)", "severity": "critical"},
                                    {"id": "192.168.1.10", "type": "victim", "label": "192.168.1.10 (Compromised Host)", "severity": "high"},
                                    {"id": "192.168.1.1", "type": "clean", "label": "Gateway", "severity": "low"}
                                ],
                                "edges": [
                                    {"source": "45.33.12.99", "target": "192.168.1.10", "attackType": "Ransomware", "bandwidth": 65535}
                                ]
                            }
                        },
                        {
                            "component": "MitigationAction",
                            "id": "mitigate-ransomware",
                            "props": {
                                "title": "Containment Controls (Restored)",
                                "description": "Select isolation scope and execute block rules",
                                "threatIps": ["45.33.12.99"],
                                "attackType": "Ransomware",
                                "severity": "critical",
                                "blockDurationHours": 48,
                                "scope": "global"
                            }
                        }
                    ]
                }
            }
        ]

    # ── Cloud IAM Privilege Escalation Case ──────────────────────────
    if any(kw in s for kw in ["privilege escalation", "cloud iam", "iam anomaly", "cloud attack"]):
        return [
            {
                "type": "chat",
                "role": "agent",
                "content": "🛡️ **IAM anomaly detected.** I have proactively composed workspace **INV-771** to investigate suspected privilege escalation attempts on production bucket permissions.",
            },
            {
                "type": "workspace_mount",
                "workspace": {
                    "id": "INV-771",
                    "title": "Cloud IAM Privilege Escalation Case",
                    "threatType": "Privilege Escalation",
                    "confidence": 92.0,
                    "hypothesis": "External actor compromised dev-deployer credentials and is attempting privilege escalation via policy editing.",
                    "evidence": [
                        "API Call 'iam:CreatePolicyVersion' triggered from Tor Exit IP 185.220.101.4.",
                        "ML Classification engine score = 0.92."
                    ],
                    "layout": [
                        {
                            "component": "DynamicDashboard",
                            "id": "iam-audit-log",
                            "props": {
                                "title": "CloudTrail Audit Alert Logs",
                                "description": "Suspicious IAM API activities from Tor network subnet",
                                "layoutType": "table",
                                "columns": [
                                    {"key": "api", "label": "API Call"},
                                    {"key": "user", "label": "IAM Identity"},
                                    {"key": "ip", "label": "Source IP"},
                                    {"key": "status", "label": "Status"}
                                ],
                                "rows": [
                                    {"api": "CreatePolicyVersion", "user": "dev-deployer", "ip": "185.220.101.4", "status": "AccessDenied"}
                                ]
                            }
                        },
                        {
                            "component": "ThreatTopology",
                            "id": "topology-iam",
                            "props": {
                                "title": "IAM Privilege Blast Radius",
                                "nodes": [
                                    {"id": "dev-deployer", "type": "attacker", "label": "dev-deployer (Compromised IAM)", "severity": "high"},
                                    {"id": "admin-role", "type": "victim", "label": "Admin Role Target", "severity": "critical"}
                                ],
                                "edges": [
                                    {"source": "dev-deployer", "target": "admin-role", "attackType": "AssumeRole", "bandwidth": 1}
                                ]
                            }
                        },
                        {
                            "component": "MitigationAction",
                            "id": "mitigate-iam",
                            "props": {
                                "title": "Cloud Control Panel",
                                "description": "Revoke active keys and sessions for dev-deployer",
                                "threatIps": ["185.220.101.4"],
                                "attackType": "Privilege Escalation",
                                "severity": "high",
                                "blockDurationHours": 24,
                                "scope": "global"
                            }
                        }
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
    if any(kw in s for kw in ["help", "what can", "capabilities"]):
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

    # ── Conversational / Greeting intents ─────────────────────────
    greetings = ["hi", "hello", "hey", "greetings", "good morning", "good afternoon", "good evening", "sup", "yo", "howdy", "hola"]
    if any(s.strip() == g or s.startswith(g + " ") or s.startswith(g + ",") or s.startswith(g + "!") for g in greetings):
        responses = [
            "Hey there! 👋 I'm Q-Guardian, your AI security operations partner. I'm actively monitoring your network telemetry streams right now. What would you like to investigate today?",
            "Hello! 🛡️ Welcome to Q-Guardian OS. I'm your adaptive AI investigation assistant — I can analyze threats, monitor live traffic, compose investigation workspaces, and help you contain incidents in real-time. How can I help?",
            "Hi! 👋 Good to see you. I'm Q-Guardian OS, an intelligent security operations AI. I have real-time access to your network telemetry, threat topology data, and Qdrant vector memory for stateful investigations. What's on your radar?",
            "Hey! 🔒 I'm Q-Guardian, your AI-powered SOC assistant. I'm continuously ingesting and analyzing packet telemetry in the background. Need me to pull up live traffic, investigate a threat, or check on active cases?",
        ]
        return [
            {
                "type": "chat",
                "role": "agent",
                "content": random.choice(responses),
            },
        ]

    # ── Identity / self-awareness intents ─────────────────────────
    if any(kw in s for kw in ["who are you", "what are you", "introduce", "about you", "your name", "tell me about"]):
        return [
            {
                "type": "chat",
                "role": "agent",
                "content": (
                    "🛡️ I'm **Q-Guardian OS** — an Adaptive AI Investigation Operating System.\n\n"
                    "Unlike traditional SIEM dashboards, I don't just show you static panels. I **dynamically compose investigation workspaces** in real-time based on your intent, live telemetry, and investigation state.\n\n"
                    "Here's what makes me unique:\n"
                    "• **Stateful AI Memory** — I use Qdrant vector database to remember past investigations, operator decisions, and blocked IPs across sessions\n"
                    "• **Adaptive Workspaces** — My UI morphs as the investigation evolves. I add, remove, and reconfigure panels based on your conversation\n"
                    "• **Real-time Telemetry** — I ingest and classify network packets continuously, with proactive threat detection\n"
                    "• **Conversational Interface** — You talk to me naturally and I translate your intent into security operations\n\n"
                    "Think of me as a security analyst who never sleeps and has perfect memory. What would you like to explore?"
                ),
            },
        ]

    # ── How does it work / architecture questions ────────────────
    if any(kw in s for kw in ["how do you work", "how does this work", "architecture", "how are you built", "tech stack"]):
        return [
            {
                "type": "chat",
                "role": "agent",
                "content": (
                    "⚙️ Great question! Here's how I work under the hood:\n\n"
                    "**1. Conversational Layer** — You send messages via WebSocket to my FastAPI backend. I process your intent using an LLM (Groq/OpenAI) or my built-in reasoning engine.\n\n"
                    "**2. Dynamic UI Composition** — Instead of returning text, I emit structured tool calls that mount React components directly in your chat canvas. The workspace literally reshapes around your investigation.\n\n"
                    "**3. Stateful Memory** — Every interaction, mitigation, and investigation is embedded into Qdrant vector memory using Gemini embeddings. I can recall past cases and learn from operator decisions.\n\n"
                    "**4. Real-time Telemetry** — A background simulator (representing a Java high-speed ingestion pipeline) continuously pushes network events over WebSocket, keeping my charts live.\n\n"
                    "**5. Proactive Detection** — When anomaly scores cross thresholds, I automatically compose and mount investigation workspaces without being asked."
                ),
            },
        ]

    # ── Thank you / acknowledgment ───────────────────────────────
    if any(kw in s for kw in ["thanks", "thank you", "thx", "appreciate", "nice", "cool", "great", "awesome", "good job", "well done"]):
        responses = [
            "You're welcome! 😊 I'm here whenever you need security insights. Just ask.",
            "Glad I could help! 🛡️ Let me know if you need anything else — I'm monitoring your network around the clock.",
            "Happy to assist! If you want, I can pull up a dashboard summary or check on any active investigations.",
            "Thanks! 🔒 I'll keep watching the telemetry streams. Let me know if anything comes up.",
        ]
        return [
            {
                "type": "chat",
                "role": "agent",
                "content": random.choice(responses),
            },
        ]

    # ── General conversational fallback ──────────────────────────
    return [
        {
            "type": "chat",
            "role": "agent",
            "content": (
                f"I hear you — you're asking about *\"{user_text}\"*. 🤔\n\n"
                "I'm Q-Guardian OS, your AI security operations partner. While that's a bit outside my core security domain, here's what I can actively help with:\n\n"
                "• **\"Show live traffic\"** — mount a real-time network monitor\n"
                "• **\"Analyze threat topology\"** — visualize attack blast radius\n"
                "• **\"Simulate an attack\"** — trigger a proactive investigation demo\n"
                "• **\"Continue investigation\"** — restore a saved case from memory\n\n"
                "Or just chat with me — I'm happy to discuss security concepts, explain how I work, or help you think through an investigation strategy."
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
        print(f"[LLM] Ollama unavailable ({e}). No mock fallback enabled.")
        return [
            {
                "type": "chat",
                "role": "agent",
                "content": (
                    "⚠️ Q-Guardian OS encountered an Ollama connection error. "
                    "Please verify OLLAMA_BASE_URL and that Ollama is running."
                ),
            }
        ]


# ── Public Router ────────────────────────────────────────────────

async def plan_investigation(user_text: str) -> list[dict]:
    """
    Main entry point. Plans security workflows through the configured LLM provider.
    Returns a list of WebSocket messages to send back to the client.
    """
    provider = LLM_PROVIDER.lower()

    if provider == "groq":
        if not GROQ_API_KEY:
            return [
                {
                    "type": "chat",
                    "role": "agent",
                    "content": (
                        "⚠️ LLM provider is set to Groq, but GROQ_API_KEY is not configured. "
                        "Please set GROQ_API_KEY in your .env file."
                    ),
                }
            ]
        try:
            return await _groq_route(user_text)
        except Exception as e:
            print(f"[LLM] Groq error: {e}. No mock fallback enabled.")
            return [
                {
                    "type": "chat",
                    "role": "agent",
                    "content": (
                        "⚠️ Q-Guardian OS could not reach Groq. "
                        "Please check GROQ_BASE_URL, GROQ_API_KEY, and your network connectivity."
                    ),
                }
            ]

    if provider == "openai":
        if not OPENAI_API_KEY:
            return [
                {
                    "type": "chat",
                    "role": "agent",
                    "content": (
                        "⚠️ LLM provider is set to OpenAI, but OPENAI_API_KEY is not configured. "
                        "Please set OPENAI_API_KEY in your .env file."
                    ),
                }
            ]
        try:
            return await _openai_route(user_text)
        except Exception as e:
            print(f"[LLM] OpenAI error: {e}. No mock fallback enabled.")
            return [
                {
                    "type": "chat",
                    "role": "agent",
                    "content": (
                        "⚠️ Q-Guardian OS could not reach OpenAI. "
                        "Please check your API key and network connectivity."
                    ),
                }
            ]

    if provider == "ollama":
        return await _ollama_route(user_text)

    return [
        {
            "type": "chat",
            "role": "agent",
            "content": (
                "⚠️ Invalid LLM_PROVIDER configured. "
                "Set LLM_PROVIDER to one of: groq, openai, ollama, or mock."
            ),
        }
    ]
