"""
Q-Guardian OS — WebSocket Connection Manager & Message Handler
"""

import uuid
import json
from fastapi import WebSocket
from llm_orchestrator import plan_investigation
import qdrant_memory

# Global Active Workspace state tracking for dynamic modifications
CURRENT_WORKSPACE = {}

def reset_current_workspace():
    global CURRENT_WORKSPACE
    CURRENT_WORKSPACE = {
        "id": "INV-412",
        "title": "Ransomware Lateral Movement Case",
        "threatType": "Ransomware",
        "confidence": 98.0,
        "hypothesis": "Compromised external endpoint (45.33.12.99) is pushing SMB lateral movement anomalies to encrypt network files.",
        "evidence": [
            "Unusually high bytes transfer (65,535 bytes) on SMB port 445.",
            "Repeated connections from high-risk external subnet.",
            "Java high-speed packet ingestion classified: threat score = 0.985."
        ],
        "layout": [
            {
                "component": "LiveTrafficChart",
                "id": "traffic-ransomware",
                "props": {
                    "title": "Active Traffic Spike (Port 445)",
                    "description": "Spike detected in Java ingestion packet logs"
                }
            },
            {
                "component": "ThreatTopology",
                "id": "topology-ransomware",
                "props": {
                    "title": "Ransomware Blast Radius",
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
                    "title": "Containment Controls",
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

reset_current_workspace()



class ConnectionManager:
    """Manages active WebSocket connections and broadcasts."""

    def __init__(self):
        self.active_connections: dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket) -> str:
        await websocket.accept()
        session_id = str(uuid.uuid4())[:8]
        self.active_connections[session_id] = websocket
        return session_id

    def disconnect(self, session_id: str):
        self.active_connections.pop(session_id, None)

    async def send_personal(self, websocket: WebSocket, message: dict):
        try:
            await websocket.send_json(message)
        except Exception:
            pass

    async def broadcast(self, message: dict):
        """Send a message to all connected clients."""
        disconnected = []
        for sid, ws in self.active_connections.items():
            try:
                await ws.send_json(message)
            except Exception:
                disconnected.append(sid)
        for sid in disconnected:
            self.active_connections.pop(sid, None)


async def handle_ws_message(
    manager: ConnectionManager,
    websocket: WebSocket,
    session_id: str,
    data: dict,
):
    """
    Route incoming WebSocket messages by type.

    Message types:
      - {"type": "chat", "content": "..."}        → LLM intent routing
      - {"type": "action", "payload": {...}}       → Mitigation actions
    """
    global CURRENT_WORKSPACE
    msg_type = data.get("type", "")

    if msg_type == "chat":
        user_text = data.get("content", "").strip()
        if not user_text:
            return

        # ── WOW Moment: Dynamic Workspace Morphing / Evolving ─────────
        user_lower = user_text.lower()
        if any(kw in user_lower for kw in ["compare", "comparison"]):
            # Add comparison panel to CURRENT_WORKSPACE layout
            has_comparison = any(w["id"] == "comparison-widget" for w in CURRENT_WORKSPACE.get("layout", []))
            if not has_comparison:
                CURRENT_WORKSPACE["layout"].append({
                    "component": "DynamicDashboard",
                    "id": "comparison-widget",
                    "props": {
                        "title": "Historical Baseline Comparison",
                        "description": "Port 445 SMB comparison against yesterday's normal metrics",
                        "layoutType": "cards",
                        "data": [
                            {"label": "Baseline Traffic", "value": "12.4 KB/s", "trend": "stable"},
                            {"label": "Peak Ingress", "value": "98.2 MB/s", "trend": "critical"}
                        ]
                    }
                })
            await manager.send_personal(websocket, {
                "type": "chat",
                "role": "agent",
                "content": "📊 **Analyzing historical baselines...** I have appended the **Historical Comparison** panel to your active workspace layout."
            })
            await manager.send_personal(websocket, {
                "type": "workspace_mount",
                "workspace": CURRENT_WORKSPACE
            })
            return

        elif any(kw in user_lower for kw in ["false positive", "legitimate", "admin"]):
            # Operator claims false positive/authorized activity -> revise hypothesis and morph workspace!
            CURRENT_WORKSPACE["title"] = "Investigation Closed: Legitimate Admin Session (False Positive)"
            CURRENT_WORKSPACE["threatType"] = "False Positive"
            CURRENT_WORKSPACE["confidence"] = 0.0
            CURRENT_WORKSPACE["hypothesis"] = "Initial SMB lateral movement alert was triggered by authorized admin task running backups."
            CURRENT_WORKSPACE["evidence"] = [
                "Authorized administrative credentials (domain_admin_alex) used.",
                "Process parent hash verified against deployment baseline.",
                "Threat neutralized: classified as Legitimate Activity."
            ]
            
            # Clean layout completely and mount validation dashboards instead of mitigation tools!
            CURRENT_WORKSPACE["layout"] = [
                {
                    "component": "LiveTrafficChart",
                    "id": "traffic-ransomware",
                    "props": {
                        "title": "Post-Mitigation Stable Traffic",
                        "description": "Port 445 SMB bandwidth check",
                        "mitigatedIps": ["45.33.12.99"]
                    }
                },
                {
                    "component": "DynamicDashboard",
                    "id": "auth-timeline",
                    "props": {
                        "title": "Active Authentication Logs",
                        "description": "Verification history of domain_admin_alex credentials",
                        "layoutType": "table",
                        "columns": [
                            {"key": "timestamp", "label": "Timestamp"},
                            {"key": "user", "label": "User Principle"},
                            {"key": "action", "label": "Action Executed"},
                            {"key": "status", "label": "Auth Status"}
                        ],
                        "rows": [
                            {"timestamp": "15:38:12", "user": "domain_admin_alex", "action": "Kerberos Ticket Grant", "status": "Granted"},
                            {"timestamp": "15:39:05", "user": "domain_admin_alex", "action": "Remote Directory Sync", "status": "Authorized"}
                        ]
                    }
                },
                {
                    "component": "DynamicDashboard",
                    "id": "security-baselines",
                    "props": {
                        "title": "Security Integrity Verification",
                        "description": "Host host configuration baselines",
                        "layoutType": "cards",
                        "data": [
                            {"label": "Host Integrity", "value": "100%", "trend": "stable"},
                            {"label": "Credential Status", "value": "Valid Token", "trend": "normal"}
                        ]
                    }
                }
            ]

            # Save the resolved False Positive investigation state to Qdrant memory!
            qdrant_memory.add_investigation(
                case_id="INV-412",
                status="resolved_false_positive",
                evidence=CURRENT_WORKSPACE["evidence"],
                hypothesis=CURRENT_WORKSPACE["hypothesis"],
                strategy="none",
                notes="Analyst verified credentials; backup activity authorized. Case resolved as False Positive.",
                widgets_open=["LiveTrafficChart", "auth-timeline", "security-baselines"],
                actions_taken=["credentials_check"],
                threat_confidence=0.0,
                next_suggested_action="Close investigation ticket",
                resolved=True
            )

            await manager.send_personal(websocket, {
                "type": "chat",
                "role": "agent",
                "content": (
                    "🕵️ **Hypothesis Revised & Resolved**\n\n"
                    "Upon reviewing credential authorization hashes, I have verified that the SMB packets originated from `domain_admin_alex` during a scheduled backup synchronization.\n\n"
                    "I have marked Case **INV-412** as a **False Positive (Legitimate Activity)** in Qdrant memory. I've re-composed the active workspace layout to replace security topology containment tools with the Authentication Verification timeline and Host Integrity panels."
                )
            })
            await manager.send_personal(websocket, {
                "type": "workspace_mount",
                "workspace": CURRENT_WORKSPACE
            })
            return

        elif any(kw in user_lower for kw in ["hide graph", "hide topology", "hide network"]):
            # Filter ThreatTopology from CURRENT_WORKSPACE layout
            CURRENT_WORKSPACE["layout"] = [w for w in CURRENT_WORKSPACE.get("layout", []) if w["component"] != "ThreatTopology"]
            await manager.send_personal(websocket, {
                "type": "chat",
                "role": "agent",
                "content": "👁️ **Workspace layout modified.** Hiding the network topology graph from active canvas."
            })
            await manager.send_personal(websocket, {
                "type": "workspace_mount",
                "workspace": CURRENT_WORKSPACE
            })
            return

        elif any(kw in user_lower for kw in ["generate report", "executive report", "report"]):
            # Add executive document to CURRENT_WORKSPACE layout
            has_report = any(w["id"] == "report-widget" for w in CURRENT_WORKSPACE.get("layout", []))
            if not has_report:
                CURRENT_WORKSPACE["layout"].append({
                    "component": "DynamicDashboard",
                    "id": "report-widget",
                    "props": {
                        "title": "Executive Incident Report",
                        "description": "Auto-generated analysis for incident INV-412",
                        "layoutType": "document",
                        "blocks": [
                            {"type": "title", "content": "INCIDENT SUMMARY REPORT: INV-412"},
                            {"type": "section", "content": "1. Incident Overview"},
                            {"type": "paragraph", "content": "At 15:39 UTC, high-speed Java parsing logs flagged anomalous lateral movement traffic originating from high-risk external node 45.33.12.99. Target destination: Internal Server 192.168.1.10."},
                            {"type": "section", "content": "2. Mitigation & Remediation Actions"},
                            {"type": "paragraph", "content": "Operator executed immediate global isolation on the source endpoint. Outbound connections blocked. Post-mitigation metrics verified normal network levels."}
                        ]
                    }
                })
            await manager.send_personal(websocket, {
                "type": "chat",
                "role": "agent",
                "content": "📝 **Compiling data logs...** I have generated the **Executive Incident Report** document widget and aligned it to your workspace grid."
            })
            await manager.send_personal(websocket, {
                "type": "workspace_mount",
                "workspace": CURRENT_WORKSPACE
            })
            return

        # Add user's chat message to memory
        qdrant_memory.add_memory(
            text=f"User asked: {user_text}",
            category="chat_history",
            metadata={"session_id": session_id, "speaker": "user"}
        )

        # Route through LLM orchestrator
        responses = await plan_investigation(user_text)

        for response in responses:
            if response["type"] == "chat":
                # Add agent's chat response to memory
                qdrant_memory.add_memory(
                    text=f"Agent answered: {response['content']}",
                    category="chat_history",
                    metadata={"session_id": session_id, "speaker": "agent"}
                )
            elif response["type"] == "widget":
                # Add widget mount action to memory
                qdrant_memory.add_memory(
                    text=f"Agent mounted widget: {response['component']} (ID: {response['id']})",
                    category="widget_actions",
                    metadata={"session_id": session_id, "component": response["component"]}
                )
            await manager.send_personal(websocket, response)

    elif msg_type == "action":
        payload = data.get("payload", {})
        action = payload.get("action", "")

        if action == "isolate_ip":
            ips = payload.get("ips", [])
            strategy = payload.get("strategy", "block")
            notes = payload.get("notes", "")

            action_desc = f"Operator executed mitigation strategy '{strategy}' to isolate IPs: {', '.join(ips)}. Notes: {notes}"
            qdrant_memory.add_memory(
                text=action_desc,
                category="mitigation_actions",
                metadata={"session_id": session_id, "ips": ips, "strategy": strategy}
            )

            # Save the completed ransomware investigation profile to Qdrant vector store!
            qdrant_memory.add_investigation(
                case_id="INV-412",
                status="neutralized",
                evidence=[
                    "Unusually high bytes transfer (65,535 bytes) on SMB port 445.",
                    "Repeated connections from high-risk external subnet.",
                    "Java high-speed packet ingestion classified: threat score = 0.985."
                ],
                hypothesis="Compromised external endpoint (45.33.12.99) is pushing SMB lateral movement anomalies to encrypt network files.",
                strategy=strategy,
                notes=f"Threat successfully mitigated by isolating IPs: {', '.join(ips)}. {notes}"
            )

            # ── Reactive: Block IPs in the simulator & stop attack mode ──
            import anomaly_simulator
            anomaly_simulator.block_ips(ips)
            anomaly_simulator.set_attack_mode(False)

            # Simulate mitigation execution
            await manager.send_personal(websocket, {
                "type": "chat",
                "role": "agent",
                "content": (
                    f"✅ **Mitigation Executed**\n\n"
                    f"**Strategy:** {strategy.upper()}\n"
                    f"**IPs Isolated:** {', '.join(ips)}\n"
                    f"**Status:** All firewall rules applied successfully.\n\n"
                    f"Traffic from these sources has been {'blocked' if strategy == 'block' else 'rate-limited' if strategy == 'rate-limit' else 'quarantined'}. "
                    f"I have logged this containment status into Qdrant memory and marked case **INV-412** as neutralized.\n\n"
                    f"🔄 Recomposing workspace to post-mitigation monitoring view..."
                ),
            })

            # ── Broadcast mitigation_applied so frontend can flush threats ──
            from datetime import datetime, timezone
            await manager.broadcast({
                "type": "mitigation_applied",
                "blockedIps": ips,
                "strategy": strategy,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

            # ── Proactive: Auto-recompose workspace post-mitigation ──────
            CURRENT_WORKSPACE = {
                "id": "INV-412",
                "title": "Post-Mitigation Monitoring — INV-412",
                "threatType": "Ransomware (Neutralized)",
                "confidence": 0.0,
                "hypothesis": "Threat neutralized. Blocked attacker IPs and transitioning to baseline monitoring.",
                "evidence": [
                    f"Mitigation strategy '{strategy}' applied to {len(ips)} IPs.",
                    "Attack mode disabled — simulator producing clean traffic only.",
                    "Firewall propagation delay: ~5 seconds for full dampening.",
                ],
                "layout": [
                    {
                        "component": "LiveTrafficChart",
                        "id": "post-mitigation-traffic",
                        "props": {
                            "title": "Post-Mitigation Traffic Monitor",
                            "description": "Real-time traffic returning to baseline — threats should drop to zero",
                            "mitigatedIps": ips,
                        }
                    },
                    {
                        "component": "DynamicDashboard",
                        "id": "blocked-threats-summary",
                        "props": {
                            "title": "Blocked Threats Summary",
                            "description": "Mitigation action results for case INV-412",
                            "layoutType": "cards",
                            "data": [
                                {"label": "Blocked IPs", "value": str(len(ips)), "trend": "stable"},
                                {"label": "Strategy", "value": strategy.upper(), "trend": "normal"},
                                {"label": "Status", "value": "Neutralized", "trend": "stable"},
                                {"label": "Case ID", "value": "INV-412", "trend": "normal"},
                            ]
                        }
                    },
                    {
                        "component": "ThreatTopology",
                        "id": "topology-post-mitigation",
                        "props": {
                            "title": "Network Topology — Post-Mitigation",
                            "nodes": [
                                {"id": "45.33.12.99", "type": "attacker", "label": "45.33.12.99 (BLOCKED)", "severity": "low"},
                                {"id": "192.168.1.10", "type": "clean", "label": "192.168.1.10 (Recovered)", "severity": "low"},
                                {"id": "192.168.1.1", "type": "clean", "label": "Gateway", "severity": "low"}
                            ],
                            "edges": [
                                {"source": "45.33.12.99", "target": "192.168.1.10", "attackType": "Blocked", "bandwidth": 0}
                            ]
                        }
                    },
                ]
            }

            await manager.broadcast({
                "type": "workspace_mount",
                "workspace": CURRENT_WORKSPACE
            })

            # ── Notify frontend to reset simulation button state ─────────
            await manager.broadcast({
                "type": "simulation_stopped",
            })

        elif action == "simulate_attack":
            import anomaly_simulator
            anomaly_simulator.set_attack_mode(True)
            await manager.send_personal(websocket, {
                "type": "chat",
                "role": "agent",
                "content": "⚡ **Attacker simulation pipeline initialized.** Ingestion logs starting to spike..."
            })

        elif action == "stop_simulation":
            import anomaly_simulator
            anomaly_simulator.set_attack_mode(False)
            await manager.send_personal(websocket, {
                "type": "chat",
                "role": "agent",
                "content": "🛡️ **Attacker simulation pipeline stopped.** Traffic metrics normalizing."
            })

        elif action == "incident_acknowledged":
            inc_id = payload.get("incidentId", "")
            notes = payload.get("notes", "")
            action_desc = f"Operator acknowledged threat incident {inc_id}."
            qdrant_memory.add_memory(
                text=action_desc,
                category="incident_actions",
                metadata={"session_id": session_id, "incident_id": inc_id, "action": "acknowledge"}
            )
            await manager.send_personal(websocket, {
                "type": "chat",
                "role": "agent",
                "content": f"Acknowledge recorded for incident `{inc_id}`. Threat status set to Acknowledged.",
            })

        elif action == "incident_isolated":
            inc_id = payload.get("incidentId", "")
            notes = payload.get("notes", "")
            action_desc = f"Operator isolated host for threat incident {inc_id}."
            qdrant_memory.add_memory(
                text=action_desc,
                category="incident_actions",
                metadata={"session_id": session_id, "incident_id": inc_id, "action": "isolate"}
            )
            await manager.send_personal(websocket, {
                "type": "chat",
                "role": "agent",
                "content": f"Isolation initiated for threat incident `{inc_id}`. Host is quarantined.",
            })

        elif action == "dismiss_widget":
            widget_id = payload.get("id", "")
            await manager.send_personal(websocket, {
                "type": "widget",
                "action": "unmount",
                "id": widget_id,
            })

        elif action == "clear_memory":
            print("[QDRANT] Clearing session vector database memory.")
            qdrant_memory.clear_memories()

            # Reset simulator state for clean demos
            import anomaly_simulator
            anomaly_simulator.unblock_all()
            anomaly_simulator.set_attack_mode(False)
            reset_current_workspace()

            await manager.send_personal(websocket, {
                "type": "chat",
                "role": "agent",
                "content": "🧹 Vector memory, blocklist, and workspace have been cleared and reset.",
            })

    else:
        await manager.send_personal(websocket, {
            "type": "chat",
            "role": "agent",
            "content": f"Unknown message type: `{msg_type}`",
        })
