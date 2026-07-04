"""
Q-Guardian OS — WebSocket Connection Manager & Message Handler
"""

import uuid
import json
from fastapi import WebSocket
from llm_orchestrator import route_intent
import qdrant_memory


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
    msg_type = data.get("type", "")

    if msg_type == "chat":
        user_text = data.get("content", "").strip()
        if not user_text:
            return

        # Add user's chat message to memory
        qdrant_memory.add_memory(
            text=f"User asked: {user_text}",
            category="chat_history",
            metadata={"session_id": session_id, "speaker": "user"}
        )

        # Route through LLM orchestrator
        responses = await route_intent(user_text)

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

            # Simulate mitigation execution
            await manager.send_personal(websocket, {
                "type": "chat",
                "role": "agent",
                "content": (
                    f"✅ **Mitigation Executed**\n\n"
                    f"**Strategy:** {strategy.upper()}\n"
                    f"**IPs Isolated:** {', '.join(ips)}\n"
                    f"**Status:** All firewall rules applied successfully.\n"
                    f"{'**Notes:** ' + notes if notes else ''}\n\n"
                    f"Traffic from these sources has been {'blocked' if strategy == 'block' else 'rate-limited' if strategy == 'rate-limit' else 'quarantined'}. "
                    f"I've recorded this action in my vector memory."
                ),
            })

            # Send a widget update to reflect the mitigation
            await manager.send_personal(websocket, {
                "type": "widget",
                "action": "mount",
                "component": "LiveTrafficChart",
                "id": "post-mitigation-traffic",
                "props": {
                    "title": "Post-Mitigation Traffic",
                    "description": f"Monitoring traffic after isolating {len(ips)} IPs",
                    "mitigatedIps": ips,
                },
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
            await manager.send_personal(websocket, {
                "type": "chat",
                "role": "agent",
                "content": "🧹 Vector memory has been cleared and reset.",
            })

    else:
        await manager.send_personal(websocket, {
            "type": "chat",
            "role": "agent",
            "content": f"Unknown message type: `{msg_type}`",
        })
