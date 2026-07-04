"""
Q-Guardian OS — Anomaly Simulator Background Task

Generates simulated network telemetry events and broadcasts them
to all connected WebSocket clients every 500ms.
"""

import asyncio
import random
import time
from datetime import datetime, timezone


ATTACK_TYPES = ["DDoS", "SQLi", "XSS", "BruteForce", "PortScan", "C2-Beacon", "DataExfil"]
SEVERITIES = ["low", "medium", "high", "critical"]
SEVERITY_WEIGHTS = [0.4, 0.3, 0.2, 0.1]
PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"]

SRC_SUBNETS = ["10.0.0", "172.16.5", "192.168.1", "45.33.32", "203.0.113"]
DST_SUBNETS = ["192.168.1", "10.10.10", "172.16.0"]


def _random_ip(subnets: list[str]) -> str:
    return f"{random.choice(subnets)}.{random.randint(1, 254)}"


def _generate_telemetry_event() -> dict:
    """Generate a single fake network telemetry event."""
    severity = random.choices(SEVERITIES, weights=SEVERITY_WEIGHTS, k=1)[0]

    # Higher severity → more bytes, more likely to be an attack
    is_attack = random.random() < (0.1 if severity == "low" else 0.3 if severity == "medium" else 0.6 if severity == "high" else 0.85)

    base_bytes = random.randint(64, 1500)
    if is_attack and severity in ("high", "critical"):
        base_bytes = random.randint(5000, 65000)

    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "src_ip": _random_ip(SRC_SUBNETS),
        "dst_ip": _random_ip(DST_SUBNETS),
        "protocol": random.choice(PROTOCOLS),
        "port": random.choice([80, 443, 22, 53, 8080, 3306, 5432, 25, 3389]),
        "bytes": base_bytes,
        "severity": severity,
        "is_threat": is_attack,
        "attack_type": random.choice(ATTACK_TYPES) if is_attack else None,
        "score": round(random.uniform(0.7, 1.0) if is_attack else random.uniform(0.0, 0.3), 3),
    }


IS_ATTACK_ACTIVE = False
PROACTIVE_TRIGGERED = False

def set_attack_mode(active: bool):
    global IS_ATTACK_ACTIVE, PROACTIVE_TRIGGERED
    IS_ATTACK_ACTIVE = active
    if not active:
        PROACTIVE_TRIGGERED = False
    print(f"[SIMULATOR] Attack mode updated: {active}")


async def anomaly_simulator(manager):
    """
    Background task that pushes telemetry events to all connected
    WebSocket clients every 500ms.
    """
    global PROACTIVE_TRIGGERED
    print("[SIMULATOR] Anomaly simulator started (500ms interval)")

    while True:
        try:
            if manager.active_connections:
                if IS_ATTACK_ACTIVE:
                    # ── Simulate Ransomware Attack Telemetry ──────────────────
                    event = {
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "src_ip": "45.33.12.99",
                        "dst_ip": "192.168.1.10",
                        "protocol": "TCP",
                        "port": 445,
                        "bytes": random.randint(30000, 65535),
                        "severity": "critical",
                        "is_threat": True,
                        "attack_type": "Ransomware",
                        "score": 0.985,
                    }
                    
                    # Broadcast telemetry
                    await manager.broadcast({
                        "type": "telemetry",
                        "data": event,
                    })

                    # If this is the start of the attack, proactively mount workspace
                    if not PROACTIVE_TRIGGERED:
                        print("[SIMULATOR] Proactive threat detected! Mounting Investigation Workspace...")
                        
                        # Generate workspace mount message
                        workspace_payload = {
                            "type": "workspace_mount",
                            "workspace": {
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
                        }

                        # Broadcast proactive AI notification in chat
                        await manager.broadcast({
                            "type": "chat",
                            "role": "agent",
                            "content": "⚠️ **CRITICAL THREAT INTRUSION DETECTED**\n\nHigh-volume SMB anomalies detected. I have proactively instantiated investigation workspace **INV-412** and mounted the Threat Topology, Traffic Monitor, and Containment panels. Recommended action: Isolate host immediately.",
                        })

                        # Mount the workspace
                        await manager.broadcast(workspace_payload)
                        PROACTIVE_TRIGGERED = True

                else:
                    # ── Generate standard random packets ────────────────────────
                    events = [_generate_telemetry_event() for _ in range(random.randint(1, 3))]
                    for event in events:
                        await manager.broadcast({
                            "type": "telemetry",
                            "data": event,
                        })

            await asyncio.sleep(0.5)

        except asyncio.CancelledError:
            print("[SIMULATOR] Anomaly simulator stopped.")
            raise
        except Exception as e:
            print(f"[SIMULATOR] Error: {e}")
            await asyncio.sleep(1)
