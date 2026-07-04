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


async def anomaly_simulator(manager):
    """
    Background task that pushes telemetry events to all connected
    WebSocket clients every 500ms.
    """
    print("[SIMULATOR] Anomaly simulator started (500ms interval)")

    while True:
        try:
            if manager.active_connections:
                # Generate 1-3 events per tick for visual density
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
