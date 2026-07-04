"""
Q-Guardian OS — Anomaly Simulator Background Task

Generates simulated network telemetry events and broadcasts them
to all connected WebSocket clients every 500ms.

Features:
  - Realistic baseline traffic with weighted protocol distributions
  - Global IP blocklist that suppresses threat telemetry from mitigated sources
  - Post-mitigation dampening to simulate firewall propagation delay
  - Proactive workspace mounting on critical threat detection
"""

import asyncio
import random
import time
from datetime import datetime, timezone


# ── Realistic Traffic Configuration ──────────────────────────────

# Protocol distributions mirroring real enterprise network patterns
PROTOCOL_PROFILES = {
    "HTTPS": {"weight": 35, "ports": [443, 8443],       "byte_range": (200, 1500),  "threat_capable": False},
    "HTTP":  {"weight": 20, "ports": [80, 8080, 8000],  "byte_range": (500, 4000),  "threat_capable": True},
    "DNS":   {"weight": 20, "ports": [53],               "byte_range": (64, 512),    "threat_capable": True},
    "TCP":   {"weight": 10, "ports": [3306, 5432, 6379], "byte_range": (100, 2000),  "threat_capable": True},
    "SSH":   {"weight": 5,  "ports": [22],               "byte_range": (64, 256),    "threat_capable": True},
    "ICMP":  {"weight": 5,  "ports": [0],                "byte_range": (64, 128),    "threat_capable": False},
    "UDP":   {"weight": 5,  "ports": [123, 514, 1194],   "byte_range": (64, 1000),   "threat_capable": False},
}

# Weighted protocol selection list
_PROTO_NAMES = []
_PROTO_WEIGHTS = []
for name, profile in PROTOCOL_PROFILES.items():
    _PROTO_NAMES.append(name)
    _PROTO_WEIGHTS.append(profile["weight"])

# Realistic internal subnet pools (weighted towards common workstation ranges)
INTERNAL_SUBNETS = [
    ("192.168.1", 40),   # Main office LAN
    ("192.168.2", 15),   # Guest network
    ("10.0.1", 20),      # Server VLAN
    ("10.0.2", 10),      # Dev VLAN
    ("172.16.0", 10),    # Management
    ("172.16.5", 5),     # DMZ
]

EXTERNAL_SUBNETS = [
    ("104.26.10", 15),   # CDN / Cloudflare
    ("142.250.80", 15),  # Google
    ("13.107.42", 10),   # Microsoft
    ("151.101.1", 10),   # Reddit/Fastly
    ("203.0.113", 5),    # Documentation range
    ("45.33.32", 5),     # Threat range
]

_INT_NETS = [s[0] for s in INTERNAL_SUBNETS]
_INT_WEIGHTS = [s[1] for s in INTERNAL_SUBNETS]
_EXT_NETS = [s[0] for s in EXTERNAL_SUBNETS]
_EXT_WEIGHTS = [s[1] for s in EXTERNAL_SUBNETS]

ATTACK_TYPES = ["DDoS", "SQLi", "XSS", "BruteForce", "PortScan", "C2-Beacon", "DataExfil"]
SEVERITIES = ["low", "medium", "high", "critical"]
SEVERITY_WEIGHTS = [0.45, 0.30, 0.18, 0.07]


# ── Global State ─────────────────────────────────────────────────

IS_ATTACK_ACTIVE = False
PROACTIVE_TRIGGERED = False
BLOCKED_IPS: set[str] = set()
_MITIGATION_TIME: float | None = None  # timestamp of when mitigation was applied
_DAMPENING_DURATION = 5.0  # seconds of gradual threat reduction after block


def _random_internal_ip() -> str:
    subnet = random.choices(_INT_NETS, weights=_INT_WEIGHTS, k=1)[0]
    return f"{subnet}.{random.randint(1, 254)}"


def _random_external_ip() -> str:
    subnet = random.choices(_EXT_NETS, weights=_EXT_WEIGHTS, k=1)[0]
    return f"{subnet}.{random.randint(1, 254)}"


def _generate_baseline_event() -> dict:
    """Generate a single realistic baseline telemetry event."""
    proto_name = random.choices(_PROTO_NAMES, weights=_PROTO_WEIGHTS, k=1)[0]
    profile = PROTOCOL_PROFILES[proto_name]

    # Determine direction: 70% outbound (internal→external), 30% internal-only
    if random.random() < 0.7:
        src_ip = _random_internal_ip()
        dst_ip = _random_external_ip()
    else:
        src_ip = _random_internal_ip()
        dst_ip = _random_internal_ip()

    byte_lo, byte_hi = profile["byte_range"]
    base_bytes = random.randint(byte_lo, byte_hi)

    # Occasional micro-bursts (10% chance of 2-5x traffic spike)
    if random.random() < 0.10:
        base_bytes = int(base_bytes * random.uniform(2.0, 5.0))

    # Small chance of low-severity anomaly in baseline (makes data realistic)
    severity = random.choices(SEVERITIES, weights=[0.70, 0.25, 0.04, 0.01], k=1)[0]
    is_threat = severity in ("high", "critical") and profile["threat_capable"] and random.random() < 0.15

    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": proto_name,
        "port": random.choice(profile["ports"]),
        "bytes": base_bytes,
        "severity": severity,
        "is_threat": is_threat,
        "attack_type": random.choice(ATTACK_TYPES) if is_threat else None,
        "score": round(random.uniform(0.6, 0.85), 3) if is_threat else round(random.uniform(0.0, 0.2), 3),
    }


def _generate_attack_event() -> dict:
    """Generate a ransomware attack telemetry event from the known attacker IP."""
    src_ip = "45.33.12.99"

    # If this IP is blocked, check dampening window
    if src_ip in BLOCKED_IPS:
        if _MITIGATION_TIME is not None:
            elapsed = time.time() - _MITIGATION_TIME
            if elapsed < _DAMPENING_DURATION:
                # Gradually reduce threat probability during dampening
                threat_chance = max(0.0, 1.0 - (elapsed / _DAMPENING_DURATION))
                if random.random() > threat_chance:
                    return _generate_baseline_event()
            else:
                # Fully dampened — only produce clean traffic
                return _generate_baseline_event()
        else:
            return _generate_baseline_event()

    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "dst_ip": "192.168.1.10",
        "protocol": "TCP",
        "port": 445,
        "bytes": random.randint(30000, 65535),
        "severity": "critical",
        "is_threat": True,
        "attack_type": "Ransomware",
        "score": round(random.uniform(0.95, 0.999), 3),
    }


def set_attack_mode(active: bool):
    global IS_ATTACK_ACTIVE, PROACTIVE_TRIGGERED
    IS_ATTACK_ACTIVE = active
    if not active:
        PROACTIVE_TRIGGERED = False
    print(f"[SIMULATOR] Attack mode updated: {active}")


def block_ips(ips: list[str]):
    """Add IPs to the global blocklist and record mitigation time."""
    global _MITIGATION_TIME
    BLOCKED_IPS.update(ips)
    _MITIGATION_TIME = time.time()
    print(f"[SIMULATOR] Blocked IPs: {ips}  (total blocked: {len(BLOCKED_IPS)})")


def unblock_all():
    """Clear the blocklist (used on reset/clear)."""
    global _MITIGATION_TIME
    BLOCKED_IPS.clear()
    _MITIGATION_TIME = None
    print("[SIMULATOR] All IPs unblocked")


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
                    # ── Attack mode: mix attack events with baseline ──────────
                    # Generate 1 attack event + 1-2 baseline events per tick
                    attack_event = _generate_attack_event()
                    await manager.broadcast({
                        "type": "telemetry",
                        "data": attack_event,
                    })

                    # Also send some baseline traffic (attacks don't stop normal traffic)
                    baseline_count = random.randint(1, 2)
                    for _ in range(baseline_count):
                        await manager.broadcast({
                            "type": "telemetry",
                            "data": _generate_baseline_event(),
                        })

                    # Proactive workspace mount on first detection
                    if not PROACTIVE_TRIGGERED and attack_event["is_threat"]:
                        print("[SIMULATOR] Proactive threat detected! Mounting Investigation Workspace...")
                        import ws_handler
                        ws_handler.reset_current_workspace()

                        await manager.broadcast({
                            "type": "chat",
                            "role": "agent",
                            "content": "⚠️ **CRITICAL THREAT INTRUSION DETECTED**\n\nHigh-volume SMB anomalies detected. I have proactively instantiated investigation workspace **INV-412** and mounted the Threat Topology, Traffic Monitor, and Containment panels. Recommended action: Isolate host immediately.",
                        })

                        await manager.broadcast({
                            "type": "workspace_mount",
                            "workspace": ws_handler.CURRENT_WORKSPACE
                        })
                        PROACTIVE_TRIGGERED = True

                else:
                    # ── Normal mode: realistic baseline traffic ───────────────
                    event_count = random.randint(2, 4)
                    for _ in range(event_count):
                        await manager.broadcast({
                            "type": "telemetry",
                            "data": _generate_baseline_event(),
                        })

            await asyncio.sleep(0.5)

        except asyncio.CancelledError:
            print("[SIMULATOR] Anomaly simulator stopped.")
            raise
        except Exception as e:
            print(f"[SIMULATOR] Error: {e}")
            await asyncio.sleep(1)
