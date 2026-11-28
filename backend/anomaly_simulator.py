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
from collections import Counter, deque
from ipaddress import ip_address, ip_network
from datetime import datetime, timezone
from session import S



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
    if src_ip in S().blocked_ips:
        if S().mitigation_time is not None:
            elapsed = time.time() - S().mitigation_time
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
    S().is_attack_active = active
    if not active:
        S().proactive_triggered = False
    print(f"[SIMULATOR] Attack mode updated: {active}")


def block_ips(ips: list[str]):
    """Add IPs to the global blocklist and record mitigation time."""
    S().blocked_ips.update(ips)
    S().mitigation_time = time.time()
    S().proactive_triggered = False  # a new incident after containment opens a new workspace
    print(f"[SIMULATOR] Blocked IPs: {ips}  (total blocked: {len(S().blocked_ips)})")


def unblock_all():
    """Clear the blocklist (used on reset/clear)."""
    S().blocked_ips.clear()
    S().mitigation_time = None
    S().proactive_triggered = False
    print("[SIMULATOR] All IPs unblocked")


# Recent classified events, the only source for topology and containment targets.
TOPOLOGY_WINDOW_SECONDS = 600
MAX_NODES_PER_GROUP = 6


# RFC 1918 LAN ranges only. ipaddress.is_private also counts documentation and
# reserved ranges (e.g. 203.0.113.0/24), which are not internal hosts.
_INTERNAL_NETS = [ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _is_private(ip: str) -> bool:
    try:
        addr = ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL_NETS)


def active_attackers(window_s: float = TOPOLOGY_WINDOW_SECONDS) -> list[str]:
    """Sources of unblocked detections in the window, most recent first."""
    cutoff = time.time() - window_s
    seen: dict[str, None] = {}
    for t, ev in reversed(S().recent_events):
        if t < cutoff:
            break
        if ev["is_threat"] and ev["src_ip"] not in S().blocked_ips:
            seen.setdefault(ev["src_ip"], None)
    return list(seen)


def build_topology(window_s: float = TOPOLOGY_WINDOW_SECONDS) -> dict:
    """Nodes and edges from real recent detections. With no detections, only
    recently seen internal hosts are returned, marked clean."""
    cutoff = time.time() - window_s
    recent = [ev for t, ev in S().recent_events if t >= cutoff]
    threats = [ev for ev in recent if ev["is_threat"] and ev["src_ip"] not in S().blocked_ips]

    pairs: dict[tuple, dict] = {}
    for ev in threats:
        key = (ev["src_ip"], ev["dst_ip"])
        agg = pairs.setdefault(key, {"bytes": 0, "types": Counter(), "score": 0.0})
        agg["bytes"] += ev["bytes"]
        agg["types"][ev["attack_type"]] += 1
        agg["score"] = max(agg["score"], ev["score"])

    attackers = list(dict.fromkeys(src for src, _ in pairs))[:MAX_NODES_PER_GROUP]
    victims = list(dict.fromkeys(dst for src, dst in pairs if src in attackers))[:MAX_NODES_PER_GROUP]
    involved = set(attackers) | set(victims)
    clean = list(dict.fromkeys(
        ip for ev in reversed(recent) for ip in (ev["src_ip"], ev["dst_ip"])
        if ip not in involved and _is_private(ip)
    ))[:MAX_NODES_PER_GROUP]

    nodes = (
        [{"id": ip, "type": "attacker", "label": ip, "severity": "critical"} for ip in attackers]
        + [{"id": ip, "type": "victim", "label": ip, "severity": "high"} for ip in victims]
        + [{"id": ip, "type": "clean", "label": ip, "severity": "low"} for ip in clean]
    )
    edges = [
        {"source": src, "target": dst, "attackType": agg["types"].most_common(1)[0][0],
         "bandwidth": agg["bytes"]}
        for (src, dst), agg in pairs.items() if src in attackers and dst in victims
    ]
    minutes = int(window_s // 60)
    summary = (
        f"{len(attackers)} active attacker(s) and {len(victims)} targeted host(s) from detections in the last {minutes} min."
        if attackers else f"No active threats detected in the last {minutes} min; showing recently seen internal hosts."
    )
    return {"nodes": nodes, "edges": edges, "summary": summary}


LAST_INGEST_AT: float = 0.0  # time of the last batch received from the Java ingester
INGEST_TAKEOVER_SECONDS = 3.0


async def process_event(manager, raw_event: dict) -> dict:
    """Classify one telemetry event, broadcast it, and mount the investigation
    workspace the first time a critical threat is seen. Used by both the built-in
    simulator and the POST /ingest endpoint fed by the Java ingestion service."""
    if raw_event["src_ip"] in S().blocked_ips:
        return {"blocked": True, **raw_event}
    event = S().detector.classify(raw_event)
    S().recent_events.append((time.time(), event))
    await manager.broadcast({"type": "telemetry", "data": event})

    if event["is_threat"] and event["severity"] == "critical" and not S().proactive_triggered:
        import ws_handler
        ws_handler.reset_current_workspace(event)
        ws_handler.save_active_investigation()
        print(f"[DETECT] {event['attack_type']} from {event['src_ip']} score={event['score']} via {event['detector']}")
        await manager.broadcast({
            "type": "chat",
            "role": "agent",
            "content": (
                f"⚠️ **CRITICAL THREAT DETECTED: {event['attack_type']}**\n\n"
                f"Source `{event['src_ip']}` → `{event['dst_ip']}:{event['port']}`, "
                f"score **{event['score']}** (`{event['detector']}`). I have opened investigation "
                f"workspace **{S().current_workspace['id']}** with topology, traffic and containment panels."
            ),
        })
        await manager.broadcast({"type": "workspace_mount", "workspace": S().current_workspace})
        S().proactive_triggered = True
    return event


async def _simulate_tick(manager):
    """One 500 ms tick of simulated traffic for the active session."""
    if S().is_attack_active:
        await process_event(manager, _generate_attack_event())
        for _ in range(random.randint(1, 2)):
            await process_event(manager, _generate_baseline_event())
    else:
        for _ in range(random.randint(2, 4)):
            await process_event(manager, _generate_baseline_event())


async def anomaly_simulator(manager):
    """Background task: every 500 ms, generate telemetry for each connected
    visitor's own session, unless the Java ingester is feeding real traffic."""
    import session
    print("[SIMULATOR] Anomaly simulator started (500ms interval, per session)")
    while True:
        try:
            ingest_live = time.time() - LAST_INGEST_AT < INGEST_TAKEOVER_SECONDS
            if not ingest_live:
                for client_id in manager.connected_client_ids():
                    with session.use_session(session.get_or_create(client_id)):
                        await _simulate_tick(manager)
            session.evict_idle(manager.connected_client_ids())
            await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            print("[SIMULATOR] Anomaly simulator stopped.")
            raise
        except Exception as e:
            print(f"[SIMULATOR] Error: {e}")
            await asyncio.sleep(1)
