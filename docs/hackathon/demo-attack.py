#!/usr/bin/env python3
"""
Q-Guardian OS — Demo Attack Script

Connects to the WebSocket backend and simulates a judge's demo flow:
  1. Opens the chat, requests live traffic monitoring.
  2. Requests threat topology analysis.
  3. Requests mitigation controls.
  4. Floods simulated anomaly telemetry for visual impact.

Usage:
    python demo-attack.py [--url ws://localhost:8000/ws/chat] [--flood-duration 10]

No external dependencies beyond Python 3.10+ standard library.
Uses the built-in `asyncio` and `websockets`-compatible raw WebSocket.
"""

import asyncio
import json
import sys
import time
import random

# ── Configuration ────────────────────────────────────────────────
WS_URL = "ws://localhost:8000/ws/chat"
FLOOD_DURATION = 10  # seconds of telemetry flood

for i, arg in enumerate(sys.argv):
    if arg == "--url" and i + 1 < len(sys.argv):
        WS_URL = sys.argv[i + 1]
    if arg == "--flood-duration" and i + 1 < len(sys.argv):
        FLOOD_DURATION = int(sys.argv[i + 1])


def color(text: str, code: str) -> str:
    """ANSI color wrapper."""
    colors = {
        "cyan": "\033[96m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "red": "\033[91m",
        "magenta": "\033[95m",
        "dim": "\033[90m",
        "bold": "\033[1m",
        "reset": "\033[0m",
    }
    return f"{colors.get(code, '')}{text}{colors['reset']}"


def print_banner():
    banner = r"""
    ╔══════════════════════════════════════════════════╗
    ║         🛡️  Q-GUARDIAN OS  DEMO ATTACK           ║
    ║         Stateful AI Agent Demo Script            ║
    ╚══════════════════════════════════════════════════╝
    """
    print(color(banner, "cyan"))


async def run_demo():
    """Main demo sequence."""
    print_banner()

    # We use the websockets library if available, else fall back to a raw approach
    try:
        import websockets
    except ImportError:
        print(color("ERROR: 'websockets' package required. Install with:", "red"))
        print(color("  pip install websockets", "yellow"))
        sys.exit(1)

    print(color(f"[1/5] Connecting to {WS_URL}...", "cyan"))

    async with websockets.connect(WS_URL) as ws:
        print(color("[1/5] ✅ Connected!", "green"))

        # Helper to read all pending messages
        async def drain_messages(timeout: float = 2.0):
            messages = []
            try:
                while True:
                    msg = await asyncio.wait_for(ws.recv(), timeout=timeout)
                    data = json.loads(msg)
                    messages.append(data)

                    if data.get("type") == "chat":
                        role = data.get("role", "?")
                        content = data.get("content", "")[:120]
                        print(color(f"  [{role.upper()}] {content}", "dim"))
                    elif data.get("type") == "widget":
                        comp = data.get("component", "?")
                        action = data.get("action", "?")
                        print(color(f"  [WIDGET] {action.upper()} → {comp}", "magenta"))
                    elif data.get("type") == "telemetry":
                        pass  # silent during drain
            except (asyncio.TimeoutError, Exception):
                pass
            return messages

        # ── Step 1: Welcome message ──────────────────────────────
        await drain_messages(2.0)

        # ── Step 2: Request Live Traffic ─────────────────────────
        print(color("\n[2/5] Sending: 'Show me live network traffic'...", "cyan"))
        await ws.send(json.dumps({"type": "chat", "content": "Show me live network traffic"}))
        await asyncio.sleep(1)
        msgs = await drain_messages(3.0)
        widget_mounts = [m for m in msgs if m.get("type") == "widget" and m.get("action") == "mount"]
        if widget_mounts:
            print(color(f"[2/5] ✅ LiveTrafficChart mounted! (id: {widget_mounts[0].get('id', '?')})", "green"))
        else:
            print(color("[2/5] ⚠️  No widget mount received", "yellow"))

        await asyncio.sleep(2)

        # ── Step 3: Request Threat Topology ──────────────────────
        print(color("\n[3/5] Sending: 'Analyze the threat topology'...", "cyan"))
        await ws.send(json.dumps({"type": "chat", "content": "Analyze the threat topology"}))
        await asyncio.sleep(1)
        msgs = await drain_messages(3.0)
        widget_mounts = [m for m in msgs if m.get("type") == "widget" and m.get("action") == "mount"]
        if widget_mounts:
            nodes = widget_mounts[0].get("props", {}).get("nodes", [])
            edges = widget_mounts[0].get("props", {}).get("edges", [])
            print(color(f"[3/5] ✅ ThreatTopology mounted! ({len(nodes)} nodes, {len(edges)} edges)", "green"))
        else:
            print(color("[3/5] ⚠️  No widget mount received", "yellow"))

        await asyncio.sleep(2)

        # ── Step 4: Request Mitigation ───────────────────────────
        print(color("\n[4/5] Sending: 'Mitigate the DDoS attack immediately'...", "cyan"))
        await ws.send(json.dumps({"type": "chat", "content": "Mitigate the DDoS attack immediately"}))
        await asyncio.sleep(1)
        msgs = await drain_messages(3.0)
        widget_mounts = [m for m in msgs if m.get("type") == "widget" and m.get("action") == "mount"]
        if widget_mounts:
            ips = widget_mounts[0].get("props", {}).get("threatIps", [])
            print(color(f"[4/5] ✅ MitigationAction mounted! ({len(ips)} threat IPs)", "green"))
        else:
            print(color("[4/5] ⚠️  No widget mount received", "yellow"))

        await asyncio.sleep(1)

        # ── Step 5: Flood Telemetry ──────────────────────────────
        print(color(f"\n[5/5] Flooding telemetry for {FLOOD_DURATION}s...", "cyan"))
        telemetry_count = 0
        start = time.time()

        while time.time() - start < FLOOD_DURATION:
            # Drain any incoming messages silently
            try:
                while True:
                    await asyncio.wait_for(ws.recv(), timeout=0.1)
            except (asyncio.TimeoutError, Exception):
                pass

            telemetry_count += 1
            elapsed = int(time.time() - start)
            sys.stdout.write(color(f"\r  ⚡ {telemetry_count} ticks | {elapsed}s / {FLOOD_DURATION}s", "yellow"))
            sys.stdout.flush()
            await asyncio.sleep(0.5)

        print(color(f"\n[5/5] ✅ Flood complete. {telemetry_count} telemetry ticks received.", "green"))

        # ── Summary ──────────────────────────────────────────────
        print(color("\n" + "═" * 52, "cyan"))
        print(color("  🛡️  DEMO COMPLETE — All widget mounts verified!", "bold"))
        print(color("═" * 52, "cyan"))
        print(color(f"\n  Open http://localhost:5173 to see the live dashboard.", "green"))
        print(color(f"  The widgets are interactive — try isolating IPs!\n", "dim"))


if __name__ == "__main__":
    asyncio.run(run_demo())
