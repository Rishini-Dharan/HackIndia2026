from fastapi.testclient import TestClient

import anomaly_simulator as sim
from session import S
import main


def test_health_reports_planner_and_source():
    with TestClient(main.app) as client:
        body = client.get("/health").json()
    assert body["status"] == "healthy"
    assert body["planner"]["mode"] in {"llm", "scripted"}
    assert body["telemetry_source"] in {"simulator", "java-ingest"}


def test_ingest_classifies_and_streams_to_websocket():
    S().proactive_triggered = False
    S().blocked_ips.clear()
    with TestClient(main.app) as client:
        with client.websocket_connect("/ws/chat") as ws:
            assert ws.receive_json()["type"] == "chat"
            assert ws.receive_json()["type"] == "agent_mode"
            resp = client.post("/ingest", json={"events": [
                {"src_ip": "45.33.12.99", "dst_ip": "192.168.1.10", "protocol": "TCP", "port": 445, "bytes": 60000}
            ]})
            assert resp.json() == {"accepted": 1, "threats": 1}
            assert client.get("/health").json()["telemetry_source"] == "java-ingest"
            seen = []
            for _ in range(50):  # bounded so a missing mount fails instead of hanging
                seen.append(ws.receive_json())
                if seen[-1]["type"] == "workspace_mount":
                    break
    # the simulator may have sent baseline telemetry before the batch arrived
    seen = [m for m in seen if not (m["type"] == "telemetry" and m["data"]["src_ip"] != "45.33.12.99")]
    types = [m["type"] for m in seen]
    assert types == ["telemetry", "chat", "workspace_mount"]
    assert seen[0]["data"]["attack_type"] == "Ransomware"
    workspace = seen[2]["workspace"]
    assert any("rule:smb-bulk-transfer" in e for e in workspace["evidence"])


def test_ingest_rejects_bad_events():
    with TestClient(main.app) as client:
        r = client.post("/ingest", json={"events": [{"src_ip": "x", "dst_ip": "y", "port": 99999, "bytes": 1}]})
    assert r.status_code == 422


def test_blocked_source_is_dropped():
    S().blocked_ips.add("45.33.12.99")
    try:
        with TestClient(main.app) as client:
            r = client.post("/ingest", json={"events": [
                {"src_ip": "45.33.12.99", "dst_ip": "192.168.1.10", "port": 445, "bytes": 60000}
            ]})
        assert r.json()["threats"] == 0
    finally:
        S().blocked_ips.clear()


def test_ingest_requires_token_when_configured(monkeypatch):
    monkeypatch.setattr(main, "INGEST_TOKEN", "s3cret")
    event = {"events": [{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "port": 443, "bytes": 100}]}
    with TestClient(main.app) as client:
        assert client.post("/ingest", json=event).status_code == 401
        assert client.post("/ingest", json=event, headers={"X-Ingest-Token": "wrong"}).status_code == 401
        assert client.post("/ingest", json=event, headers={"X-Ingest-Token": "s3cret"}).status_code == 200


def test_websocket_requires_token_when_configured(monkeypatch):
    import pytest
    from starlette.websockets import WebSocketDisconnect

    monkeypatch.setattr(main, "WS_TOKEN", "s3cret")
    with TestClient(main.app) as client:
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws/chat") as ws:
                ws.receive_json()
        with client.websocket_connect("/ws/chat?token=s3cret") as ws:
            assert ws.receive_json()["type"] == "chat"


def _scan_batch(src):
    return {"events": [{"ts": "1720000000", "src_ip": src, "dst_ip": "10.0.0.5", "port": p * 13, "bytes": 0}
                       for p in range(1, 40)]}


def test_live_detection_retargets_workspace_to_real_attacker():
    import ws_handler
    S().proactive_triggered = False
    S().blocked_ips.clear()
    with TestClient(main.app) as client:
        client.post("/ingest", json=_scan_batch("198.51.100.7"))
    ws = S().current_workspace
    text = str(ws)
    assert ws["threatType"] == "PortScan"
    assert "198.51.100.7" in ws["hypothesis"]
    assert "45.33.12.99" not in text, "template attacker IP leaked into a live workspace"
    mitigation = next(w for w in ws["layout"] if w["component"] == "MitigationAction")
    assert mitigation["props"]["threatIps"] == ["198.51.100.7"]
    ws_handler.reset_current_workspace()


def test_containment_rearms_proactive_alerts():
    S().proactive_triggered = True
    sim.block_ips(["198.51.100.7"])
    assert S().proactive_triggered is False
    sim.unblock_all()


def test_empty_batch_does_not_pause_simulator_and_epoch_ts_is_converted():
    sim.LAST_INGEST_AT = 0.0
    with TestClient(main.app) as client:
        client.post("/ingest", json={"events": []})
        assert sim.LAST_INGEST_AT == 0.0
        with client.websocket_connect("/ws/chat") as ws:
            ws.receive_json(); ws.receive_json()
            client.post("/ingest", json={"events": [
                {"ts": "1720000000", "src_ip": "10.0.1.9", "dst_ip": "10.0.0.2", "port": 443, "bytes": 900}]})
            for _ in range(20):
                m = ws.receive_json()
                if m["type"] == "telemetry" and m["data"]["src_ip"] == "10.0.1.9":
                    break
    assert m["data"]["ts"].startswith("2024-07-03T")


def test_continue_restores_latest_saved_case():
    import session

    cid = "restore-client-0001"
    with TestClient(main.app) as client:
        with client.websocket_connect(f"/ws/chat?client={cid}") as ws:
            ws.receive_json(); ws.receive_json()
            client.post("/ingest", json=_scan_batch("198.51.100.44"))
            visitor = session.SESSIONS[cid]
            saved_id = visitor.case_id
            assert saved_id.startswith("INV-") and saved_id != "INV-412"
            with session.use_session(visitor):
                import ws_handler
                ws_handler.reset_current_workspace()  # simulate a restart losing in-process state
            ws.send_json({"type": "chat", "content": "continue yesterday's investigation"})
            msgs, restored = [], False
            for _ in range(200):
                msgs.append(ws.receive_json())
                restored = restored or (msgs[-1]["type"] == "chat" and "Restored" in msgs[-1].get("content", ""))
                if restored and msgs[-1]["type"] == "workspace_mount":
                    break
    chat = next(m for m in msgs if m["type"] == "chat" and "Restored" in m.get("content", ""))
    assert saved_id in chat["content"]
    workspace = msgs[-1]["workspace"]
    assert any("T1046" in e for e in workspace["evidence"])
    assert "198.51.100.44" in workspace["hypothesis"]


def test_visitors_are_isolated():
    """One visitor's attack, workspace and memory never reach another visitor."""
    import session

    a, b = "visitor-aaaa-0001", "visitor-bbbb-0002"
    with TestClient(main.app) as client:
        with client.websocket_connect(f"/ws/chat?client={a}") as wa,              client.websocket_connect(f"/ws/chat?client={b}") as wb:
            for w in (wa, wb):
                w.receive_json(); w.receive_json()
            wa.send_json({"type": "action", "payload": {"action": "simulate_attack"}})
            seen_a = []
            for _ in range(80):
                seen_a.append(wa.receive_json())
                if seen_a[-1]["type"] == "workspace_mount":
                    break
            assert any(m["type"] == "workspace_mount" for m in seen_a)
            assert session.SESSIONS[a].is_attack_active
            assert not session.SESSIONS[b].is_attack_active
            assert not session.SESSIONS[b].proactive_triggered
            # B's stream has telemetry only from its own (benign) simulation
            for _ in range(15):
                m = wb.receive_json()
                assert m["type"] != "workspace_mount"
                if m["type"] == "telemetry":
                    assert m["data"]["src_ip"] != "45.33.12.99"
            # B clearing memory leaves A's saved case intact
            wb.send_json({"type": "action", "payload": {"action": "clear_memory"}})
            import qdrant_memory
            with session.use_session(session.SESSIONS[a]):
                assert qdrant_memory.get_latest_investigation() is not None
            with session.use_session(session.SESSIONS[b]):
                assert qdrant_memory.get_latest_investigation() is None
            wa.send_json({"type": "action", "payload": {"action": "stop_simulation"}})

def test_live_case_id_replaces_template_id_everywhere():
    import ws_handler
    S().proactive_triggered = False
    S().blocked_ips.clear()
    with TestClient(main.app) as client:
        with client.websocket_connect("/ws/chat") as ws:
            ws.receive_json(); ws.receive_json()
            client.post("/ingest", json=_scan_batch("198.51.100.77"))
            case_id = S().case_id
            assert case_id != "INV-412"
            ws.send_json({"type": "action", "payload": {"action": "isolate_ip", "ips": ["198.51.100.77"], "strategy": "block"}})
            msgs = []
            for _ in range(60):
                msgs.append(ws.receive_json())
                if msgs[-1]["type"] == "workspace_mount" and "Post-Mitigation" in msgs[-1]["workspace"]["title"]:
                    break
    blob = str([m for m in msgs if m["type"] in {"chat", "workspace_mount"}])
    assert "INV-412" not in blob
    assert case_id in blob
    assert msgs[-1]["workspace"]["id"] == case_id
    sim.unblock_all()
    ws_handler.reset_current_workspace()


def test_topology_uses_only_real_detections():
    import llm_orchestrator as llm
    S().recent_events.clear()
    S().blocked_ips.clear()
    empty = sim.build_topology()
    assert not [n for n in empty["nodes"] if n["type"] == "attacker"]
    assert "No active threats" in empty["summary"]

    S().proactive_triggered = True  # keep this test from opening a workspace
    with TestClient(main.app) as client:
        client.post("/ingest", json=_scan_batch("198.51.100.90"))
    topo = sim.build_topology()
    attackers = [n["id"] for n in topo["nodes"] if n["type"] == "attacker"]
    assert attackers == ["198.51.100.90"]
    assert all(e["source"] == "198.51.100.90" and e["attackType"] == "PortScan" for e in topo["edges"])
    assert llm._live_threat_ips("block them") == ["198.51.100.90"]
    assert llm._live_threat_ips("block 203.0.113.5", ["203.0.113.5", "1.2.3.4"]) == ["203.0.113.5"]

    S().blocked_ips.add("198.51.100.90")
    assert not [n for n in sim.build_topology()["nodes"] if n["type"] == "attacker"]
    S().blocked_ips.clear()
    S().proactive_triggered = False


def test_llm_proposed_topology_nodes_are_replaced(monkeypatch):
    import asyncio
    import json as _json
    import llm_orchestrator as llm
    S().recent_events.clear()

    class FakeResp:
        def raise_for_status(self): pass
        def json(self):
            args = {"component": "ThreatTopology", "title": "Map",
                    "props": {"nodes": [{"id": "6.6.6.6", "type": "attacker"}]}}
            return {"choices": [{"message": {"content": None, "tool_calls": [
                {"function": {"name": "render_security_widget", "arguments": _json.dumps(args)}}]}}]}

    class FakeClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
        async def post(self, *a, **k): return FakeResp()

    monkeypatch.setattr(llm.httpx, "AsyncClient", FakeClient)
    msgs = asyncio.run(llm._openai_compatible_route("map the attack", api_url="x", api_key="k", model="m"))
    widget = next(m for m in msgs if m["type"] == "widget")
    assert all(n["id"] != "6.6.6.6" for n in widget["props"]["nodes"])
    assert "No active threats" in widget["props"]["description"]
