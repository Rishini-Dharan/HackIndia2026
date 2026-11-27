from fastapi.testclient import TestClient

import anomaly_simulator as sim
import main


def test_health_reports_planner_and_source():
    with TestClient(main.app) as client:
        body = client.get("/health").json()
    assert body["status"] == "healthy"
    assert body["planner"]["mode"] in {"llm", "scripted"}
    assert body["telemetry_source"] in {"simulator", "java-ingest"}


def test_ingest_classifies_and_streams_to_websocket():
    sim.PROACTIVE_TRIGGERED = False
    sim.BLOCKED_IPS.clear()
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
    sim.BLOCKED_IPS.add("45.33.12.99")
    try:
        with TestClient(main.app) as client:
            r = client.post("/ingest", json={"events": [
                {"src_ip": "45.33.12.99", "dst_ip": "192.168.1.10", "port": 445, "bytes": 60000}
            ]})
        assert r.json()["threats"] == 0
    finally:
        sim.BLOCKED_IPS.clear()


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
    sim.PROACTIVE_TRIGGERED = False
    sim.BLOCKED_IPS.clear()
    with TestClient(main.app) as client:
        client.post("/ingest", json=_scan_batch("198.51.100.7"))
    ws = ws_handler.CURRENT_WORKSPACE
    text = str(ws)
    assert ws["threatType"] == "PortScan"
    assert "198.51.100.7" in ws["hypothesis"]
    assert "45.33.12.99" not in text, "template attacker IP leaked into a live workspace"
    mitigation = next(w for w in ws["layout"] if w["component"] == "MitigationAction")
    assert mitigation["props"]["threatIps"] == ["198.51.100.7"]
    ws_handler.reset_current_workspace()


def test_containment_rearms_proactive_alerts():
    sim.PROACTIVE_TRIGGERED = True
    sim.block_ips(["198.51.100.7"])
    assert sim.PROACTIVE_TRIGGERED is False
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
    import qdrant_memory
    import ws_handler

    qdrant_memory.clear_memories()
    sim.PROACTIVE_TRIGGERED = False
    sim.BLOCKED_IPS.clear()
    with TestClient(main.app) as client:
        client.post("/ingest", json=_scan_batch("198.51.100.44"))
        saved_id = ws_handler.CURRENT_WORKSPACE["id"]
        ws_handler.reset_current_workspace()  # simulate a restart losing in-process state
        with client.websocket_connect("/ws/chat") as ws:
            ws.receive_json(); ws.receive_json()
            ws.send_json({"type": "chat", "content": "continue yesterday's investigation"})
            msgs = []
            for _ in range(30):
                msgs.append(ws.receive_json())
                if msgs[-1]["type"] == "workspace_mount":
                    break
    chat = next(m for m in msgs if m["type"] == "chat" and "Restored" in m["content"])
    assert saved_id in chat["content"]
    workspace = msgs[-1]["workspace"]
    assert workspace["id"] == saved_id
    assert any("T1046" in e for e in workspace["evidence"])
    assert "198.51.100.44" in workspace["hypothesis"]
    ws_handler.reset_current_workspace()
