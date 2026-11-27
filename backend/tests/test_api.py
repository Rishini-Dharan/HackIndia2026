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
