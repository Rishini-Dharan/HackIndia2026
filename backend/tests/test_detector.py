import json
from pathlib import Path

import pytest

from ml_detector import MLAnomalyDetector, THREAT_THRESHOLD
import anomaly_simulator as sim

ML_DIR = Path(__file__).resolve().parents[1] / "ml"


def ev(src="10.0.1.5", port=443, nbytes=800, proto="TCP", dst="10.0.0.5"):
    return {"src_ip": src, "dst_ip": dst, "protocol": proto, "port": port, "bytes": nbytes}


def test_model_artifacts_are_consistent():
    model = json.loads((ML_DIR / "model.json").read_text())
    assert len(model["coef"]) == len(model["classes"])
    assert all(len(row) == len(model["features"]) for row in model["coef"])
    metrics = json.loads((ML_DIR / "metrics.json").read_text())
    assert metrics["binary_attack_vs_normal"]["f1"] > 0.8


def test_probabilities_sum_to_one():
    d = MLAnomalyDetector()
    p = d.predict_proba(d.features_for(ev()))
    assert p.sum() == pytest.approx(1.0)


def test_simulated_benign_traffic_rarely_alerts():
    d = MLAnomalyDetector()
    flagged = sum(d.classify(sim._generate_baseline_event())["is_threat"] for _ in range(2000))
    assert flagged / 2000 < 0.01


def test_port_scan_is_detected_by_model():
    d = MLAnomalyDetector()
    for i in range(1, 40):
        r = d.classify(ev(src="198.51.100.7", port=i * 13, nbytes=0))
    assert r["is_threat"] and r["attack_type"] == "PortScan"
    assert r["detector"] == "model:nsl-kdd-lr"
    assert r["score"] >= THREAT_THRESHOLD


def test_flood_is_detected_as_ddos():
    d = MLAnomalyDetector()
    for _ in range(200):
        r = d.classify(ev(src="198.51.100.8", port=80, nbytes=0))
    assert r["attack_type"] == "DDoS"


def test_smb_bulk_transfer_rule_needs_external_source():
    d = MLAnomalyDetector()
    external = d.classify(ev(src="45.33.12.99", port=445, nbytes=60000))
    assert external["attack_type"] == "Ransomware"
    assert external["detector"] == "rule:smb-bulk-transfer"
    internal = d.classify(ev(src="192.168.1.20", port=445, nbytes=60000))
    assert internal["attack_type"] != "Ransomware"


def test_detections_carry_mitre_technique():
    d = MLAnomalyDetector()
    for i in range(1, 40):
        r = d.classify(ev(src="198.51.100.9", port=i * 13, nbytes=0))
    assert r["mitre"] == {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"}
    smb = d.classify(ev(src="45.33.12.99", port=445, nbytes=60000))
    assert smb["mitre"]["id"] == "T1486"
    assert d.classify(ev())["mitre"] is None
