import sys
import os
import time

# Ensure we can import from backend
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml_detector import MLAnomalyDetector

def test_detector():
    detector = MLAnomalyDetector()
    print("=== Testing ML Telemetry Classifier Engine ===")
    
    # 1. Test baseline traffic
    print("\n[Test 1] Simulating 10 baseline HTTPS packets...")
    for i in range(10):
        evt = {
            "src_ip": f"192.168.1.{50 + i}",
            "dst_ip": "104.26.10.12",
            "protocol": "HTTPS",
            "port": 443,
            "bytes": 500 + i * 50
        }
        res = detector.classify(evt)
        print(f"  Packet {i+1}: score={res['score']}, is_threat={res['is_threat']}, attack_type={res['attack_type']}, severity={res['severity']}")
        assert not res["is_threat"], "Baseline packet should not be flagged as threat"
        assert res["score"] < 0.25, "Baseline score should be low"
        
    # 2. Test Ransomware traffic (port 445, high bytes)
    print("\n[Test 2] Simulating anomalous SMB packet (Ransomware)...")
    ransomware_evt = {
        "src_ip": "45.33.12.99",
        "dst_ip": "192.168.1.10",
        "protocol": "TCP",
        "port": 445,
        "bytes": 62000
    }
    res = detector.classify(ransomware_evt)
    print(f"  Result: score={res['score']}, is_threat={res['is_threat']}, attack_type={res['attack_type']}, severity={res['severity']}")
    assert res["is_threat"], "Anomalous SMB packet should be flagged as threat"
    assert res["attack_type"] == "Ransomware", "Attack type should be Ransomware"
    assert res["score"] > 0.90, "Ransomware anomaly score should be very high"
    
    # 3. Test DDoS traffic (volumetric rate anomaly)
    print("\n[Test 3] Simulating volumetric DDoS spike...")
    # Feed multiple events from single source rapidly
    ddos_ip = "185.220.101.4"
    for i in range(15):
        ddos_evt = {
            "src_ip": ddos_ip,
            "dst_ip": "192.168.1.10",
            "protocol": "TCP",
            "port": 80,
            "bytes": 500
        }
        res = detector.classify(ddos_evt)
        # Add a tiny delay to ensure timestamps increments slightly
        time.sleep(0.02)
        if i == 14:
            print(f"  Result at packet 15: score={res['score']}, is_threat={res['is_threat']}, attack_type={res['attack_type']}, severity={res['severity']}")
            assert res["is_threat"], "High pps spike should be flagged as threat"
            assert res["attack_type"] == "DDoS", "Attack type should be DDoS"
            assert res["score"] > 0.82, "DDoS anomaly score should be high"
            
    # 4. Test PortScan traffic
    print("\n[Test 4] Simulating PortScan anomaly...")
    scan_ip = "88.99.11.22"
    for idx, p in enumerate([22, 80, 443, 445, 8080]):
        scan_evt = {
            "src_ip": scan_ip,
            "dst_ip": "192.168.1.10",
            "protocol": "TCP",
            "port": p,
            "bytes": 64
        }
        res = detector.classify(scan_evt)
        if idx == 4:
            print(f"  Result at port {p}: score={res['score']}, is_threat={res['is_threat']}, attack_type={res['attack_type']}, severity={res['severity']}")
            assert res["is_threat"], "Scanning multiple ports should be flagged"
            assert res["attack_type"] == "PortScan", "Attack type should be PortScan"

    print("\n=== All Tests Passed Successfully! ===")

if __name__ == "__main__":
    test_detector()
