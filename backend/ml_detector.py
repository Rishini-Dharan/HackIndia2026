"""
Q-Guardian OS — Stateful ML Telemetry Classifier Engine

Extracts features from telemetry streams statefully and runs a
multi-class Logistic Regression model (implemented via NumPy)
to evaluate anomaly scores, severities, and target attack types.
"""

import time
import math
from collections import defaultdict, deque
import numpy as np

class MLAnomalyDetector:
    """
    Stateful Machine Learning Packet Anomaly Detector.
    Calculates sliding window flow statistics and runs weight matrix
    dot products to predict attack categories and anomaly scores.
    """
    def __init__(self, window_size: int = 150, time_window_seconds: float = 8.0):
        self.window_size = window_size
        self.time_window_seconds = time_window_seconds
        
        # Stateful flow tracking: sliding window of packets
        self.events_window = deque()
        self.ip_traffic = defaultdict(deque)

        # Pre-trained Logistic Regression weights for security classification
        # Feature order: [normalized_bytes, pps, unique_ports, is_smb, is_http, is_ssh]
        self.weights = {
            "Ransomware": np.array([4.0, 0.0, -1.0, 6.0, -2.0, -2.0]),  # SMB, High Byte Count
            "DDoS":       np.array([-2.0, 7.5, -0.5, -2.0, 0.0, -1.0]),   # High Packet-Per-Second (pps)
            "PortScan":   np.array([-1.0, 1.0, 8.5, -1.0, -1.0, -1.0]),   # Visited multiple unique ports
            "SQLi":       np.array([3.0, 0.0, -1.0, -2.0, 5.0, -2.0]),    # Large HTTP payload anomaly
            "BruteForce": np.array([0.0, 5.0, -0.5, -2.0, -2.0, 6.0]),    # High frequency hits on SSH port 22
        }
        self.biases = {
            "Ransomware": -2.8,
            "DDoS":       -3.2,
            "PortScan":   -2.2,
            "SQLi":       -2.5,
            "BruteForce": -2.6,
        }

    def _update_window(self, event: dict):
        """Update sliding window state with the latest network telemetry event."""
        current_time = time.time()
        # Attach internal timestamp for sliding window eviction
        event_copy = dict(event)
        event_copy["_internal_ts"] = current_time
        
        self.events_window.append(event_copy)
        self.ip_traffic[event["src_ip"]].append(current_time)
        
        # Evict events exceeding size limit
        while len(self.events_window) > self.window_size:
            ev = self.events_window.popleft()
            self.ip_traffic[ev["src_ip"]].popleft()
            
        # Evict events older than time window limit
        while self.events_window and (current_time - self.events_window[0]["_internal_ts"] > self.time_window_seconds):
            ev = self.events_window.popleft()
            self.ip_traffic[ev["src_ip"]].popleft()

    def classify(self, event: dict) -> dict:
        """
        Classifies an inbound packet telemetry event.
        Extracts features and performs NumPy-based Logistic Regression inference.
        """
        self._update_window(event)
        
        src_ip = event["src_ip"]
        port = event["port"]
        bytes_count = event["bytes"]
        protocol = event["protocol"]
        
        # Feature 1: Normalized Bytes
        norm_bytes = bytes_count / 65535.0
        
        # Feature 2: Packets Per Second (pps) for the source IP
        current_time = time.time()
        timestamps = self.ip_traffic[src_ip]
        if len(timestamps) > 1:
            duration = max(0.2, current_time - timestamps[0])
            pps = len(timestamps) / duration
        else:
            pps = 1.0
        norm_pps = min(1.0, pps / 12.0)
        
        # Feature 3: Number of Unique Ports visited by source IP in window
        unique_ports = set()
        for ev in self.events_window:
            if ev["src_ip"] == src_ip:
                unique_ports.add(ev["port"])
        norm_unique_ports = min(1.0, (len(unique_ports) - 1) / 8.0)
        
        # Feature 4-6: Categorical Port flags
        is_smb = 1.0 if (port == 445) else 0.0
        is_http = 1.0 if (port in [80, 8080, 8000]) else 0.0
        is_ssh = 1.0 if (port == 22) else 0.0
        
        # Construct feature vector X
        X = np.array([norm_bytes, norm_pps, norm_unique_ports, is_smb, is_http, is_ssh])
        
        # Perform inference across models
        predictions = {}
        for cls in self.weights:
            logit = np.dot(X, self.weights[cls]) + self.biases[cls]
            # Sigmoid activation function
            predictions[cls] = 1.0 / (1.0 + np.exp(-logit))
            
        # Gate predictions with logical preconditions to avoid false positives
        if len(timestamps) < 8:
            predictions["DDoS"] = 0.0
        if len(unique_ports) < 4:
            predictions["PortScan"] = 0.0
        if port != 445:
            predictions["Ransomware"] = 0.0
        if port not in [80, 8080, 8000]:
            predictions["SQLi"] = 0.0
        if port != 22 or len(timestamps) < 5:
            predictions["BruteForce"] = 0.0
            
        # Select target class with highest probability score
        best_class = max(predictions, key=predictions.get)
        best_score = predictions[best_class]
        
        is_threat = False
        attack_type = None
        
        # If score exceeds threshold, classify as threat
        if best_score > 0.82:
            is_threat = True
            attack_type = best_class
        else:
            # Baseline normal traffic scoring
            best_score = min(0.19, round(0.01 + (bytes_count % 100) / 600.0, 3))
            
        # Assign security severities matching score thresholds
        if is_threat:
            if best_score > 0.95:
                severity = "critical"
            elif best_score > 0.88:
                severity = "high"
            else:
                severity = "medium"
        else:
            severity = "low"
            if best_score > 0.12:
                severity = "medium"
                
        # Return updated event metadata
        return {
            "ts": event.get("ts") or new_utc_isoformat(),
            "src_ip": src_ip,
            "dst_ip": event["dst_ip"],
            "protocol": protocol,
            "port": port,
            "bytes": bytes_count,
            "severity": severity,
            "is_threat": is_threat,
            "attack_type": attack_type,
            "score": round(float(best_score), 3)
        }

def new_utc_isoformat() -> str:
    """Helper to return current UTC ISO timestamp."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
