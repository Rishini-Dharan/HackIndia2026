"""
Q-Guardian OS — streaming threat detector.

Two detectors run on every telemetry event:

1. A multinomial logistic-regression model trained on NSL-KDD (see ml/train.py,
   held-out metrics in ml/metrics.json). Weights are loaded from ml/model.json and
   evaluated with NumPy, so the backend does not need scikit-learn at runtime.
2. A signature rule for SMB bulk transfer from an external address (ransomware-style
   lateral movement). NSL-KDD has no ransomware class, so this is a rule, and events
   it flags are labelled `detector: "rule:smb-bulk-transfer"`.

Features are computed per source IP over a sliding window, which approximates the
NSL-KDD traffic features the model was trained on (see ml/train.py).
"""

import json
import math
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path

import numpy as np

MODEL_PATH = Path(__file__).resolve().parent / "ml" / "model.json"
UNSW_MODEL_PATH = Path(__file__).resolve().parent / "ml" / "unsw_gbm.json"

# Model category -> attack label shown in the UI
CATEGORY_LABEL = {"dos": "DDoS", "probe": "PortScan", "r2l": "Intrusion", "u2r": "PrivilegeEscalation"}

HTTP_PORTS = {80, 8080, 8000, 443, 8443}
SMB_PORTS = {139, 445}
DNS_PORTS = {53}
SSH_PORTS = {22}

# P(attack) needed to flag an event. At 0.80 the model flagged ~12% of the simulator's
# benign database/ICMP traffic; at 0.95 it flagged none while scans and floods still
# score > 0.97. Held-out precision/recall at this operating point is in ml/metrics.json.
THREAT_THRESHOLD = 0.95

# MITRE ATT&CK technique for each attack label (enterprise matrix, v15).
# NSL-KDD categories are coarse, so these are the closest technique, not a proof of it.
MITRE_ATTACK = {
    "Ransomware": ("T1486", "Data Encrypted for Impact", "Impact"),
    "DDoS": ("T1498", "Network Denial of Service", "Impact"),
    "PortScan": ("T1046", "Network Service Discovery", "Discovery"),
    "BruteForce": ("T1110", "Brute Force", "Credential Access"),
    "Intrusion": ("T1190", "Exploit Public-Facing Application", "Initial Access"),
    "PrivilegeEscalation": ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
    # UNSW-NB15 families with a clear technique; Generic, Backdoor, Shellcode and
    # Analysis are too broad to map honestly, so they carry no tag.
    "Exploit": ("T1190", "Exploit Public-Facing Application", "Initial Access"),
    "Fuzzing": ("T1595", "Active Scanning", "Reconnaissance"),
    "Worm": ("T1210", "Exploitation of Remote Services", "Lateral Movement"),
}
SMB_BULK_BYTES = 20_000          # rule: SMB transfer larger than this from an external IP
RULE_SCORE = 0.97                # confidence assigned to signature hits (critical severity)


class GBMModel:
    """Gradient-boosted trees exported by ml/train_unsw_live.py, evaluated with NumPy."""

    def __init__(self, spec: dict):
        self.classes = spec["classes"]
        self.baseline = np.array(spec["baseline"], dtype=float)
        self.trees = spec["trees"]

    def raw(self, x: np.ndarray) -> np.ndarray:
        out = self.baseline.copy()
        for k, trees in enumerate(self.trees):
            for tree in trees:
                node = 0
                f, t, left, right, missing, leaf = tree["f"], tree["t"], tree["l"], tree["r"], tree["m"], tree["leaf"]
                while not leaf[node]:
                    val = x[f[node]]
                    go_left = missing[node] if val != val else val <= t[node]  # val != val: NaN
                    node = left[node] if go_left else right[node]
                out[k] += tree["v"][node]
        return out


_UNSW = None


def unsw_models():
    """Loaded once per process and shared by every visitor's detector."""
    global _UNSW
    if _UNSW is None and UNSW_MODEL_PATH.exists():
        spec = json.loads(UNSW_MODEL_PATH.read_text())
        _UNSW = {"features": spec["features"], "labels": spec["labels"],
                 "attack": GBMModel(spec["attack"]), "family": GBMModel(spec["family"])}
    return _UNSW


HTTP_SERVICES, SSH_SERVICES, DNS_SERVICES = {"http", "ssl"}, {"ssh"}, {"dns"}


def flow_features(flow: dict, features: list[str]) -> np.ndarray:
    """The 11 window features from sensor-computed flow fields (mirrors
    train.featurize_unsw, without pandas)."""
    count = max(1.0, float(flow["ct_src_ltm"]))
    same = min(1.0, max(0.0, float(flow["ct_src_dport_ltm"]) / count))
    proto, svc = str(flow["proto"]).lower(), str(flow["service"]).lower()
    values = {
        "log_bytes": math.log1p(min(float(flow["sbytes"]), 10_000_000)),
        "log_count": math.log1p(float(flow["ct_src_ltm"])),
        "diff_srv_rate": 1.0 - same,
        "same_srv_rate": same,
        "proto_tcp": float(proto == "tcp"),
        "proto_udp": float(proto == "udp"),
        "proto_icmp": float(proto == "icmp"),
        "svc_http": float(svc in HTTP_SERVICES),
        "svc_ssh": float(svc in SSH_SERVICES),
        "svc_smb": 0.0,
        "svc_dns": float(svc in DNS_SERVICES),
    }
    return np.array([values[name] for name in features])


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_external(ip: str) -> bool:
    try:
        return ip_address(ip).is_global
    except ValueError:
        return False


class MLAnomalyDetector:
    def __init__(self, window_size: int = 300, time_window_seconds: float = 2.0, model_path: Path = MODEL_PATH):
        self.window_size = window_size
        self.time_window_seconds = time_window_seconds
        self.events_window: deque = deque()
        self.by_src: dict[str, deque] = defaultdict(deque)

        model = json.loads(Path(model_path).read_text())
        self.features: list[str] = model["features"]
        self.classes: list[str] = model["classes"]
        self.mean = np.array(model["mean"])
        self.std = np.array(model["std"])
        self.coef = np.array(model["coef"])
        self.intercept = np.array(model["intercept"])

    # ── window bookkeeping ──────────────────────────────────────
    def _evict(self, now: float):
        while self.events_window and (
            len(self.events_window) > self.window_size
            or now - self.events_window[0][0] > self.time_window_seconds
        ):
            _, src, _ = self.events_window.popleft()
            q = self.by_src[src]
            q.popleft()
            if not q:
                del self.by_src[src]

    def _update(self, src: str, port: int, now: float):
        self.events_window.append((now, src, port))
        self.by_src[src].append(port)
        self._evict(now)

    # ── features & inference ────────────────────────────────────
    def features_for(self, event: dict) -> np.ndarray:
        src, port = event["src_ip"], int(event["port"])
        ports = self.by_src.get(src, deque([port]))
        count = len(ports)
        same = sum(1 for p in ports if p == port) / count
        proto = str(event.get("protocol", "")).upper()
        is_udp = proto in {"UDP", "DNS"}
        is_icmp = proto == "ICMP"
        values = {
            "log_bytes": math.log1p(max(0, int(event["bytes"]))),
            "log_count": math.log1p(count),
            "diff_srv_rate": 1.0 - same,
            "same_srv_rate": same,
            "proto_tcp": float(not is_udp and not is_icmp),
            "proto_udp": float(is_udp),
            "proto_icmp": float(is_icmp),
            "svc_http": float(port in HTTP_PORTS),
            "svc_ssh": float(port in SSH_PORTS),
            "svc_smb": float(port in SMB_PORTS),
            "svc_dns": float(port in DNS_PORTS),
        }
        return np.array([values[f] for f in self.features])

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        z = (x - self.mean) / self.std
        logits = self.coef @ z + self.intercept
        logits -= logits.max()
        e = np.exp(logits)
        return e / e.sum()

    def classify(self, event: dict) -> dict:
        now = time.time()
        src, port, nbytes = event["src_ip"], int(event["port"]), int(event["bytes"])
        self._update(src, port, now)

        models = unsw_models() if event.get("flow") else None
        if models:
            # Sensor-computed flow features (replayed UNSW-NB15 flows): gradient boosting.
            x = flow_features(event["flow"], models["features"])
            p_attack = float(1.0 / (1.0 + math.exp(-models["attack"].raw(x)[0])))
            attack_type, detector, score = None, "model:unsw-nb15-gbm", p_attack
            if p_attack >= THREAT_THRESHOLD:
                family = models["family"].classes[int(models["family"].raw(x).argmax())]
                attack_type = models["labels"].get(family, "Anomaly")
            top = None
        else:
            proba = self.predict_proba(self.features_for(event))
            p_attack = float(1.0 - proba[self.classes.index("normal")])
            top = self.classes[int(proba.argmax())]
            attack_type, detector, score = None, "model:nsl-kdd-lr", p_attack
        if port in SMB_PORTS and nbytes > SMB_BULK_BYTES and _is_external(src):
            attack_type, detector = "Ransomware", "rule:smb-bulk-transfer"
            score = max(p_attack, RULE_SCORE)
        elif top is not None and p_attack >= THREAT_THRESHOLD and top != "normal":
            attack_type = CATEGORY_LABEL[top]
            if top == "r2l" and port in SSH_PORTS:
                attack_type = "BruteForce"

        is_threat = attack_type is not None
        # Every threat clears THREAT_THRESHOLD (or is a rule hit), so threats are critical;
        # non-threats are graded by how close the model came.
        if is_threat:
            severity = "critical"
        else:
            severity = "medium" if score > 0.5 else "low"

        return {
            "ts": event.get("ts") or _utc_now(),
            "src_ip": src,
            "dst_ip": event["dst_ip"],
            "protocol": event.get("protocol", "TCP"),
            "port": port,
            "bytes": nbytes,
            "severity": severity,
            "is_threat": is_threat,
            "attack_type": attack_type,
            "score": round(score, 3),
            "detector": detector,
            "mitre": (
                {"id": t[0], "name": t[1], "tactic": t[2]} if (t := MITRE_ATTACK.get(attack_type)) else None
            ),
        }
