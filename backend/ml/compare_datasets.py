"""
Cross-dataset check of the streaming detector's 11 window features.

Answers three questions the NSL-KDD numbers alone can't:
  1. Does the deployed NSL-KDD model transfer to modern traffic (UNSW-NB15)?
  2. On UNSW-NB15, how far does the linear model fall short of a non-linear one
     trained on the same features?
  3. Would a UNSW-NB15 model work on the live demo's simulated traffic?

Usage (from backend/):
    python ml/compare_datasets.py --nsl-model ml/model.json \
        --unsw-train UNSW_NB15_training-set.csv --unsw-test UNSW_NB15_testing-set.csv
Writes ml/cross_dataset.json.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

import numpy as np

os.environ.setdefault("LOKY_MAX_CPU_COUNT", "4")  # silences a joblib core-count probe on Windows
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from sklearn.ensemble import HistGradientBoostingClassifier  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score  # noqa: E402

import train as T  # noqa: E402


def binary(y, p, threshold=0.5):
    return {
        "f1": round(float(f1_score(y, p >= threshold)), 4),
        "precision": round(float(precision_score(y, p >= threshold, zero_division=0)), 4),
        "recall": round(float(recall_score(y, p >= threshold)), 4),
        "roc_auc": round(float(roc_auc_score(y, p)), 4),
    }


def nsl_attack_proba(model: dict, X: np.ndarray) -> np.ndarray:
    z = (X - np.array(model["mean"])) / np.array(model["std"])
    logits = z @ np.array(model["coef"]).T + np.array(model["intercept"])
    p = np.exp(logits - logits.max(axis=1, keepdims=True))
    p /= p.sum(axis=1, keepdims=True)
    return 1.0 - p[:, model["classes"].index("normal")]


def simulator_features(n: int = 3000):
    """Window features of the live demo's simulated benign traffic, plus a
    synthetic port scan and flood, computed exactly as the runtime does."""
    import anomaly_simulator as sim
    from ml_detector import MLAnomalyDetector

    d = MLAnomalyDetector()
    benign = []
    for _ in range(n):
        ev = sim._generate_baseline_event()
        d._update(ev["src_ip"], int(ev["port"]), time.time())
        benign.append(d.features_for(ev))

    def last_features(events):
        det = MLAnomalyDetector()
        for ev in events:
            det._update(ev["src_ip"], int(ev["port"]), time.time())
        return det.features_for(events[-1])

    scan = [{"src_ip": "198.51.100.7", "dst_ip": "10.0.0.5", "protocol": "TCP", "port": p * 13, "bytes": 0}
            for p in range(1, 40)]
    flood = [{"src_ip": "198.51.100.8", "dst_ip": "10.0.0.5", "protocol": "TCP", "port": 80, "bytes": 0}] * 200
    return np.array(benign), np.array([last_features(scan), last_features(flood)])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nsl-model", default=str(HERE / "model.json"))
    ap.add_argument("--unsw-train", required=True)
    ap.add_argument("--unsw-test", required=True)
    ap.add_argument("--out", default=str(HERE / "cross_dataset.json"))
    args = ap.parse_args()

    tr, te = T.load_unsw(args.unsw_train), T.load_unsw(args.unsw_test)
    Xtr, Xte = T.featurize_unsw(tr), T.featurize_unsw(te)
    ytr = (tr["category"] != "normal").astype(int).to_numpy()
    yte = (te["category"] != "normal").astype(int).to_numpy()

    nsl = json.loads(Path(args.nsl_model).read_text())
    p_transfer = nsl_attack_proba(nsl, Xte)

    mean, std = Xtr.mean(axis=0), Xtr.std(axis=0) + 1e-9
    lr = LogisticRegression(max_iter=3000, class_weight="balanced").fit((Xtr - mean) / std, ytr)
    p_lr = lr.predict_proba((Xte - mean) / std)[:, 1]

    gbm = HistGradientBoostingClassifier(max_iter=200, max_leaf_nodes=31, random_state=0).fit(Xtr, ytr)
    p_gbm = gbm.predict_proba(Xte)[:, 1]

    benign, attacks = simulator_features()
    sim_benign = gbm.predict_proba(benign)[:, 1]
    sim_attacks = gbm.predict_proba(attacks)[:, 1]

    result = {
        "features": T.FEATURES,
        "unsw_test_rows": int(len(yte)),
        "nsl_model_on_unsw_test": binary(yte, p_transfer),
        "unsw_logistic_regression": binary(yte, p_lr),
        "unsw_gradient_boosting": {**binary(yte, p_gbm), "at_0.95": binary(yte, p_gbm, 0.95)},
        "unsw_gradient_boosting_on_demo_simulator": {
            "benign_flagged_at_0.95": round(float((sim_benign >= 0.95).mean()), 4),
            "synthetic_port_scan_score": round(float(sim_attacks[0]), 4),
            "synthetic_flood_score": round(float(sim_attacks[1]), 4),
        },
        "conclusion": (
            "The NSL-KDD model does not transfer to UNSW-NB15. On UNSW-NB15 the window features "
            "carry signal a non-linear model can use, but that model misreads the demo simulator's "
            "traffic, so the live detector stays on NSL-KDD until the simulator replays real flows."
        ),
    }
    Path(args.out).write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
