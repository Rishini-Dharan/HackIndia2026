"""
Build the live UNSW-NB15 detector and the demo's replay sample.

Outputs (all in backend/ml/):
  unsw_gbm.json      gradient-boosted trees, evaluated with NumPy at runtime:
                     - "attack": binary attack-vs-normal model
                     - "family": attack-family model (trained on attack rows only)
  unsw_replay.csv.gz flows sampled from the held-out UNSW-NB15 *testing* set,
                     replayed by the demo simulator (the model never trained on them)
  unsw_live_metrics.json

Features are the same 11 used everywhere else (train.featurize_unsw). The replayed
flows carry their own flow features, as a network sensor (e.g. Zeek) would compute
them, so the live detector scores exactly what it was evaluated on.

Usage (from backend/):
    python ml/train_unsw_live.py --train UNSW_NB15_training-set.csv --test UNSW_NB15_testing-set.csv
Dataset: https://research.unsw.edu.au/projects/unsw-nb15-dataset (Moustafa & Slay, 2015)
"""

import argparse
import json
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

os.environ.setdefault("LOKY_MAX_CPU_COUNT", "4")
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from sklearn.ensemble import HistGradientBoostingClassifier  # noqa: E402
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score  # noqa: E402

import train as T  # noqa: E402

REPLAY_COLUMNS = ["proto", "service", "sbytes", "ct_src_ltm", "ct_src_dport_ltm", "attack_cat"]
REPLAY_ATTACKS = {"DoS": 400, "Exploits": 400, "Reconnaissance": 400, "Fuzzers": 400, "Generic": 400}
REPLAY_NORMAL = 3000
SEED = 0


def export_trees(est) -> dict:
    """HistGradientBoostingClassifier -> plain JSON (one list of trees per output)."""
    n_outputs = len(est._predictors[0])
    trees = [[] for _ in range(n_outputs)]
    for iteration in est._predictors:
        for k, predictor in enumerate(iteration):
            n = predictor.nodes
            trees[k].append({
                "f": n["feature_idx"].astype(int).tolist(),
                "t": [float(x) for x in n["num_threshold"]],
                "l": n["left"].astype(int).tolist(),
                "r": n["right"].astype(int).tolist(),
                "m": n["missing_go_to_left"].astype(int).tolist(),
                "leaf": n["is_leaf"].astype(int).tolist(),
                "v": [float(x) for x in n["value"]],
            })
    return {
        "classes": [str(c) for c in est.classes_],
        "baseline": [float(x) for x in np.ravel(est._baseline_prediction)],
        "trees": trees,
    }


def numpy_raw(model: dict, X: np.ndarray) -> np.ndarray:
    """Reference implementation mirrored by ml_detector.GBMModel."""
    out = np.tile(np.array(model["baseline"]), (len(X), 1))
    for k, trees in enumerate(model["trees"]):
        for tree in trees:
            for i, x in enumerate(X):
                node = 0
                while not tree["leaf"][node]:
                    val = x[tree["f"][node]]
                    go_left = tree["m"][node] if np.isnan(val) else val <= tree["t"][node]
                    node = tree["l"][node] if go_left else tree["r"][node]
                out[i, k] += tree["v"][node]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", required=True)
    ap.add_argument("--test", required=True)
    args = ap.parse_args()

    tr, te = T.load_unsw(args.train), T.load_unsw(args.test)
    Xtr, Xte = T.featurize_unsw(tr), T.featurize_unsw(te)
    ytr = (tr["category"] != "normal").astype(int).to_numpy()
    yte = (te["category"] != "normal").astype(int).to_numpy()

    attack = HistGradientBoostingClassifier(max_iter=200, max_leaf_nodes=31, random_state=SEED).fit(Xtr, ytr)
    p = attack.predict_proba(Xte)[:, 1]

    atk_tr, atk_te = tr["category"] != "normal", te["category"] != "normal"
    family = HistGradientBoostingClassifier(max_iter=60, max_leaf_nodes=15, random_state=SEED,
                                            class_weight="balanced").fit(Xtr[atk_tr.to_numpy()],
                                                                         tr.loc[atk_tr, "category"])
    fam_pred = family.predict(Xte[atk_te.to_numpy()])

    model = {"features": T.FEATURES, "attack": export_trees(attack), "family": export_trees(family),
             "labels": T.LABELS["unsw"]}

    # The runtime must reproduce scikit-learn exactly.
    sample = Xte[np.random.default_rng(SEED).choice(len(Xte), 300, replace=False)]
    raw = numpy_raw(model["attack"], sample)[:, 0]
    assert np.allclose(1 / (1 + np.exp(-raw)), attack.predict_proba(sample)[:, 1], atol=1e-9), "attack export mismatch"
    fam_raw = numpy_raw(model["family"], sample)
    assert (np.array(model["family"]["classes"])[fam_raw.argmax(1)] == family.predict(sample)).all(), "family export mismatch"

    # Replay sample: held-out test flows only.
    rng = np.random.default_rng(SEED)
    parts = [te[te["attack_cat"] == "Normal"].sample(REPLAY_NORMAL, random_state=SEED)]
    for cat, n in REPLAY_ATTACKS.items():
        rows = te[te["attack_cat"] == cat]
        parts.append(rows.sample(min(n, len(rows)), random_state=SEED))
    replay = pd.concat(parts)[REPLAY_COLUMNS].sample(frac=1.0, random_state=SEED)
    replay.to_csv(HERE / "unsw_replay.csv.gz", index=False, compression="gzip")

    # False-alarm behaviour on the replayed normal flows.
    normal_replay = T.featurize_unsw(replay[replay["attack_cat"] == "Normal"].assign(
        category="normal"))
    p_normal = attack.predict_proba(normal_replay)[:, 1]

    metrics = {
        "dataset": "UNSW-NB15 official training-set -> testing-set",
        "attack_model": {
            "roc_auc": round(float(roc_auc_score(yte, p)), 4),
            "at_0.95": {"precision": round(float(precision_score(yte, p >= 0.95)), 4),
                        "recall": round(float(recall_score(yte, p >= 0.95)), 4)},
            "normal_flows_flagged_at_0.95": round(float((p[yte == 0] >= 0.95).mean()), 4),
        },
        "family_model_on_attack_rows": {
            "macro_f1": round(float(f1_score(te.loc[atk_te, "category"], fam_pred, average="macro")), 4),
            "accuracy": round(float((fam_pred == te.loc[atk_te, "category"].to_numpy()).mean()), 4),
        },
        "replay_sample": {"normal": REPLAY_NORMAL, **REPLAY_ATTACKS,
                          "normal_flagged_at_0.95": round(float((p_normal >= 0.95).mean()), 4)},
        "export_check": "NumPy tree evaluation matches scikit-learn on 300 held-out rows",
    }
    (HERE / "unsw_gbm.json").write_text(json.dumps(model, separators=(",", ":")))
    (HERE / "unsw_live_metrics.json").write_text(json.dumps(metrics, indent=2))
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
