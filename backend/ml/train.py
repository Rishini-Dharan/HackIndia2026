"""
Train the streaming threat classifier on NSL-KDD.

The runtime detector (backend/ml_detector.py) only sees one packet event at a time
plus a sliding window of recent events, so the model is restricted to features that
can be computed from that window:

    log_bytes        log1p(src_bytes)
    log_count        log1p(connections seen in the window)          ~ NSL-KDD `count`
    diff_srv_rate    share of window connections to other services ~ NSL-KDD `diff_srv_rate`
    same_srv_rate    share of window connections to this service   ~ NSL-KDD `same_srv_rate`
    proto_tcp/udp/icmp, svc_http, svc_ssh, svc_smb, svc_dns       one-hot flags

NSL-KDD computes `count` per destination host over 2 s; the runtime approximates it
per source over its window. That is an approximation and is documented in README.

Output: backend/ml/model.json (scaler + multinomial logistic-regression weights, loaded
with NumPy only, so the backend has no scikit-learn dependency) and backend/ml/metrics.json.

Usage:
    python backend/ml/train.py --train data/KDDTrain+.txt --test data/KDDTest+.txt
Dataset: https://www.unb.ca/cic/datasets/nsl.html
"""

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, f1_score, roc_auc_score

COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty",
]

# Standard NSL-KDD attack-name -> category mapping (includes test-only attacks).
CATEGORY = {
    "normal": "normal",
    **{a: "dos" for a in ["back", "land", "neptune", "pod", "smurf", "teardrop", "apache2",
                          "mailbomb", "processtable", "udpstorm"]},
    **{a: "probe" for a in ["ipsweep", "nmap", "portsweep", "satan", "mscan", "saint"]},
    **{a: "r2l" for a in ["ftp_write", "guess_passwd", "imap", "multihop", "phf", "spy",
                          "warezclient", "warezmaster", "sendmail", "named", "snmpgetattack",
                          "snmpguess", "xlock", "xsnoop", "worm"]},
    **{a: "u2r" for a in ["buffer_overflow", "loadmodule", "perl", "rootkit", "httptunnel",
                          "ps", "sqlattack", "xterm"]},
}

FEATURES = [
    "log_bytes", "log_count", "diff_srv_rate", "same_srv_rate",
    "proto_tcp", "proto_udp", "proto_icmp",
    "svc_http", "svc_ssh", "svc_smb", "svc_dns",
]

CLASSES = ["normal", "dos", "probe", "r2l", "u2r"]


def load(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, header=None, names=COLUMNS)
    df["category"] = df["label"].map(CATEGORY)
    missing = df["category"].isna().sum()
    if missing:
        raise ValueError(f"{missing} rows with unmapped labels: {df.loc[df.category.isna(), 'label'].unique()}")
    return df


def featurize(df: pd.DataFrame) -> np.ndarray:
    svc = df["service"]
    out = pd.DataFrame({
        "log_bytes": np.log1p(df["src_bytes"].clip(upper=10_000_000)),
        "log_count": np.log1p(df["count"]),
        "diff_srv_rate": df["diff_srv_rate"],
        "same_srv_rate": df["same_srv_rate"],
        "proto_tcp": (df["protocol_type"] == "tcp").astype(float),
        "proto_udp": (df["protocol_type"] == "udp").astype(float),
        "proto_icmp": (df["protocol_type"] == "icmp").astype(float),
        "svc_http": svc.isin(["http", "http_443", "http_8001", "http_2784"]).astype(float),
        "svc_ssh": (svc == "ssh").astype(float),
        "svc_smb": svc.isin(["netbios_ssn", "netbios_ns", "netbios_dgm"]).astype(float),
        "svc_dns": (svc == "domain_u").astype(float) + (svc == "domain").astype(float),
    })
    return out[FEATURES].to_numpy(dtype=np.float64)


def _binary(y, yhat):
    tp = int(((yhat == 1) & (y == 1)).sum())
    fp = int(((yhat == 1) & (y == 0)).sum())
    fn = int(((yhat == 0) & (y == 1)).sum())
    return {"precision": round(tp / max(1, tp + fp), 4), "recall": round(tp / max(1, tp + fn), 4)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent))
    args = ap.parse_args()

    train, test = load(args.train), load(args.test)
    Xtr, Xte = featurize(train), featurize(test)
    ytr = train["category"].map(CLASSES.index).to_numpy()
    yte = test["category"].map(CLASSES.index).to_numpy()

    mean, std = Xtr.mean(axis=0), Xtr.std(axis=0) + 1e-9
    Ztr, Zte = (Xtr - mean) / std, (Xte - mean) / std

    lr = LogisticRegression(max_iter=3000, class_weight="balanced", C=1.0)
    lr.fit(Ztr, ytr)
    proba = lr.predict_proba(Zte)
    pred = proba.argmax(axis=1)

    # Reference model with the same features, to show what the linear model gives up.
    rf = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=0, class_weight="balanced")
    rf.fit(Ztr, ytr)
    rf_pred = rf.predict(Zte)

    attack_score = 1.0 - proba[:, 0]
    is_attack = (yte != 0).astype(int)
    binary_pred = (pred != 0).astype(int)
    tp = int(((binary_pred == 1) & (is_attack == 1)).sum())
    fp = int(((binary_pred == 1) & (is_attack == 0)).sum())
    fn = int(((binary_pred == 0) & (is_attack == 1)).sum())

    report = classification_report(yte, pred, target_names=CLASSES, output_dict=True, zero_division=0)
    metrics = {
        "dataset": "NSL-KDD (train: KDDTrain+, test: KDDTest+, which includes attack types unseen in training)",
        "n_train": int(len(ytr)),
        "n_test": int(len(yte)),
        "features": FEATURES,
        "model": "multinomial logistic regression, balanced class weights",
        "binary_attack_vs_normal": {
            "precision": round(tp / (tp + fp), 4),
            "recall": round(tp / (tp + fn), 4),
            "f1": round(2 * tp / (2 * tp + fp + fn), 4),
            "roc_auc": round(float(roc_auc_score(is_attack, attack_score)), 4),
        },
        "operating_point_p_attack_ge_0.95": _binary(is_attack, (attack_score >= 0.95).astype(int)),
        "multiclass_macro_f1": round(float(f1_score(yte, pred, average="macro")), 4),
        "multiclass_accuracy": round(float(report["accuracy"]), 4),
        "per_class": {c: {k: round(v, 4) for k, v in report[c].items()} for c in CLASSES},
        "confusion_matrix": {"labels": CLASSES, "rows_true_cols_pred": confusion_matrix(yte, pred).tolist()},
        "reference_random_forest": {
            "multiclass_macro_f1": round(float(f1_score(yte, rf_pred, average="macro")), 4),
            "multiclass_accuracy": round(float((rf_pred == yte).mean()), 4),
        },
    }

    model = {
        "features": FEATURES,
        "classes": CLASSES,
        "mean": mean.tolist(),
        "std": std.tolist(),
        "coef": lr.coef_.tolist(),
        "intercept": lr.intercept_.tolist(),
    }

    out = Path(args.out)
    (out / "model.json").write_text(json.dumps(model, indent=2))
    (out / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(json.dumps({k: metrics[k] for k in ["binary_attack_vs_normal", "operating_point_p_attack_ge_0.95", "multiclass_macro_f1",
                                              "multiclass_accuracy", "reference_random_forest"]}, indent=2))


if __name__ == "__main__":
    main()
