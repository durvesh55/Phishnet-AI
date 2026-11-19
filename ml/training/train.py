"""Train, validate and (optionally) activate a new phishing model.

Usage:  python -m ml.training.train [--no-activate] [--min-f1 0.85] [--seed 42]

Pipeline: load+clean -> stratified train/test split (test held out, never used for
tuning) -> GridSearchCV (stratified 5-fold, TF-IDF params + C) on TRAIN only ->
evaluate once on TEST -> save versioned artifacts -> smoke-test -> activate only
if validation passes. A previously active model is never replaced by a failing one.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, UTC
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import GridSearchCV, StratifiedKFold, train_test_split
from sklearn.pipeline import Pipeline

from ml.training.dataset import load_dataset

ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = ROOT / "models"
EVAL_DIR = ROOT / "evaluation"

SMOKE_CASES = [
    ("URGENT: your PayPal account is suspended. Verify your password immediately at http://paypa1-secure.com", 1),
    ("Hi team, the weekly sync is on Thursday at 3 PM in Conference Room B. Please bring your updates.", 0),
]


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def train(seed: int = 42, activate: bool = True, min_f1: float = 0.85) -> dict:
    df, report = load_dataset()
    X_tr, X_te, y_tr, y_te = train_test_split(df["text"], df["label"], test_size=0.2, stratify=df["label"], random_state=seed)

    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(lowercase=True, sublinear_tf=True, strip_accents="unicode")),
        ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", solver="liblinear", random_state=seed)),
    ])
    grid = {
        "tfidf__ngram_range": [(1, 1), (1, 2)],
        "tfidf__max_features": [5000, 20000],
        "tfidf__min_df": [1, 2],
        "clf__C": [0.3, 1.0, 3.0, 10.0],
    }
    search = GridSearchCV(pipe, grid, scoring="f1", cv=StratifiedKFold(5, shuffle=True, random_state=seed), n_jobs=1, refit=True)
    search.fit(X_tr, y_tr)
    best: Pipeline = search.best_estimator_

    pred = best.predict(X_te)
    metrics = {
        "accuracy": float(accuracy_score(y_te, pred)),
        "precision": float(precision_score(y_te, pred, zero_division=0)),
        "recall": float(recall_score(y_te, pred, zero_division=0)),
        "f1": float(f1_score(y_te, pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_te, pred).tolist(),
        "confusion_matrix_labels": ["SAFE(0)", "PHISHING(1)"],
        "classification_report": classification_report(y_te, pred, target_names=["safe", "phishing"], output_dict=True, zero_division=0),
        "cv_best_f1_mean": float(search.best_score_),
        "best_params": {k: (list(v) if isinstance(v, tuple) else v) for k, v in search.best_params_.items()},
        "n_train": int(len(X_tr)), "n_test": int(len(X_te)),
    }

    version = datetime.now(UTC).strftime("v%Y%m%d%H%M%S")
    out = MODELS_DIR / version
    out.mkdir(parents=True, exist_ok=True)
    artifact = out / "model.joblib"
    joblib.dump(best, artifact, compress=3)
    meta = {
        "version": version, "artifact": "model.joblib", "sha256": sha256_file(artifact),
        "trained_at": datetime.now(UTC).isoformat(), "seed": seed,
        "sklearn_version": sklearn.__version__, "numpy_version": np.__version__,
        "dataset": {"rows": report.rows_final, "class_counts": report.class_counts, "warnings": report.warnings,
                    "cleaning": {k: v for k, v in report.__dict__.items() if k.endswith("dropped")}},
        "metrics": metrics,
        "caveats": "Score is a model-derived risk indicator, not a calibrated probability. Metrics are on a held-out split of THIS dataset only.",
    }
    (out / "meta.json").write_text(json.dumps(meta, indent=2))
    EVAL_DIR.mkdir(exist_ok=True)
    (EVAL_DIR / f"{version}.json").write_text(json.dumps(meta, indent=2))

    # ---- validation gate ----
    problems = []
    loaded = joblib.load(artifact)
    for text, expected in SMOKE_CASES:
        p = float(loaded.predict_proba([text])[0][1])
        if (p >= 0.5) != bool(expected):
            problems.append(f"smoke test failed (p={p:.2f}) for: {text[:50]}")
    if metrics["f1"] < min_f1:
        problems.append(f"held-out F1 {metrics['f1']:.3f} < required {min_f1}")
    meta["validation_problems"] = problems

    if problems:
        print("MODEL NOT ACTIVATED:", *problems, sep="\n  - ")
    elif activate:
        tmp = MODELS_DIR / "active.json.tmp"
        tmp.write_text(json.dumps({"version": version}))
        tmp.replace(MODELS_DIR / "active.json")  # atomic switch
        print(f"Activated model {version}")
    print(json.dumps({k: metrics[k] for k in ("accuracy", "precision", "recall", "f1", "confusion_matrix", "best_params")}, indent=2))
    for w in report.warnings:
        print("WARNING:", w)
    meta["activated"] = bool(activate and not problems)
    return meta


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--no-activate", action="store_true")
    ap.add_argument("--min-f1", type=float, default=0.85)
    a = ap.parse_args()
    res = train(a.seed, not a.no_activate, a.min_f1)
    sys.exit(0 if not res.get("validation_problems") else 1)
