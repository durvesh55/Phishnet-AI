"""Dataset loading, validation and cleaning for the phishing classifier."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

DATASET_DIR = Path(__file__).resolve().parent.parent / "dataset"
LABEL_MAP = {"phishing": 1, "phish": 1, "spam": 1, "1": 1, 1: 1, "safe": 0, "ham": 0, "legitimate": 0, "0": 0, 0: 0}


@dataclass
class DatasetReport:
    rows_raw: int = 0
    missing_dropped: int = 0
    invalid_labels_dropped: int = 0
    too_short_dropped: int = 0
    duplicates_dropped: int = 0
    conflicting_duplicates_dropped: int = 0
    rows_final: int = 0
    class_counts: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)


def normalise_text(s: str) -> str:
    return re.sub(r"\s+", " ", str(s)).strip()


def load_dataset(paths: list[Path] | None = None) -> tuple[pd.DataFrame, DatasetReport]:
    """Load every CSV (columns: text,label[,source]) and return a cleaned frame + report."""
    paths = paths or sorted(DATASET_DIR.glob("*.csv"))
    if not paths:
        raise FileNotFoundError(f"No CSV files found in {DATASET_DIR}")
    frames = []
    for p in paths:
        df = pd.read_csv(p)
        if not {"text", "label"} <= set(df.columns):
            raise ValueError(f"{p.name}: needs columns 'text' and 'label'")
        df["source"] = df["source"] if "source" in df.columns else p.stem
        frames.append(df[["text", "label", "source"]])
    df = pd.concat(frames, ignore_index=True)
    rep = DatasetReport(rows_raw=len(df))

    n = len(df)
    df = df.dropna(subset=["text", "label"])
    rep.missing_dropped = n - len(df)

    df["label"] = df["label"].map(lambda v: LABEL_MAP.get(str(v).strip().lower(), LABEL_MAP.get(v)))
    n = len(df)
    df = df.dropna(subset=["label"])
    rep.invalid_labels_dropped = n - len(df)
    df["label"] = df["label"].astype(int)

    df["text"] = df["text"].map(normalise_text)
    n = len(df)
    df = df[df["text"].str.len() >= 15]
    rep.too_short_dropped = n - len(df)

    # Same text with different labels is label noise -> drop all copies.
    key = df["text"].str.lower()
    conflict = df.groupby(key)["label"].transform("nunique") > 1
    rep.conflicting_duplicates_dropped = int(conflict.sum())
    df = df[~conflict]
    n = len(df)
    df = df.drop_duplicates(subset="text", keep="first")
    rep.duplicates_dropped = n - len(df)

    df = df.reset_index(drop=True)
    rep.rows_final = len(df)
    rep.class_counts = {int(k): int(v) for k, v in df["label"].value_counts().items()}
    if rep.rows_final < 200:
        rep.warnings.append("Fewer than 200 usable rows: metrics will be unreliable.")
    if rep.class_counts and min(rep.class_counts.values()) / max(rep.class_counts.values()) < 0.3:
        rep.warnings.append("Severe class imbalance (minority < 30% of majority).")
    if len(rep.class_counts) < 2:
        raise ValueError("Dataset must contain both classes")
    if "synthetic" in set(df["source"]):
        share = (df["source"] == "synthetic").mean()
        rep.warnings.append(f"{share:.0%} of rows are template-generated synthetic data; metrics are optimistic.")
    return df, rep
