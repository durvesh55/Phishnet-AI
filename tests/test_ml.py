import json
import shutil

import pytest

from app.services.ml_service import MLService, ModelUnavailable, classify
from ml.training.dataset import DATASET_DIR, load_dataset

MODEL_DIR = DATASET_DIR.parent / "models"


@pytest.fixture(scope="module")
def svc():
    s = MLService(MODEL_DIR)
    assert s.load(), s.error
    return s


def test_thresholds():
    assert classify(0, 30, 60) == "SAFE"
    assert classify(29.9, 30, 60) == "SAFE"
    assert classify(30, 30, 60) == "SUSPICIOUS"
    assert classify(59.9, 30, 60) == "SUSPICIOUS"
    assert classify(60, 30, 60) == "PHISHING"
    assert classify(100, 30, 60) == "PHISHING"


def test_custom_thresholds():
    assert classify(45, 50, 80) == "SAFE"


def test_predict_phish_and_safe(svc):
    p = svc.predict("URGENT: your PayPal account is suspended. Verify your password immediately at http://paypa1-secure.com")
    s = svc.predict("Hi team, the weekly sync is on Thursday at 3 PM in Conference Room B.")
    assert p.classification == "PHISHING" and s.classification == "SAFE"
    assert abs(p.risk_score - p.probability * 100) <= 0.06  # probability is stored to 4 dp
    assert 0 <= s.risk_score <= 100
    assert p.model_version == svc.version


@pytest.mark.parametrize("bad", ["", "   ", None, 123])
def test_invalid_input(svc, bad):
    with pytest.raises(ValueError):
        svc.predict(bad)


def test_missing_model_is_safe(tmp_path):
    s = MLService(tmp_path)
    assert not s.load() and s.error
    with pytest.raises(ModelUnavailable):
        s.predict("hello there")


def test_tampered_model_rejected_and_previous_kept(svc, tmp_path):
    d = tmp_path / "models"
    shutil.copytree(MODEL_DIR, d)
    s = MLService(d)
    assert s.load()
    v = s.version
    art = d / v / "model.joblib"
    art.write_bytes(art.read_bytes() + b"tamper")
    assert not s.load()
    assert "checksum" in s.error
    assert s.ready and s.version == v  # working model not replaced by invalid one


def test_dataset_cleaning(tmp_path):
    p = tmp_path / "d.csv"
    p.write_text("text,label\nhello this is a long enough safe message,0\nhello this is a long enough safe message,0\n"
                 "conflict conflict conflict conflict,0\nconflict conflict conflict conflict,1\n,1\nshort,1\n"
                 "phish phish phish phish phish,phishing\nbad label bad label bad label,maybe\n")
    df, rep = load_dataset([p])
    assert rep.duplicates_dropped == 1 and rep.conflicting_duplicates_dropped == 2
    assert rep.missing_dropped == 1 and rep.too_short_dropped == 1 and rep.invalid_labels_dropped == 1
    assert set(df["label"]) == {0, 1}


def test_metadata_has_honest_metrics():
    active = json.loads((MODEL_DIR / "active.json").read_text())
    meta = json.loads((MODEL_DIR / active["version"] / "meta.json").read_text())
    assert {"accuracy", "precision", "recall", "f1", "confusion_matrix"} <= set(meta["metrics"])
    assert "caveats" in meta
