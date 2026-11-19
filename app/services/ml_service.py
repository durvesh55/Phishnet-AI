"""Machine-learning inference. Loads a persisted, versioned model once at startup.

This module never looks at rule-engine output. The risk score is simply
phishing_probability * 100 from the trained TF-IDF + LogisticRegression pipeline.
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
from dataclasses import dataclass
from pathlib import Path

import joblib

log = logging.getLogger("phishnet.ml")


class ModelUnavailable(RuntimeError):
    """Raised when no valid model is loaded."""


@dataclass
class MLResult:
    classification: str
    risk_score: float
    probability: float  # phishing-class probability in [0, 1]
    model_version: str


def classify(risk_score: float, suspicious: float, phishing: float) -> str:
    if risk_score >= phishing:
        return "PHISHING"
    if risk_score >= suspicious:
        return "SUSPICIOUS"
    return "SAFE"


class MLService:
    def __init__(self, model_dir: str | Path, suspicious: float = 30.0, phishing: float = 60.0):
        self.model_dir = Path(model_dir)
        self.suspicious, self.phishing = suspicious, phishing
        self._pipeline = None
        self.version: str | None = None
        self.meta: dict = {}
        self.error: str | None = None
        self._lock = threading.Lock()

    @property
    def ready(self) -> bool:
        return self._pipeline is not None

    def load(self) -> bool:
        """Load the active model. On any problem keep the previous model (if any) and record the error."""
        try:
            active = json.loads((self.model_dir / "active.json").read_text())
            vdir = self.model_dir / active["version"]
            meta = json.loads((vdir / "meta.json").read_text())
            artifact = vdir / meta["artifact"]
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            if digest != meta["sha256"]:
                raise ValueError("model artifact checksum mismatch")
            pipeline = joblib.load(artifact)
            p = float(pipeline.predict_proba(["smoke test"])[0][1])
            if not 0.0 <= p <= 1.0:
                raise ValueError("model produced invalid probability")
        except Exception as exc:  # noqa: BLE001 - any failure must be non-fatal
            self.error = f"{type(exc).__name__}: {exc}"
            log.error("model load failed: %s", self.error)
            return False
        with self._lock:
            self._pipeline, self.version, self.meta, self.error = pipeline, meta["version"], meta, None
        log.info("loaded model %s", self.version)
        return True

    def predict(self, text: str) -> MLResult:
        if not isinstance(text, str) or not text.strip():
            raise ValueError("text must be a non-empty string")
        if not self.ready:
            raise ModelUnavailable(self.error or "no model loaded")
        with self._lock:
            pipe, version = self._pipeline, self.version
        prob = float(pipe.predict_proba([text])[0][1])
        score = round(prob * 100.0, 1)
        return MLResult(classify(score, self.suspicious, self.phishing), score, round(prob, 4), version or "unknown")
