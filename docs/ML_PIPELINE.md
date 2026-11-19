# ML pipeline

Code: `ml/training/{dataset,synthetic,train}.py`, inference `app/services/ml_service.py`.

## Data
`ml/dataset/*.csv` with columns `text,label[,source]` (label 1/phishing, 0/safe/ham). `load_dataset` handles missing values, label validation (unknown labels dropped), normalising whitespace, dropping texts < 15 chars, **removing texts that appear with conflicting labels**, de-duplication, class-balance and size warnings. Duplicates are removed **before** the train/test split to prevent leakage.

### ⚠️ Honest status of the bundled data
* `seed_samples.csv` – the 30 hand-written samples from the original repo.
* `synthetic.csv` – 1,200 rows generated from ~32 templates (`synthetic.py`). After de-duplication only ~139 unique rows remain (the rows are template-instantiations). **This is not real email.**
Consequently the reported held-out metrics (e.g. F1 = 1.0) are meaningless as a real-world estimate: the test split contains near-copies of training templates. The model works as a demonstrator, not as a production detector.

### Importing a real dataset
1. Choose a corpus whose licence permits your use (e.g. SpamAssassin public corpus, Enron-Spam, Nazario phishing corpus – check each licence).
2. Convert to `text,label,source` CSV, drop it into `ml/dataset/`, and record provenance + licence in `ml/dataset/PROVENANCE.md`.
3. Remove or reduce `synthetic.csv`. 4. Retrain (below). Never add user-submitted emails or feedback without explicit user consent.

## Method
Stratified 80/20 split (`seed=42`). On the **training** part only: `GridSearchCV`, 5-fold stratified, scoring F1, over `TfidfVectorizer(ngram_range ∈ {(1,1),(1,2)}, max_features ∈ {5000,20000}, min_df ∈ {1,2}, sublinear_tf=True)` × `LogisticRegression(C ∈ {0.3,1,3,10}, class_weight=balanced)`. The test split is used once for the final report. Output: accuracy, precision, recall, F1, confusion matrix, classification report → `ml/models/<version>/meta.json` and `ml/evaluation/<version>.json`.

**Metrics:** *accuracy* = share correct (misleading with imbalance); *precision* = of emails flagged phishing, how many really were (false-alarm cost); *recall* = of real phishing, how many were caught (miss cost); *F1* = harmonic mean of the two; the *confusion matrix* shows TN/FP/FN/TP counts.

## Scoring
`risk_score = P(phishing) × 100` (rounded to 0.1). SAFE < 30 ≤ SUSPICIOUS < 60 ≤ PHISHING (configurable `RISK_THRESHOLD_*`). It is a **model-derived risk indicator, not a calibrated probability**; thresholds should be tuned on real validation data.

## Persistence & versions
Artifacts: `ml/models/<vYYYYMMDDHHMMSS>/{model.joblib,meta.json}`; pointer `ml/models/active.json`. At startup `MLService.load()` checks the artifact SHA-256 against `meta.json`, runs a smoke prediction, and only then swaps the model in; on failure it keeps the previous model (or reports `ModelUnavailable` → HTTP 503). Each scan stores `model_version`. (joblib is pickle-based: only load artifacts you produced.)

## Retraining workflow
```bash
python -m ml.training.train              # trains, validates, activates only if smoke tests + min F1 pass
python -m ml.training.train --no-activate  # train/evaluate only
flask --app run record-model             # register in model_versions
flask --app run reload-model             # (or restart workers) to pick up the new active model
```
Rollback: edit `ml/models/active.json` to a previous version and restart. Training is never triggered by user requests or feedback.
