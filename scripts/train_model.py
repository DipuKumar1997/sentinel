"""Trains `phishing_classifier_v1`, a real (fitted, not hand-weighted)
scikit-learn LogisticRegression over the feature space defined in
`app/services/ml_features.py`.

Honesty note (carried through to docs/threat_model.md and the model's
own `model_version` string): no real-world labeled email corpus is
available in this environment, so the training data below is
**synthetically generated** by sampling plausible feature combinations
for "phishing" vs "benign" classes with added noise -- it is a
proof-of-the-pipeline model, not one validated against real-world
ground truth. Swapping in a real labeled dataset later requires no
change to `app/services/ml_scoring.py` or the model-loading code, only
replacing the data generation in this script (or pointing it at a real
CSV/dataset) and re-running it.

Usage:
    python -m scripts.train_model
"""
from __future__ import annotations

import random
from pathlib import Path

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from app.services.ml_features import FEATURE_NAMES

MODEL_DIR = Path(__file__).resolve().parent.parent / "app" / "ml_models"
MODEL_PATH = MODEL_DIR / "phishing_classifier.joblib"
MODEL_VERSION = "1.0.0-synthetic"
RANDOM_SEED = 42


def _sample_phishing_row(rng: random.Random) -> list[float]:
    # Phishing emails: skew towards multiple simultaneous red flags, but
    # with realistic variance (not every phish trips every signal).
    return [
        float(rng.choices([0, 1, 2, 3], weights=[10, 25, 40, 25])[0]),  # auth_fail_count
        float(rng.choices([0, 1, 2, 3], weights=[15, 30, 35, 20])[0]),  # urgency_keyword_count
        float(rng.choices([0, 1], weights=[35, 65])[0]),  # display_name_mismatch
        float(rng.choices([0, 1], weights=[40, 60])[0]),  # reply_to_mismatch
        float(rng.choices([0, 1, 2, 3, 4, 5], weights=[10, 15, 20, 20, 20, 15])[0]),  # url_count_capped
        float(rng.choices([0, 1], weights=[55, 45])[0]),  # has_raw_ip_link
        float(rng.choices([0, 1], weights=[60, 40])[0]),  # has_url_shortener
        float(rng.choices([0, 1], weights=[45, 55])[0]),  # has_low_reputation_tld
        float(rng.choices([0, 1], weights=[70, 30])[0]),  # has_attachment
        float(rng.choices([0, 1], weights=[40, 60])[0]),  # subject_has_urgency_word
    ]


def _sample_benign_row(rng: random.Random) -> list[float]:
    # Benign emails: mostly clean, with occasional single false-positive-
    # prone signal (e.g. a legitimate marketing email with urgency words,
    # or a mailing list with a Reply-To alias) so the model learns these
    # signals are only meaningful in combination.
    return [
        float(rng.choices([0, 1], weights=[92, 8])[0]),  # auth_fail_count (rare)
        float(rng.choices([0, 1, 2], weights=[70, 22, 8])[0]),  # urgency_keyword_count
        float(rng.choices([0, 1], weights=[93, 7])[0]),  # display_name_mismatch
        float(rng.choices([0, 1], weights=[80, 20])[0]),  # reply_to_mismatch (mailing lists)
        float(rng.choices([0, 1, 2], weights=[55, 30, 15])[0]),  # url_count_capped
        float(rng.choices([0, 1], weights=[97, 3])[0]),  # has_raw_ip_link
        float(rng.choices([0, 1], weights=[88, 12])[0]),  # has_url_shortener (legit marketing uses these too)
        float(rng.choices([0, 1], weights=[85, 15])[0]),  # has_low_reputation_tld
        float(rng.choices([0, 1], weights=[75, 25])[0]),  # has_attachment
        float(rng.choices([0, 1], weights=[75, 25])[0]),  # subject_has_urgency_word (sales emails!)
    ]


def generate_dataset(n_per_class: int = 2500, seed: int = RANDOM_SEED) -> tuple[np.ndarray, np.ndarray]:
    rng = random.Random(seed)
    rows: list[list[float]] = []
    labels: list[int] = []

    for _ in range(n_per_class):
        rows.append(_sample_phishing_row(rng))
        labels.append(1)
    for _ in range(n_per_class):
        rows.append(_sample_benign_row(rng))
        labels.append(0)

    X = np.array(rows, dtype=float)
    y = np.array(labels, dtype=int)
    return X, y


def train() -> None:
    X, y = generate_dataset()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y
    )

    clf = LogisticRegression(max_iter=1000, random_state=RANDOM_SEED)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    report = classification_report(y_test, y_pred, target_names=["benign", "phishing"])
    print("Held-out synthetic test set performance:\n")
    print(report)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    bundle = {
        "model": clf,
        "feature_names": FEATURE_NAMES,
        "model_name": "phishing_classifier_lr",
        "model_version": MODEL_VERSION,
        "classes": ["benign", "phishing"],
        "trained_on": "synthetic_data",
    }
    joblib.dump(bundle, MODEL_PATH)
    print(f"\nSaved trained model bundle to {MODEL_PATH}")


if __name__ == "__main__":
    train()
