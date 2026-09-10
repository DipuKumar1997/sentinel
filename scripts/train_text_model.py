"""Trains `text_content_classifier`, a TF-IDF + Logistic Regression model
fit on REAL, publicly available labeled email data (not synthetic) --
see `scripts/fetch_datasets.py` for where the data comes from and
`app/services/dataset_loader.py` for how heterogeneous CSVs are
harmonized into one (text, label) schema.

This is intentionally a classical (non-deep-learning) model:
- It trains in well under a minute on tens of thousands of emails on
  any modern CPU -- a GPU buys you nothing here, since there's no
  matrix-multiply-heavy neural network involved.
- TF-IDF + Logistic Regression is a genuinely strong, well-established
  baseline for this exact task (spam/phishing text classification) --
  it will comfortably beat the synthetic-feature heuristic model this
  project shipped with previously, because it's trained on real
  language patterns from real phishing/spam campaigns rather than
  hand-guessed feature weights.
- If you later want a heavier neural model (e.g. fine-tuning
  DistilBERT) to make use of a GPU, this script's data-loading and
  reporting logic is reusable -- only the vectorize+fit block would
  need to change. Not implemented here to keep the default path fast,
  dependency-light, and reliably reproducible.

This script is run BY YOU, not by Claude -- see the printed dataset
report and classification_report output for exactly what it trained on
and how well it did on held-out real data before you trust it.

Usage:
    python -m scripts.fetch_datasets      # first time only, or to refresh
    python -m scripts.train_text_model
"""
from __future__ import annotations

import json
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from app.services.dataset_loader import DATA_DIR, LoadedDataset, load_all_datasets

KAGGLE_DIR = Path(__file__).resolve().parent.parent / "data" / "raw" / "kaggle"
MODEL_DIR = Path(__file__).resolve().parent.parent / "app" / "ml_models"
MODEL_PATH = MODEL_DIR / "text_content_classifier.joblib"
DATASETS_MANIFEST_PATH = MODEL_DIR / "text_content_classifier.datasets.json"
MODEL_VERSION = "1.0.0-real-corpus"
RANDOM_SEED = 42

# Optional safety valve for memory-constrained machines. Leave as None
# to train on every available row.
MAX_ROWS: int | None = None


def _print_dataset_report(reports: list[LoadedDataset]) -> None:
    print("\n" + "=" * 72)
    print("DATASETS USED FOR TRAINING (see this list any time you need to know")
    print("exactly what data this model was trained on):")
    print("=" * 72)
    total_rows = total_pos = total_neg = total_dropped = 0
    for r in reports:
        print(
            f"  {r.source_file:<24} rows={r.rows:<8} phishing/spam={r.positive_rows:<8} "
            f"legitimate={r.negative_rows:<8} dropped={r.dropped_rows}"
        )
        total_rows += r.rows
        total_pos += r.positive_rows
        total_neg += r.negative_rows
        total_dropped += r.dropped_rows
    print("-" * 72)
    print(f"  {'TOTAL':<24} rows={total_rows:<8} phishing/spam={total_pos:<8} legitimate={total_neg:<8} dropped={total_dropped}")
    print("=" * 72 + "\n")


def train() -> None:
    combined, reports = load_all_datasets([DATA_DIR, KAGGLE_DIR])
    _print_dataset_report(reports)

    if MAX_ROWS and len(combined) > MAX_ROWS:
        combined = combined.sample(n=MAX_ROWS, random_state=RANDOM_SEED)
        print(f"Subsampled to MAX_ROWS={MAX_ROWS} rows.")

    print(f"Training on {len(combined)} total examples "
          f"({(combined['label'] == 1).sum()} phishing/spam, {(combined['label'] == 0).sum()} legitimate)...")

    X_train, X_test, y_train, y_test = train_test_split(
        combined["text"], combined["label"],
        test_size=0.15, random_state=RANDOM_SEED, stratify=combined["label"],
    )

    vectorizer = TfidfVectorizer(
        max_features=60_000,
        ngram_range=(1, 2),
        min_df=2,
        sublinear_tf=True,
        stop_words="english",
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    clf = LogisticRegression(
        max_iter=2000,
        class_weight="balanced",
        solver="liblinear",
        random_state=RANDOM_SEED,
    )
    clf.fit(X_train_vec, y_train)

    y_pred = clf.predict(X_test_vec)
    print("\nHeld-out REAL test set performance:\n")
    print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing/spam"]))
    print("Confusion matrix (rows=actual, cols=predicted) [legitimate, phishing/spam]:")
    print(confusion_matrix(y_test, y_pred))

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    bundle = {
        "vectorizer": vectorizer,
        "model": clf,
        "model_name": "text_content_classifier",
        "model_version": MODEL_VERSION,
        "classes": ["legitimate", "phishing_or_spam"],
        "trained_on": "real_public_datasets",
    }
    joblib.dump(bundle, MODEL_PATH)
    print(f"\nSaved trained model bundle to {MODEL_PATH}")

    manifest = [
        {
            "source_file": r.source_file,
            "rows_used": r.rows,
            "positive_rows": r.positive_rows,
            "negative_rows": r.negative_rows,
            "dropped_rows": r.dropped_rows,
        }
        for r in reports
    ]
    DATASETS_MANIFEST_PATH.write_text(json.dumps(manifest, indent=2))
    print(f"Saved dataset manifest to {DATASETS_MANIFEST_PATH}")


if __name__ == "__main__":
    train()
