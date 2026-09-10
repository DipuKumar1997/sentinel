"""Harmonizes heterogeneous raw email-dataset CSVs into one common
(text, label) schema for training.

Every dataset we've found -- whether pulled automatically by
`scripts/fetch_datasets.py` or manually dropped into `data/raw/kaggle/`
after you download it from Kaggle yourself -- uses different column
names for the same concepts. This module is the ONLY place that mapping
lives, so adding a new dataset means adding one entry here, not touching
the training script.

Design principle carried over from the rest of this codebase: if a file
doesn't match any known schema, we skip it with a clear warning rather
than guessing -- a silently mis-mapped label column would poison the
whole training run.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "raw"

# --------------------------------------------------------------------------
# Known column-name variants, in priority order, per logical field.
# Add new synonyms here as you encounter new datasets (e.g. your own
# Kaggle downloads) rather than renaming columns in the CSVs themselves.
# --------------------------------------------------------------------------
_SUBJECT_COLUMNS = ["subject", "Subject", "email_subject", "Email_Subject", "title"]
_BODY_COLUMNS = [
    "body", "Body", "text", "Text", "email_text", "Email_Text", "Email_Content",
    "message", "Message", "content", "Content",
]
_LABEL_COLUMNS = ["label", "Label", "class", "Class", "spam", "is_phishing", "target"]

# Label value normalization: every dataset we've seen encodes the
# "malicious/phishing/spam" class as one of these (case-insensitive).
# Anything not recognized is treated as the negative (benign) class,
# except rows that fail to parse as either -- those are dropped (see
# `_normalize_label`).
_POSITIVE_LABEL_STRINGS = {"1", "1.0", "phishing", "phish", "spam", "true", "malicious", "fraud"}
_NEGATIVE_LABEL_STRINGS = {"0", "0.0", "ham", "legit", "legitimate", "benign", "false", "safe"}


@dataclass
class LoadedDataset:
    source_file: str
    rows: int
    positive_rows: int
    negative_rows: int
    dropped_rows: int


def _find_column(df: pd.DataFrame, candidates: list[str]) -> str | None:
    for name in candidates:
        if name in df.columns:
            return name
    # Case-insensitive fallback.
    lower_map = {c.lower(): c for c in df.columns}
    for name in candidates:
        if name.lower() in lower_map:
            return lower_map[name.lower()]
    return None


def _normalize_label(raw_value) -> int | None:
    if pd.isna(raw_value):
        return None
    value_str = str(raw_value).strip().lower()
    if value_str in _POSITIVE_LABEL_STRINGS:
        return 1
    if value_str in _NEGATIVE_LABEL_STRINGS:
        return 0
    return None  # unrecognized value -- drop the row rather than guess


_WHITESPACE_RE = re.compile(r"\s+")


def _clean_text(value) -> str:
    if pd.isna(value):
        return ""
    text = str(value)
    text = _WHITESPACE_RE.sub(" ", text).strip()
    return text


def load_csv_as_examples(path: Path) -> tuple[pd.DataFrame, LoadedDataset]:
    """Loads one CSV and returns a DataFrame with exactly two columns:
    `text` (subject + body, cleaned and concatenated) and `label` (0/1
    int), plus a small report of what was found/dropped.
    """
    df = pd.read_csv(path, engine="python", on_bad_lines="skip", encoding_errors="replace")

    subject_col = _find_column(df, _SUBJECT_COLUMNS)
    body_col = _find_column(df, _BODY_COLUMNS)
    label_col = _find_column(df, _LABEL_COLUMNS)

    if label_col is None or (subject_col is None and body_col is None):
        raise ValueError(
            f"{path.name}: could not find a recognizable label column and/or "
            f"subject/body text column. Columns present: {list(df.columns)}. "
            "Add this dataset's column names to _SUBJECT_COLUMNS/_BODY_COLUMNS/"
            "_LABEL_COLUMNS in app/services/dataset_loader.py."
        )

    subject_series = df[subject_col].apply(_clean_text) if subject_col else ""
    body_series = df[body_col].apply(_clean_text) if body_col else ""
    if subject_col and body_col:
        text_series = subject_series + " . " + body_series
    else:
        text_series = subject_series if subject_col else body_series

    label_series = df[label_col].apply(_normalize_label)

    out = pd.DataFrame({"text": text_series, "label": label_series})
    total_rows = len(out)
    out = out[out["text"].str.len() > 0]
    out = out.dropna(subset=["label"])
    out["label"] = out["label"].astype(int)

    report = LoadedDataset(
        source_file=path.name,
        rows=len(out),
        positive_rows=int((out["label"] == 1).sum()),
        negative_rows=int((out["label"] == 0).sum()),
        dropped_rows=total_rows - len(out),
    )
    return out, report


def load_all_datasets(data_dirs: list[Path]) -> tuple[pd.DataFrame, list[LoadedDataset]]:
    """Loads and concatenates every *.csv file found in the given
    directories (non-recursive per directory, but you can pass multiple
    directories -- e.g. data/raw/ and data/raw/kaggle/).
    """
    frames: list[pd.DataFrame] = []
    reports: list[LoadedDataset] = []

    for data_dir in data_dirs:
        if not data_dir.exists():
            continue
        for csv_path in sorted(data_dir.glob("*.csv")):
            try:
                df, report = load_csv_as_examples(csv_path)
            except ValueError as exc:
                print(f"[dataset_loader] SKIPPING {csv_path.name}: {exc}")
                continue
            frames.append(df)
            reports.append(report)

    if not frames:
        raise RuntimeError(
            "No usable datasets found. Run `python -m scripts.fetch_datasets` first, "
            "or drop Kaggle-downloaded CSVs into data/raw/kaggle/."
        )

    combined = pd.concat(frames, ignore_index=True)
    combined = combined.drop_duplicates(subset=["text"])
    return combined, reports
