"""Downloads real, labeled, publicly available phishing/spam/legitimate
email datasets into data/raw/, so the training script has real-world
data to work with out of the box.

Provenance (all are well-known academic/research corpora, mirrored as
plain CSVs in a public GitHub repo so they can be fetched with no
authentication -- unlike Kaggle, which requires a login + API token
this script deliberately does not attempt to automate):

- CEAS_08.csv        -- CEAS 2008 Live Spam Challenge corpus
- Enron.csv          -- Enron corporate email corpus (legitimate mail)
- Ling.csv           -- Ling-Spam corpus
- Nazario.csv        -- Jose Nazario's phishing corpus
- Nigerian_Fraud.csv -- classic "419" advance-fee fraud corpus
- SpamAssasin.csv    -- Apache SpamAssassin public spam corpus

These are the same canonical sources most "phishing email" datasets on
Kaggle themselves repackage. Combined, they total roughly 80,000+ real,
labeled emails spanning corporate ham, classic spam, and multiple
distinct phishing/fraud campaign styles.

If you have your own Kaggle-downloaded CSVs (e.g. the datasets
referenced in docs/threat_model.md's training notes), just drop them
into data/raw/kaggle/ -- `app/services/dataset_loader.py` will pick up
any CSV in either directory automatically, as long as it has a
recognizable label column and subject/body text column (see that
module's _SUBJECT_COLUMNS/_BODY_COLUMNS/_LABEL_COLUMNS for what's
already recognized, and add to them if your file uses different names).

Usage:
    python -m scripts.fetch_datasets
"""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

import httpx

from app.services.dataset_loader import DATA_DIR

KAGGLE_DIR = DATA_DIR / "kaggle"

_REPO_ZIP_URL = "https://codeload.github.com/rokibulroni/Phishing-Email-Dataset/zip/refs/heads/main"
_WANTED_FILES = {
    "CEAS_08.csv", "Enron.csv", "Ling.csv", "Nazario.csv",
    "Nigerian_Fraud.csv", "SpamAssasin.csv",
}


def fetch() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    KAGGLE_DIR.mkdir(parents=True, exist_ok=True)

    already_present = {f.name for f in DATA_DIR.glob("*.csv")}
    if _WANTED_FILES.issubset(already_present):
        print("All real datasets already present in data/raw/ -- nothing to fetch.")
        return

    print(f"Downloading dataset archive from {_REPO_ZIP_URL} ...")
    with httpx.Client(timeout=120.0, follow_redirects=True) as client:
        response = client.get(_REPO_ZIP_URL)
        response.raise_for_status()

    print("Extracting relevant CSVs...")
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        for member in archive.namelist():
            filename = member.rsplit("/", 1)[-1]
            if filename in _WANTED_FILES:
                target = DATA_DIR / filename
                with archive.open(member) as src, open(target, "wb") as dst:
                    dst.write(src.read())
                print(f"  saved {target}")

    missing = _WANTED_FILES - {f.name for f in DATA_DIR.glob("*.csv")}
    if missing:
        print(f"WARNING: could not extract: {missing}. The upstream repo layout may have changed.")
    else:
        print("Done. All 6 real datasets are in data/raw/.")

    if not any(KAGGLE_DIR.iterdir()):
        print(
            "\nTip: if you have Kaggle-downloaded CSVs (e.g. the datasets referenced in "
            "docs/threat_model.md), drop them into data/raw/kaggle/ -- the training script "
            "picks up any CSV there automatically, as long as it has a recognizable label "
            "and text column (see app/services/dataset_loader.py)."
        )


if __name__ == "__main__":
    fetch()
