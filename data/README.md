# Training Data

This is the **single source of truth** for exactly what data trains
`text_content_classifier` (see `scripts/train_text_model.py`). If you
ever need to answer "what was this model trained on," this file is it.

## What's included by default (auto-fetched, real, no login required)

Running `python -m scripts.fetch_datasets` downloads six real, publicly
available, academically-cited labeled email datasets, mirrored as plain
CSVs in a public GitHub repository (no Kaggle account/API token needed
for these):

| File | Rows (usable) | Phishing/Spam | Legitimate | Source |
|---|---|---|---|---|
| `CEAS_08.csv` | 39,153 | 21,842 | 17,311 | CEAS 2008 Live Spam Challenge |
| `Enron.csv` | 29,763 | 13,976 | 15,787 | Enron corporate email corpus |
| `Ling.csv` | 2,859 | 458 | 2,401 | Ling-Spam corpus |
| `Nazario.csv` | 1,563 | 1,563 | 0 | Jose Nazario's phishing corpus |
| `Nigerian_Fraud.csv` | 3,332 | 3,332 | 0 | Classic "419" advance-fee fraud corpus |
| `SpamAssasin.csv` | 5,805 | 1,716 | 4,089 | Apache SpamAssassin public spam corpus |
| **TOTAL** | **82,475** | **42,887** | **39,588** | |

(Row counts above are what survives `app/services/dataset_loader.py`'s
cleaning -- a small number of rows in `Enron.csv` and `SpamAssasin.csv`
are dropped because their `label` column contains malformed/non-numeric
values from source CSV quoting issues; this is reported, not silently
absorbed, every time you run the training script.)

**These are the same canonical academic sources most "phishing email"
datasets on Kaggle themselves repackage or derive from** -- Nazario's
corpus, the Nigerian-fraud/419 corpus, the Enron corpus, Ling-Spam, and
SpamAssassin are the standard building blocks of nearly every public
phishing/spam email dataset, including the ones on Kaggle.

## Adding your own Kaggle datasets (or any other CSV)

The four Kaggle URLs you referenced can't be fetched automatically --
Kaggle requires a logged-in session + API token, and this project's
sandboxed build/training environment has no path to authenticate with
Kaggle on your behalf. **On your own machine, though, you already have
Kaggle access** -- just:

1. Download the CSV(s) from Kaggle normally (browser or `kaggle` CLI).
2. Drop them into `data/raw/kaggle/` (this directory is created
   automatically by `scripts/fetch_datasets.py`).
3. Run `python -m scripts.train_text_model` -- it automatically picks up
   every `*.csv` in both `data/raw/` and `data/raw/kaggle/`.

The only requirement is that each CSV has:
- A **label** column recognizable as one of: `label`, `Label`, `class`,
  `Class`, `spam`, `is_phishing`, `target` -- with values like `1`/`0`,
  `phishing`/`legitimate`, `spam`/`ham`, `true`/`false`, etc. (see
  `_POSITIVE_LABEL_STRINGS`/`_NEGATIVE_LABEL_STRINGS` in
  `app/services/dataset_loader.py` for the exact recognized set).
- A **subject** and/or **body** text column recognizable as one of:
  `subject`/`Subject`/`email_subject`, `body`/`Body`/`text`/
  `email_text`/`message`/`content`.

If your Kaggle CSV uses different column names, add them to the
`_SUBJECT_COLUMNS`/`_BODY_COLUMNS`/`_LABEL_COLUMNS` lists at the top of
`app/services/dataset_loader.py` -- that's the only change needed; the
rest of the pipeline (harmonization, training, reporting) requires no
other edits.

Datasets we'd specifically expect to work once downloaded (based on the
column names visible in their Kaggle previews, unverified since we
can't fetch them directly):

- `subhajournal/phishingemails` (`Phishing_Email.csv`) -- likely
  `Email Text`/`Email Type` columns; add these exact names if the
  auto-detection above doesn't already catch them.
- `kuladeep19/phishing-and-legitimate-emails-dataset`
- `vincentamonde/simulated-email-dataset`
- `gokulraja84/emails-dataset-for-spam-detection`

After adding any of these, re-run `python -m scripts.train_text_model`
and check the printed per-file dataset report -- it will show you
exactly how many rows were used/dropped from each file you add, so a
misconfigured column mapping is immediately visible rather than
silently training on garbage.

## Regenerating this data

```bash
python -m scripts.fetch_datasets      # (re-)downloads the 6 real datasets above
# optionally: drop your own Kaggle CSVs into data/raw/kaggle/
python -m scripts.train_text_model    # trains + prints the dataset report + held-out metrics
```

`app/ml_models/text_content_classifier.datasets.json` is written every
time training runs -- a machine-readable copy of exactly which files
and row counts went into the currently-deployed model, so you never
have to guess after the fact.
