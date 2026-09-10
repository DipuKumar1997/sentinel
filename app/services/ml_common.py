"""Shared types for the model-scoring subsystem.

Two independent, separately-trained models feed the risk-fusion engine
(see docs/architecture.md "Multi-model architecture"):

1. `ml_scoring_structural.py` -- trained on synthetically generated
   structural/header features (auth failures, urgency keyword counts,
   display-name mismatch, etc.) via `scripts/train_model.py`.
2. `ml_scoring_text.py` -- trained on real, publicly available labeled
   email TEXT (subject+body) via `scripts/train_text_model.py`.

They look at different evidence, are trained differently, can each be
present or absent independently, and are never combined into a single
"the model said X" black box -- both surface as separate, individually
labeled findings.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ModelOutput:
    model_name: str
    model_version: str
    label: str  # phishing|bec|spam|benign|legitimate
    probability: float
    is_external_model: bool = False
