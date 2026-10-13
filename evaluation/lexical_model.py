"""Optional logistic regression, saved as inspectable JSON instead of executable pickle."""

from __future__ import annotations

import math
from urllib.parse import urlsplit

import numpy as np

from url_analysis import analyze_url, normalize_url

from .benchmark import validate_splits
from .metrics import classification_metrics

FEATURES = [
    "length",
    "digit_fraction",
    "hyphens",
    "subdomains",
    "ip_host",
    "heuristic",
    "punycode",
    "http",
]


def features(url: str) -> list[float]:
    normalized = normalize_url(url)
    data = analyze_url(normalized)
    hostname = urlsplit(normalized).hostname
    return [
        min(len(normalized) / 200, 5),
        sum(c.isdigit() for c in normalized) / len(normalized),
        min(hostname.count("-") / 5, 5),
        min(data["observations"]["subdomain_count"] / 5, 5),
        float(data["observations"]["is_ip_address"]),
        data["score"],
        float("xn--" in hostname),
        float(normalized.startswith("http:")),
    ]


def validate_model(model: dict) -> None:
    if not isinstance(model, dict) or model.get("schema") != 1 or model.get("features") != FEATURES:
        raise ValueError("Unsupported lexical model schema")
    weights = model.get("weights")
    if not isinstance(weights, list) or len(weights) != len(FEATURES):
        raise ValueError("Invalid lexical model weights")
    values = weights + [model.get("bias"), model.get("threshold")]
    if any(
        type(value) not in (int, float) or not math.isfinite(value) or abs(value) > 100
        for value in values
    ):
        raise ValueError("Invalid lexical model parameters")
    if not 0 < model["threshold"] < 1:
        raise ValueError("Invalid classifier threshold")


def predict(model: dict, url: str) -> dict:
    validate_model(model)
    values = features(url)
    z = sum(w * x for w, x in zip(model["weights"], values, strict=True)) + model["bias"]
    output = 1 / (1 + math.exp(-max(-50, min(50, z))))
    return {
        "model_output": round(output, 6),
        "threshold": model["threshold"],
        "flagged": output >= model["threshold"],
        "feature_values": dict(zip(FEATURES, values, strict=True)),
        "training_source": model.get("training_source", "unspecified"),
        "note": "Experimental, uncalibrated model output; not part of the four-layer risk score.",
    }


def train(rows: list[dict], *, source: str) -> dict:
    validate_splits(rows)
    training = [row for row in rows if row["split"] == "train"]
    validation = [row for row in rows if row["split"] == "validation"]
    test = [row for row in rows if row["split"] == "test"]
    if not training or not validation or not test or {row["label"] for row in training} != {0, 1}:
        raise ValueError(
            "Need training examples of both classes and separate validation/test splits"
        )
    x = np.asarray([features(row["url"]) for row in training])
    y = np.asarray([row["label"] for row in training])
    weights = np.zeros(len(FEATURES))
    bias = 0.0
    for _ in range(1500):
        probabilities = 1 / (1 + np.exp(-np.clip(x @ weights + bias, -50, 50)))
        residual = probabilities - y
        weights -= 0.15 * (x.T @ residual / len(y) + 0.01 * weights)
        bias -= 0.15 * residual.mean()
    model = {
        "schema": 1,
        "features": FEATURES,
        "weights": weights.tolist(),
        "bias": float(bias),
        "threshold": 0.5,
        "training_source": source,
        "training_rows": len(training),
        "method": "L2-regularized logistic regression; fixed deterministic gradient descent",
    }
    candidates = []
    for threshold in (0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8):
        model["threshold"] = threshold
        metrics = classification_metrics(
            [row["label"] for row in validation],
            [predict(model, row["url"])["flagged"] for row in validation],
        )
        candidates.append(
            (
                metrics["f1_on_assessed"] or 0,
                -metrics["false_positive"],
                -abs(threshold - 0.5),
                threshold,
            )
        )
    model["threshold"] = max(candidates)[3]
    model["test_metrics"] = classification_metrics(
        [row["label"] for row in test], [predict(model, row["url"])["flagged"] for row in test]
    )
    validate_model(model)
    return model
