"""Metrics, ablations and validation-only calibration over saved evidence."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

from shared.contracts import LAYER_WEIGHTS, validate_layer_result
from url_analysis import registered_domain

from .fixtures import fixture_cases, replay_fixture
from .metrics import classification_metrics


def validate_splits(rows: list[dict]) -> None:
    seen, groups, domains = set(), {}, {}
    for row in rows:
        if (
            row["id"] in seen
            or row["split"] not in {"train", "validation", "test"}
            or type(row["label"]) is not int
            or row["label"] not in {0, 1}
        ):
            raise ValueError(
                "Each case needs a unique id, a train/validation/test split and binary label"
            )
        seen.add(row["id"])
        group = row.get("group")
        if not isinstance(group, str) or not group:
            raise ValueError("Each case needs a non-empty grouping key to prevent leakage")
        if group in groups and groups[group] != row["split"]:
            raise ValueError(f"Group {group} leaks across data splits")
        groups[group] = row["split"]
        hostname = urlsplit(
            row.get("url") or row.get("report", {}).get("input", {}).get("url") or ""
        ).hostname
        if hostname:
            domain = registered_domain(hostname)
            if domain in domains and domains[domain] != row["split"]:
                raise ValueError(f"Domain {domain} leaks across data splits")
            domains[domain] = row["split"]


def load_reports(manifest: Path | None = None) -> list[dict]:
    if manifest is None:
        rows = [{**case, "report": replay_fixture(case)} for case in fixture_cases()]
    else:
        data = json.loads(manifest.read_text())
        if not isinstance(data, list) or len(data) > 10000:
            raise ValueError("Manifest must contain a list of at most 10,000 records")
        rows = []
        for item in data:
            report = item.get("report")
            if not isinstance(report, dict):
                report = json.loads((manifest.parent / item["report_path"]).read_text())
            for name in LAYER_WEIGHTS:
                validate_layer_result(report["layers"][name])
            rows.append({**item, "report": report})
    validate_splits(rows)
    return rows


def predict_report(report: dict, weights: dict, threshold: float) -> bool | None:
    layers = report["layers"]
    if any(layers[name]["status"] != "complete" for name, weight in weights.items() if weight > 0):
        return None
    denominator = sum(weights.values())
    if denominator <= 0:
        return None
    score = (
        sum(weights[name] * layers[name]["score"] for name in weights if weights[name] > 0)
        / denominator
        * 100
    )
    return score >= threshold


def run_benchmark(manifest: Path | None = None) -> dict:
    rows = load_reports(manifest)
    approaches = {
        "all_layers": LAYER_WEIGHTS,
        "url_only": {"lexical": 1.0},
        "url_and_redirect": {"lexical": 0.20, "redirect": 0.25},
        "without_qr_structure": {"lexical": 0.20, "redirect": 0.25, "network": 0.50},
    }
    results = {}
    for split in ("train", "validation", "test"):
        selected = [row for row in rows if row["split"] == split]
        results[split] = {
            name: classification_metrics(
                [row["label"] for row in selected],
                [predict_report(row["report"], weights, 35) for row in selected],
            )
            for name, weights in approaches.items()
        }
    return {
        "dataset": "external saved reports"
        if manifest
        else "30 labelled synthetic teaching fixtures",
        "threshold": 35,
        "splits": results,
        "cases": [
            {
                "id": row["id"],
                "split": row["split"],
                "label": row["label"],
                "score": row["report"]["risk"]["score"],
                "verdict": row["report"]["risk"]["verdict"],
            }
            for row in rows
        ],
        "limitations": [
            "Fixture labels encode scenario intent; this is not a real-world accuracy estimate.",
            "Abstentions are excluded from assessed-only metrics and included in overall recall.",
            "Changing layer weights changes the meaning of the same numeric threshold.",
        ],
    }


def calibrate(manifest: Path | None = None) -> dict:
    rows = load_reports(manifest)
    validation = [row for row in rows if row["split"] == "validation"]
    test = [row for row in rows if row["split"] == "test"]
    if not validation or not test:
        raise ValueError("Calibration requires separate validation and held-out test records")
    candidates = []
    for network in (0.4, 0.5, 0.6):
        remaining = 0.95 - network
        weights = {
            "lexical": remaining * 4 / 9,
            "redirect": remaining * 5 / 9,
            "network": network,
            "qr_structure": 0.05,
        }
        for threshold in range(10, 71, 5):
            metrics = classification_metrics(
                [row["label"] for row in validation],
                [predict_report(row["report"], weights, threshold) for row in validation],
            )
            if metrics["assessed"]:
                candidates.append(
                    (
                        metrics["f1_on_assessed"] or 0,
                        -(metrics["false_positive"]),
                        -abs(threshold - 35),
                        weights,
                        threshold,
                        metrics,
                    )
                )
    if not candidates:
        raise ValueError("No complete validation evidence is available for calibration")
    chosen = max(candidates, key=lambda row: row[:3])
    _, _, _, weights, threshold, metrics = chosen
    return {
        "weights": weights,
        "suspicious_threshold": threshold,
        "selected_using": "validation split only",
        "validation_metrics": metrics,
        "held_out_test_metrics": classification_metrics(
            [row["label"] for row in test],
            [predict_report(row["report"], weights, threshold) for row in test],
        ),
        "applied_to_application": False,
        "note": "Candidate for review. Synthetic tuning does not justify replacing the application's default weights.",
    }
