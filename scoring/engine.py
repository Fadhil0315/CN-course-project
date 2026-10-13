"""Preserve missing evidence, normalize available weights, explain contributions."""

from __future__ import annotations

from shared.contracts import validate_layer_result

from .config import HIGH_RISK_THRESHOLD, SUSPICIOUS_THRESHOLD, WEIGHTS


def calculate_risk(layers: dict[str, dict]) -> dict:
    for name in WEIGHTS:
        validate_layer_result(layers[name])
    available = {
        name: value
        for name, value in layers.items()
        if name in WEIGHTS and value["score"] is not None
    }
    denominator = sum(WEIGHTS[name] for name in available)
    contributions = {
        name: {
            "weight": WEIGHTS[name],
            "sub_score": value["score"],
            "normalized_weight": WEIGHTS[name] / denominator,
            "points": round(100 * WEIGHTS[name] * value["score"] / denominator, 6),
            "status": value["status"],
        }
        for name, value in available.items()
    }
    score = (
        round(sum(item["points"] for item in contributions.values()), 4) if denominator else None
    )
    # A malformed/non-URL input cannot acquire a risk score from image quality.
    if layers["lexical"]["score"] is None:
        score = None
    core_complete = all(
        layers[name]["status"] == "complete" for name in ("lexical", "redirect", "network")
    )
    complete = core_complete and layers["qr_structure"]["status"] == "complete"
    status = "complete" if complete else "complete_for_url" if core_complete else "incomplete"
    verdict = "insufficient_evidence"
    if core_complete and score is not None:
        verdict = (
            "high_risk"
            if score >= HIGH_RISK_THRESHOLD
            else "suspicious"
            if score >= SUSPICIOUS_THRESHOLD
            else "low_observed_risk"
        )
    excluded = [name for name in WEIGHTS if name not in available]
    limitations = ["Heuristic score, not a phishing probability or a guarantee of safety."]
    limitations.extend(
        f"{name}: {layers[name]['status']}; excluded from scoring." for name in excluded
    )
    limitations.extend(
        f"{name}: partial observations contribute to a provisional score."
        for name in available
        if layers[name]["status"] == "partial"
    )
    if not core_complete:
        limitations.append(
            "One or more core checks are incomplete; no final risk verdict is available."
        )
    if any(value["evidence_source"] == "synthetic" for value in layers.values()):
        limitations.append(
            "Synthetic scenario: this score demonstrates rules, not a real website assessment."
        )
    return {
        "score": score,
        "verdict": verdict,
        "assessment_status": status,
        "completed_weight": round(
            sum(WEIGHTS[name] for name in WEIGHTS if layers[name]["status"] == "complete"), 8
        ),
        "excluded_layers": excluded,
        "layer_contributions": contributions,
        "explanations": [
            f"{name}: {item['sub_score']:.2f} sub-score × {item['normalized_weight']:.3f} normalized weight = {item['points']:.2f} points."
            for name, item in contributions.items()
        ],
        "limitations": limitations,
        "thresholds": {"suspicious": SUSPICIOUS_THRESHOLD, "high_risk": HIGH_RISK_THRESHOLD},
        "weights": dict(WEIGHTS),
    }
