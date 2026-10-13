import pytest

from scoring.engine import calculate_risk
from shared.contracts import LAYER_WEIGHTS, layer_result


def layers(score=0):
    return {name: layer_result(status="complete", score=score) for name in LAYER_WEIGHTS}


@pytest.mark.parametrize(
    ("score", "verdict"),
    [
        (0, "low_observed_risk"),
        (0.349, "low_observed_risk"),
        (0.35, "suspicious"),
        (0.699, "suspicious"),
        (0.7, "high_risk"),
        (1, "high_risk"),
    ],
)
def test_exact_score_bands(score, verdict):
    result = calculate_risk(layers(score))
    assert result["score"] == pytest.approx(score * 100)
    assert result["verdict"] == verdict
    assert result["completed_weight"] == 1


def test_weighting_and_missing_qr_renormalization():
    values = layers(0)
    values["network"]["score"] = 1
    values["qr_structure"] = layer_result(status="unavailable", score=None)
    result = calculate_risk(values)
    assert result["score"] == pytest.approx(50 / 0.95, abs=0.0001)
    assert result["excluded_layers"] == ["qr_structure"]
    assert result["assessment_status"] == "complete_for_url"


@pytest.mark.parametrize("missing", ["lexical", "redirect", "network"])
def test_any_missing_core_layer_forces_abstention(missing):
    values = layers(1)
    values[missing] = layer_result(status="unavailable", score=None)
    result = calculate_risk(values)
    assert result["verdict"] == "insufficient_evidence"
    assert result["assessment_status"] == "incomplete"


def test_partial_layer_has_score_but_no_completed_coverage():
    values = layers()
    values["network"] = layer_result(status="partial", score=1)
    result = calculate_risk(values)
    assert result["score"] == 50 and result["completed_weight"] == 0.5
    assert result["verdict"] == "insufficient_evidence"


def test_all_absent_returns_null_not_zero():
    result = calculate_risk(
        {name: layer_result(status="unavailable", score=None) for name in LAYER_WEIGHTS}
    )
    assert result["score"] is None and result["completed_weight"] == 0
