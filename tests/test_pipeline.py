"""Integration tests verify actual input flow and teammate failure boundaries."""

import json
import socket

import pytest

import pipeline
from demo_cases import qr_bytes
from shared.contracts import layer_result, validate_layer_result


@pytest.fixture(autouse=True)
def deny_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("Offline integration tests must not make network requests")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)


def test_uploaded_qr_flows_to_lexical_without_live_requests():
    report = pipeline.analyze_image(qr_bytes("https://example.com/"))
    assert report["input"]["url"] == "https://example.com/"
    assert report["input"]["kind"] == "image"
    assert report["qr"]["payload"] == "https://example.com/"
    assert report["layers"]["lexical"]["status"] == "complete"
    assert report["layers"]["redirect"]["status"] == "unavailable"
    assert report["layers"]["network"]["status"] == "unavailable"
    assert report["risk"]["score"] == 0
    assert report["risk"]["verdict"] == "insufficient_evidence"
    assert report["risk"]["completed_weight"] == 0.25
    json.dumps(report, allow_nan=False)


@pytest.mark.parametrize("case_id", ["ordinary", "suspicious", "loop"])
def test_demos_decode_real_qr_and_explicitly_label_network_fixtures(case_id):
    report = pipeline.run_demo(case_id)
    assert report["qr"]["payload"] == report["input"]["url"]
    assert report["mode"] == "synthetic"
    for result in report["layers"].values():
        validate_layer_result(result)
        assert result["evidence_source"] == "synthetic"
    assert report["layers"]["network"]["status"] == "complete"
    assert report["risk"]["score"] is not None
    assert (report["risk"]["verdict"] == "insufficient_evidence") == (case_id == "loop")
    expected = "partial" if case_id == "loop" else "complete"
    assert report["layers"]["redirect"]["status"] == expected


def test_non_url_qr_and_corrupt_image_have_actionable_errors():
    for payload in [qr_bytes("hello"), b"not an image"]:
        report = pipeline.analyze_image(payload)
        assert report["errors"]
        assert report["risk"]["score"] is None
        assert report["layers"]["lexical"]["status"] == "unavailable"


def test_malformed_allowlist_returns_report_instead_of_crashing():
    report = pipeline.analyze_url_input(
        "https://example.com/", live=True, approved_hosts=("https://example.com",)
    )
    assert report["layers"]["redirect"]["errors"][0]["code"] == "INVALID_TRACE_POLICY"


def test_offline_execution_does_not_invoke_network_provider(monkeypatch):
    calls = []

    def loader(module, function):
        calls.append(module)
        return None

    monkeypatch.setattr(pipeline, "_load_provider", loader)
    pipeline.analyze_url_input("https://example.com/")
    assert "network_analysis.analyzer" not in calls


def test_live_pipeline_passes_eligible_chain_to_network_provider(monkeypatch):
    hop = {
        "index": 0,
        "url": "https://example.com/",
        "hostname": "example.com",
        "scheme": "https",
        "port": 443,
        "status_code": 200,
        "next_url": None,
        "error": None,
        "network_eligible": True,
    }
    monkeypatch.setattr(
        pipeline,
        "trace_redirects",
        lambda *args, **kwargs: layer_result(
            status="complete", score=0, observations={"hops": [hop]}
        ),
    )
    calls = []

    def provider(hops):
        calls.append(hops)
        return layer_result(status="complete", score=0.1, observations={"hops": []})

    monkeypatch.setattr(
        pipeline,
        "_load_provider",
        lambda module, function: provider if module.startswith("network_analysis") else None,
    )
    report = pipeline.analyze_url_input("https://example.com/", live=True)
    assert calls == [[hop]]
    assert report["layers"]["network"]["score"] == 0.1
    assert report["risk"]["score"] is None


def test_bad_network_provider_is_not_accepted(monkeypatch):
    monkeypatch.setattr(
        pipeline,
        "trace_redirects",
        lambda *args, **kwargs: layer_result(
            status="complete",
            score=0,
            observations={"hops": [{"status_code": 200, "network_eligible": True}]},
        ),
    )
    monkeypatch.setattr(
        pipeline,
        "_load_provider",
        lambda module, function: (
            (lambda hops: {"score": 0}) if module.startswith("network_analysis") else None
        ),
    )
    report = pipeline.analyze_url_input("https://example.com/", live=True)
    assert report["layers"]["network"]["status"] == "unavailable"
    assert report["layers"]["network"]["errors"][0]["code"] == "NETWORK_PROVIDER_ERROR"


def test_incomplete_evidence_cannot_get_reassuring_verdict(monkeypatch):
    def bad_scorer(layers):
        result = pipeline._pending_risk(layers, "test")
        result.update(score=0, verdict="low_observed_risk", assessment_status="complete_for_r2")
        return result

    monkeypatch.setattr(pipeline, "_load_provider", lambda *args: bad_scorer)
    report = pipeline.analyze_url_input("https://example.com/")
    assert report["risk"]["score"] is None
    assert report["risk"]["verdict"] == "insufficient_evidence"
    assert report["errors"][0]["code"] == "SCORING_PROVIDER_ERROR"


@pytest.mark.parametrize("score", [float("nan"), float("inf"), -0.1, 1.1, True])
def test_layer_contract_rejects_invalid_scores(score):
    with pytest.raises(ValueError):
        layer_result(status="complete", score=score)


def test_layer_contract_rejects_missing_fields():
    with pytest.raises(ValueError):
        validate_layer_result(
            {
                "status": "unavailable",
                "evidence_source": "live",
                "findings": [],
                "observations": {},
                "errors": [],
            }
        )


def test_blocked_redirect_target_never_reaches_network_provider(monkeypatch):
    allowed = {"index": 0, "hostname": "example.com", "status_code": 302, "network_eligible": True}
    blocked = {
        "index": 1,
        "hostname": "unapproved.test",
        "status_code": None,
        "network_eligible": False,
    }
    monkeypatch.setattr(
        pipeline,
        "trace_redirects",
        lambda *args, **kwargs: layer_result(
            status="partial", score=0.12, observations={"hops": [allowed, blocked]}
        ),
    )
    calls = []

    def network(hops):
        calls.append(hops)
        return layer_result(status="complete", score=0, observations={"hops": []})

    monkeypatch.setattr(
        pipeline,
        "_load_provider",
        lambda module, function: network if module.startswith("network_analysis") else None,
    )
    report = pipeline.analyze_url_input("https://example.com/", live=True)
    assert calls == [[allowed]]
    assert report["layers"]["redirect"]["status"] == "partial"
    assert report["risk"]["verdict"] == "insufficient_evidence"


def test_tls_failure_on_eligible_host_can_reach_network_provider(monkeypatch):
    hop = {"index": 0, "hostname": "example.com", "status_code": None, "network_eligible": True}
    monkeypatch.setattr(
        pipeline,
        "trace_redirects",
        lambda *args, **kwargs: layer_result(
            status="unavailable", score=None, observations={"hops": [hop]}
        ),
    )
    calls = []

    def network(hops):
        calls.append(hops)
        return layer_result(status="partial", score=0.5)

    monkeypatch.setattr(
        pipeline,
        "_load_provider",
        lambda module, function: network if module.startswith("network_analysis") else None,
    )
    pipeline.analyze_url_input("https://example.com/", live=True)
    assert calls == [[hop]]


@pytest.mark.parametrize("value", [float("nan"), {1: "invalid key"}, {"date": object()}])
def test_layer_contract_rejects_non_json_observations(value):
    with pytest.raises(ValueError):
        layer_result(status="complete", score=0, observations={"nested": value})


def test_scoring_contract_rejects_missing_score_and_bad_coverage():
    layers = {name: layer_result(status="complete", score=0) for name in pipeline.LAYER_WEIGHTS}
    result = pipeline._pending_risk(layers, "fixture")
    result.update(
        verdict="low_observed_risk",
        assessment_status="complete_for_r2",
        completed_weight="all done",
    )
    with pytest.raises(ValueError):
        pipeline._validate_risk(result, layers)
    result["completed_weight"] = 1.0
    with pytest.raises(ValueError):
        pipeline._validate_risk(result, layers)
