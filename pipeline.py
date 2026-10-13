"""Input-to-evidence orchestration for all four analysis layers."""

from __future__ import annotations

import importlib
import math
from collections.abc import Callable
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

from qr_input import QRInputError, decode_qr
from qr_structure import analyze_structure
from redirect_analysis import TracePolicy, trace_redirects
from shared.contracts import (
    LAYER_WEIGHTS,
    SCHEMA_VERSION,
    error_record,
    layer_result,
    validate_json_value,
    validate_layer_result,
)
from url_analysis import URLValidationError, analyze_url, normalize_url, registered_domain

DEFAULT_APPROVED_HOSTS = ("example.com", "www.example.com", "httpbin.org")


def _base_report(kind: str, mode: str) -> dict[str, Any]:
    source = "synthetic" if mode == "synthetic" else "live"
    return {
        "schema_version": SCHEMA_VERSION,
        "created_at": datetime.now(UTC).isoformat(),
        "input": {"kind": kind, "url": None},
        "mode": mode,
        "qr": None,
        "layers": {
            "lexical": layer_result(status="unavailable", score=None, evidence_source=source),
            "redirect": layer_result(status="unavailable", score=None, evidence_source=source),
            "network": layer_result(
                status="unavailable",
                score=None,
                evidence_source=source,
                observations={"hops": [], "note": "Live network checks were not requested."},
            ),
            "qr_structure": layer_result(
                status="unavailable",
                score=None,
                evidence_source=source,
                observations={"note": "No QR image was supplied."},
            ),
        },
        "risk": {},
        "errors": [],
    }


def _pending_risk(layers: dict[str, dict], note: str) -> dict[str, Any]:
    """Fail closed if the scoring component cannot produce a valid report."""
    return {
        "score": None,
        "verdict": "insufficient_evidence",
        "assessment_status": "incomplete",
        "completed_weight": round(
            sum(
                LAYER_WEIGHTS[name] for name, item in layers.items() if item["status"] == "complete"
            ),
            2,
        ),
        "excluded_layers": [name for name, item in layers.items() if item["score"] is None],
        "layer_contributions": {},
        "explanations": [],
        "limitations": [
            note,
            "Layer sub-scores are heuristic signals, not probabilities or a safety guarantee.",
        ],
    }


def _load_provider(module_name: str, function_name: str) -> Callable | None:
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name in {module_name, module_name.split(".")[0]}:
            return None
        raise
    function = getattr(module, function_name, None)
    if not callable(function):
        raise ValueError(f"{module_name} must export {function_name}().")
    return function


def _validate_risk(result: Any, layers: dict[str, dict]) -> None:
    if not isinstance(result, dict):
        raise ValueError("Scoring provider must return a dictionary.")
    validate_json_value(result)
    required = {
        "score",
        "verdict",
        "assessment_status",
        "completed_weight",
        "excluded_layers",
        "layer_contributions",
        "explanations",
        "limitations",
    }
    if not required <= result.keys():
        raise ValueError("Scoring provider omitted required result fields.")
    score = result["score"]
    if score is not None and (
        type(score) not in (int, float) or not math.isfinite(score) or not 0 <= score <= 100
    ):
        raise ValueError("Composite score must be null or between zero and 100.")
    core_complete = all(
        layers[name]["status"] == "complete" for name in ("lexical", "redirect", "network")
    )
    if not core_complete and (
        result["verdict"] != "insufficient_evidence" or result["assessment_status"] != "incomplete"
    ):
        raise ValueError("Incomplete core analysis must remain insufficient_evidence.")
    if result["verdict"] not in {
        "insufficient_evidence",
        "low_observed_risk",
        "suspicious",
        "high_risk",
    }:
        raise ValueError("Unsupported verdict from scoring provider.")
    if result["assessment_status"] not in {
        "complete",
        "complete_for_url",
        "complete_for_r2",
        "incomplete",
    }:
        raise ValueError("Unsupported assessment status.")
    if result["assessment_status"] == "complete" and layers["qr_structure"]["status"] != "complete":
        raise ValueError("A full assessment requires complete QR structural evidence.")
    if not isinstance(result["layer_contributions"], dict) or any(
        not isinstance(result[field], list)
        for field in ("excluded_layers", "explanations", "limitations")
    ):
        raise ValueError("Malformed scoring explanation fields.")
    coverage = result["completed_weight"]
    expected_coverage = sum(
        LAYER_WEIGHTS[name] for name, layer in layers.items() if layer["status"] == "complete"
    )
    if (
        type(coverage) not in (int, float)
        or not math.isfinite(coverage)
        or not math.isclose(coverage, expected_coverage, abs_tol=1e-8)
    ):
        raise ValueError("completed_weight must match the fully completed layers.")
    excluded = result["excluded_layers"]
    expected_excluded = {name for name, layer in layers.items() if layer["score"] is None}
    if (
        any(not isinstance(name, str) for name in excluded)
        or len(excluded) != len(set(excluded))
        or set(excluded) != expected_excluded
    ):
        raise ValueError("excluded_layers must identify every absent score exactly once.")
    if any(
        not isinstance(item, str)
        for field in ("explanations", "limitations")
        for item in result[field]
    ):
        raise ValueError("Explanations and limitations must be strings.")
    if result["assessment_status"] != "incomplete":
        if score is None:
            raise ValueError("Complete assessments require a score.")
        expected_verdict = (
            "high_risk" if score >= 70 else "suspicious" if score >= 35 else "low_observed_risk"
        )
        if result["verdict"] != expected_verdict:
            raise ValueError("Verdict does not match the agreed score bands.")
    elif result["verdict"] != "insufficient_evidence":
        raise ValueError("Incomplete assessments must not offer a risk verdict.")


def _finish(report: dict, *, use_network: bool, network_options: dict | None = None) -> dict:
    layers = report["layers"]
    hops = [
        hop
        for hop in layers["redirect"]["observations"].get("hops", [])
        if hop.get("network_eligible") is True
    ]
    if use_network:
        try:
            provider = _load_provider("network_analysis.analyzer", "analyze_network")
            if provider is not None and hops:
                value = provider(deepcopy(hops), **(network_options or {}))
                validate_layer_result(value)
                if value["evidence_source"] != "live":
                    raise ValueError("Live network provider must identify its evidence as live.")
                layers["network"] = value
            elif provider is not None:
                layers["network"] = layer_result(
                    status="unavailable",
                    score=None,
                    observations={
                        "hops": [],
                        "note": "No destination passed the live trace policy; network inspection was skipped.",
                    },
                )
        except Exception as exc:
            layers["network"] = layer_result(
                status="unavailable",
                score=None,
                errors=[
                    error_record(
                        "NETWORK_PROVIDER_ERROR",
                        f"Network module could not complete: {type(exc).__name__}: {exc}",
                    )
                ],
            )
    note = "The scoring component is unavailable."
    report["risk"] = _pending_risk(layers, note)
    try:
        scorer = _load_provider("scoring.engine", "calculate_risk")
        if scorer is not None:
            result = scorer(deepcopy(layers))
            _validate_risk(result, layers)
            report["risk"] = result
    except Exception as exc:
        report["errors"].append(
            error_record(
                "SCORING_PROVIDER_ERROR",
                f"Scoring module could not complete: {type(exc).__name__}: {exc}",
            )
        )
        report["risk"] = _pending_risk(
            layers, "Scoring provider failed validation; no final verdict is available."
        )
    return report


def _analyze_chain_urls(report: dict) -> None:
    """Score the most concerning observed URL, including a concealed landing URL."""
    chain = report["layers"]["redirect"]["observations"].get("hops", [])
    if not chain or report["layers"]["lexical"]["status"] != "complete":
        return
    observations, findings, scores = [], [], []
    for hop in chain:
        if not hop.get("url"):
            continue
        result = analyze_url(hop["url"])
        observations.append({"hop_index": hop["index"], **result["observations"]})
        findings.extend({**item, "hop_index": hop["index"]} for item in result["findings"])
        if result["score"] is not None:
            scores.append(result["score"])
    if scores:
        layer = report["layers"]["lexical"]
        layer["score"] = max(scores)
        layer["findings"] = findings
        layer["observations"]["hops"] = observations
        layer["observations"]["aggregation"] = "maximum observed URL score"


def analyze_url_input(
    value: str,
    *,
    live: bool = False,
    approved_hosts: tuple[str, ...] = DEFAULT_APPROVED_HOSTS,
    expected_domain: str | None = None,
    include_geolocation: bool = False,
    expected_asns: tuple[int, ...] = (),
    expected_countries: tuple[str, ...] = (),
    lexical_model: dict | None = None,
) -> dict:
    """Inspect a pasted URL. Offline is the default and makes no network calls."""
    report = _base_report("url", "live" if live else "offline")
    try:
        url = normalize_url(value)
    except URLValidationError as exc:
        report["errors"].append(error_record(exc.code, str(exc)))
        return _finish(report, use_network=False)
    report["input"]["url"] = url
    report["layers"]["lexical"] = analyze_url(url)
    if live:
        try:
            policy = TracePolicy(approved_hosts=tuple(approved_hosts))
        except ValueError as exc:
            report["layers"]["redirect"] = layer_result(
                status="unavailable",
                score=None,
                observations={"hops": []},
                errors=[error_record("INVALID_TRACE_POLICY", str(exc))],
            )
        else:
            report["layers"]["redirect"] = trace_redirects(url, policy=policy)
    else:
        report["layers"]["redirect"] = layer_result(
            status="unavailable",
            score=None,
            observations={
                "hops": [],
                "note": "Offline inspection selected. No HTTP or DNS requests were made.",
            },
        )
    _analyze_chain_urls(report)
    if expected_domain:
        _compare_destination(report, expected_domain)
    options = {}
    if include_geolocation or expected_asns or expected_countries:
        options = {
            "include_geolocation": include_geolocation,
            "expected_asns": expected_asns,
            "expected_countries": expected_countries,
        }
    report = _finish(report, use_network=live, network_options=options)
    if lexical_model is not None:
        from evaluation.lexical_model import predict

        try:
            report["experimental_ml"] = predict(lexical_model, url)
        except (ValueError, KeyError, TypeError) as exc:
            report["errors"].append(error_record("LEXICAL_MODEL_INVALID", str(exc)))
    return report


def _compare_destination(report: dict, expected: str) -> None:
    from urllib.parse import urlsplit

    try:
        policy = TracePolicy(approved_hosts=(expected,))
        domain = registered_domain(policy.approved_hosts[0])
    except ValueError:
        report["errors"].append(
            error_record(
                "INVALID_EXPECTED_DOMAIN",
                "Expected domain must be an exact hostname, such as paypal.com.",
            )
        )
        return
    report["input"]["expected_domain"] = domain
    redirect = report["layers"]["redirect"]
    hops = redirect["observations"].get("hops", [])
    if redirect["status"] != "complete" or not hops:
        redirect["observations"]["brand_comparison"] = (
            "Final destination unknown; comparison deferred."
        )
        return
    final_domain = registered_domain(urlsplit(hops[-1]["url"]).hostname)
    redirect["observations"]["brand_comparison"] = {
        "expected": domain,
        "observed": final_domain,
        "matches": domain == final_domain,
    }
    if domain != final_domain:
        redirect["findings"].append(
            {
                "code": "EXPECTED_DOMAIN_MISMATCH",
                "severity": "warning",
                "message": "The final registered domain differs from the expected domain supplied for this scan. Third-party payment and login services can also cause this.",
                "hop_index": hops[-1]["index"],
                "details": {
                    "expected": domain,
                    "observed": final_domain,
                    "score_contribution": 0.35,
                },
            }
        )
        redirect["score"] = min(1.0, redirect["score"] + 0.35)


def analyze_image(
    image_bytes: bytes,
    *,
    live: bool = False,
    approved_hosts: tuple[str, ...] = DEFAULT_APPROVED_HOSTS,
    **options,
) -> dict:
    """Decode a single QR image, then apply the same URL pipeline."""
    try:
        decoded = decode_qr(image_bytes)
    except QRInputError as exc:
        report = _base_report("image", "live" if live else "offline")
        report["errors"].append(error_record(exc.code, str(exc)))
        return _finish(report, use_network=False)
    report = analyze_url_input(
        decoded["payload"], live=live, approved_hosts=approved_hosts, **options
    )
    report["input"]["kind"] = "image"
    report["qr"] = decoded
    report["layers"]["qr_structure"] = analyze_structure(decoded.get("structure"))
    return _finish(report, use_network=False)


def list_demo_cases() -> list[dict]:
    from demo_cases import DEMO_CASES

    return [
        {"id": key, "title": case["title"], "description": case["description"]}
        for key, case in DEMO_CASES.items()
    ]


def run_demo(case_id: str) -> dict:
    """Decode a real generated QR and replay synthetic HTTP headers, fully offline."""
    from urllib.parse import urlsplit

    from demo_cases import DEMO_CASES, qr_bytes
    from redirect_analysis import HTTPResponse

    case = DEMO_CASES[case_id]
    report = analyze_image(qr_bytes(case["url"]))
    report["mode"] = "synthetic"
    report["input"]["kind"] = "demo"
    report["demo"] = {"id": case_id, "title": case["title"], "description": case["description"]}

    def replay(url: str, address: str, timeout: float) -> HTTPResponse:
        if case.get("invalid_tls"):
            raise OSError("Synthetic TLS certificate validation failure")
        status, location = case["responses"][url]
        return HTTPResponse(status=status, location=location)

    hosts = tuple(sorted({urlsplit(url).hostname for url in case["responses"]}))
    report["layers"]["redirect"] = trace_redirects(
        case["url"],
        policy=TracePolicy(approved_hosts=hosts),
        resolver=lambda host, timeout: ["93.184.216.34"],
        transport=replay,
    )
    from demo_cases import synthetic_network

    report["layers"]["network"] = synthetic_network(
        case, report["layers"]["redirect"]["observations"]["hops"]
    )
    _analyze_chain_urls(report)
    if case.get("expected_domain"):
        _compare_destination(report, case["expected_domain"])
    for layer in report["layers"].values():
        layer["evidence_source"] = "synthetic"
    report = _finish(report, use_network=False)
    report["risk"]["limitations"].append(
        "Demo HTTP, DNS, TLS, ASN and location observations are explicitly synthetic; no external connections occur."
    )
    return report
