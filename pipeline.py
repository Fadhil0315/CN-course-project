"""Fadhil's orchestration: input, analysis, and explicit teammate boundaries."""

from __future__ import annotations

import importlib
import math
from collections.abc import Callable
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

from qr_input import QRInputError, decode_qr
from redirect_analysis import TracePolicy, trace_redirects
from shared.contracts import (
    LAYER_WEIGHTS,
    SCHEMA_VERSION,
    error_record,
    layer_result,
    pending_layer,
    validate_json_value,
    validate_layer_result,
)
from url_analysis import URLValidationError, analyze_url, normalize_url

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
            "network": pending_layer(
                "Awaiting Charan's network_analysis.analyzer module.", evidence_source=source
            ),
            "qr_structure": pending_layer(
                "Review 3 experimental layer; planned weight 5%.", evidence_source=source
            ),
        },
        "risk": {},
        "errors": [],
    }


def _pending_risk(layers: dict[str, dict], note: str) -> dict[str, Any]:
    """UI state only: no composite score is implemented on Charan's behalf."""
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
    if result["assessment_status"] not in {"complete_for_r2", "incomplete"}:
        raise ValueError("Unsupported assessment status.")
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
    if result["assessment_status"] == "complete_for_r2":
        if score is None:
            raise ValueError("Complete assessments require a score.")
        expected_verdict = (
            "high_risk" if score >= 70 else "suspicious" if score >= 35 else "low_observed_risk"
        )
        if result["verdict"] != expected_verdict:
            raise ValueError("Verdict does not match the agreed score bands.")
    elif result["verdict"] != "insufficient_evidence":
        raise ValueError("Incomplete assessments must not offer a risk verdict.")


def _finish(report: dict, *, use_network: bool) -> dict:
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
                value = provider(deepcopy(hops))
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
    note = "Final score pending Charan's scoring.engine.calculate_risk implementation."
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


def analyze_url_input(
    value: str,
    *,
    live: bool = False,
    approved_hosts: tuple[str, ...] = DEFAULT_APPROVED_HOSTS,
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
    return _finish(report, use_network=live)


def analyze_image(
    image_bytes: bytes,
    *,
    live: bool = False,
    approved_hosts: tuple[str, ...] = DEFAULT_APPROVED_HOSTS,
) -> dict:
    """Decode a single QR image, then apply the same URL pipeline."""
    try:
        decoded = decode_qr(image_bytes)
    except QRInputError as exc:
        report = _base_report("image", "live" if live else "offline")
        report["errors"].append(error_record(exc.code, str(exc)))
        return _finish(report, use_network=False)
    report = analyze_url_input(decoded["payload"], live=live, approved_hosts=approved_hosts)
    report["input"]["kind"] = "image"
    report["qr"] = decoded
    return report


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
        status, location = case["responses"][url]
        return HTTPResponse(status=status, location=location)

    hosts = tuple(sorted({urlsplit(url).hostname for url in case["responses"]}))
    report["layers"]["redirect"] = trace_redirects(
        case["url"],
        policy=TracePolicy(approved_hosts=hosts),
        resolver=lambda host, timeout: ["93.184.216.34"],
        transport=replay,
    )
    for layer in report["layers"].values():
        layer["evidence_source"] = "synthetic"
    report = _finish(report, use_network=False)
    report["risk"]["limitations"].append(
        "Demo HTTP responses and resolver addresses are synthetic; no external connections occur. Network/scoring ownership remains with Charan."
    )
    return report
