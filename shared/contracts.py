"""JSON-compatible boundary types and validation, independent of the UI."""

from __future__ import annotations

import math
from typing import Any, Literal, TypedDict

SCHEMA_VERSION = 1
LAYER_WEIGHTS = {"lexical": 0.20, "redirect": 0.25, "network": 0.50, "qr_structure": 0.05}
LayerStatus = Literal["complete", "partial", "unavailable", "not_implemented"]
EvidenceSource = Literal["live", "recorded", "synthetic"]


class ErrorRecord(TypedDict):
    code: str
    message: str
    hop_index: int | None


class Finding(TypedDict):
    code: str
    severity: Literal["info", "warning", "high"]
    message: str
    hop_index: int | None
    details: dict[str, Any]


class LayerResult(TypedDict):
    status: LayerStatus
    score: float | None
    evidence_source: EvidenceSource
    findings: list[Finding]
    observations: dict[str, Any]
    errors: list[ErrorRecord]


def error_record(code: str, message: str, hop_index: int | None = None) -> ErrorRecord:
    return {"code": code, "message": message, "hop_index": hop_index}


def layer_result(
    *,
    status: LayerStatus,
    score: float | None,
    evidence_source: EvidenceSource = "live",
    findings: list[Finding] | None = None,
    observations: dict[str, Any] | None = None,
    errors: list[ErrorRecord] | None = None,
) -> LayerResult:
    result: LayerResult = {
        "status": status,
        "score": score,
        "evidence_source": evidence_source,
        "findings": findings or [],
        "observations": observations or {},
        "errors": errors or [],
    }
    validate_layer_result(result)
    return result


def validate_layer_result(value: Any) -> None:
    """Reject malformed plugin results at the integration boundary."""
    if not isinstance(value, dict):
        raise ValueError("Layer result must be a dictionary.")
    validate_json_value(value)
    if (
        not {"status", "score", "evidence_source", "findings", "observations", "errors"}
        <= value.keys()
    ):
        raise ValueError("Layer result omitted required fields.")
    if value.get("status") not in {"complete", "partial", "unavailable", "not_implemented"}:
        raise ValueError("Invalid layer status.")
    score = value.get("score")
    if score is not None and (
        isinstance(score, bool)
        or not isinstance(score, (float, int))
        or not math.isfinite(score)
        or not 0 <= score <= 1
    ):
        raise ValueError("Layer score must be null or a finite number between zero and one.")
    if value["status"] == "complete" and score is None:
        raise ValueError("Complete layers must include an assessment score.")
    if value["status"] in {"unavailable", "not_implemented"} and score is not None:
        raise ValueError("Unavailable layers must not include a score.")
    if value.get("evidence_source") not in {"live", "recorded", "synthetic"}:
        raise ValueError("Invalid evidence source.")
    if not isinstance(value.get("observations"), dict):
        raise ValueError("Layer observations must be a dictionary.")
    for field in ("findings", "errors"):
        if not isinstance(value.get(field), list):
            raise ValueError(f"Layer {field} must be a list.")
        for item in value[field]:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("code"), str)
                or not isinstance(item.get("message"), str)
            ):
                raise ValueError(f"Each {field} entry needs a code and message.")
            if "hop_index" not in item or (
                item["hop_index"] is not None
                and (type(item["hop_index"]) is not int or item["hop_index"] < 0)
            ):
                raise ValueError("hop_index must be null or a nonnegative integer.")
            if field == "findings" and (
                item.get("severity") not in {"info", "warning", "high"}
                or not isinstance(item.get("details"), dict)
            ):
                raise ValueError("Findings require a severity and details dictionary.")


def validate_json_value(value: Any) -> None:
    """Reject plugin values that could crash export or serialize non-finite data."""
    if value is None or type(value) in (str, bool, int):
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("JSON numbers must be finite.")
        return
    if type(value) is list:
        for item in value:
            validate_json_value(item)
        return
    if type(value) is dict:
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON object keys must be strings.")
            validate_json_value(item)
        return
    raise ValueError(
        f"Unsupported JSON value: {type(value).__name__}; serialize dates as ISO strings."
    )


def pending_layer(message: str, *, evidence_source: EvidenceSource = "live") -> LayerResult:
    return layer_result(
        status="not_implemented",
        score=None,
        evidence_source=evidence_source,
        observations={"note": message},
    )
