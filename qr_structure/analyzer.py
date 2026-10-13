"""Measure decoded Model 2 symbols; do not mistake legal QR choices for phishing."""

from __future__ import annotations

import math

import cv2
import numpy as np
import qrcode
from qrcode.util import BCH_type_info, pattern_position

from shared.contracts import layer_result

ECC_NAMES = {0: "M", 1: "L", 2: "H", 3: "Q"}


def _format(matrix: np.ndarray) -> dict:
    n = len(matrix)
    copies = [0, 0]
    for bit in range(15):
        row = bit if bit < 6 else bit + 1 if bit < 8 else n - 15 + bit
        col = n - bit - 1 if bit < 8 else 15 - bit if bit == 8 else 14 - bit
        copies[0] |= int(matrix[row, 8]) << bit
        copies[1] |= int(matrix[8, col]) << bit
    decoded = []
    for value in copies:
        distance, data = min(
            ((value ^ BCH_type_info(data)).bit_count(), data) for data in range(32)
        )
        decoded.append({"distance": distance, "data": data if distance <= 3 else None})
    usable = [copy for copy in decoded if copy["data"] is not None]
    data = min(usable, key=lambda copy: copy["distance"])["data"] if usable else None
    return {
        "copies": decoded,
        "consistent": len(usable) == 2 and usable[0]["data"] == usable[1]["data"],
        "ecc": ECC_NAMES[data >> 3] if data is not None else None,
        "mask_pattern": data & 7 if data is not None else None,
        "ecc_value": data >> 3 if data is not None else None,
    }


def inspect_symbol(straight, points, gray: np.ndarray, payload: str) -> dict:
    if straight is None or straight.ndim != 2 or straight.shape[0] != straight.shape[1]:
        return {"available": False, "note": "Decoder did not expose a rectified symbol"}
    n = len(straight)
    if n < 21 or n > 177 or (n - 17) % 4:
        return {"available": False, "note": "Unrecognized Model 2 module dimensions"}
    version = (n - 17) // 4
    matrix = straight < 128
    fmt = _format(matrix)
    finder = np.array(
        [
            [r in {0, 6} or c in {0, 6} or (2 <= r <= 4 and 2 <= c <= 4) for c in range(7)]
            for r in range(7)
        ]
    )
    finder_mismatch = sum(
        int(np.count_nonzero(matrix[r : r + 7, c : c + 7] != finder))
        for r, c in ((0, 0), (n - 7, 0), (0, n - 7))
    )
    timing = sum(int(matrix[6, i]) != int(i % 2 == 0) for i in range(8, n - 8))
    timing += sum(int(matrix[i, 6]) != int(i % 2 == 0) for i in range(8, n - 8))
    alignment_mismatch, alignment_count = 0, 0
    align = np.array(
        [[abs(r) == 2 or abs(c) == 2 or r == c == 0 for c in range(-2, 3)] for r in range(-2, 3)]
    )
    for r in pattern_position(version):
        for c in pattern_position(version):
            if (r <= 8 and c <= 8) or (r <= 8 and c >= n - 9) or (r >= n - 9 and c <= 8):
                continue
            alignment_count += 1
            alignment_mismatch += int(
                np.count_nonzero(matrix[r - 2 : r + 3, c - 2 : c + 3] != align)
            )
    minimum_version = None
    if fmt["ecc_value"] is not None:
        reference = qrcode.QRCode(error_correction=fmt["ecc_value"], border=0)
        reference.add_data(payload)
        reference.make(fit=True)
        minimum_version = reference.version
    result = {
        "available": True,
        "version": version,
        "module_count": n,
        "format": fmt,
        "dark_module_fraction": round(float(matrix.mean()), 4),
        "payload_utf8_bytes": len(payload.encode()),
        "reference_minimum_version": minimum_version,
        "finder_mismatched_modules": finder_mismatch,
        "timing_mismatched_modules": timing,
        "alignment_patterns": alignment_count,
        "alignment_mismatched_modules": alignment_mismatch,
        "grayscale_contrast": round(float(np.percentile(gray, 95) - np.percentile(gray, 5)), 2),
        "sharpness_laplacian_variance": round(float(cv2.Laplacian(gray, cv2.CV_64F).var()), 2),
    }
    if points is not None:
        corners = np.asarray(points, dtype=np.float32).reshape(4, 2)
        sides = np.linalg.norm(corners - np.roll(corners, -1, axis=0), axis=1)
        result.update(
            corners=corners.astype(float).tolist(),
            rotation_degrees=round(math.degrees(math.atan2(*(corners[1] - corners[0])[::-1])), 2),
            perspective_side_ratio=round(float(sides.max() / max(sides.min(), 1)), 3),
            estimated_pixels_per_module=round(float(sides.mean() / n), 2),
        )
        # Project a four-module quiet zone. Mask out coordinates outside the
        # supplied image: a clipped border is unknown, not automatically black.
        target = np.array([[4, 4], [n + 4, 4], [n + 4, n + 4], [4, n + 4]], np.float32)
        transform = cv2.getPerspectiveTransform(corners, target)
        patch = cv2.warpPerspective(
            gray, transform, (n + 8, n + 8), flags=cv2.INTER_NEAREST, borderValue=0
        )
        valid = cv2.warpPerspective(
            np.ones_like(gray, dtype=np.uint8), transform, (n + 8, n + 8), flags=cv2.INTER_NEAREST
        )
        border = np.ones((n + 8, n + 8), dtype=bool)
        border[4 : n + 4, 4 : n + 4] = False
        covered = border & (valid != 0)
        result["quiet_zone_coverage"] = round(float(covered.sum() / border.sum()), 4)
        result["quiet_zone_white_fraction"] = (
            round(float((patch[covered] > 200).mean()), 4) if covered.any() else None
        )
    return result


def analyze_structure(metadata: dict | None) -> dict:
    if not metadata or not metadata.get("available"):
        return layer_result(
            status="unavailable",
            score=None,
            observations={"note": (metadata or {}).get("note", "No QR image was supplied")},
        )
    findings, score = [], 0.0

    def add(code, message, weight=0.0):
        nonlocal score
        score += weight
        findings.append(
            {
                "code": code,
                "severity": "warning" if weight else "info",
                "message": message,
                "hop_index": None,
                "details": {"score_contribution": weight},
            }
        )

    if not metadata["format"]["consistent"]:
        add(
            "QR_FORMAT_INCONSISTENCY",
            "The two format-information copies were not consistently readable; damage or preprocessing can cause this.",
            0.5,
        )
    if (
        metadata["finder_mismatched_modules"]
        or metadata["timing_mismatched_modules"]
        or metadata["alignment_mismatched_modules"]
    ):
        add(
            "QR_PATTERN_INCONSISTENCY",
            "Rectified structural patterns contain mismatched modules. This is an experimental integrity signal, not phishing proof.",
            0.5,
        )
    if (
        metadata.get("quiet_zone_coverage", 1) < 0.95
        or (metadata.get("quiet_zone_white_fraction") or 0) < 0.9
    ):
        add(
            "QR_QUIET_ZONE",
            "The surrounding quiet zone is clipped or contains dark pixels; this may reduce scan reliability.",
        )
    if metadata["grayscale_contrast"] < 80:
        add(
            "QR_LOW_CONTRAST",
            "The image has limited contrast; use a clearer capture if decoding becomes unreliable.",
        )
    if (
        metadata.get("reference_minimum_version")
        and metadata["version"] > metadata["reference_minimum_version"]
    ):
        add(
            "QR_EXTRA_CAPACITY",
            "The symbol uses a larger version than a reference encoding needs. This is permitted and receives no risk penalty.",
        )
    return layer_result(
        status="complete",
        score=min(score, 1.0),
        findings=findings,
        observations={
            **metadata,
            "limitations": [
                "Measurements use the decoder's rectified symbol and may not preserve every original defect.",
                "Any standard ECC level or larger valid version is allowed; neither is phishing evidence.",
                "Image quality and generation choices do not identify a phishing kit.",
            ],
        },
    )
