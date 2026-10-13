"""Measure actual QR decoding on deterministic transformations, fully offline."""

import time
from io import BytesIO

import cv2
import numpy as np
from PIL import Image, ImageEnhance, ImageFilter

from demo_cases import qr_bytes
from qr_input import QRInputError, decode_qr


def transformed_images(payload: str) -> list[tuple[str, bytes]]:
    original = Image.open(BytesIO(qr_bytes(payload))).convert("RGB")
    w, h = original.size
    source = np.float32([[0, 0], [w - 1, 0], [w - 1, h - 1], [0, h - 1]])
    destination = np.float32([[20, 0], [w - 25, 15], [w - 1, h - 10], [0, h - 25]])
    perspective = Image.fromarray(
        cv2.warpPerspective(
            np.asarray(original),
            cv2.getPerspectiveTransform(source, destination),
            (w, h),
            borderValue=(255, 255, 255),
        )
    )
    variants = [
        ("clean", original),
        ("rotation_90", original.rotate(90, expand=True)),
        ("rotation_15", original.rotate(15, expand=True, fillcolor="white")),
        ("low_resolution", original.resize((100, 100))),
        ("blur", original.filter(ImageFilter.GaussianBlur(0.8))),
        ("low_contrast", ImageEnhance.Contrast(original).enhance(0.35)),
        ("perspective", perspective),
    ]
    result = []
    for name, image in variants:
        buffer = BytesIO()
        image.save(buffer, format="PNG")
        result.append((name, buffer.getvalue()))
    jpeg = BytesIO()
    original.save(jpeg, format="JPEG", quality=25)
    result.append(("jpeg_quality_25", jpeg.getvalue()))
    return result


def run_robustness() -> dict:
    rows = []
    for payload in ("https://example.com/", "https://paypal.com.account-check.test/start"):
        for transformation, image in transformed_images(payload):
            started = time.monotonic()
            try:
                result = decode_qr(image)
                matched, error = result["payload"] == payload, None
            except QRInputError as exc:
                matched, error = False, exc.code
            rows.append(
                {
                    "url": payload,
                    "transformation": transformation,
                    "decoded_correctly": matched,
                    "error": error,
                    "seconds": round(time.monotonic() - started, 4),
                }
            )
    return {
        "cases": rows,
        "correct": sum(row["decoded_correctly"] for row in rows),
        "total": len(rows),
        "note": "Synthetic transformations of two images, not a camera field-study or guarantee for arbitrary damage.",
    }
