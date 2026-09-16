"""Decode one unambiguous QR payload without making network requests."""

from __future__ import annotations

import io
import warnings

import cv2
import numpy as np
from PIL import Image, ImageOps, UnidentifiedImageError

MAX_IMAGE_BYTES = 8 * 1024 * 1024
MAX_IMAGE_PIXELS = 16_000_000
SUPPORTED_FORMATS = frozenset({"PNG", "JPEG", "WEBP"})


class QRInputError(ValueError):
    """An actionable input error with a stable machine-readable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _load_image(image_bytes: bytes) -> tuple[np.ndarray, int, int]:
    if not isinstance(image_bytes, bytes) or not image_bytes:
        raise QRInputError("EMPTY_IMAGE", "Choose a non-empty QR image.")
    if len(image_bytes) > MAX_IMAGE_BYTES:
        raise QRInputError("IMAGE_TOO_LARGE", "The image must be 8 MiB or smaller.")

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(image_bytes)) as source:
                if source.format not in SUPPORTED_FORMATS:
                    raise QRInputError("UNSUPPORTED_IMAGE", "Use a PNG, JPEG, or WebP image.")
                if source.width * source.height > MAX_IMAGE_PIXELS:
                    raise QRInputError(
                        "IMAGE_DIMENSIONS_TOO_LARGE", "The image must not exceed 16 megapixels."
                    )
                if getattr(source, "n_frames", 1) > 1:
                    raise QRInputError("ANIMATED_IMAGE", "Use a single, non-animated image.")
                source.load()
                oriented = ImageOps.exif_transpose(source)
                width, height = oriented.size
                # Transparent pixels should appear on a white scan surface.
                rgba = oriented.convert("RGBA")
                white = Image.new("RGBA", rgba.size, "white")
                white.alpha_composite(rgba)
                gray = np.asarray(white.convert("L"))
    except QRInputError:
        raise
    except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
        raise QRInputError(
            "IMAGE_DIMENSIONS_TOO_LARGE", "The image exceeds the supported pixel limit."
        ) from exc
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise QRInputError("INVALID_IMAGE", "The file is not a readable image.") from exc

    if max(gray.shape) > 2400:
        scale = 2400 / max(gray.shape)
        target_size = (max(1, round(gray.shape[1] * scale)), max(1, round(gray.shape[0] * scale)))
        try:
            gray = cv2.resize(gray, target_size, interpolation=cv2.INTER_AREA)
        except cv2.error as exc:
            raise QRInputError(
                "QR_DECODE_FAILED", "The image could not be resized for QR inspection."
            ) from exc
    return gray, width, height


def decode_qr(image_bytes: bytes) -> dict:
    """Return a payload and image metadata, or raise :class:`QRInputError`.

    Only one detected QR is accepted. Multiple detected symbols are ambiguous,
    including when only one can be decoded. Detection cannot guarantee discovery
    of every obscured or badly damaged symbol. Grayscale, thresholding, and
    bounded resizing are attempted; payloads are never stripped or rewritten.
    """
    gray, width, height = _load_image(image_bytes)
    variants = [("grayscale", gray)]
    _, thresholded = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)
    variants.append(("otsu_threshold", thresholded))
    # OpenCV's finder-pattern detection is scale-sensitive even for clean QR
    # images. One bounded reduction recovers some symbols missed at native size.
    if min(gray.shape) >= 100:
        variants.append(
            (
                "grayscale_reduced",
                cv2.resize(gray, None, fx=0.5, fy=0.5, interpolation=cv2.INTER_AREA),
            )
        )
    if max(gray.shape) < 900:
        variants.append(
            (
                "grayscale_enlarged",
                cv2.resize(gray, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC),
            )
        )

    decoded_candidates: list[tuple[str, str]] = []
    detector = cv2.QRCodeDetector()
    try:
        for preprocessing, candidate in variants:
            detected, corners = detector.detectMulti(candidate)
            if detected and corners is not None and len(corners) > 1:
                raise QRInputError(
                    "MULTIPLE_QR_CODES", "Upload an image containing only one QR code."
                )
            decoded, _, _ = detector.detectAndDecode(candidate)
            if decoded:
                decoded_candidates.append((preprocessing, decoded))
    except cv2.error as exc:
        raise QRInputError("QR_DECODE_FAILED", "The QR image could not be processed.") from exc
    except UnicodeDecodeError as exc:
        raise QRInputError(
            "INVALID_QR_TEXT", "The QR code does not contain readable UTF-8 text."
        ) from exc

    payloads = {payload for _, payload in decoded_candidates}
    if len(payloads) > 1:
        raise QRInputError(
            "MULTIPLE_QR_CODES", "The image produces ambiguous QR contents. Use one clear QR code."
        )
    if not decoded_candidates:
        raise QRInputError(
            "QR_NOT_FOUND", "No readable QR code was found. Try a clearer, tightly cropped image."
        )
    preprocessing, payload = decoded_candidates[0]
    return {
        "payload": payload,
        "width": width,
        "height": height,
        "preprocessing": preprocessing,
    }
