"""Exercise actual QR image decoding and bounded image failure handling."""

from io import BytesIO

import pytest
import qrcode
from PIL import Image

from qr_input import QRInputError, decode_qr
from qr_input.decoder import MAX_IMAGE_BYTES


def image_bytes(image, image_format="PNG"):
    buffer = BytesIO()
    image.save(buffer, format=image_format)
    return buffer.getvalue()


def make_qr(payload):
    return qrcode.make(payload, box_size=8, border=4).convert("RGB")


@pytest.mark.parametrize("image_format", ["PNG", "JPEG", "WEBP"])
def test_decodes_supported_formats(image_format):
    image = make_qr("https://example.com/demo?one=1")
    result = decode_qr(image_bytes(image, image_format))
    assert result["payload"] == "https://example.com/demo?one=1"
    assert (result["width"], result["height"]) == image.size
    assert result["preprocessing"]


def test_preserves_payload_for_separate_url_validation():
    result = decode_qr(image_bytes(make_qr("This is a QR note, not a URL.")))
    assert result["payload"] == "This is a QR note, not a URL."


def test_decodes_rotated_qr():
    result = decode_qr(image_bytes(make_qr("https://example.com/").rotate(90, expand=True)))
    assert result["payload"] == "https://example.com/"


def test_decodes_clean_qr_with_scale_sensitive_finder_pattern():
    payload = "https://paypal.com.account-check.test/start"
    result = decode_qr(image_bytes(make_qr(payload)))
    assert result["payload"] == payload


def test_rotated_scale_sensitive_fixture_decodes():
    payload = "https://paypal.com.account-check.test/start"
    result = decode_qr(image_bytes(make_qr(payload).rotate(90, expand=True)))
    assert result["payload"] == payload


def test_two_qr_codes_are_ambiguous():
    left = make_qr("https://example.com/one")
    right = make_qr("https://example.com/two")
    sheet = Image.new(
        "RGB", (left.width + right.width + 100, max(left.height, right.height) + 80), "white"
    )
    sheet.paste(left, (20, 40))
    sheet.paste(right, (left.width + 80, 40))
    with pytest.raises(QRInputError) as error:
        decode_qr(image_bytes(sheet))
    assert error.value.code == "MULTIPLE_QR_CODES"


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b"", "EMPTY_IMAGE"),
        (b"not an image", "INVALID_IMAGE"),
        (b"x" * (MAX_IMAGE_BYTES + 1), "IMAGE_TOO_LARGE"),
    ],
)
def test_rejects_empty_invalid_and_oversized_uploads(payload, expected):
    with pytest.raises(QRInputError) as error:
        decode_qr(payload)
    assert error.value.code == expected


def test_rejects_excessive_pixel_dimensions_before_decoding():
    payload = image_bytes(Image.new("1", (4001, 4000), "white"))
    with pytest.raises(QRInputError) as error:
        decode_qr(payload)
    assert error.value.code == "IMAGE_DIMENSIONS_TOO_LARGE"


def test_rejects_unsupported_format():
    with pytest.raises(QRInputError) as error:
        decode_qr(image_bytes(Image.new("RGB", (20, 20), "white"), "GIF"))
    assert error.value.code == "UNSUPPORTED_IMAGE"


def test_blank_image_is_not_reported_as_a_decoded_qr():
    with pytest.raises(QRInputError) as error:
        decode_qr(image_bytes(Image.new("RGB", (240, 240), "white")))
    assert error.value.code == "QR_NOT_FOUND"


@pytest.mark.parametrize("dimensions", [(5000, 1), (1, 5000)])
def test_thin_valid_image_produces_actionable_input_error(dimensions):
    with pytest.raises(QRInputError) as error:
        decode_qr(image_bytes(Image.new("RGB", dimensions, "white")))
    assert error.value.code in {"QR_NOT_FOUND", "QR_DECODE_FAILED"}
