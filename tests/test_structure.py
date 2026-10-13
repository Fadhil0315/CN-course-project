from io import BytesIO

import numpy as np
import pytest
import qrcode

from qr_input import decode_qr
from qr_structure import analyze_structure, inspect_symbol


@pytest.mark.parametrize(("ecc", "name"), [(1, "L"), (0, "M"), (3, "Q"), (2, "H")])
def test_all_standard_ecc_levels_are_valid_and_not_risky(ecc, name):
    qr = qrcode.QRCode(error_correction=ecc, box_size=8)
    qr.add_data("https://example.com/")
    qr.make(fit=True)
    buffer = BytesIO()
    qr.make_image().save(buffer, format="PNG")
    decoded = decode_qr(buffer.getvalue())
    data = decoded["structure"]
    assert data["format"]["ecc"] == name
    assert data["version"] == qr.version
    assert analyze_structure(data)["score"] == 0


def test_oversized_valid_symbol_is_not_risky():
    qr = qrcode.QRCode(version=6, border=0)
    qr.add_data("https://example.com/")
    qr.make(fit=False)
    gray = np.where(np.asarray(qr.get_matrix()), 0, 255).astype(np.uint8)
    metadata = inspect_symbol(gray, None, gray, "https://example.com/")
    assert metadata["reference_minimum_version"] < 6
    assert analyze_structure(metadata)["score"] == 0


def test_missing_structure_stays_unavailable():
    result = analyze_structure(None)
    assert result["score"] is None and result["status"] == "unavailable"
