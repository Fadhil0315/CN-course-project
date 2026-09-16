"""Small synthetic examples for reproducible demonstrations, not an accuracy dataset."""

from io import BytesIO

import qrcode

DEMO_CASES = {
    "ordinary": {
        "title": "Ordinary destination",
        "description": "A real QR image with a synthetic HTTP 200 response and no redirect.",
        "url": "https://example.com/",
        "responses": {"https://example.com/": (200, None)},
    },
    "suspicious": {
        "title": "Misleading domain + redirect",
        "description": "A brand name hidden in subdomains, a domain change, and an HTTPS-to-HTTP downgrade. Reserved .test names are never contacted.",
        "url": "https://paypal.com.account-check.test/start",
        "responses": {
            "https://paypal.com.account-check.test/start": (302, "http://paypa1.test/signin"),
            "http://paypa1.test/signin": (200, None),
        },
    },
    "loop": {
        "title": "Redirect loop",
        "description": "Two synthetic locations redirect into each other; the tracer stops and reports incomplete evidence.",
        "url": "https://loop.test/start",
        "responses": {
            "https://loop.test/start": (302, "/again"),
            "https://loop.test/again": (302, "/start"),
        },
    },
}


def qr_bytes(payload: str) -> bytes:
    image = qrcode.make(payload, box_size=8, border=4)
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()
