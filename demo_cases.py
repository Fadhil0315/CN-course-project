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
        "expected_domain": "paypal.com",
        "responses": {
            "https://paypal.com.account-check.test/start": (302, "http://paypa1.test/signin"),
            "http://paypa1.test/signin": (200, None),
        },
    },
    "invalid_tls": {
        "title": "Certificate validation failure",
        "description": "Synthetic expired certificate evidence; the trace cannot finish, so the score remains provisional.",
        "url": "https://expired.test/",
        "responses": {"https://expired.test/": (200, None)},
        "invalid_tls": True,
    },
    "stacked": {
        "title": "Stacked shorteners + misleading destination",
        "description": "A synthetic multi-domain chain, transport downgrade and misleading brand destination.",
        "url": "https://bit.ly/course-demo",
        "expected_domain": "paypal.com",
        "responses": {
            "https://bit.ly/course-demo": (302, "https://tinyurl.com/course-demo"),
            "https://tinyurl.com/course-demo": (302, "https://relay.test/start"),
            "https://relay.test/start": (302, "http://paypal.com.account-check.test/login"),
            "http://paypal.com.account-check.test/login": (200, None),
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


def synthetic_network(case: dict, hops: list[dict]) -> dict:
    """Pass declared fixtures through the real network scoring rules, offline."""
    from network_analysis.analyzer import score_observations

    observations = []
    for hop in hops:
        tls = (
            {"status": "not_applicable", "errors": []}
            if hop["scheme"] == "http"
            else {
                "status": "complete",
                "validated": not case.get("invalid_tls", False),
                "hostname_match": True,
                "issuer": "Synthetic teaching CA",
                "not_before": "2026-09-01T00:00:00+00:00",
                "not_after": "2027-09-01T00:00:00+00:00",
                "certificate_age_days": 40,
                "protocol": "TLSv1.3",
                "errors": [],
                "verification_message": "Synthetic expired certificate"
                if case.get("invalid_tls")
                else None,
            }
        )
        observations.append(
            {
                "hop_index": hop["index"],
                "hostname": hop["hostname"],
                "dns": {
                    "status": "complete",
                    "addresses": ["93.184.216.34"],
                    "records": [{"type": "A", "address": "93.184.216.34", "ttl": 300}],
                    "errors": [],
                },
                "tls": tls,
                "asn": {
                    "status": "complete",
                    "addresses": [
                        {
                            "status": "complete",
                            "ip": "93.184.216.34",
                            "asns": [64496],
                            "organizations": [
                                {"asn": 64496, "name": "Synthetic documentation network"}
                            ],
                            "source": "synthetic fixture",
                        }
                    ],
                    "errors": [],
                },
                "geolocation": {
                    "status": "complete",
                    "addresses": [
                        {
                            "status": "complete",
                            "country_code": "US",
                            "country": "United States",
                            "source": "synthetic fixture",
                            "approximate": True,
                        }
                    ],
                },
            }
        )
    return score_observations(observations, evidence_source="synthetic")


def qr_bytes(payload: str) -> bytes:
    image = qrcode.make(payload, box_size=8, border=4)
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()
