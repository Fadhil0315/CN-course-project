"""A verified TLS handshake with SNI, pinned public IP and no application data."""

from __future__ import annotations

import hashlib
import socket
import ssl
import time
from datetime import UTC, datetime

import certifi

from redirect_analysis.tracer import _public_address


def _name(parts: tuple) -> str:
    return ", ".join(f"{key}={value}" for group in parts for key, value in group)


def check_tls(hostname: str, address: str, port: int = 443, timeout: float = 4.0) -> dict:
    _public_address(address)
    if port not in {80, 443}:
        raise ValueError("Only ports 80 and 443 are allowed")
    started = time.monotonic()
    result = {
        "status": "unavailable",
        "validated": None,
        "hostname_match": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "address": address,
        "errors": [],
    }
    context = ssl.create_default_context(cafile=certifi.where())
    context.set_alpn_protocols(["http/1.1"])
    try:
        with socket.create_connection((address, port), timeout=timeout) as raw:
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                raise TimeoutError("TLS deadline exceeded")
            raw.settimeout(remaining)
            with context.wrap_socket(raw, server_hostname=hostname) as connection:
                certificate = connection.getpeercert()
                before = datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(certificate["notBefore"]), UTC
                )
                after = datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(certificate["notAfter"]), UTC
                )
                now = datetime.now(UTC)
                result.update(
                    status="complete",
                    validated=True,
                    hostname_match=True,
                    issuer=_name(certificate.get("issuer", ())),
                    subject=_name(certificate.get("subject", ())),
                    subject_alt_names=[
                        list(item) for item in certificate.get("subjectAltName", ())
                    ],
                    not_before=before.isoformat(),
                    not_after=after.isoformat(),
                    certificate_age_days=round((now - before).total_seconds() / 86400, 2),
                    days_until_expiry=round((after - now).total_seconds() / 86400, 2),
                    protocol=connection.version(),
                    cipher=list(connection.cipher()),
                    alpn=connection.selected_alpn_protocol(),
                    certificate_sha256=hashlib.sha256(
                        connection.getpeercert(binary_form=True)
                    ).hexdigest(),
                )
    except ssl.SSLCertVerificationError as exc:
        # A completed validation check with a negative outcome is evidence.
        # Never reconnect with CERT_NONE to turn a failed check into success.
        result.update(
            status="complete",
            validated=False,
            verification_code=exc.verify_code,
            verification_message=exc.verify_message,
            hostname_match=False if exc.verify_code in {62, 64} else None,
        )
        result["errors"].append({"code": "TLS_CERTIFICATE_INVALID", "message": exc.verify_message})
    except (OSError, ssl.SSLError, ValueError) as exc:
        result["errors"].append({"code": "TLS_FAILED", "message": f"{type(exc).__name__}: {exc}"})
    result["elapsed_seconds"] = round(time.monotonic() - started, 4)
    return result
