"""Canonicalize HTTP URLs without DNS lookups or public-suffix downloads."""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from functools import lru_cache
from urllib.parse import quote, urlsplit, urlunsplit

import idna
import tldextract

MAX_URL_LENGTH = 8192
_NUMERIC_LABEL = re.compile(r"(?:[0-9]+|0[xX][0-9a-fA-F]+)\Z")
_INVALID_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")
_ENCODED_CONTROL = re.compile(r"%(?:0[0-9a-f]|1[0-9a-f]|7f)", re.IGNORECASE)
_EXTRACTOR = tldextract.TLDExtract(
    cache_dir=None, suffix_list_urls=(), include_psl_private_domains=True
)


class URLValidationError(ValueError):
    """A rejected URL and a stable reason code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _normalize_hostname(hostname: str) -> str:
    had_ascii_root_dot = hostname.endswith(".")
    if had_ascii_root_dot:
        hostname = hostname[:-1]
    if not hostname or "%" in hostname:
        raise URLValidationError(
            "INVALID_HOST", "The URL needs a valid hostname without a zone identifier."
        )
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        if ":" in hostname:
            raise URLValidationError("INVALID_HOST", "The IPv6 address is malformed.") from None
    else:
        return address.compressed
    try:
        hostname = idna.encode(hostname, uts46=True, std3_rules=True).decode("ascii").lower()
    except idna.IDNAError as exc:
        raise URLValidationError("INVALID_HOST", "The URL hostname is malformed.") from exc
    # UTS46 also maps Unicode full stops to ASCII, including a terminal root dot.
    # Remove that newly mapped dot before numeric-host validation and extraction.
    if hostname.endswith("."):
        if had_ascii_root_dot:
            raise URLValidationError(
                "INVALID_HOST", "The URL hostname has repeated terminal separators."
            )
        hostname = hostname[:-1]
    # Some clients interpret shortened, octal, hexadecimal, or integer hosts as
    # IPv4. Only unambiguous four-part decimal IPv4 is accepted by ipaddress above.
    if _NUMERIC_LABEL.fullmatch(hostname.rsplit(".", 1)[-1]):
        raise URLValidationError("AMBIGUOUS_IP", "Use a canonical dotted-decimal IPv4 address.")
    if len(hostname) > 253:
        raise URLValidationError("INVALID_HOST", "The URL hostname is too long.")
    return hostname


def normalize_url(value: str) -> str:
    """Validate a URL and return a deterministic HTTP(S) representation.

    Credentials, raw whitespace/control characters, backslashes, malformed
    escapes, encoded ASCII controls, and ambiguous numeric addresses are rejected.
    Unicode DNS labels use IDNA; Unicode paths/queries use UTF-8 percent encoding.
    This is syntax validation, not authorization to contact a destination.
    """
    if not isinstance(value, str) or not value:
        raise URLValidationError("EMPTY_URL", "The QR code must contain an HTTP or HTTPS URL.")
    if len(value) > MAX_URL_LENGTH:
        raise URLValidationError("URL_TOO_LONG", "The URL exceeds the 8192-character limit.")
    if any(
        character.isspace() or unicodedata.category(character).startswith("C")
        for character in value
    ):
        raise URLValidationError(
            "INVALID_CHARACTERS", "URLs cannot contain raw whitespace or control characters."
        )
    if "\\" in value:
        raise URLValidationError("INVALID_CHARACTERS", "Backslashes are not accepted in URLs.")
    if _INVALID_PERCENT.search(value) or _ENCODED_CONTROL.search(value):
        raise URLValidationError(
            "INVALID_ESCAPE", "The URL contains a malformed escape or encoded control character."
        )
    try:
        parts = urlsplit(value)
        if parts.scheme.lower() not in {"http", "https"}:
            raise URLValidationError(
                "UNSUPPORTED_SCHEME", "Only HTTP and HTTPS URLs are supported."
            )
        if not parts.netloc or not parts.hostname:
            raise URLValidationError("INVALID_HOST", "The URL needs a hostname.")
        if "@" in parts.netloc:
            raise URLValidationError(
                "URL_CREDENTIALS", "URLs containing usernames or passwords are not accepted."
            )
        if parts.netloc.startswith("[") and not re.fullmatch(
            r"\[[^\]]+\](?::[0-9]+)?", parts.netloc
        ):
            raise URLValidationError(
                "INVALID_HOST", "The bracketed IP address has a malformed authority."
            )
        hostname = _normalize_hostname(parts.hostname)
        if parts.netloc.startswith("[") and ":" not in hostname:
            raise URLValidationError(
                "INVALID_HOST", "Bracketed hosts must contain a valid IPv6 address."
            )
        port = parts.port
        if port == 0 or parts.netloc.endswith(":"):
            raise URLValidationError("INVALID_PORT", "Use a port from 1 to 65535, or omit it.")
    except URLValidationError:
        raise
    except ValueError as exc:
        raise URLValidationError(
            "INVALID_URL", "The URL has a malformed hostname or port."
        ) from exc

    scheme = parts.scheme.lower()
    host_text = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if scheme == "https" else 80
    authority = host_text if port is None or port == default_port else f"{host_text}:{port}"
    path = quote(parts.path or "/", safe="/:@!$&'()*+,;=-._~%")
    query = quote(parts.query, safe="/?:@!$&'()*+,;=-._~%")
    normalized = urlunsplit((scheme, authority, path, query, ""))
    if len(normalized) > MAX_URL_LENGTH:
        raise URLValidationError(
            "URL_TOO_LONG", "The encoded URL exceeds the 8192-character limit."
        )
    return normalized


@lru_cache(maxsize=1024)
def registered_domain(hostname: str) -> str:
    """Return the registrable domain using the bundled, offline PSL snapshot.

    Private suffixes (such as github.io) are included. For an unknown suffix
    such as .test, use the final two labels. Return IPs/single-label hosts intact.
    """
    hostname = _normalize_hostname(hostname)
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        extracted = _EXTRACTOR(hostname)
        if extracted.suffix and extracted.domain:
            return f"{extracted.domain}.{extracted.suffix}"
        return ".".join(hostname.split(".")[-2:])
    return hostname
