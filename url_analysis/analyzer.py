"""Explainable, provisional URL rules; this module does not access the network.

    Raw IP host: .25; brand token in unrelated subdomain: .40;
    one-edit brand lookalike: .30; four or more subdomain labels: .10;
    URL over 200 characters: .05. Scores add and are capped at 1.

Punycode and known shorteners are informational, with no score contribution.
These deliberately small reference lists are not a phishing feed. TLDs, HTTPS,
and the absence of findings do not establish that a destination is trustworthy.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit

import idna

from .validation import URLValidationError, normalize_url, registered_domain

BRAND_DOMAINS: dict[str, frozenset[str]] = {
    "paypal": frozenset({"paypal.com"}),
    "google": frozenset({"google.com"}),
    "microsoft": frozenset({"microsoft.com", "live.com", "outlook.com", "office.com"}),
    "apple": frozenset({"apple.com", "icloud.com"}),
    "amazon": frozenset({"amazon.com", "amazon.co.uk", "amazon.in"}),
    "github": frozenset({"github.com"}),
}
SHORTENERS = frozenset(
    {"bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "cutt.ly", "rb.gy", "rebrand.ly"}
)

# A deliberately limited, reviewable reference set, not a universal Unicode
# confusables implementation. The original and normalized names are retained.
CONFUSABLES = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "і": "i",
        "ј": "j",
        "ѕ": "s",
        "α": "a",
        "ο": "o",
        "ρ": "p",
        "ι": "i",
    }
)


def _one_edit_apart(left: str, right: str) -> bool:
    """Recognize one insertion, deletion, or substitution, excluding exact matches."""
    if left == right or abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        return sum(a != b for a, b in zip(left, right, strict=True)) == 1
    if len(left) > len(right):
        left, right = right, left
    cursor = 0
    while cursor < len(left) and left[cursor] == right[cursor]:
        cursor += 1
    return left[cursor:] == right[cursor + 1 :]


def analyze_url(url: str) -> dict:
    """Analyze URL text and return a shared LayerResult-compatible dictionary."""
    try:
        normalized = normalize_url(url)
    except URLValidationError as exc:
        return {
            "status": "unavailable",
            "score": None,
            "evidence_source": "live",
            "findings": [],
            "observations": {},
            "errors": [{"code": exc.code, "message": str(exc), "hop_index": None}],
        }

    hostname = urlsplit(normalized).hostname
    assert hostname is not None  # Established by normalize_url.
    domain = registered_domain(hostname)
    findings: list[dict] = []
    total = 0.0

    def add(code: str, severity: str, message: str, weight: float, **details: object) -> None:
        nonlocal total
        total += weight
        findings.append(
            {
                "code": code,
                "severity": severity,
                "message": message,
                "hop_index": None,
                "details": {"score_contribution": weight, **details},
            }
        )

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        is_ip = False
    else:
        is_ip = True
        add(
            "IP_ADDRESS_HOST",
            "warning",
            "The URL uses an IP address instead of a domain name.",
            0.25,
            hostname=hostname,
        )

    subdomains = [] if is_ip or hostname == domain else hostname[: -(len(domain) + 1)].split(".")
    subdomain_tokens = set(re.split(r"[.\-]", ".".join(subdomains)))
    misleading_brands = sorted(
        brand
        for brand, allowed in BRAND_DOMAINS.items()
        if brand in subdomain_tokens and domain not in allowed
    )
    if misleading_brands:
        add(
            "BRAND_IN_SUBDOMAIN",
            "warning",
            "A reference brand appears in a subdomain of an unrelated registered domain.",
            0.40,
            brands=misleading_brands,
            registered_domain=domain,
        )

    label = domain.split(".", 1)[0]
    lookalikes = sorted(
        brand
        for brand, allowed in BRAND_DOMAINS.items()
        if len(brand) >= 5 and domain not in allowed and _one_edit_apart(label, brand)
    )
    if not is_ip and lookalikes:
        add(
            "BRAND_LOOKALIKE",
            "warning",
            "The registered-domain label is one edit away from a reference brand name.",
            0.30,
            reference_brands=lookalikes,
            domain_label=label,
        )
    if len(subdomains) >= 4:
        add(
            "DEEP_SUBDOMAINS",
            "warning",
            "The hostname contains four or more subdomain labels.",
            0.10,
            subdomain_count=len(subdomains),
        )
    if len(normalized) > 200:
        add(
            "LONG_URL",
            "info",
            "The URL is longer than 200 characters; legitimate URLs can also be long.",
            0.05,
            length=len(normalized),
        )
    if any(label.startswith("xn--") for label in hostname.split(".")):
        add(
            "INTERNATIONALIZED_HOST",
            "info",
            "The hostname contains IDNA-encoded internationalized labels; this alone is not suspicious.",
            0,
            hostname=hostname,
        )
        unicode_domain = idna.decode(domain.encode("ascii"))
        skeleton = unicodedata.normalize("NFKC", unicode_domain).lower().translate(CONFUSABLES)
        skeleton_label = skeleton.split(".", 1)[0]
        if skeleton != unicode_domain and skeleton_label in BRAND_DOMAINS:
            add(
                "BRAND_HOMOGLYPH",
                "warning",
                "Internationalized characters resemble a reference brand in the domain label.",
                0.40,
                unicode_domain=unicode_domain,
                reference_brand=skeleton_label,
                limitation="Limited character reference set; legitimate internationalized names may also resemble brands.",
            )
    if domain.rsplit(".", 1)[-1] in {"tk", "xyz", "top"}:
        add(
            "TLD_CONTEXT",
            "info",
            "This suffix appeared in the proposal's watch list. A suffix alone receives no risk penalty.",
            0,
            suffix=domain.rsplit(".", 1)[-1],
        )
    if domain in SHORTENERS:
        add(
            "KNOWN_SHORTENER",
            "info",
            "This is a known shortening service; the destination requires redirect inspection.",
            0,
            registered_domain=domain,
        )

    return {
        "status": "complete",
        "score": round(min(total, 1.0), 4),
        "evidence_source": "live",
        "findings": findings,
        "observations": {
            "normalized_url": normalized,
            "hostname": hostname,
            "registered_domain": domain,
            "is_ip_address": is_ip,
            "subdomain_count": len(subdomains),
            "url_length": len(normalized),
            "method": "offline lexical rules",
            "rule_version": "1",
            "limitations": [
                "Heuristic score, not a probability of phishing.",
                "Reference brand and shortener lists are intentionally incomplete.",
                "No finding does not establish that a URL is safe.",
            ],
        },
        "errors": [],
    }
