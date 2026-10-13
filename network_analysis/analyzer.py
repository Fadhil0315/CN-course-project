"""Aggregate independently validated network observations without following URLs."""

from __future__ import annotations

import time
from copy import deepcopy
from urllib.parse import urlsplit

from redirect_analysis.tracer import _public_address
from shared.contracts import error_record, layer_result
from url_analysis import normalize_url

from .asn_lookup import lookup_asn
from .dns_checks import check_dns
from .geolocation import lookup_location
from .tls_checks import check_tls


def score_observations(
    observations: list[dict],
    *,
    evidence_source: str = "live",
    expected_asns: tuple[int, ...] = (),
    expected_countries: tuple[str, ...] = (),
) -> dict:
    findings, errors, hop_scores = [], [], []
    complete = bool(observations)
    any_evidence = False
    final_index = observations[-1]["hop_index"] if observations else None

    def finding(code, message, index, weight=0.0, **details):
        findings.append(
            {
                "code": code,
                "severity": "high" if weight >= 0.5 else "warning" if weight else "info",
                "message": message,
                "hop_index": index,
                "details": {"score_contribution": weight, **details},
            }
        )
        return weight

    for hop in observations:
        index, dns, tls, asn = hop["hop_index"], hop["dns"], hop["tls"], hop["asn"]
        score = 0.0
        for item in (dns, tls, asn):
            if item["status"] not in {"complete", "not_applicable"}:
                complete = False
            any_evidence |= item["status"] == "complete"
            errors.extend(
                error_record(e["code"], e["message"], index) for e in item.get("errors", [])
            )
        ttls = [record["ttl"] for record in dns.get("records", [])]
        if ttls and min(ttls) < 60:
            finding(
                "SHORT_OBSERVED_TTL",
                "A DNS TTL below 60 seconds was observed. Caching and CDNs also produce short TTLs.",
                index,
                ttl=min(ttls),
            )
        if tls.get("validated") is False:
            score += finding(
                "TLS_CERTIFICATE_INVALID",
                "The certificate failed trust, date or hostname validation.",
                index,
                0.85,
                reason=tls.get("verification_message"),
            )
        elif tls["status"] == "not_applicable":
            score += finding(
                "UNENCRYPTED_HTTP",
                "This hop uses HTTP, so transport encryption and certificate identity checks are absent.",
                index,
                0.35,
            )
        if tls.get("certificate_age_days") is not None and tls["certificate_age_days"] < 7:
            finding(
                "RECENT_CERTIFICATE",
                "The certificate was issued within seven days. This is not the domain's registration age and is not scored alone.",
                index,
                age_days=tls["certificate_age_days"],
            )
        actual_asns = {
            number for item in asn.get("addresses", []) for number in item.get("asns", [])
        }
        if (
            index == final_index
            and expected_asns
            and asn["status"] == "complete"
            and actual_asns
            and not actual_asns.intersection(expected_asns)
        ):
            score += finding(
                "HOSTING_BASELINE_MISMATCH",
                "Observed ASNs differ from the baseline supplied for this scan. Legitimate hosting migrations can also cause this.",
                index,
                0.20,
                expected=list(expected_asns),
                observed=sorted(actual_asns),
            )
        geo = hop.get("geolocation", {})
        if geo.get("status") in {"partial", "unavailable"}:
            complete = False
            errors.extend(
                error_record(e["code"], e["message"], index) for e in geo.get("errors", [])
            )
        countries = {
            item.get("country_code")
            for item in geo.get("addresses", [])
            if item.get("country_code")
        }
        if (
            index == final_index
            and expected_countries
            and geo.get("status") == "complete"
            and countries
            and not countries.intersection(expected_countries)
        ):
            score += finding(
                "LOCATION_BASELINE_MISMATCH",
                "Approximate IP location differs from the supplied country baseline; geolocation can be inaccurate.",
                index,
                0.05,
                expected=list(expected_countries),
                observed=sorted(countries),
            )
        hop_scores.append(min(score, 1.0))
    return layer_result(
        status="complete" if complete else "partial" if any_evidence else "unavailable",
        score=round(max(hop_scores, default=0), 4) if any_evidence else None,
        evidence_source=evidence_source,
        findings=findings,
        errors=errors,
        observations={
            "hops": observations,
            "aggregation": "maximum observed hop score",
            "limitations": [
                "Network posture is not proof of phishing or safety.",
                "ASN registry country is not geolocation.",
                "TLS inspects one validated IP per unique hostname/port; other endpoints may differ.",
            ],
        },
    )


def analyze_network(
    hops: list[dict],
    *,
    include_geolocation: bool = False,
    expected_asns: tuple[int, ...] = (),
    expected_countries: tuple[str, ...] = (),
    dns_checker=None,
    tls_checker=None,
    asn_checker=None,
    geo_checker=None,
    total_timeout: float = 25.0,
) -> dict:
    if not 0 < total_timeout <= 60:
        raise ValueError("Network budget must be between 0 and 60 seconds")
    dns_checker, tls_checker = dns_checker or check_dns, tls_checker or check_tls
    asn_checker, geo_checker = asn_checker or lookup_asn, geo_checker or lookup_location
    started = time.monotonic()
    endpoints, asn_cache, geo_cache = {}, {}, {}
    observations = []
    if len(hops) > 21:
        raise ValueError("At most 21 network hops are accepted")

    def missing(code, message):
        return {"status": "unavailable", "errors": [{"code": code, "message": message}]}

    def call(function, *args, limit=3.0):
        remaining = total_timeout - (time.monotonic() - started)
        if remaining <= 0:
            return missing("NETWORK_DEADLINE", "Network analysis exhausted its time budget")
        try:
            return function(*args, timeout=min(limit, remaining))
        except Exception as exc:
            return missing("COLLECTOR_FAILED", f"{type(exc).__name__}: {exc}")

    for hop in hops:
        parsed = urlsplit(normalize_url(hop["url"]))
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if (
            hop.get("network_eligible") is not True
            or port not in {80, 443}
            or parsed.hostname != hop["hostname"]
        ):
            raise ValueError("Network hop is not an eligible, matching HTTP(S) destination")
        key = (parsed.scheme, parsed.hostname, port)
        if key in endpoints:
            item = deepcopy(endpoints[key])
            item.update(hop_index=hop["index"], cached=True)
            observations.append(item)
            continue
        item = {"hop_index": hop["index"], "hostname": parsed.hostname, "cached": False}
        dns = call(dns_checker, parsed.hostname)
        item["dns"] = dns
        item["tls"] = missing(
            "DNS_REQUIRED", "TLS inspection requires a complete public DNS answer set"
        )
        item["asn"] = missing("DNS_REQUIRED", "ASN lookup requires validated public addresses")
        item["geolocation"] = {"status": "not_requested", "addresses": [], "errors": []}
        if dns["status"] == "complete":
            try:
                addresses = [_public_address(address) for address in dns["addresses"]]
                if not addresses:
                    raise ValueError("DNS returned no addresses")
            except Exception as exc:
                item["dns"] = missing("NON_PUBLIC_ADDRESS", str(exc))
            else:
                item["tls"] = (
                    call(tls_checker, parsed.hostname, addresses[0], port, limit=4.0)
                    if parsed.scheme == "https"
                    else {"status": "not_applicable", "errors": []}
                )
                selected = addresses[:8]
                mappings, locations = [], []
                for address in selected:
                    if address not in asn_cache:
                        asn_cache[address] = call(asn_checker, address)
                    mappings.append(deepcopy(asn_cache[address]))
                    if include_geolocation:
                        if address not in geo_cache:
                            geo_cache[address] = call(geo_checker, address)
                        locations.append(deepcopy(geo_cache[address]))
                item["asn"] = {
                    "status": "complete"
                    if len(addresses) <= 8 and all(m["status"] == "complete" for m in mappings)
                    else "partial",
                    "addresses": mappings,
                    "errors": [e for m in mappings for e in m.get("errors", [])],
                    "address_limit": 8,
                    "total_addresses": len(addresses),
                }
                if len(addresses) > 8:
                    item["asn"]["errors"].append(
                        {
                            "code": "ADDRESS_LIMIT",
                            "message": "Only eight addresses were enriched to bound provider requests",
                        }
                    )
                if include_geolocation:
                    item["geolocation"] = {
                        "status": "complete"
                        if len(addresses) <= 8 and all(g["status"] == "complete" for g in locations)
                        else "partial",
                        "addresses": locations,
                        "errors": [e for g in locations for e in g.get("errors", [])],
                    }
        endpoints[key] = deepcopy(item)
        observations.append(item)
    result = score_observations(
        observations, expected_asns=expected_asns, expected_countries=expected_countries
    )
    result["observations"]["elapsed_seconds"] = round(time.monotonic() - started, 4)
    result["observations"]["geolocation_requested"] = include_geolocation
    return result
