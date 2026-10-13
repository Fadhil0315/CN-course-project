"""Team Cymru DNS IP-to-ASN mapping; registry country is NOT geolocation."""

from __future__ import annotations

import ipaddress
import time

import dns.resolver

from redirect_analysis.tracer import _public_address


def lookup_asn(address: str, timeout: float = 3.0, *, resolver=None) -> dict:
    address = _public_address(address)
    ip = ipaddress.ip_address(address)
    query = (
        ".".join(reversed(address.split("."))) + ".origin.asn.cymru.com"
        if ip.version == 4
        else ".".join(reversed(ip.exploded.replace(":", ""))) + ".origin6.asn.cymru.com"
    )
    started = time.monotonic()
    result = {
        "status": "unavailable",
        "ip": address,
        "source": "Team Cymru DNS",
        "asns": [],
        "organizations": [],
        "errors": [],
    }
    resolver = resolver or dns.resolver.Resolver()

    def txt(name: str) -> list[str]:
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise TimeoutError("ASN deadline exceeded")
        answer = resolver.resolve(name, "TXT", lifetime=remaining, search=False)
        return [b"".join(record.strings).decode("utf-8") for record in answer]

    try:
        rows = [value.split("|") for value in txt(query)]
        if not rows or any(len(row) < 5 for row in rows):
            raise ValueError("Malformed ASN response")
        result["prefixes"] = []
        for row in rows:
            numbers, prefix, country, registry, allocated = (value.strip() for value in row[:5])
            network = ipaddress.ip_network(prefix)
            if ip not in network:
                raise ValueError("Provider returned a prefix unrelated to the queried address")
            result["prefixes"].append(
                {
                    "prefix": prefix,
                    "registry_country": country,
                    "registry": registry,
                    "allocated": allocated,
                }
            )
            result["asns"].extend(int(value) for value in numbers.split())
        result["asns"] = sorted(set(result["asns"]))
        if not result["asns"] or len(result["asns"]) > 8:
            raise ValueError("Unexpected ASN count")
        for number in result["asns"]:
            rows = txt(f"AS{number}.asn.cymru.com")
            fields = [value.strip() for value in rows[0].split("|", 4)]
            if len(fields) != 5 or int(fields[0]) != number:
                raise ValueError("Malformed ASN organization response")
            result["organizations"].append({"asn": number, "name": fields[4]})
        result["status"] = "complete"
    except Exception as exc:
        result["errors"].append({"code": "ASN_FAILED", "message": f"{type(exc).__name__}: {exc}"})
    result["elapsed_seconds"] = round(time.monotonic() - started, 4)
    return result
