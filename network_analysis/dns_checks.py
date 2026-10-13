"""Collect both address families inside one deadline, failing closed."""

from __future__ import annotations

import ipaddress
import time

import dns.exception
import dns.resolver

from redirect_analysis.tracer import _public_address


def check_dns(hostname: str, timeout: float = 3.0, *, resolver=None) -> dict:
    started = time.monotonic()
    result = {"status": "unavailable", "addresses": [], "records": [], "errors": []}
    try:
        try:
            literal = ipaddress.ip_address(hostname)
        except ValueError:
            literal = None
        if literal is not None:
            result["addresses"] = [_public_address(str(literal))]
            result.update(status="complete", source="IP literal; no DNS query")
        else:
            resolver = resolver or dns.resolver.Resolver()
            for kind in ("A", "AAAA"):
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    raise TimeoutError("DNS deadline exceeded")
                try:
                    answer = resolver.resolve(hostname, kind, lifetime=remaining, search=False)
                except dns.resolver.NoAnswer:
                    continue
                ttl = int(answer.rrset.ttl)
                for item in answer:
                    address = str(item.address)
                    result["records"].append({"type": kind, "address": address, "ttl": ttl})
                    result["addresses"].append(address)
            result["addresses"] = list(dict.fromkeys(result["addresses"]))
            if not result["addresses"]:
                raise ValueError("DNS returned no A or AAAA records")
            for address in result["addresses"]:
                _public_address(address)
            result.update(status="complete", source="system DNS resolver")
    except Exception as exc:
        result["errors"].append(
            {"code": getattr(exc, "code", "DNS_FAILED"), "message": f"{type(exc).__name__}: {exc}"}
        )
    result["elapsed_seconds"] = round(time.monotonic() - started, 4)
    result["validated_public"] = result["status"] == "complete"
    return result
