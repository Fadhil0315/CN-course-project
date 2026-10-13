"""Optional approximate IP location from the ipwho.is free API."""

from __future__ import annotations

import json
import ssl

import certifi
import urllib3

from redirect_analysis.tracer import _public_address, resolve_public_candidates


def lookup_location(address: str, timeout: float = 3.0) -> dict:
    address = _public_address(address)
    result = {
        "status": "unavailable",
        "ip": address,
        "source": "ipwho.is",
        "approximate": True,
        "errors": [],
    }
    pool = None
    response = None
    try:
        candidates = resolve_public_candidates("ipwho.is", timeout)
        candidates = [_public_address(item) for item in candidates]
        pool = urllib3.HTTPSConnectionPool(
            candidates[0],
            port=443,
            server_hostname="ipwho.is",
            assert_hostname="ipwho.is",
            cert_reqs=ssl.CERT_REQUIRED,
            ca_certs=certifi.where(),
            timeout=urllib3.Timeout(total=timeout),
            maxsize=1,
        )
        response = pool.request(
            "GET",
            f"/{address}",
            headers={"Host": "ipwho.is"},
            retries=False,
            redirect=False,
            preload_content=False,
        )
        if response.status != 200:
            raise ValueError(f"Location provider returned HTTP {response.status}")
        payload = response.read(65537)
        if len(payload) > 65536:
            raise ValueError("Location response too large")
        data = json.loads(payload)
        if data.get("success") is not True or data.get("ip") != address:
            raise ValueError("Location provider did not return a matching successful result")
        if not isinstance(data.get("country_code"), str) or len(data["country_code"]) != 2:
            raise ValueError("Location provider did not return a country code")
        result.update(
            status="complete",
            country=data.get("country"),
            country_code=data.get("country_code"),
            region=data.get("region"),
            city=data.get("city"),
            latitude=data.get("latitude"),
            longitude=data.get("longitude"),
        )
    except Exception as exc:
        result["errors"].append(
            {"code": "GEOLOCATION_FAILED", "message": f"{type(exc).__name__}: {exc}"}
        )
    finally:
        if response is not None:
            response.close()
        if pool is not None:
            pool.close()
    return result
