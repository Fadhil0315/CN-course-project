import json

import pytest

from network_analysis import geolocation


@pytest.mark.parametrize("mode", ["success", "mismatched_ip", "oversized", "rate_limited"])
def test_location_response_validation_and_connection_cleanup(monkeypatch, mode):
    closed = []
    connections = []

    class Response:
        status = 429 if mode == "rate_limited" else 200

        def read(self, limit):
            assert limit == 65537
            if mode == "oversized":
                return b"x" * limit
            return json.dumps(
                {
                    "success": True,
                    "ip": "8.8.4.4" if mode == "mismatched_ip" else "8.8.8.8",
                    "country_code": "US",
                    "country": "United States",
                }
            ).encode()

        def close(self):
            closed.append("response")

    class Pool:
        def __init__(self, host, **options):
            connections.append((host, options))

        def request(self, method, path, **options):
            assert path == "/8.8.8.8"
            assert options["redirect"] is False and options["retries"] is False
            return Response()

        def close(self):
            closed.append("pool")

    monkeypatch.setattr(geolocation, "resolve_public_candidates", lambda *args: ["1.1.1.1"])
    monkeypatch.setattr(geolocation.urllib3, "HTTPSConnectionPool", Pool)
    result = geolocation.lookup_location("8.8.8.8")
    assert result["status"] == ("complete" if mode == "success" else "unavailable")
    assert closed == ["response", "pool"]
    assert connections[0][0] == "1.1.1.1"
    assert connections[0][1]["server_hostname"] == "ipwho.is"
    assert connections[0][1]["assert_hostname"] == "ipwho.is"
