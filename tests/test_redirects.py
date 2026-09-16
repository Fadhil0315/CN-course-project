"""Reproducible redirect tests: no requests leave the test process."""

import ssl
from unittest.mock import MagicMock, patch

import pytest

from redirect_analysis import HTTPResponse, TracePolicy, trace_redirects
from redirect_analysis.tracer import TraceFailure, request_headers, resolve_public_candidates

PUBLIC_IP = "93.184.216.34"


class FixtureTransport:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, url, address, timeout):
        self.calls.append((url, address, timeout))
        response = self.responses[url]
        if isinstance(response, Exception):
            raise response
        return response


def resolve_public(hostname, timeout):
    return [PUBLIC_IP]


def policy(*hosts, **kwargs):
    return TracePolicy(approved_hosts=hosts or ("example.com",), **kwargs)


def trace(url, responses, *, trace_policy=None, resolver=resolve_public):
    transport = FixtureTransport(responses)
    result = trace_redirects(
        url, policy=trace_policy or policy(), resolver=resolver, transport=transport
    )
    return result, transport


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_follows_each_http_redirect_status_and_relative_location(status):
    result, transport = trace(
        "https://example.com/start",
        {
            "https://example.com/start": HTTPResponse(status, "/end"),
            "https://example.com/end": HTTPResponse(200),
        },
    )
    assert result["status"] == "complete"
    assert result["score"] == 0.0
    assert result["observations"]["redirect_count"] == 1
    assert result["observations"]["hops"][0]["next_url"] == "https://example.com/end"
    assert len(transport.calls) == 2
    assert all(call[1] == PUBLIC_IP and 0 < call[2] <= 4 for call in transport.calls)


def test_canonical_loop_detected_without_repeating_request():
    result, transport = trace(
        "https://EXAMPLE.com:443/start#initial",
        {"https://example.com/start": HTTPResponse(302, "https://example.com:443/start#other")},
    )
    assert result["status"] == "partial"
    assert result["errors"][0]["code"] == "REDIRECT_LOOP"
    assert result["score"] > 0
    assert len(transport.calls) == 1


def test_redirect_target_must_be_exactly_approved():
    lookups = []

    def resolver(hostname, timeout):
        lookups.append(hostname)
        return [PUBLIC_IP]

    result, transport = trace(
        "https://example.com/",
        {"https://example.com/": HTTPResponse(302, "https://sub.example.com/end")},
        resolver=resolver,
    )
    assert result["status"] == "partial"
    assert result["errors"][0]["code"] == "HOST_NOT_APPROVED"
    assert result["observations"]["hops"][1]["status_code"] is None
    assert result["observations"]["hops"][1]["network_eligible"] is False
    assert result["observations"]["hops"][0]["network_eligible"] is True
    assert result["observations"]["followed_redirect_count"] == 0
    assert lookups == ["example.com"]
    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "0.0.0.0",
        "100.64.0.1",
        "224.0.0.1",
        "240.0.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "ff02::1",
        "::ffff:8.8.8.8",
        "64:ff9b::7f00:1",
        "64:ff9b:1::7f00:1",
        "2002:7f00:1::",
        "2002:0808:0808::",
        "2001:0000:4136:e378:8000:63bf:3fff:fdd2",
    ],
)
def test_rejects_non_public_addresses_before_opening_connection(address):
    result, transport = trace("https://example.com/", {}, resolver=lambda host, timeout: [address])
    assert result["status"] == "unavailable"
    assert result["score"] is None
    assert result["errors"][0]["code"] == "NON_PUBLIC_ADDRESS"
    assert result["observations"]["hops"][0]["network_eligible"] is False
    assert transport.calls == []


def test_rejects_mixed_public_and_private_dns_answers():
    result, transport = trace(
        "https://example.com/", {}, resolver=lambda host, timeout: [PUBLIC_IP, "127.0.0.1"]
    )
    assert result["errors"][0]["code"] == "NON_PUBLIC_ADDRESS"
    assert not transport.calls


def test_dns_is_rechecked_at_each_hop_and_private_second_answer_is_blocked():
    resolutions = iter([[PUBLIC_IP], ["127.0.0.1"]])
    result, transport = trace(
        "https://example.com/start",
        {"https://example.com/start": HTTPResponse(302, "/end")},
        resolver=lambda host, timeout: next(resolutions),
    )
    assert result["status"] == "partial"
    assert result["errors"][0]["code"] == "NON_PUBLIC_ADDRESS"
    assert len(transport.calls) == 1


def test_all_public_addresses_are_vetted_but_transport_receives_pinned_ip():
    result, transport = trace(
        "https://example.com/",
        {"https://example.com/": HTTPResponse(200)},
        resolver=lambda host, timeout: [PUBLIC_IP, "2606:4700:4700::1111"],
    )
    assert result["status"] == "complete"
    assert transport.calls[0][1] == PUBLIC_IP


def test_redirect_limit_bounds_number_of_requests():
    result, transport = trace(
        "https://example.com/0",
        {
            "https://example.com/0": HTTPResponse(302, "/1"),
            "https://example.com/1": HTTPResponse(302, "/2"),
        },
        trace_policy=policy(max_redirects=1),
    )
    assert result["status"] == "partial"
    assert result["errors"][0]["code"] == "REDIRECT_LIMIT"
    assert len(transport.calls) == 2
    assert result["observations"]["redirect_count"] == 2
    assert result["observations"]["followed_redirect_count"] == 1


@pytest.mark.parametrize(
    "location",
    [
        "file:///etc/passwd",
        "javascript:alert(1)",
        "https://user:password@example.com/",
        "https://example.com/\r\nHeader: value",
        "\\\\localhost\\file",
        " https://example.com/end",
        "\u2003https://example.com/end",
        "/path with spaces",
    ],
)
def test_unsafe_redirect_locations_stop_without_second_request(location):
    result, transport = trace(
        "https://example.com/", {"https://example.com/": HTTPResponse(302, location)}
    )
    assert result["status"] == "partial"
    assert result["errors"][0]["code"] == "INVALID_LOCATION"
    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    "url", ["file:///etc/passwd", "javascript:alert(1)", "ftp://example.com/file"]
)
def test_unsupported_initial_scheme_is_unavailable(url):
    result, transport = trace(url, {})
    assert result["status"] == "unavailable"
    assert result["score"] is None
    assert not transport.calls


def test_nonstandard_port_blocked_before_dns_or_transport():
    resolver = MagicMock(return_value=[PUBLIC_IP])
    result, transport = trace("https://example.com:8443/", {}, resolver=resolver)
    assert result["errors"][0]["code"] == "PORT_NOT_ALLOWED"
    resolver.assert_not_called()
    assert not transport.calls


def test_request_failure_is_not_reported_as_a_zero_risk_result():
    result, _ = trace(
        "https://example.com/", {"https://example.com/": TimeoutError("test timeout")}
    )
    assert result["status"] == "unavailable"
    assert result["score"] is None
    assert result["errors"][0]["code"] == "REQUEST_FAILED"


def test_tls_transport_failure_retains_network_eligibility_after_vetting():
    result, _ = trace(
        "https://example.com/",
        {"https://example.com/": ssl.SSLCertVerificationError("test certificate failure")},
    )
    hop = result["observations"]["hops"][0]
    assert hop["network_eligible"] is True
    assert hop["status_code"] is None
    assert result["status"] == "unavailable"


def test_failure_after_first_response_retains_partial_evidence():
    result, _ = trace(
        "https://example.com/start",
        {
            "https://example.com/start": HTTPResponse(302, "/end"),
            "https://example.com/end": TimeoutError(),
        },
    )
    assert result["status"] == "partial"
    assert len(result["observations"]["hops"]) == 2
    assert result["observations"]["hops"][0]["status_code"] == 302
    assert result["observations"]["hops"][1]["error"] is not None


def test_missing_redirect_location_is_explicit():
    result, _ = trace("https://example.com/", {"https://example.com/": HTTPResponse(302)})
    assert result["status"] == "partial"
    assert result["errors"][0]["code"] == "MISSING_LOCATION"


def test_domain_change_and_https_downgrade_have_explanations():
    result, _ = trace(
        "https://example.com/",
        {
            "https://example.com/": HTTPResponse(302, "http://httpbin.org/"),
            "http://httpbin.org/": HTTPResponse(200),
        },
        trace_policy=policy("example.com", "httpbin.org"),
    )
    assert result["status"] == "complete"
    assert result["score"] == pytest.approx(0.47)
    assert {finding["code"] for finding in result["findings"]} == {
        "REDIRECT_DOMAIN_CHANGE",
        "HTTPS_DOWNGRADE",
    }


@pytest.mark.parametrize("status", [401, 403, 404, 429, 500, 503])
def test_http_error_status_is_observed_without_becoming_a_transport_failure(status):
    result, _ = trace("https://example.com/", {"https://example.com/": HTTPResponse(status)})
    assert result["status"] == "complete"
    assert result["observations"]["hops"][0]["status_code"] == status
    assert result["score"] == 0.0
    finding = result["findings"][0]
    assert finding["code"] == "HTTP_ERROR_RESPONSE"
    assert finding["details"]["status_code"] == status


def test_expired_total_budget_stops_before_transport():
    resolver = MagicMock(return_value=[PUBLIC_IP])
    with patch("redirect_analysis.tracer.time.monotonic", side_effect=[0.0, 0.0, 0.0, 25.0, 25.0]):
        result, transport = trace("https://example.com/", {}, resolver=resolver)
    assert result["errors"][0]["code"] == "TOTAL_TIMEOUT"
    assert not transport.calls


def test_live_transport_pins_ip_preserves_hostname_and_closes_without_reading_body():
    response = MagicMock(status=302)
    response.headers = {"Location": "/next"}
    pool = MagicMock()
    pool.request.return_value = response
    with patch("urllib3.HTTPSConnectionPool", return_value=pool) as constructor:
        result = request_headers("https://example.com/path?q=1", PUBLIC_IP, 2.0)
    assert result == HTTPResponse(302, "/next")
    kwargs = constructor.call_args.kwargs
    assert kwargs["host"] == PUBLIC_IP
    assert kwargs["server_hostname"] == "example.com"
    assert kwargs["assert_hostname"] == "example.com"
    assert kwargs["cert_reqs"] == ssl.CERT_REQUIRED
    assert kwargs["ca_certs"]
    request = pool.request.call_args
    assert request.args == ("GET", "/path?q=1")
    assert request.kwargs["headers"]["Host"] == "example.com"
    assert not {"cookie", "authorization", "referer"} & {
        name.lower() for name in request.kwargs["headers"]
    }
    assert request.kwargs["redirect"] is False
    assert request.kwargs["retries"] is False
    assert request.kwargs["preload_content"] is False
    response.read.assert_not_called()
    response.close.assert_called_once()
    response.release_conn.assert_called_once()
    pool.close.assert_called_once()


def test_dns_checks_both_families_with_one_timeout_budget():
    answers = [[MagicMock(address=PUBLIC_IP)], [MagicMock(address="2606:4700:4700::1111")]]
    dns_resolver = MagicMock()
    dns_resolver.resolve.side_effect = answers
    with (
        patch("dns.resolver.Resolver", return_value=dns_resolver),
        patch("redirect_analysis.tracer.time.monotonic", side_effect=[100.0, 100.0, 101.0]),
    ):
        result = resolve_public_candidates("example.com", 3.0)
    assert result == [PUBLIC_IP, "2606:4700:4700::1111"]
    calls = dns_resolver.resolve.call_args_list
    assert calls[0].args == ("example.com", "A")
    assert calls[0].kwargs == {"lifetime": 3.0, "search": False}
    assert calls[1].args == ("example.com", "AAAA")
    assert calls[1].kwargs == {"lifetime": 2.0, "search": False}


def test_dns_does_not_ignore_failed_second_address_family():
    import dns.resolver

    dns_resolver = MagicMock()
    dns_resolver.resolve.side_effect = [
        [MagicMock(address=PUBLIC_IP)],
        dns.resolver.LifetimeTimeout(),
    ]
    with (
        patch("dns.resolver.Resolver", return_value=dns_resolver),
        pytest.raises(TraceFailure) as caught,
    ):
        resolve_public_candidates("example.com", 3.0)
    assert caught.value.code == "DNS_TIMEOUT"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_redirects": -1},
        {"max_redirects": 21},
        {"max_redirects": True},
        {"total_timeout": 0},
        {"dns_timeout": float("inf")},
        {"approved_hosts": ("*.example.com",)},
        {"approved_hosts": "example.com"},
    ],
)
def test_invalid_policy_rejected(kwargs):
    with pytest.raises(ValueError):
        TracePolicy(**kwargs)
