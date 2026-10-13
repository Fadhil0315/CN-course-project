"""Network evidence under DNS, TLS and provider success and failure, without internet."""

import ssl
from types import SimpleNamespace
from unittest.mock import MagicMock

import dns.resolver
import pytest

from network_analysis.analyzer import analyze_network, score_observations
from network_analysis.asn_lookup import lookup_asn
from network_analysis.dns_checks import check_dns
from network_analysis.tls_checks import check_tls
from shared.contracts import validate_layer_result

PUBLIC = "93.184.216.34"


class Answer(list):
    rrset = SimpleNamespace(ttl=120)


def test_dns_collects_both_families_and_ttl():
    resolver = MagicMock()
    resolver.resolve.side_effect = [
        Answer([SimpleNamespace(address=PUBLIC)]),
        Answer([SimpleNamespace(address="2606:4700:4700::1111")]),
    ]
    result = check_dns("example.com", resolver=resolver)
    assert result["status"] == "complete"
    assert result["records"][1]["type"] == "AAAA"
    assert result["records"][0]["ttl"] == 120
    assert all(call.kwargs["search"] is False for call in resolver.resolve.call_args_list)


@pytest.mark.parametrize(
    "second",
    [
        TimeoutError("timeout"),
        dns.resolver.NXDOMAIN(),
        Answer([SimpleNamespace(address="127.0.0.1")]),
    ],
)
def test_dns_incomplete_or_mixed_addresses_fail_closed(second):
    resolver = MagicMock()
    resolver.resolve.side_effect = [Answer([SimpleNamespace(address=PUBLIC)]), second]
    result = check_dns("example.com", resolver=resolver)
    assert result["status"] == "unavailable"
    assert result["validated_public"] is False


def test_dns_noanswer_and_public_literal():
    resolver = MagicMock()
    resolver.resolve.side_effect = [
        Answer([SimpleNamespace(address=PUBLIC)]),
        dns.resolver.NoAnswer(),
    ]
    assert check_dns("example.com", resolver=resolver)["status"] == "complete"
    resolver.reset_mock()
    assert check_dns(PUBLIC, resolver=resolver)["records"] == []
    resolver.resolve.assert_not_called()
    assert check_dns("::1")["status"] == "unavailable"


def test_asn_parses_origin_and_organization():
    resolver = MagicMock()
    resolver.resolve.side_effect = [
        [SimpleNamespace(strings=(b"15169 | 8.8.8.0/24 | US | arin | 1992-12-01",))],
        [SimpleNamespace(strings=(b"15169 | US | arin | 2000-03-30 | GOOGLE, US",))],
    ]
    result = lookup_asn("8.8.8.8", resolver=resolver)
    assert result["status"] == "complete"
    assert result["organizations"] == [{"asn": 15169, "name": "GOOGLE, US"}]
    assert resolver.resolve.call_args_list[0].args[0] == "8.8.8.8.origin.asn.cymru.com"
    assert result["prefixes"][0]["registry_country"] == "US"


def test_asn_provider_timeout_and_wrong_prefix():
    resolver = MagicMock()
    resolver.resolve.side_effect = TimeoutError("unavailable")
    assert lookup_asn(PUBLIC, resolver=resolver)["status"] == "unavailable"
    resolver.resolve.side_effect = [
        [SimpleNamespace(strings=(b"1 | 1.1.1.0/24 | US | arin | date",))]
    ]
    assert lookup_asn(PUBLIC, resolver=resolver)["status"] == "unavailable"


def test_asn_ipv6_query_uses_reverse_nibbles():
    resolver = MagicMock()
    resolver.resolve.side_effect = TimeoutError()
    lookup_asn("2606:4700:4700::1111", resolver=resolver)
    name = resolver.resolve.call_args.args[0]
    assert name.endswith(".origin6.asn.cymru.com")
    assert len(name.split(".")[:-4]) == 32


def test_tls_success_pins_ip_and_validates_hostname(monkeypatch):
    context = MagicMock()
    connection = context.wrap_socket.return_value.__enter__.return_value
    cert = {
        "notBefore": "Jan  1 00:00:00 2026 GMT",
        "notAfter": "Jan  1 00:00:00 2027 GMT",
        "issuer": ((("organizationName", "Test CA"),),),
        "subjectAltName": (("DNS", "example.com"),),
    }
    connection.getpeercert.side_effect = [cert, b"DER certificate"]
    connection.version.return_value = "TLSv1.3"
    connection.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    connection.selected_alpn_protocol.return_value = "http/1.1"
    socket_mock = MagicMock()
    monkeypatch.setattr("network_analysis.tls_checks.socket.create_connection", socket_mock)
    monkeypatch.setattr(
        "network_analysis.tls_checks.ssl.create_default_context", lambda **kwargs: context
    )
    result = check_tls("example.com", PUBLIC)
    assert socket_mock.call_args.args[0] == (PUBLIC, 443)
    assert context.wrap_socket.call_args.kwargs["server_hostname"] == "example.com"
    assert result["validated"] is True
    assert result["hostname_match"] is True
    assert len(result["certificate_sha256"]) == 64


@pytest.mark.parametrize("verify_code", [10, 18, 62])
def test_tls_invalid_certificate_is_negative_evidence_not_transport_failure(
    monkeypatch, verify_code
):
    context = MagicMock()
    error = ssl.SSLCertVerificationError("invalid certificate")
    error.verify_code, error.verify_message = verify_code, "synthetic validation error"
    context.wrap_socket.side_effect = error
    monkeypatch.setattr("network_analysis.tls_checks.socket.create_connection", MagicMock())
    monkeypatch.setattr(
        "network_analysis.tls_checks.ssl.create_default_context", lambda **kwargs: context
    )
    result = check_tls("example.com", PUBLIC)
    assert result["status"] == "complete"
    assert result["validated"] is False
    assert context.wrap_socket.call_count == 1  # no insecure retry


def test_tls_timeout_is_missing_evidence(monkeypatch):
    def timeout(*args, **kwargs):
        raise TimeoutError("test")

    monkeypatch.setattr("network_analysis.tls_checks.socket.create_connection", timeout)
    result = check_tls("example.com", PUBLIC)
    assert result["status"] == "unavailable"
    assert result["validated"] is None


def hop(index=0, scheme="https"):
    return {
        "index": index,
        "url": f"{scheme}://example.com/{index}",
        "hostname": "example.com",
        "network_eligible": True,
    }


def dns_ok(*args, **kwargs):
    return {
        "status": "complete",
        "addresses": [PUBLIC],
        "records": [{"type": "A", "address": PUBLIC, "ttl": 10}],
        "errors": [],
    }


def tls_ok(*args, **kwargs):
    return {"status": "complete", "validated": True, "certificate_age_days": 2, "errors": []}


def asn_ok(*args, **kwargs):
    return {"status": "complete", "ip": PUBLIC, "asns": [1234], "errors": []}


def test_analyzer_caches_endpoint_evidence_and_does_not_penalize_recent_certificates():
    dns_mock = MagicMock(side_effect=dns_ok)
    tls_mock = MagicMock(side_effect=tls_ok)
    result = analyze_network(
        [hop(0), hop(1)], dns_checker=dns_mock, tls_checker=tls_mock, asn_checker=asn_ok
    )
    validate_layer_result(result)
    assert result["status"] == "complete" and result["score"] == 0
    assert dns_mock.call_count == tls_mock.call_count == 1
    assert result["observations"]["hops"][1]["hop_index"] == 1
    assert result["observations"]["hops"][1]["cached"] is True


def test_analyzer_revalidates_dns_and_never_connects_to_private_address():
    blocked = dns_ok()
    blocked["addresses"].append("192.168.1.1")
    transport = MagicMock()
    result = analyze_network(
        [hop()], dns_checker=lambda *a, **k: blocked, tls_checker=transport, asn_checker=transport
    )
    transport.assert_not_called()
    assert result["status"] == "unavailable" and result["score"] is None


def test_asn_outage_retains_tls_findings_and_partial_status():
    result = analyze_network(
        [hop()],
        dns_checker=dns_ok,
        tls_checker=lambda *a, **k: {"status": "complete", "validated": False, "errors": []},
        asn_checker=lambda *a, **k: {"status": "unavailable", "errors": []},
    )
    assert result["status"] == "partial" and result["score"] == 0.85


def test_http_skips_tls_and_hosting_baseline_is_explicit():
    transport = MagicMock()
    result = analyze_network(
        [hop(scheme="http")],
        dns_checker=dns_ok,
        tls_checker=transport,
        asn_checker=asn_ok,
        expected_asns=(9876,),
    )
    transport.assert_not_called()
    assert result["score"] == 0.55
    assert {f["code"] for f in result["findings"]} >= {
        "HOSTING_BASELINE_MISMATCH",
        "UNENCRYPTED_HTTP",
    }


def test_empty_and_ineligible_hops():
    assert score_observations([])["status"] == "unavailable"
    bad = hop()
    bad["network_eligible"] = False
    with pytest.raises(ValueError):
        analyze_network([bad])
