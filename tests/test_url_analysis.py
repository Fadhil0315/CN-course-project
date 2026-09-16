"""Offline URL correctness and regressions for misleading representations."""

import pytest

from url_analysis import URLValidationError, analyze_url, normalize_url, registered_domain


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("HTTPS://EXAMPLE.COM:443/a?b=c#section", "https://example.com/a?b=c"),
        ("http://example.com", "http://example.com/"),
        ("https://example.com.:8443/", "https://example.com:8443/"),
        ("https://example.com。/", "https://example.com/"),
        ("https://bücher.de/über?q=café", "https://xn--bcher-kva.de/%C3%BCber?q=caf%C3%A9"),
        ("http://192.0.2.1:80/", "http://192.0.2.1/"),
        ("https://[2001:0db8:0:0:0:0:0:1]:443/a", "https://[2001:db8::1]/a"),
        ("https://example.com/a%20b?q=a%2Fb", "https://example.com/a%20b?q=a%2Fb"),
    ],
)
def test_normalization_is_deterministic_and_idempotent(source, expected):
    assert normalize_url(source) == expected
    assert normalize_url(expected) == expected


@pytest.mark.parametrize(
    "url",
    [
        "",
        "example.com",
        "ftp://example.com",
        "javascript:alert(1)",
        "https:///missing-host",
        "https://user:password@example.com",
        "https://user@example.com",
        "https://example.com:0",
        "https://example.com:65536",
        "https://example.com:",
        "https://example.com:bad",
        "https://[::1]evil.com/",
        "https://[not-ip]/",
        "https://[v1.foo]/",
        "https://[fe80::1%25en0]/",
        "https://example..com/",
        "https://example.com../",
        "https://example.com。./",
        "https://-example.com/",
        "https://example_com/",
        "https://example.com\\@evil.test/",
        " https://example.com/",
        "https://example.com/a b",
        "https://example.com/\nheader",
        "https://example.com/%0d%0aHeader",
        "https://example.com/%00",
        "https://example.com/%zz",
        "https://example.com/%",
        "https://example.com/\u200b",
        "https://" + "a" * 64 + ".com",
        "https://example.com/" + "a" * 8192,
    ],
)
def test_rejects_malformed_or_ambiguous_urls(url):
    with pytest.raises(URLValidationError) as error:
        normalize_url(url)
    assert error.value.code


@pytest.mark.parametrize(
    "host",
    [
        "2130706433",
        "127.1",
        "0177.0.0.1",
        "0x7f000001",
        "0x7f.0.0.1",
        "001.002.003.004",
        "127。0。0。1",
        "127.1。",
    ],
)
def test_rejects_noncanonical_numeric_ip_hosts(host):
    with pytest.raises(URLValidationError) as error:
        normalize_url(f"http://{host}/")
    assert error.value.code == "AMBIGUOUS_IP"


@pytest.mark.parametrize(
    ("hostname", "expected"),
    [
        ("login.example.co.uk", "example.co.uk"),
        ("a.b.example.com", "example.com"),
        ("docs.alice.github.io", "alice.github.io"),
        ("paypal.com.evil.test", "evil.test"),
        ("EXAMPLE.COM.", "example.com"),
        ("example.com。", "example.com"),
        ("bücher.de", "xn--bcher-kva.de"),
        ("192.0.2.1", "192.0.2.1"),
        ("2001:db8::1", "2001:db8::1"),
        ("localhost", "localhost"),
    ],
)
def test_registered_domain_uses_public_and_private_suffixes(hostname, expected):
    assert registered_domain(hostname) == expected


def codes(result):
    return {finding["code"] for finding in result["findings"]}


def test_detects_misleading_brand_subdomain_without_trusting_its_text():
    result = analyze_url("https://paypal.com.evil.test/login")
    assert "BRAND_IN_SUBDOMAIN" in codes(result)
    assert result["observations"]["registered_domain"] == "evil.test"
    assert result["score"] == 0.4


@pytest.mark.parametrize(
    "url",
    [
        "https://paypal.com/",
        "https://www.paypal.com/",
        "https://support.google.com/",
        "https://www.amazon.co.uk/",
    ],
)
def test_reference_brand_domains_do_not_trigger_impersonation(url):
    result = analyze_url(url)
    assert result["score"] == 0
    assert "BRAND_IN_SUBDOMAIN" not in codes(result)
    assert "BRAND_LOOKALIKE" not in codes(result)


def test_single_edit_lookalike_has_explanation_but_exact_brand_is_excluded():
    result = analyze_url("https://paypa1.example/")
    assert "BRAND_LOOKALIKE" in codes(result)
    assert result["score"] == 0.3
    assert "BRAND_LOOKALIKE" not in codes(analyze_url("https://paypal.test/"))


def test_idna_and_shortening_service_are_informational():
    for url, code in [
        ("https://bücher.de/", "INTERNATIONALIZED_HOST"),
        ("https://bit.ly/abc", "KNOWN_SHORTENER"),
    ]:
        result = analyze_url(url)
        assert code in codes(result)
        assert result["score"] == 0


def test_raw_ip_and_deep_subdomains_have_distinct_rules():
    assert analyze_url("https://192.0.2.1/")["score"] == 0.25
    result = analyze_url("https://a.b.c.d.example.com/")
    assert result["observations"]["subdomain_count"] == 4
    assert "DEEP_SUBDOMAINS" in codes(result)


def test_invalid_input_returns_unavailable_instead_of_zero_risk():
    result = analyze_url("mailto:someone@example.com")
    assert result["status"] == "unavailable"
    assert result["score"] is None
    assert result["errors"][0]["code"] == "UNSUPPORTED_SCHEME"


def test_no_blanket_tld_penalty():
    assert analyze_url("https://example.xyz/")["score"] == 0
