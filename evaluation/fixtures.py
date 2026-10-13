"""Labelled, constructed scenarios. Labels describe author intent, not intelligence feeds."""

from urllib.parse import urlsplit

from demo_cases import synthetic_network
from pipeline import _analyze_chain_urls, _base_report, _compare_destination, _finish
from redirect_analysis import HTTPResponse, TracePolicy, trace_redirects
from shared.contracts import layer_result
from url_analysis import analyze_url


def fixture_cases() -> list[dict]:
    cases = []
    for split, prefix in (("train", "train"), ("validation", "valid"), ("test", "test")):
        for category in range(10):
            host = f"{prefix}-{category}.test"
            url = f"https://{host}/"
            case = {
                "id": f"{split}-{category}",
                "group": host,
                "split": split,
                "label": int(category >= 5),
                "url": url,
                "responses": {url: (200, None)},
                "provenance": "constructed synthetic scenario",
            }
            if category == 1:  # Ordinary analytics redirect.
                end = f"https://{host}/landing"
                case["responses"] = {url: (302, end), end: (200, None)}
            elif category == 2:  # Benign provider change is not inherently malicious.
                end = f"https://cdn-{host}/"
                case["responses"] = {url: (302, end), end: (200, None)}
            elif category == 3:  # Long but legitimate path.
                case["url"] = url + "documentation/" * 18
                case["responses"] = {case["url"]: (200, None)}
            elif category == 4:  # Failed benign check should abstain.
                case["invalid_tls"] = True
            elif category == 5:
                case["url"] = f"https://paypal.com.{host}/start"
                end = f"http://landing-{host}/login"
                case["responses"] = {case["url"]: (302, end), end: (200, None)}
                case["expected_domain"] = "paypal.com"
            elif category == 6:  # Clean-looking phishing is an intentional false negative.
                case["note"] = (
                    "Malicious intent is not inferable from these clean network/URL features"
                )
            elif category == 7:
                case["url"] = f"https://microsoft.com.{host}/"
                case["responses"] = {case["url"]: (200, None)}
                case["invalid_tls"] = True
            elif category == 8:
                end = f"http://google.com.{host}/signin"
                case["responses"] = {url: (302, end), end: (200, None)}
                case["expected_domain"] = "google.com"
            elif category == 9:  # An evasive loop must abstain, not claim high confidence.
                case["responses"] = {url: (302, "/again"), url + "again": (302, "/")}
            cases.append(case)
    return cases


def replay_fixture(case: dict) -> dict:
    report = _base_report("fixture", "synthetic")
    report["input"]["url"] = case["url"]
    report["layers"]["lexical"] = analyze_url(case["url"])
    hosts = tuple(sorted({urlsplit(url).hostname for url in case["responses"]}))

    def transport(url, address, timeout):
        if case.get("invalid_tls"):
            raise OSError("Synthetic TLS validation failure")
        return HTTPResponse(*case["responses"][url])

    report["layers"]["redirect"] = trace_redirects(
        case["url"],
        policy=TracePolicy(approved_hosts=hosts),
        resolver=lambda host, timeout: ["93.184.216.34"],
        transport=transport,
    )
    report["layers"]["network"] = synthetic_network(
        case, report["layers"]["redirect"]["observations"]["hops"]
    )
    # This benchmark isolates evidence aggregation; actual image transformations
    # and format extraction are measured by the separate robustness suite.
    report["layers"]["qr_structure"] = layer_result(
        status="complete",
        score=0,
        evidence_source="synthetic",
        observations={"note": "Declared clean structure fixture; not an image measurement"},
    )
    _analyze_chain_urls(report)
    if case.get("expected_domain"):
        _compare_destination(report, case["expected_domain"])
    for layer in report["layers"].values():
        layer["evidence_source"] = "synthetic"
    return _finish(report, use_network=False)
