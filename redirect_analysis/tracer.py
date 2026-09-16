"""Inspect HTTP redirect headers without downloading or rendering page bodies.

Every hop is independently allowlisted and resolved. All returned addresses must
be public, then the connection is pinned to one vetted address. HTTPS preserves
the original hostname for SNI and certificate validation. This avoids resolving
the hostname a second time when opening the connection.

Resolver and transport injection support deterministic tests and labelled demo
fixtures; neither bypasses the destination checks in this module.
"""

from __future__ import annotations

import ipaddress
import math
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from shared.contracts import LayerResult, layer_result
from url_analysis import normalize_url, registered_domain

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
SHORTENER_DOMAINS = frozenset(
    {
        "bit.ly",
        "t.co",
        "tinyurl.com",
        "ow.ly",
        "is.gd",
        "rb.gy",
        "cutt.ly",
        "goo.gl",
        "shorturl.at",
        "lnkd.in",
    }
)
# IPv6 transition addresses can encode another IPv4 destination. Conservatively
# exclude them instead of relying on Python-version-specific is_global behavior
# or assumptions about the local network's NAT64/6to4/Teredo routing.
DISALLOWED_TRANSITION_NETWORKS = tuple(
    ipaddress.IPv6Network(prefix)
    for prefix in ("64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32")
)


@dataclass(frozen=True)
class TracePolicy:
    """Exact approved hostnames and finite resource limits for live tracing.

    The total budget is checked between operations. Socket connect/read timeouts
    bound individual waits, but are not a hard cancellation deadline against a
    server that continuously trickles response headers.
    """

    approved_hosts: tuple[str, ...] = ("example.com", "www.example.com", "httpbin.org")
    max_redirects: int = 5
    per_request_timeout: float = 4.0
    dns_timeout: float = 3.0
    total_timeout: float = 20.0

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_redirects, bool)
            or not isinstance(self.max_redirects, int)
            or not 0 <= self.max_redirects <= 20
        ):
            raise ValueError("max_redirects must be an integer between 0 and 20")
        for name in ("per_request_timeout", "dns_timeout", "total_timeout"):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError(f"{name} must be a finite positive number")
        if isinstance(self.approved_hosts, str):
            raise ValueError("approved_hosts must be a sequence of exact hostnames")
        hosts = []
        for host in self.approved_hosts:
            if not isinstance(host, str) or not host or any(char in host for char in "/:@*?#[]\\"):
                raise ValueError("approved_hosts must contain exact DNS hostnames")
            normalized = normalize_url(f"https://{host}")
            hosts.append(urlsplit(normalized).hostname)
        object.__setattr__(self, "approved_hosts", tuple(dict.fromkeys(hosts)))


@dataclass(frozen=True)
class HTTPResponse:
    """The only response data the tracer needs; response bodies are not read."""

    status: int
    location: str | None = None


Resolver = Callable[[str, float], list[str]]
Transport = Callable[[str, str, float], HTTPResponse]


class TraceFailure(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _public_address(address: str) -> str:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as exc:
        raise TraceFailure("INVALID_DNS_ADDRESS", "DNS returned an invalid IP address.") from exc
    is_transition = isinstance(parsed, ipaddress.IPv6Address) and any(
        parsed in network for network in DISALLOWED_TRANSITION_NETWORKS
    )
    if (
        not parsed.is_global
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
        or parsed.is_loopback
        or parsed.is_link_local
        or getattr(parsed, "ipv4_mapped", None) is not None
        or getattr(parsed, "scope_id", None) is not None
        or is_transition
    ):
        raise TraceFailure(
            "NON_PUBLIC_ADDRESS",
            "The destination resolves to a non-public or disallowed IP address.",
        )
    return str(parsed)


def resolve_public_candidates(hostname: str, timeout: float) -> list[str]:
    """Resolve A and AAAA within one shared DNS deadline.

    NoAnswer is acceptable for either family. An incomplete lookup (for example
    an AAAA timeout after an A response) fails closed, rather than ignoring a
    potentially unsafe address family.
    """
    try:
        return [str(ipaddress.ip_address(hostname))]
    except ValueError:
        pass
    import dns.resolver

    deadline = time.monotonic() + timeout
    dns_resolver = dns.resolver.Resolver()
    addresses: list[str] = []
    for record_type in ("A", "AAAA"):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TraceFailure("DNS_TIMEOUT", "DNS lookups exceeded their time budget.")
        try:
            answer = dns_resolver.resolve(hostname, record_type, lifetime=remaining, search=False)
            addresses.extend(str(record.address) for record in answer)
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN as exc:
            raise TraceFailure("DNS_NOT_FOUND", "The destination hostname does not exist.") from exc
        except dns.resolver.LifetimeTimeout as exc:
            raise TraceFailure("DNS_TIMEOUT", "DNS lookups exceeded their time budget.") from exc
        except dns.resolver.NoNameservers as exc:
            raise TraceFailure(
                "DNS_FAILURE", "No DNS server could answer the destination lookup."
            ) from exc
    if not addresses:
        raise TraceFailure("DNS_NO_ADDRESSES", "DNS returned no A or AAAA addresses.")
    return list(dict.fromkeys(addresses))


def request_headers(url: str, address: str, timeout: float) -> HTTPResponse:
    """Make one verified, IP-pinned GET and close it after reading the headers.

    urllib3 does not inherit environment proxies or send a cookie jar. Separate
    pools per hop avoid retaining authentication or cookies across destinations.
    """
    import certifi
    import urllib3

    parsed = urlsplit(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    timeout_config = urllib3.Timeout(total=timeout, connect=timeout, read=timeout)
    if parsed.scheme == "https":
        pool = urllib3.HTTPSConnectionPool(
            host=address,
            port=port,
            timeout=timeout_config,
            maxsize=1,
            block=True,
            server_hostname=hostname,
            assert_hostname=hostname,
            cert_reqs=ssl.CERT_REQUIRED,
            ca_certs=certifi.where(),
        )
    else:
        pool = urllib3.HTTPConnectionPool(
            host=address, port=port, timeout=timeout_config, maxsize=1, block=True
        )
    host_header = hostname
    if ":" in hostname:
        host_header = f"[{hostname}]"
    if port != (443 if parsed.scheme == "https" else 80):
        host_header = f"{host_header}:{port}"
    target = parsed.path or "/"
    if parsed.query:
        target += f"?{parsed.query}"
    response = None
    try:
        response = pool.request(
            "GET",
            target,
            headers={
                "Host": host_header,
                "User-Agent": "QR-Phishing-Shield-Coursework/0.1",
                "Accept": "*/*",
                "Connection": "close",
            },
            retries=False,
            redirect=False,
            preload_content=False,
            decode_content=False,
            timeout=timeout_config,
        )
        return HTTPResponse(status=response.status, location=response.headers.get("Location"))
    finally:
        if response is not None:
            response.close()
            response.release_conn()
        pool.close()


def _findings_and_score(
    hops: list[dict], redirect_count: int, loop_detected: bool
) -> tuple[list[dict], float]:
    findings: list[dict] = []
    score = 0.0

    def add(
        code: str, severity: str, message: str, hop_index: int | None, details: dict, weight: float
    ) -> None:
        nonlocal score
        findings.append(
            {
                "code": code,
                "severity": severity,
                "message": message,
                "hop_index": hop_index,
                "details": details,
            }
        )
        score += weight

    # Score only transitions actually observed in HTTP response headers, never
    # infer that a failed/blocked destination is a completed network request.
    domain_changes = 0
    for hop in hops:
        if hop["status_code"] is not None and hop["status_code"] >= 400:
            add(
                "HTTP_ERROR_RESPONSE",
                "info",
                "The destination returned an HTTP error status; no further HTTP redirect was observed and page content was not evaluated.",
                hop["index"],
                {"status_code": hop["status_code"]},
                0.0,
            )
        if not hop["next_url"]:
            continue
        target = urlsplit(hop["next_url"])
        if registered_domain(hop["hostname"]) != registered_domain(target.hostname):
            domain_changes += 1
            add(
                "REDIRECT_DOMAIN_CHANGE",
                "info",
                "An HTTP redirect changes the registered domain.",
                hop["index"],
                {"from": hop["hostname"], "to": target.hostname},
                0.12 if domain_changes <= 3 else 0.0,
            )
        if hop["scheme"] == "https" and target.scheme == "http":
            add(
                "HTTPS_DOWNGRADE",
                "warning",
                "An HTTPS response redirects to an unencrypted HTTP URL.",
                hop["index"],
                {"destination": hop["next_url"]},
                0.35,
            )
    if redirect_count > 3:
        add(
            "LONG_REDIRECT_CHAIN",
            "info",
            "The observed chain contains more than three HTTP redirects.",
            None,
            {"redirect_count": redirect_count},
            min(0.20, (redirect_count - 3) * 0.05),
        )
    shorteners = sorted(
        {registered_domain(hop["hostname"]) for hop in hops if hop["status_code"] is not None}
        & SHORTENER_DOMAINS
    )
    if len(shorteners) >= 2:
        add(
            "STACKED_SHORTENERS",
            "warning",
            "The observed chain passes through multiple known shortening services.",
            None,
            {"domains": shorteners},
            0.20,
        )
    if loop_detected:
        add(
            "REDIRECT_LOOP",
            "warning",
            "The redirect chain returns to a URL already visited.",
            None,
            {},
            0.20,
        )
    return findings, round(min(score, 1.0), 4)


def trace_redirects(
    url: str,
    *,
    policy: TracePolicy | None = None,
    resolver: Resolver | None = None,
    transport: Transport | None = None,
) -> LayerResult:
    """Trace an approved URL and return the shared analysis-layer contract.

    ``max_redirects`` counts allowed transitions: five allows six requests.
    ``redirect_count`` counts redirect responses observed, which may be one
    larger when a chain is stopped at the limit. Only HTTP Location redirects
    are handled; JavaScript and HTML meta redirects are not executed.

    Completion describes HTTP redirect inspection, not a successful page load.
    A terminal 4xx/5xx response is retained as an informational finding and does
    not itself imply phishing. The total timeout is a soft operation budget;
    see TracePolicy for the socket-timeout limitation.
    """
    policy = policy or TracePolicy()
    resolver = resolver or resolve_public_candidates
    transport = transport or request_headers
    started = time.monotonic()
    hops: list[dict] = []
    errors: list[dict] = []
    seen: set[str] = set()
    redirect_count = 0
    followed_count = 0
    complete = False
    loop_detected = False

    def remaining() -> float:
        value = policy.total_timeout - (time.monotonic() - started)
        if value <= 0:
            raise TraceFailure("TOTAL_TIMEOUT", "Redirect tracing exceeded its total time budget.")
        return value

    def record_error(code: str, message: str, hop: dict | None = None) -> None:
        error = {"code": code, "message": message, "hop_index": hop["index"] if hop else None}
        errors.append(error)
        if hop is not None:
            hop["error"] = error.copy()

    try:
        current = normalize_url(url)
    except ValueError as exc:
        record_error(getattr(exc, "code", "INVALID_URL"), str(exc))
        current = None

    while current is not None:
        parsed = urlsplit(current)
        hop = {
            "index": len(hops),
            "url": current,
            "scheme": parsed.scheme,
            "hostname": parsed.hostname,
            "port": parsed.port or (443 if parsed.scheme == "https" else 80),
            "status_code": None,
            "next_url": None,
            "error": None,
            "network_eligible": False,
        }
        hops.append(hop)
        try:
            remaining()
            if parsed.hostname not in policy.approved_hosts:
                raise TraceFailure(
                    "HOST_NOT_APPROVED",
                    "This exact destination hostname is not approved for live tracing.",
                )
            if hop["port"] not in {80, 443}:
                raise TraceFailure(
                    "PORT_NOT_ALLOWED", "Only destination ports 80 and 443 are allowed."
                )
            seen.add(current)
            candidates = resolver(parsed.hostname, min(policy.dns_timeout, remaining()))
            if not candidates:
                raise TraceFailure("DNS_NO_ADDRESSES", "DNS returned no destination addresses.")
            # Validate the complete answer set before opening any connection.
            addresses = [_public_address(address) for address in candidates]
            # Integration may pass only these destinations to Charan's module.
            # It must still independently validate any new DNS answers before
            # making its own connections; this flag is not a reusable permit.
            hop["network_eligible"] = True
            request_timeout = min(policy.per_request_timeout, remaining())
            if hop["index"] > 0:
                followed_count += 1
            response = transport(current, addresses[0], request_timeout)
            remaining()
            if (
                isinstance(response.status, bool)
                or not isinstance(response.status, int)
                or not 100 <= response.status <= 599
            ):
                raise TraceFailure(
                    "INVALID_HTTP_RESPONSE", "The transport returned an invalid HTTP status."
                )
            hop["status_code"] = response.status
            if response.status not in REDIRECT_STATUSES:
                complete = True
                break
            redirect_count += 1
            if not isinstance(response.location, str) or not response.location.strip():
                raise TraceFailure(
                    "MISSING_LOCATION",
                    "A redirect response did not include a usable Location header.",
                )
            # Validate raw headers BEFORE urljoin: urllib strips some control
            # characters, which must be rejected rather than silently accepted.
            location = response.location
            if (
                any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in location)
                or "\\" in location
            ):
                raise TraceFailure(
                    "INVALID_LOCATION", "The redirect Location contains forbidden characters."
                )
            try:
                destination = normalize_url(urljoin(current, location))
            except ValueError as exc:
                raise TraceFailure(
                    "INVALID_LOCATION",
                    f"The redirect destination is not a supported HTTP(S) URL: {exc}",
                ) from exc
            hop["next_url"] = destination
            if destination in seen:
                loop_detected = True
                raise TraceFailure("REDIRECT_LOOP", "The redirect destination was already visited.")
            if followed_count >= policy.max_redirects:
                raise TraceFailure(
                    "REDIRECT_LIMIT", "The chain exceeds the configured redirect limit."
                )
            current = destination
        except TraceFailure as exc:
            record_error(exc.code, str(exc), hop)
            break
        except Exception as exc:
            # Network and injected-dependency failures remain observable data;
            # callers never have to mistake a failed trace for a safe result.
            record_error(
                "REQUEST_FAILED", f"The network operation failed ({type(exc).__name__}).", hop
            )
            break

    findings, observed_score = _findings_and_score(hops, redirect_count, loop_detected)
    observed_response = any(hop["status_code"] is not None for hop in hops)
    return layer_result(
        status="complete" if complete else ("partial" if observed_response else "unavailable"),
        score=observed_score if observed_response else None,
        findings=findings,
        observations={
            "hops": hops,
            "redirect_count": redirect_count,
            "followed_redirect_count": followed_count,
            "max_redirects": policy.max_redirects,
            "elapsed_seconds": round(time.monotonic() - started, 4),
            "http_only": True,
            "limitations": [
                "JavaScript and HTML meta redirects are not executed.",
                "A completed HTTP trace does not establish that a website is safe.",
            ],
        },
        errors=errors,
    )
