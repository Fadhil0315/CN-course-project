# Verification record

Verified during the 2026-09-16 implementation session on macOS, Python 3.12.4. Dependency versions are captured in requirements-lock.txt.

## Automated checks

- Full suite: **172 passed**.
- Ruff lint: passed.
- Ruff format check: passed after formatting.
- Dependency compatibility (`python -m pip check`): no broken requirements.

The same full suite and quality checks were repeated successfully from the installed project at `/Users/fadhil/projects/CN-qr-phishing` using its own `.venv` (172 passed in 35.28 seconds on the initial run there).

The suite exercises real QR image generation/decoding, invalid and ambiguous input, URL canonicalization, brand/domain rules, all supported HTTP redirect statuses, loops and budgets, mixed/private DNS answers, IPv6 transition addresses, hostname-preserving IP-pinned TLS transport configuration, provider contract validation, blocked-hop isolation, incomplete scoring behavior, and dashboard state persistence.

All automated tests are offline. Synthetic resolver addresses and HTTP responses are injected; they are not real network evidence. Tests injecting a fake network/scoring provider verify integration contracts only and do not implement or validate Charan's collectors/scoring algorithm.

## Separate live smoke check

Approved destination: https://example.com/

- Mode: live.
- Observed HTTP status: 200.
- Redirect analysis: complete, no redirects.
- The transport used DNS-vetted address pinning, original-hostname TLS verification, and header-only processing.
- Charan's network analysis: not implemented.
- Composite score: null, as expected.

This single connectivity check validates a benign request path, not detection accuracy or reliability across arbitrary websites. The response can change on later runs.

## Browser verification

Launched the installed project's Streamlit dashboard on 127.0.0.1:8501. In the browser, selected Misleading domain + redirect and ran the analysis. Confirmed actual decoded QR preview, the expected URL, lexical sub-score 40/100, redirect sub-score 47/100, final score Pending, and synthetic evidence labels. The redirect table displayed the expected 302 then 200 responses and distinct hostnames. Checked the rendered layout at the browser's current narrow viewport; cards and controls remained usable.

## Scope still unverified

Real DNS TTL/TLS certificate/ASN evidence collection by Charan, composite scoring, phishing classification accuracy, larger datasets, webcam capture, and QR structural risk features remain outside this milestone.
