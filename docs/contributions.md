# Contribution and verification record

## Ownership

| Owner | Responsibility |
|---|---|
| Fadhil | QR input, URL analysis, HTTP redirect tracing, dashboard, application integration, and related tests |
| Charan | DNS/TLS/ASN collection, network sub-score, final scoring, and related tests — pending separate implementation |

## Current development record

2026-09-16: Fadhil requested implementation of his modules with Codex assistance. Code, tests, shared interface documentation, and Charan's handoff were generated with that assistance. This log records the actual implementation session; it does not claim Fadhil manually authored every line or that Charan has already contributed code. Both students should review and be able to explain their assigned work and follow the course's assistance policy.

Completed implementation areas in this session:

- Versioned JSON-compatible integration contract and explicit missing-module behavior.
- Bounded single-QR image decoding and malformed-input handling.
- Offline URL normalization, public-suffix-aware domain extraction, and explainable rules.
- Allowlisted HTTP redirect tracing with validated IP pinning and failure reporting.
- Streamlit dashboard, deterministic synthetic demonstrations, CLI, and module/integration tests.
- Handoff documentation specifying Charan's responsibilities and plug-in import paths.

Actual setup issue: initial dependency installation could not reach the package index within the restricted environment; an authorized network-enabled installation was used. An OpenCV wheel download then timed out, so it was retried with a longer read timeout and a local dependency cache. These are setup issues, not detection-algorithm findings.

Actual integration review findings and adaptations:

- A trace records a blocked destination so the user can see why it stopped. Forwarding all those records to the future network provider would cross the user's approved-host boundary. Added an explicit eligibility marker and filtered the provider input while preserving the full display trace. Eligible TLS failures can still be inspected; blocked targets cannot.
- Nested plugin values such as datetime objects could pass shallow checks and later crash JSON export. Added recursive JSON/finite-number validation at module boundaries.
- A future scorer could return contradictory coverage, verdict, and score fields. Added cross-field checks and a distinct provisional-score label for incomplete assessments.

These were found through code review before Charan's modules existed. Regression tests cover the cases; they are not claims of bugs encountered in a deployed detector.

Actual runtime finding: OpenCV did not decode the clean QR generated for the misleading-domain demonstration at its original size. A bounded half-scale grayscale pass decoded it successfully. The decoder now includes that fallback and the exact payload has a regression test. Very thin valid images also needed minimum-one-pixel resize dimensions to avoid an unhandled OpenCV exception.

Test and runtime results are recorded in verification.md. The initial local build was completed before Git setup. Its implementation is captured in one commit on `fadhil/input-redirect-ui` in https://github.com/Fadhil0315/CN-qr-phishing, using Fadhil's configured Git author and committer identity. Remote publication status can be checked with `git status -sb`; no earlier history has been invented.

## Template for subsequent human contributions

| Date | Person | Task/change | Evidence (commit/PR/test artifact) | Result/problem and response |
|---|---|---|---|---|
| | | | | |

Use actual changes and actual test results. Do not backdate entries or distribute code under another person's identity to create artificial contribution evidence.
