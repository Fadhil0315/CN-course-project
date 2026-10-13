# Verification record — 11 October 2026

Environment: macOS Apple silicon, Python 3.12, the committed `requirements-lock.txt`, application version 1.0.0. This record describes observed checks, not a production certification or real-world QR phishing accuracy claim.

## Automated checks

- **231 tests passed** in the final project-environment run (`python -m pytest -q`, 6.25 seconds).
- A fresh virtual environment installed the complete locked dependencies and a non-editable application wheel. The then-current **227-test suite also passed** there; the final four additional tests exercise dashboard upload/model workflows in the project environment.
- Ruff lint and formatting checks passed. `git diff --check` passed. The clean environment's `pip check` reported no broken requirements.
- Installed `qr-phishing-shield --demo suspicious` and `qr-shield-evaluate --help` worked from `/private/tmp`, outside the source tree.

Tests cover URL normalization and lexical rules, redirect policies and loop handling, private/mixed DNS rejection, IPv4/IPv6 ASN parsing, verified TLS and certificate failures, optional geolocation validation and resource cleanup, scoring boundaries and missing evidence, QR format/ECC/pattern checks, native decoding fallbacks, batch limits/deduplication/failure isolation, CSV formula protection, hard scan deadlines and child cleanup, dataset label conversion and split leakage, model validation, metrics and validation-only calibration.

Streamlit tests exercise explicit analysis/reset, report persistence across input changes, incomplete-score warnings, camera empty-input handling, processing captured image bytes, saved batch result selection without rescanning, the fixture benchmark and the bundled lexical model. Upload tests substitute only the file chooser boundary; image upload, image batches and CSV batches then execute the real scanner, parser, workers and report rendering.

## Live and demonstration runs

- A live URL scan of `https://example.com/` with optional geolocation completed DNS, verified TLS, ASN and geolocation observations. Its URL-only assessment excluded QR structure as expected.
- A live scan of `examples/ordinary.png` completed **all four layers**, returned **100% completed evidence weight** and a score of **0/100** with no network errors. This benign smoke test demonstrates integration, not website safety or classifier accuracy.
- `--demo-batch` ran through isolated workers. All five demo scenarios use actual QR decoding with explicitly synthetic transport and network evidence.
- The misleading-domain demo returned **46/100, suspicious**, with contributions of 8 URL points, 20.5 redirect points, 17.5 network points and 0 structural points. The invalid-certificate demo retained its network finding while reporting insufficient overall evidence after the failed redirect request.
- Actual image transformations decoded the expected payload in **16/16 cases**: two payloads across clean, 90°/15° rotation, low resolution, blur, low contrast, perspective and JPEG degradation. This is a small reproducible robustness suite, not a field camera study.

The measurements above describe the recorded verification run. Saved scan outputs are generated artifacts and are not required to run the application. Commands in the README recreate the offline benchmark, calibration, robustness and demo reports in the ignored `reports/` directory. A new live scan collects current evidence, which may differ from the historical observations above.

## Model experiment

The bundled eight-feature lexical model uses a deterministic 12,000-URL UCI PhiUSIIL sample with disjoint registered-domain splits: 7,201 train, 2,354 validation and 2,445 test URLs. Validation selected threshold 0.4. The test split produced TP=1,017, FP=11, TN=1,230, FN=187: 91.90% accuracy, 98.93% precision and 84.47% recall. Dataset attribution, checksum, split metadata and limitations are in `models/README.md` and the model JSON.

These are historical, balanced **URL-only** results. They do not measure the four-layer scanner, live network evidence or QR phishing accuracy. The model remains an optional separate signal. No dataset destination was contacted.

## Interface review

Chrome captures were inspected at 1365 × 900 and 390 × 844, including separate input and scrolled report views. Mobile document width equaled viewport width. Native evidence tabs and tables scroll within their own regions. Temporary review screenshots are not part of the final application.

The interface review identified a caption-contrast issue. The caption container's inherited opacity was removed and the caption color set to `#34485e`. The optional design detector did not run because its launcher could not initialize its cache; this was not treated as a detector pass.

The Chrome automation extension denied file upload because its local-file access was unavailable. This blocked browser automation of the picker, not a known application upload failure. The corresponding application paths passed the Streamlit tests described above. Browser/native automation could not complete a physical webcam capture; no camera permission was granted. Physical camera permission, lighting and device-specific capture remain manual verification items.

## Practical limits

DNS/TLS/enrichment observations can change and providers can fail or rate-limit. The app reports such gaps; it does not convert them to evidence of safety. Only HTTP Location redirects are followed. QR structure is experimental and limited to 5% weight. Weights and bands remain explainable heuristics. The local tool is not intended as a publicly exposed scanning service.
