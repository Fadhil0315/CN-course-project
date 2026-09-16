# QR Phishing Shield

A local Computer Networks course prototype by Fadhil and Charan. This milestone implements **Fadhil's QR input, lexical URL analysis, bounded HTTP redirect tracing, and dashboard**. It makes no novelty or validated detection-accuracy claim.

**Charan's DNS/TLS/ASN analysis and composite scoring are not implemented here.** The dashboard displays a pending final score until his modules are integrated. A lexical sub-score is not an overall verdict.

## Run locally

Requires Python 3.12 or newer (the locked NumPy version requires 3.12). Run these commands from the project directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-lock.txt
python -m pip install --no-deps -e .
python -m streamlit run app.py
```

If the virtual environment is already installed, only activation and the last command are needed. `requirements-lock.txt` records the tested dependency versions; it does not include the project itself. For dependency updates use `python -m pip install -e '.[dev]'` and re-run tests before replacing the lock.

The app binds to localhost. Choose **Demo scenarios** for a fully offline demonstration. Upload PNG, JPEG, or WebP QR images, or paste a URL for offline lexical inspection. Live tracing is an explicit option and contacts only the exact public hostnames you approve; every redirect target must also be approved.

## Repeatable command-line demonstrations

```bash
python cli.py --demo ordinary
python cli.py --demo suspicious
python cli.py --demo loop
python cli.py --image examples/ordinary.png
python cli.py --url 'https://example.com/' --live
```

All commands except the last are offline. Demo QR images are really decoded; their HTTP headers and resolver addresses are synthetic. No malicious websites are visited. The examples are functional test scenarios, not a labelled research dataset or accuracy benchmark.

## Verify

```bash
python -m pytest
python -m ruff check .
python -m ruff format --check .
```

The automated tests use injected resolvers/transports; they do not require internet access. They cover actual image decoding, URL validation, redirect failure behavior, network destination restrictions, integration boundaries, and dashboard interactions.

## Responsibilities and layout

| Path | Owner / purpose |
|---|---|
| `qr_input/` | Fadhil: bounded single-QR decoding |
| `url_analysis/` | Fadhil: normalization and explainable URL rules |
| `redirect_analysis/` | Fadhil: HTTP redirect inspection and request policy |
| `pipeline.py`, `app.py`, `cli.py` | Fadhil: orchestration, dashboard, command-line demo |
| `shared/contracts.py` | Shared version 1 result types and validation |
| `network_analysis/` | Reserved for Charan; not supplied in this milestone |
| `scoring/` | Reserved for Charan; not supplied in this milestone |
| `docs/CHARAN_HANDOFF.md` | Charan's implementation instructions |
| `docs/interfaces.md` | Exact integration contract |
| `docs/review2.md` | Demonstration plan, actual scope, and limitations |
| `docs/contributions.md` | Honest contribution/evidence record |

## Request boundaries and limitations

- HTTP(S) only; credentials in URLs are rejected. Live requests allow ports 80 and 443 only.
- Exact hostname allowlist, public-IP checks for all DNS answers, and connections pinned to a validated address. HTTPS uses the original hostname for SNI and certificate checking.
- No proxy environment, cookies, browser execution, automatic redirects, or webpage rendering. Response bodies are not downloaded for analysis.
- Redirect and timeout limits are defensive bounds, not a full sandbox. This prototype is intended for local, approved demonstrations, not deployment as a public URL scanning service.
- Only HTTP Location redirects are supported. JavaScript and HTML meta-refresh redirects remain outside scope.
- Scores and thresholds are provisional. No result guarantees safety. Network failures are missing evidence, not a zero-risk finding.
- The bundled Public Suffix List is used offline; it can age. The brand reference set is small. Unicode/confusable detection is limited.
- Input URLs and query strings can contain private information. Analysis stays in session memory unless you choose to export a report; inspect exports before sharing.

## Design references

- [OpenCV QRCodeDetector](https://docs.opencv.org/4.x/de/dc3/classcv_1_1QRCodeDetector.html)
- [urllib3 custom SNI hostname](https://urllib3.readthedocs.io/en/stable/advanced-usage.html#custom-sni-hostname)
- [Streamlit AppTest](https://docs.streamlit.io/develop/api-reference/app-testing/st.testing.v1.apptest)

QR structural analysis is deferred to Review 3 with a provisional 5% weight. Batch mode, webcam capture, broader evaluation, and score calibration are also deferred.
